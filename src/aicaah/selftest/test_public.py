"""Portable AICAAH installation, parsing, policy and incremental-cache regression tests."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from installation import api, setup
from parsing import languages, settings, parse_cs
from documents import workflow
from serving import service
from storage import settings_store, ledger, snapshot


class PublicTests(unittest.TestCase):
    """Runs without repository fixtures, Unity, Node, Java or Go executables."""

    def test_guided_installation(self):
        """Number menus cover locales, navigation, zero limits, cancellation and preservation."""
        from installation import wizard
        for choice, locale in enumerate(settings.LOCALES, 1):
            with self.subTest(locale=locale), tempfile.TemporaryDirectory() as root:
                Path(root, 'src', 'core').mkdir(parents=True)
                args = SimpleNamespace(root=root, dry_run=False)
                answers = [str(choice), 'oops', '1', '1', '2', '4', '1', '1',
                           '2', '4', '4', '1', '1', '2', '1', '1', '1', '1', '-2', '0',
                           '1', '0', '1', '1']
                output = io.StringIO()
                with patch('builtins.input', side_effect=answers), contextlib.redirect_stdout(output):
                    self.assertEqual(wizard.run(args), 0)
                config = settings.load(root)
                self.assertEqual(config['locale'], locale)
                self.assertEqual(config['sources'], ['src'])
                self.assertEqual(config['structure']['modules'][0]['path'], 'src/core')
                rule = config['standards']['rules'][0]
                self.assertEqual((rule['unit'], rule['metric'], rule['max']), ('folder', 'files', 0))
                self.assertNotIn('folder.files=', output.getvalue())
                self.assertNotIn('"schemaVersion"', output.getvalue())
                before = {str(p.relative_to(root)):p.read_bytes() for p in Path(root).rglob('*') if p.is_file()}
                with patch('builtins.input', side_effect=[str(choice), '1']), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(wizard.run(args), 0)
                self.assertEqual(before, {str(p.relative_to(root)):p.read_bytes() for p in Path(root).rglob('*') if p.is_file()})
        for responses in (['2', '-1'], ['2'], ['2', '1', '1', '2', '1', '1', '1', '1', '-1']):
            with tempfile.TemporaryDirectory() as root:
                args = SimpleNamespace(root=root, dry_run=False)
                iterator = iter(responses)
                def reply(prompt):
                    try: return next(iterator)
                    except StopIteration: raise EOFError()
                with patch('builtins.input', side_effect=reply), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(wizard.run(args), 0)
                self.assertEqual(list(Path(root).iterdir()), [])
        with tempfile.TemporaryDirectory() as root:
            args = SimpleNamespace(root=root, dry_run=True)
            with patch('builtins.input', side_effect=['1','1','1','2','1','1','1','1']), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(wizard.run(args), 0)
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_installation(self):
        """Preview and repeated installation preserve files in every display language."""
        for locale in settings.LOCALES:
            with self.subTest(locale=locale), tempfile.TemporaryDirectory() as root:
                args = SimpleNamespace(root=root, language=locale, languages=None, source=['src'],
                    module=None, limit=['folder.files=10'], config=None, yes=True, dry_run=True)
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(setup.initialize(args), 0)
                    self.assertEqual(list(Path(root).iterdir()), [])
                    args.dry_run = False
                    self.assertEqual(setup.initialize(args), 0)
                    config = Path(root, 'aicaah.json')
                    saved = config.read_bytes()
                    self.assertEqual(setup.initialize(args), 0)
                    self.assertEqual(config.read_bytes(), saved)
                self.assertEqual(settings.load(root)['locale'], locale)
                config.rename(Path(root, 'specconformance.json'))
                self.assertEqual(settings.load(root)['locale'], locale)
                settings_store.save(root, settings.load(root), settings_store.fingerprint(root))
                self.assertFalse(config.exists())
                config.write_bytes(saved)
                with self.assertRaises(ValueError): settings.load(root)

    def test_parsers(self):
        """All six languages expose declarations without executing the target source."""
        samples = {'sample.py':'def Run(x):\n    return x\n',
                   'Sample.cs':'public class Sample { public int Run(int x) { return x; } }',
                   'sample.js':'function Run(x) { return x; }',
                   'sample.ts':'function Run(x: number): number { return x; }',
                   'Sample.java':'class Sample { int Run(int x) { return x; } }',
                   'sample.go':'package sample\nfunc Run(x int) int { return x }\n'}
        for filename, source in samples.items():
            with self.subTest(filename=filename):
                self.assertTrue(any(s.name == 'Run' for s in languages.parse(source, filename)))
        with self.assertRaises(ValueError): languages.parse('x', 'file.unknown')
        with self.assertRaises(parse_cs.ParseError): languages.parse('function {{{', 'broken.js')

    def test_policy_and_reuse(self):
        """A real violation clears on edit and unchanged structure reuses cached facts."""
        with contextlib.ExitStack() as stack:
            root = stack.enter_context(tempfile.TemporaryDirectory())
            stack.callback(snapshot.release, root)
            stack.callback(ledger.close_tables, root)
            workflow.set_mode(root, 'code-to-document', 'allow')
            folder = Path(root, 'src'); folder.mkdir()
            first = folder / 'one.py'; second = folder / 'two.py'
            first.write_text('def first():\n    return 1\n', encoding='utf-8')
            second.write_text('def second():\n    return 2\n', encoding='utf-8')
            config = settings.defaults()
            config['standards']['rules'] = [{'id':'small', 'unit':'folder', 'metric':'files',
                'max':1, 'scope':'src', 'depth':'direct', 'enabled':True}]
            settings_store.save(root, config, None)
            Path(root, settings.FILE).rename(Path(root, settings.LEGACY_FILE))
            instance = service.Service(root)
            first_result = instance.run('portable', force=False)
            self.assertTrue(any(f.rule == 'STRUCTURE:small' for f in first_result.findings))
            self.assertTrue(all(row['source'] == settings.LEGACY_FILE for row in instance.standard_findings))
            instance.run('portable-warm', force=False)
            second.unlink()
            after = instance.run('portable-edit', force=False)
            self.assertFalse(any(f.rule == 'STRUCTURE:small' for f in after.findings))
            self.assertFalse(any(f.code.startswith(('P', 'D')) for f in after.findings), after.findings)
            facts = instance.stage_work['structureStandards']['structure-facts']
            self.assertGreaterEqual(facts['reused'], 1)

    def test_api_and_settings(self):
        """Versioned public protocol and invalid policy remain explicit."""
        with tempfile.TemporaryDirectory() as root:
            value = api.dispatch(root, {'schemaVersion':1, 'method':'capabilities'})
            self.assertEqual((value['product'], value['version']), ('AICAAH', '0.1'))
            self.assertEqual(len(value['languages']), 6)
            with self.assertRaises(ValueError): api.dispatch(root, {'schemaVersion':2, 'method':'capabilities'})
            config = settings.defaults(); config['unknown'] = True
            with self.assertRaises(ValueError): settings_store.save(root, config, None)


if __name__ == '__main__':
    if sys.argv[1:] == ['--list']:
        print(json.dumps(unittest.defaultTestLoader.getTestCaseNames(PublicTests)))
    else:
        unittest.main(verbosity=2)
