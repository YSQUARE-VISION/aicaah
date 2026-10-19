"""Allowlisted, project-independent AICAAH source export; never publishes remotely."""
import hashlib
import json
import os
from pathlib import Path
import sys
from parsing import settings

RUNTIME_PATTERNS = ('__init__.py', '__main__.py', 'engine.py', 'parsing/*.py', 'documents/*.py',
                    'storage/*.py', 'graph/*.py', 'graph/RefGraph/*.cs', 'judging/*.py',
                    'output/*.py', 'serving/*.py', 'installation/*.py', 'selftest/test_public.py',
                    'locales/*.json', 'pyproject.toml', 'README.md', 'LICENSE')
PUBLIC_FILES = ('README.ko.md', 'README.zh.md', 'README.ja.md', 'CHANGELOG.md', 'CONTRIBUTING.md',
                'THIRD_PARTY_NOTICES.md', '.gitignore', 'MANIFEST.in', 'docs/INSTALL.md',
                'docs/CONFIGURATION.md', 'docs/CONTRACTS.md', 'docs/API.md', 'docs/PERFORMANCE.md',
                'docs/RELEASING.md', 'docs/LIMITATIONS.md', 'examples/aicaah.json',
                'scripts/benchmark.py', '.github/workflows/ci.yml', '.github/workflows/publish.yml')


def export(args):
    """Validate all input files before writing a new source tree and its content manifest."""
    try:
        source = Path(__file__).resolve().parents[1]
        destination = Path(args.destination).absolute()
        if os.path.lexists(destination):
            raise ValueError('Export destination already exists; choose a new directory')
        payload = {}
        for pattern in RUNTIME_PATTERNS:
            paths = sorted(source.glob(pattern))
            if not paths: raise ValueError('Missing distribution input: ' + pattern)
            for path in paths:
                if path.is_symlink() or not path.resolve().is_relative_to(source):
                    raise ValueError('Distribution input escapes the source tree')
                payload['src/aicaah/' + path.relative_to(source).as_posix()] = path.read_bytes()
        for name in PUBLIC_FILES:
            path = source / 'public' / name
            if path.is_symlink() or not path.resolve().is_relative_to(source):
                raise ValueError('Public input escapes the source tree')
            data = path.read_bytes()
            payload[name] = data
            payload['src/aicaah/public/' + name] = data
        for name in ('README.md', 'LICENSE'):
            payload[name] = payload['src/aicaah/' + name]
        payload['README.md'] = payload['README.md'].replace(b'(public/', b'(')
        project = payload['src/aicaah/pyproject.toml'].decode('utf-8')
        marker = 'package-dir = {aicaah = "."}'
        if marker not in project: raise ValueError('Unexpected package layout')
        payload['pyproject.toml'] = project.replace(marker, 'package-dir = {aicaah = "src/aicaah"}').encode('utf-8')
        manifest = {'product':'AICAAH', 'version':settings.VERSION,
                    'files':{name:hashlib.sha256(data).hexdigest() for name,data in sorted(payload.items())}}
        destination.mkdir(parents=True, exist_ok=False)
        for name, data in payload.items():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (destination / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
        print(json.dumps({'destination':str(destination), 'version':settings.VERSION, 'files':len(payload)}, ensure_ascii=False))
        return 0
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
