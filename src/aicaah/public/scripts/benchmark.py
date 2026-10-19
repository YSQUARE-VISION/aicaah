"""Reproducible public-API benchmark; target programs are never executed."""
import argparse
import datetime
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from aicaah import Client, __version__


def main():
    """Measure fresh-cache, unchanged and one-file-edit requests in an isolated project."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--files', type=int, default=100)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.files < 2 or args.repeats < 1: parser.error('Use at least 2 files and 1 repeat')
    with tempfile.TemporaryDirectory(prefix='aicaah-benchmark-') as root:
        source = Path(root, 'src'); source.mkdir()
        for index in range(args.files):
            (source / ('sample_' + str(index) + '.py')).write_text(
                'class Item' + str(index) + ':\n    def value(self):\n        return ' + str(index) + '\n', encoding='utf-8')
        command = [sys.executable, '-X', 'utf8', '-m', 'aicaah', '--root', root, '--local']
        for options in (['init', '--yes', '--language', 'en', '--languages', 'python', '--source', 'src'],
                        ['mode', 'code-to-document', '--code-policy', 'allow']):
            subprocess.run(command + options, check=True, capture_output=True, timeout=30)
        client = Client(root)
        timings = {}
        counts = {}
        for scenario in ('cold', 'warm', 'one-file-edit'):
            if scenario == 'one-file-edit':
                with (source / 'sample_0.py').open('a', encoding='utf-8') as stream:
                    stream.write('\ndef added():\n    return 1\n')
            samples = []
            for _ in range(args.repeats if scenario == 'warm' else 1):
                started = time.perf_counter()
                result = client.request('structure')
                samples.append(round(time.perf_counter() - started, 6))
                if any(row['code'].startswith(('P', 'D')) for row in result['findings']):
                    raise RuntimeError('Benchmark has blocking parse/document errors: ' + repr(result['findings'][:3]))
            timings[scenario] = {'samplesSeconds':samples, 'medianSeconds':statistics.median(samples)}
            counts[scenario] = len(result['findings'])
        report = {'product':'AICAAH', 'version':__version__, 'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'python':platform.python_version(), 'platform':platform.platform(), 'files':args.files,
                  'sourceLanguage':'python', 'repeats':args.repeats, 'timings':timings, 'findings':counts,
                  'includes':'Client subprocess startup, disk cache, diagnosis and JSON serialization',
                  'peakMemoryMeasured':False}
        text = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
        if args.output: args.output.write_text(text, encoding='utf-8')
        print(text, end='')


if __name__ == '__main__':
    main()
