# Contributing

Install from the source checkout with `python -m pip install -e .`. Run `python -m aicaah selftest --portable` before and after changes. Add a regression demonstrating a bug before fixing operational behavior. The portable suite lives in `src/aicaah/selftest/test_public.py`.

Separate language parsing, shared structure, policies, storage/cache, presentation and installation responsibilities. A new language parser must produce the shared declaration contract without installing or running that language's project environment. Preserve explicit unsupported-capability reporting.

Do not discard findings, weaken completion checks or turn missing verification into success. Preserve existing user configuration and review state. Use the versioned API for embedding; internal imports are implementation details.

For a bug report include AICAAH/Python/OS versions, the smallest reproducible source and configuration, expected and actual findings, and whether the run was cold or warm. For performance changes provide the workload and timing scope. Remove private source and credentials from reports.

Build checks: `python -m pip install build twine`, `python -m build`, `python -m twine check dist/*`. The CI matrix is a proposed verification target until its runs actually pass. See [release procedure](docs/RELEASING.md).
