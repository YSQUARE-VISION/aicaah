# Installation

## Requirements and release status

Use Python 3.10+ with pip. Windows with Python 3.10 is the locally verified baseline. The provided CI workflow targets Windows and Linux with Python 3.10 and 3.12; an unrun workflow is not evidence of platform support. macOS has not been verified for this beta.

AICAAH needs one Python installation and its declared parser dependencies. Python's AST parser handles Python; the built-in C# parser handles C# structure; Tree-sitter grammars handle JavaScript, TypeScript, Java and Go. No Node.js, JDK, Go SDK or .NET runtime is required for ordinary structure checks. pip may need platform-compatible dependency wheels; source builds of dependencies can require compiler tools when a compatible wheel is unavailable.

The first public version is exactly `0.1` and its maturity classifier is Beta. This is not a PEP 440 prerelease spelling such as `0.1b1`; after publication pip can select `0.1` without `--pre`.

## Install the prepared release

An optional Python virtual environment keeps the common engine isolated. It is created by the user, not by AICAAH for each target language:

```sh
python -m venv .venv
```

Activate with `.venv\Scripts\Activate.ps1` in PowerShell or `source .venv/bin/activate` in a POSIX shell, then choose one installation source:

```sh
python -m pip install .
# Or, using the prepared wheel:
python -m pip install ./aicaah-0.1-py3-none-any.whl
```

These commands work before registry publication. Only after the package owner publishes to PyPI:

```sh
python -m pip install aicaah==0.1
```

## Configure a project

Run `aicaah` (or `python -m aicaah`). This opens the terminal installer; `aicaah init` is an equivalent entry point.

| Step | Your input |
|---|---|
| 1. Display language | Choose a number for English, 한국어, 中文 or 日本語. |
| 2. Project folder | Browse numbered folders, choose the current folder, or enter a path. |
| 3. Source languages | Toggle the numbered languages, then choose Next. |
| 4. Inspection folders | Add folders with the browser, then choose Next. At least one is required. |
| 5. Module boundaries | Select folders inside the inspection folders, or proceed without modules. |
| 6. Structure limits | Add a limit: select unit, count type, path scope and counting depth, then enter a nonnegative maximum. Repeat as needed. |
| 7. Review and save | Check the readable summary and choose Confirm and install. |

Menu `0` goes back and `-1` cancels. Ctrl+C or closed input also cancels. Within a numeric maximum prompt, **0 means zero allowed**, a blank input returns to the limits menu, and -1 cancels. No files or server are created before final confirmation. Repeating setup preserves existing settings. No module or numeric limit is invented automatically. Default exclusions cover dependency, Git and cache folders; the app's settings page lets you customize them afterward.

The installer verifies that the saved configuration can be read back. This is installation verification, not a claim that all project findings have passed. Installation does not change existing workflow, approvals or hook trust.

From the selected project folder run `aicaah ask status`, then open the printed URL. Normally it is `http://127.0.0.1:5700/`. Choose the workflow in the app: code-to-document for an existing codebase, document-to-code for work based on approved specifications. Select the code edit policy appropriate for the project; these choices do not approve documents automatically.

Run `aicaah check` for conformance. Use `aicaah --local check` for a one-shot process; it still maintains the project's persistent cache. Use `aicaah stop` to stop the server. Automated deployments can use `init --yes` with the explicit options in the [configuration reference](CONFIGURATION.md); ordinary installation uses the numbered guide above.

## Confirm the installation

```sh
python -m aicaah --version
python -m aicaah selftest --portable
python -m pip check
```

The version must be `0.1`. Portable tests require no original development project. Full project-specific regression cases are intentionally excluded from public wheels.

## Upgrade, migration and removal

Stop a running server before upgrading: `aicaah stop`, then install the newer wheel. Restart with `aicaah ask status`. An already running process keeps its loaded code until restarted.

Existing `specconformance.json` is supported in place. Do not keep it alongside `aicaah.json`: ambiguous configuration is rejected. Existing `.spec-conformance/` state paths retain their names so approval history, snapshots and cache ownership remain intact. The old distribution name `specconformance` is not an alias published on PyPI; remove a separately installed old package with `python -m pip uninstall specconformance` when migrating.

Uninstall with `python -m pip uninstall aicaah`. Your project's configuration and `.spec-conformance/` data remain. That directory contains review history and snapshots as well as caches; deleting it is not just clearing expendable cache data.

## Troubleshooting

- Command not found: use `python -m aicaah` with the interpreter used for installation.
- No matching distribution: before publication use the source/wheel; also check Python version and parser-wheel platform compatibility.
- Approval missing: inspect `aicaah mode` and `aicaah ask review`; explicitly choose the workflow appropriate to your project.
- Port 5700 occupied: stop the other AICAAH project, or use `--local check`. Arbitrary port selection is not exposed by the 0.1 CLI.
- Empty browser graph offline: the current viewer needs access to the Mermaid CDN; CLI checks remain available.
- Warnings immediately after setup: structure configuration does not create design contracts for existing source. Follow [document contracts](CONTRACTS.md).
