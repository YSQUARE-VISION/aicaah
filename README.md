# AICAAH

**AI Coding Agent Architecture Harness · 0.1 beta · MIT**

AICAAH checks project structure and agreement between source code and design documents. Set your own module boundaries and limits for folders, files, classes, interfaces, functions and variables. Use the same policies across Python, C#, JavaScript, TypeScript, Java and Go.

It parses source text. It does not install or run the target languages' applications, SDKs or development environments. A shared Python engine serves the CLI, Python API and local browser interface.

## Install and start

Requires Python 3.10 or later. **Pre-publication status:** this source bundle and its wheel are installable. `pip install aicaah` becomes available after the first successful PyPI publication; a name lookup alone does not reserve the name.

From a downloaded source checkout:

```sh
python -m pip install .
```

Or from the prepared wheel:

```sh
python -m pip install ./aicaah-0.1-py3-none-any.whl
```

Start the numbered terminal installer:

```sh
aicaah
```

1. Select **English / 한국어 / 中文 / 日本語** by number.
2. Browse and select the project folder. You can also enter a different path.
3. Choose the source languages by toggling their numbers.
4. Select folders to inspect and optional module boundaries.
5. Choose each structural unit, what to count, the applicable folder, counting depth and numeric maximum. Repeat for additional limits.
6. Review the readable summary, then choose **Confirm and install**.

Menus use **0 = previous** and **-1 = cancel**. A limit of **0 is valid**; limits are not imposed unless you select them. Setup writes only after final confirmation and preserves an existing configuration. `aicaah init` opens the same installer. No language flags, setting expressions or JSON are needed.

After setup, run `aicaah ask status` from the selected project folder and open the printed local address (normally `http://127.0.0.1:5700/`). Choose the workflow in the app: existing code as the reference, or approved specifications as the reference. Installation preserves the existing workflow and document approvals. Undocumented code remains reportable.

The left graph is shared; the right panel separates findings and planned implementation. `aicaah stop` stops this project's server. Use `python -m aicaah` if the console command is not on PATH.

After publication the registry install command will be:

```sh
python -m pip install aicaah==0.1
```

## Set your own standards

The installer uses menus for folder, module, class, interface, function and variable limits. Select a unit and count type, then enter only the maximum number. No universal limits are imposed by default.

After installation, use the browser's structure settings to change limits, scopes, counting depth, overrides and explained exceptions. The [configuration reference](docs/CONFIGURATION.md) also documents advanced automation.

## What 0.1 provides

- Shared structure policies across six source languages, including module boundaries, interfaces, classes, functions, variables, parameters and local variables.
- Document ownership by source folder, declaration comparison, architecture contracts and implementation / verification obligations.
- A common incremental cache for source facts, affected checks and derived reports. Unchanged input can be reused; changed shared dependencies still invalidate their consumers.
- A local code map, document review and configuration UI with four selectable display languages.
- A versioned JSON API and Python `aicaah.Client`; no per-language connector packages.

## Verification and performance

```sh
aicaah selftest --portable
python scripts/benchmark.py --files 100 --repeats 3
```

Portable tests exercise six-language parsing, setup preservation, invalid settings, real policy violations and cache reuse. They require no original project, Unity, Node.js, Java or Go installation. The benchmark generates its own temporary Python project and measures cold, warm and one-file-edit API calls, including process startup. See [performance and methodology](docs/PERFORMANCE.md); timings depend on project size and the machine.

## Beta boundaries

Syntax and structure support is broader than semantic reference analysis. Java, Go, JavaScript and TypeScript do not yet have full compiler-resolved dependency graphs. C# semantic analysis uses an optional Unity/Roslyn path; ordinary structure inspection does not require it. Some advanced diagnostics, CLI help and machine-readable document headings retain Korean text. The browser graph currently loads Mermaid from a CDN. Multi-project server port selection and a full offline browser bundle are not implemented.

The installer does not enable or trust coding-agent hooks. A zero exit from a verification-permission check is not a completion claim. See [limitations](docs/LIMITATIONS.md) and [document contracts](docs/CONTRACTS.md).

## Documentation

- [Installation and upgrade](docs/INSTALL.md) · [Configuration](docs/CONFIGURATION.md)
- [Document contracts](docs/CONTRACTS.md) · [API](docs/API.md) · [Performance](docs/PERFORMANCE.md)
- [Git and PyPI release procedure](docs/RELEASING.md) · [Contributing](CONTRIBUTING.md)
- [한국어](README.ko.md) · [中文](README.zh.md) · [日本語](README.ja.md)

Licensed under the [MIT License](LICENSE). Dependencies retain their own [notices](THIRD_PARTY_NOTICES.md).
