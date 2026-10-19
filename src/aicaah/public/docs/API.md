# Public API and CLI results

```python
from aicaah import Client

client = Client("/path/to/project")
capabilities = client.request("capabilities")
symbols = client.request("parse", file="example.go", source="package p\nfunc Run() {}\n")
config = client.request("settings")
result = client.request("structure")
```

The client invokes the installed common engine in a subprocess without a shell. It uses the current Python interpreter by default. Each request starts a process; set `timeout=` explicitly if a large project needs more than the default 120 seconds. Structure inspection writes the target project's cache and returns `rev`, `findings` and `standards`; it applies the configured workflow and does not bypass document approval.

Other tools can communicate over stdin/stdout:

```sh
echo '{"schemaVersion":1,"method":"capabilities","params":{}}' | aicaah api
```

Success is `{"schemaVersion":1,"result":...}`. Failure is `{"schemaVersion":1,"error":{"code":"invalid-request","message":"..."}}` with exit 2. Supported methods are `capabilities`, `parse`, `settings` and `structure`. `parse` requires exactly the string fields `file` and `source`. Source programs are not executed.

Do not import internal `parsing`, `serving` or `storage` modules into an embedding application's global module namespace; the public client isolates these implementation modules.

| CLI operation | Result |
|---|---|
| Ordinary `check` | 0: no findings; 1: warnings/layer findings; 2: document or parse errors. |
| `docs` | Checks document format only; 0 does not mean code conformance. |
| `priority`, `ask status` | Successful retrieval is 0 even when findings remain. |
| `check --gate --purpose verification` | Execution permission, not code-edit approval or completion. |
| `finish` | Read its JSON decision and remaining count; exit 0 only means response delivery. |
| `selftest --portable` | 0 only if the portable installation regression suite passes. |

Full completion requires the current complete comparison and `completion.complete=true`. A subset with zero findings is not sufficient. `ask status` may start a server when none is running; `priority` reads stored results without a fresh analysis. `ask new` requests an update.

Agent hook integration is explicit and host-dependent. The `agent-hook --client codex` and `--client claude` entry points process actual tool/Stop input. Installing the library or running `finish` alone does not connect hooks or establish host trust.
