# Structure configuration

`aicaah.json` belongs to the inspected project. The [complete example](../examples/aicaah.json) is intentionally small; its numbers are examples, not universal architecture rules. `aicaah settings --schema` lists the authoritative supported combinations. `aicaah settings --file path/to/config.json --dry-run` validates a prepared configuration; omit `--dry-run` to save it.

| Key | Meaning |
|---|---|
| `schemaVersion` | Must be integer `1`. |
| `locale` | `en`, `ko`, `zh` or `ja`. |
| `languages` | Any supported source-language selection. |
| `sources` | Project-relative source directories. |
| `exclude` | Project-relative glob patterns. |
| `structure.modules` | Explicit `{ "id": "core", "path": "src/core" }` boundaries. |
| `standards.rules` | Explicit, independently applied counting policies. |

Modules are named path boundaries, not an alias for file count. Source paths must remain inside the project, including when symlinks are resolved for settings writes. Absolute paths and `..` traversal are rejected. Keep dependency directories, virtual environments, generated output and AICAAH state excluded.

## Units and metrics

| Unit | Metrics |
|---|---|
| `folder` | `files`, `folders`, `modules`, `classes`, `interfaces`, `functions`, `variables` |
| `module` | `files`, `modules`, `classes`, `interfaces`, `functions`, `variables` |
| `file` | `classes`, `interfaces`, `functions`, `variables` |
| `class` | `functions`, `variables`, `classes` |
| `interface` | `functions`, `variables` |
| `function` | `parameters`, `locals` |

Each rule requires `id`, `unit`, `metric`, `max`, `scope`, `depth` and `enabled`. `scope` is a project-relative glob. `depth` is `direct` for immediate children or `recursive` for descendants. A count equal to `max` passes; only a greater count is a violation. Zero is a valid prohibition. An enabled rule must have an integer limit; disabled rules are retained without enforcing their limit.

```json
{
  "id": "folder-files", "unit": "folder", "metric": "files", "max": 12,
  "scope": "src/**", "depth": "direct", "enabled": true,
  "reason": "Keep modules reviewable",
  "overrides": [{"scope": "src/adapters/**", "max": 20, "priority": 10}],
  "exceptions": [{"scope": "src/generated/**", "reason": "Generated bindings"}]
}
```

Higher-priority matching overrides take precedence. Matching overrides with equal priority are rejected as ambiguous. An exception requires a nonempty reason. Unknown keys, duplicate IDs, negative or fractional limits and unsupported metrics are errors, not silently ignored settings.

The browser saves settings with a content fingerprint. A stale browser tab gets a conflict instead of overwriting a newer edit. Changed settings trigger a new diagnosis while reusable source facts remain cached. Rules from document contracts still apply; JSON settings do not suppress them.
