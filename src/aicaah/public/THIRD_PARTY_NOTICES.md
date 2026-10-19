# Third-party dependencies

AICAAH source is MIT licensed. Dependencies are installed separately by pip and retain their own copyright and license notices.

| Component | Purpose | License |
|---|---|---|
| tree-sitter | Common parsing runtime | MIT |
| tree-sitter-javascript | JavaScript grammar | MIT |
| tree-sitter-typescript | TypeScript / TSX grammar | MIT |
| tree-sitter-java | Java grammar | MIT |
| tree-sitter-go | Go grammar | MIT |

The declared compatible ranges are in `pyproject.toml`. Installed distributions contain their full upstream license notices. Mermaid is loaded by the browser from its CDN under its upstream MIT license; it is not bundled in the wheel. Optional Unity/Roslyn semantic tooling is not redistributed here and remains subject to its upstream terms.
