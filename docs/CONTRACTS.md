# Code and document contracts

Structure limits live in `aicaah.json`. Design contracts are Markdown under `Docs/`; `Docs/98_History/` and `Docs/99_Legacy/` are excluded from current design parsing. Keep current requirements in `Docs/04_Specifications/` and dated measurements and review history in `Docs/98_History/`.

Divide documents by the source folders they own. For example:

```text
src/core/...          Docs/04_Specifications/core/...
src/adapters/...      Docs/04_Specifications/adapters/...
```

A document can map ownership with the following exact protocol headings. Display-language selection does not translate these headings or state values in 0.1.

```markdown
| 소스 폴더 | 문서 폴더 | 이유 |
|---|---|---|
| `src/core` | `Docs/04_Specifications/core` | Core domain |
| `src/adapters` | `Docs/04_Specifications/adapters` | External boundaries |
```

The individual owning document describes its files and declarations:

```markdown
| 파일 | 상태 | 책임 |
|---|---|---|
| `src/core/math.py` | 유지 | Arithmetic operations |

| 파일 | 형 | 종류 | 시그니처 | 상태 | 설명 |
|---|---|---|---|---|---|
| `src/core/math.py` | `-` | method | `def add(a, b)` | 구현완료 | Return the sum |
```

Generate a declaration-table draft from actual code with `aicaah scaffold src/core/math.py`. Review its descriptions and implementation states before saving. A draft copied from code is not proof of behavioral correctness or user approval.

Architecture contracts additionally declare module ownership, public entries and calls using Mermaid graphs and architecture tables. Full declarations must link to their owning module/flow; adding a member table alone does not satisfy every architecture check. The canonical parser schema is `src/aicaah/documents/docs.py` in the public source tree; `COLUMNS`, `STATES` and `VALUES` define accepted fields. That schema is currently a beta protocol with Korean headings.

Behavior contracts distinguish a planned implementation from implemented but unverified behavior. They identify a condition, guarantee, implementation target, test connection, verification level and current evidence. `설계완료` means designed, `구현완료` means implemented; neither substitutes for a passing test with current input evidence. Do not remove test obligations to clear the screen.

Use `aicaah docs` for format diagnostics and `aicaah check` for the whole comparison. W2 can identify undocumented declarations, W8 unfinished implementation, W9 uncovered source and W12 outstanding verification work. D/P findings prevent reliable comparison and require investigation even in code-to-document mode.

Document approval is separate from code-edit policy. Choose the work direction explicitly with `aicaah mode`, inspect `aicaah ask review`, and review documents in the browser. The installer does not approve, trust or rewrite user documents.
