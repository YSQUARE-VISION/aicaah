# 0.1 beta boundaries

- Ordinary parsing covers Python, C#, JavaScript, TypeScript, Java and Go. This does not mean identical compiler-level semantics or complete language-version coverage.
- Python reference analysis is static and cannot resolve all dynamic imports or runtime dispatch. C# semantic reference analysis uses Unity/Roslyn tooling configured by `--unity` or the legacy `AIKA_UNITY_EDITOR` variable. The historical Windows fallback points to Unity 2022.3.62f3. This optional path is not needed for basic C# structure checks and is not a general .NET build service.
- Java, Go, JavaScript and TypeScript currently provide structure extraction, not a full semantic dependency graph. A missing semantic edge must not be interpreted as proof that no dependency exists.
- Setup, common UI and structure messages support English, Korean, Chinese and Japanese. Some advanced diagnostics, CLI help and document-protocol headings remain Korean. User source and document text are never automatically translated.
- The graph uses Mermaid from `cdn.jsdelivr.net`; a complete offline browser asset bundle is not supplied. Source code is not uploaded to that CDN by AICAAH. The browser makes an external asset request.
- The local server uses loopback port 5700 and has no public-hosting authentication model. It is intended for local use. The 0.1 CLI has no per-project port selector; use one server at a time or local checks.
- Large projects can still require substantial startup time and memory. Incremental reuse reduces repeated work but cannot eliminate changes whose dependencies genuinely affect many checks. Benchmark results are not memory or latency guarantees.
- Structure configuration alone does not author design documents. Existing undocumented code remains reportable. Approval and completion gates are retained.
- Installation does not automatically connect coding-agent hooks or establish user trust. Host-side hook activation must be checked in the actual host.
- The public regression suite is independent of the original project. It does not certify your application or replace its own behavior tests. Windows/Python 3.10 is locally verified; other CI targets are configured but require actual CI execution.
