# Performance

Performance must be measured against a defined workload. AICAAH uses a shared persistent cache for parsed sources, affected checks and derived output. A source change invalidates consumers of that input; unchanged producers and reports can be reused. Changes to common contracts or analyzers can legitimately affect more of the project.

## Reproduce the public benchmark

Install this source release, then run from the source checkout:

```sh
python scripts/benchmark.py --files 100 --repeats 3 --output benchmark.json
```

The script creates a temporary Python project, explicitly selects code-to-document mode, then measures a first structure request, repeated unchanged requests and a one-file edit. The measurements include the public client's child-process startup, cache loading and result serialization. Cold means a fresh AICAAH project cache, not a cold operating-system disk cache. No server restart, browser rendering or target-application execution is timed. The output records Python, OS, package version, workload and observed findings.

Measured on 2026-10-20 (Asia/Tokyo), with the 0.1 release candidate installed into a fresh environment: Python 3.10.11, Windows build 26200, 100 generated Python files. The host also ran its existing development server. These are local observations, not isolated machine-wide performance claims.

| Scenario | Observed seconds | Samples |
|---|---:|---|
| Fresh project cache | 4.581309 | One run |
| Unchanged project | 3.354332 median | 3.354332, 3.411317, 3.208673 |
| One file changed | 3.280011 | One run |

The generated source has no design documents, so it intentionally reported 300 undocumented/coverage findings, then 301 after adding a function. There were no blocking parse/document errors. Run the script on your machine for a comparable workload. Peak memory is not measured by this script; these times include child-process startup.

## Large-project development observation

A development workspace with 1,353 persisted source-owner records was measured after a real priority-report implementation edit. Observed startup was **35.7811 s**, including **23.2659 s** synchronization. Restoring the previous implementation measured **32.1722 s**, including **17.8905 s** synchronization. The corresponding run reused 95 map cards and 1,352 unchanged source records, rebuilt no complete graph/metadata/map, and rebuilt the affected priority producer once.

These are observations from the earlier development build, not a controlled old/new comparison or a 0.1 performance guarantee. They do not establish an improvement percentage. They also do not establish a maximum memory footprint; large-project memory remains a beta optimization area.

## Investigate slow runs

Record project size, source languages, document count, cold/warm state, changed files, machine details and the same revision's timing/counter output. Distinguish source parsing, checks, report construction, persistent storage and process startup. Repeated public `Client` calls include a fresh child process each time. The browser server retains a process and responds differently; do not compare those timings as if they were the same operation.
