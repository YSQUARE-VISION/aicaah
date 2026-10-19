# -*- coding: utf-8 -*-
"""기존 엔진 지적을 문서 위치별로 표시한다. 판정 규칙과 작업 파일은 변경하지 않는다."""
import os
import re
from collections import defaultdict, Counter

from documents import workflow
from judging import check
from parsing import globs
from storage import ledger

PROGRESS_FILE = ".spec-conformance/History/code-to-document-progress.bin"
DOCUMENT_REF = re.compile(r"(Docs/[^\n()|]*?\.md):(\d+)")


def build(root, ds, findings, current, blocked=False, previous=None, deltas=None, unchanged_docs=False):
    scope = workflow.inspect_code(root, current)
    def locations_same(item):
        if unchanged_docs:
            return True
        for location in item.get("documents", []):
            lines = ds.texts.get(location["file"], [])
            at = location["line"] - 1
            text = lines[at][:700] if 0 <= at < len(lines) else ""
            if text != location.get("text", ""):
                return False
        return True

    if (previous is not None and deltas is not None and not blocked
            and not previous.get("blocked") and not any(f.code.startswith(("D", "P")) for f in findings)):
        changed = set(deltas)
        reflection = list(findings)
        old = previous.get("items",[])
        identity = lambda i:(i["code"],i["file"],i["line"],i["message"],i.get("rule", ""))
        if (not any(i.get("file") in changed for i in old)
                and all(locations_same(i) for i in old)
                and Counter(identity(vars(f)) for f in reflection) == Counter(identity(i) for i in old)):
            other = [dict(code=f.code,file=f.file,line=f.line,message=f.message) for f in findings
                     if not workflow.reflection_finding(f) and not f.code.startswith(("D","P"))
                     and f.code not in ("A1","A2","W11")]
            return dict(previous,scope=scope,otherFindings=other,otherCount=len(other),
                        reviewCount=sum(f.code in ("A1", "A2", "W11") for f in findings),
                        validation=[dict(code=f.code,file=f.file,line=f.line,message=f.message)
                                    for f in findings if f.code.startswith(("D","P"))])
    baseline = ledger.read_binary(root, workflow.BASELINE_FILE, {})
    history = ledger.read_binary(root, PROGRESS_FILE, {})
    if history.get("epoch") != baseline.get("epoch"):
        history = {"epoch": baseline.get("epoch"), "known": {}, "initial": None}
    validation = [f for f in findings if f.code.startswith(("D", "P"))]
    review_count = sum(f.code in ("A1", "A2", "W11") for f in findings)
    other = [f for f in findings if not workflow.reflection_finding(f) and not f.code.startswith(("D", "P")) and f.code not in ("A1", "A2", "W11")]
    blocked = blocked or bool(validation)
    rows_by_file = defaultdict(list)
    wildcard_rows = []
    for row in ds.selected_rows(set(deltas) if unchanged_docs and deltas is not None and previous is not None else None,
                               ('scope','members','body','constants','changes','overview')):
        file = row.cells.get("파일")
        if file:
            if "*" in file:
                wildcard_rows.append((globs.to_regex(file), row))
            else:
                rows_by_file[file].append(row)
    # Findings often repeat the same source file. Resolve that file's exact and
    # wildcard document rows once instead of testing every wildcard for every
    # finding in it.
    rows_for_file = {}

    def document_rows(file):
        rows = rows_for_file.get(file)
        if rows is None:
            rows = rows_by_file.get(file, [])
            rows = rows + [row for pattern, row in wildcard_rows if pattern.match(file)]
            rows_for_file[file] = rows
        return rows

    symbols_by_file = {}
    symbol_for_location = {}
    active = {}
    reusable = {item["key"]:item for item in (previous or {}).get("items",[])
                if item.get("file") not in (deltas or {}) and locations_same(item)}
    source_lines = {}
    occurrences = defaultdict(int)
    for finding in findings:
        base_key = check.finding_key(finding)
        occurrences[base_key] += 1
        item_key = base_key if occurrences[base_key] == 1 else base_key + "|occurrence:" + str(occurrences[base_key])
        saved = reusable.get(item_key)
        if saved is not None:
            active[saved["key"]] = saved
            continue
        location_key = (finding.file, finding.line)
        symbol = symbol_for_location.get(location_key)
        if symbol is None:
            if finding.file not in symbols_by_file:
                symbols_by_file[finding.file] = (current.get(finding.file) or {}).get("symbols") or []
            containing = [s for s in symbols_by_file.get(finding.file, [])
                          if s.get("line", 0) <= finding.line <= s.get("end", s.get("line", 0))]
            symbol = min(containing, key=lambda s: s.get("end", s.get("line", 0))-s.get("line", 0)) if containing else {}
            symbol_for_location[location_key] = symbol
        locations = []
        if finding.file.startswith("Docs/"):
            locations.append({"file": finding.file, "line": finding.line, "precise": True})
        else:
            locations.extend({"file": doc, "line": int(line), "precise": True}
                             for doc,line in DOCUMENT_REF.findall(finding.message))
            rows = document_rows(finding.file)
            exact = [r for r in rows if r.kind == "members" and
                     r.cells.get("시그니처") == symbol.get("signature") and
                     r.cells.get("형", "-") == (symbol.get("path") or "-")]
            mentioned = [r for r in rows if r.kind == "members" and r.cells.get("시그니처", "-") != "-" and
                         r.cells["시그니처"] in finding.message]
            matched = exact or mentioned
            if not locations:
                chosen = matched if symbol.get("signature") else (mentioned or [r for r in rows if r.kind == "scope"])
                locations.extend({"file": r.doc, "line": r.line, "precise": bool(matched)} for r in chosen)
        locations = list({(r["file"],r["line"]):r for r in locations}.values())
        for location in locations:
            lines = ds.texts.get(location["file"], [])
            at = location["line"]-1
            location["text"] = lines[at][:700] if 0 <= at < len(lines) else ""
        item = {"key": item_key, "code": finding.code, "file": finding.file,"rule":finding.rule,
                "line": finding.line, "message": finding.message, "documents": locations, "status": "미해결"}
        if finding.file not in source_lines and not finding.file.startswith("Docs/"):
            try:
                with open(os.path.join(root, finding.file), encoding="utf-8-sig") as stream:
                    source_lines[finding.file] = stream.read().splitlines()
            except (OSError, UnicodeError):
                source_lines[finding.file] = []
        lines = source_lines.get(finding.file, [])
        at = finding.line-1
        item["source"] = {"path": symbol.get("path", ""), "name": symbol.get("name", ""),
                          "line": symbol.get("line", finding.line),
                          "signature": symbol.get("signature", ""), "text": lines[at][:700] if 0 <= at < len(lines) else ""}
        base_key = item["key"]
        occurrence = 1
        while item["key"] in active:
            occurrence += 1
            item["key"] = base_key + "|occurrence:" + str(occurrence)
        active[item["key"]] = item
    if history["initial"] is None and not blocked:
        history["initial"] = len(active)
    if "startingKnownCount" not in history and not blocked:
        history["startingKnownCount"] = len(set(history["known"]) | set(active))
    if blocked:
        # D/P failures do not prove that previous code/document mismatches were fixed.
        # known includes resolved history. Only the last active set may wait for
        # rechecking. Old progress files recover that set from the live ledger.
        previous = history.get("active")
        if previous is None:
            previous = list((ledger.load(root,lazy=True) or {}).get("reported", {}))
        for key in previous:
            item = history["known"].get(key)
            if item is None:
                continue
            if key not in active:
                active[key] = dict(item, status="재검사 대기")
    else:
        history["known"].update(active)
        history["active"] = list(active)
    resolved = [dict(item,status="해소") for key,item in history["known"].items() if key not in active]
    ledger.write_binary(root, PROGRESS_FILE, history)
    initial = history["initial"]
    return {"scope": scope, "items": list(active.values()), "resolved": resolved,
            "remaining": len(active), "initial": initial, "resolvedCount": len(resolved),
            "newCount": max(0,len(history["known"])-history.get("startingKnownCount", len(history["known"]))), "blocked": blocked,
            "validation": [dict(code=f.code, file=f.file, line=f.line, message=f.message) for f in validation],
            "otherFindings": [dict(code=f.code, file=f.file, line=f.line, message=f.message) for f in other],
            "otherCount": len(other), "reviewCount": review_count, "complete": not blocked and not active}
