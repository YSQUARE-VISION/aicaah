# -*- coding: utf-8 -*-
"""보고서(SPEC-36 2.7). 지적을 파일별로 묶어 파일:줄 · 코드 · 내용 · 원문 한 줄로 적는다. 글(txt)과 JSON 두 벌."""
import datetime
import json
import os
from collections import Counter

from judging import check as checkmod
from storage import snapshot
from storage import ledger
from output import phase
from parsing import cache as cachemod

ORDER = ["P1", "P2", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "A2", "A1", "W9", "S1", "S2", "S4", "I1", "I3", "I4", "I2", "L1", "L2", "L6", "W7", "W4", "W2", "W3", "W5", "W1",
         "W10", "W12", "W6", "L3", "L4", "L5", "W8"]


def _rank(code):
    """보고서 안의 지적 순서(형식 → 범위 → 멤버 → 변경 → 규칙)."""
    return ORDER.index(code) if code in ORDER else len(ORDER)


def _snippet(root, rel, line, cache):
    """파일의 그 줄 원문(200자까지)."""
    if rel not in cache:
        path = os.path.join(root, rel)
        cache[rel] = snapshot.read_text(root, rel).split("\n") if os.path.isfile(path) else []
    lines = cache[rel]
    return lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""


def build(root, command, base, ds, findings, notes, new=None, resolved=None, rev=None, changes=0, places=None, source_cache=None, current=None, assigned=None, previous=None, unchanged_docs=False, document_hashes=None):
    """보고서 자료(dict). 패스(2.10)에서 부르면 판·변경 수·새 지적·해소 열쇠도 싣는다. places = 참조 메타데이터의 자리 → 문서(페이즈 `@문서` 대상)."""
    cache = {}
    items = []
    ranks, remaining, phase_current, following = (assigned if assigned is not None else phase.assign(ds, findings, places)) if not ds.issues else ({}, {}, None, None)
    retained = {(item["code"],item["file"],item["line"],item["message"],item["rule"]):item
                for item in (previous or {}).get("findings",[])}
    needed = {}
    headers = dict(current.summaries()) if isinstance(current,ledger.SourceIndex) else (current or {})
    headers = dict(headers,**{path:dict(sha256=stamp) for path,stamp in (document_hashes or {}).items()})
    for finding in findings:
        needed.setdefault(finding.file, set()).add(finding.line)
    source_keys = {rel:cachemod.POLICY.key('publication-snippet',(root,rel,headers.get(rel,{}).get('sha256'))) for rel in needed}
    valid_sources = {rel for rel,saved in (source_cache or {}).items() if saved[0] == source_keys.get(rel)}
    snippets = {}
    for f in sorted(findings, key=lambda x: (x.file, x.line, _rank(x.code))):
        rank = ranks.get(checkmod.finding_key(f))
        old = retained.get((f.code,f.file,f.line,f.message,f.rule))
        saved = (source_cache or {}).get(f.file)
        if old is not None and unchanged_docs and f.file in ds.texts and f.file in valid_sources:
            items.append(dict(old,phase=list(rank) if rank else None))
            continue
        if (old is not None and old["phase"] == (list(rank) if rank else None)
                and f.file in valid_sources and f.line in saved[1]):
            items.append(old)
            snippets.setdefault(f.file, {})[f.line] = old["snippet"]
            continue
        if f.file in valid_sources and f.line in saved[1]:
            snippet = saved[1][f.line]
        else:
            if f.file not in cache and f.file in ds.texts:
                cache[f.file] = ds.texts[f.file]
            snippet = _snippet(root, f.file, f.line, cache)
        snippets.setdefault(f.file, {})[f.line] = snippet
        items.append({"code": f.code, "file": f.file, "line": f.line, "message": f.message, "rule": f.rule,
                      "snippet": snippet, "phase": list(rank) if rank else None})
    if source_cache is not None and current is not None:
        for rel, rows in snippets.items():
            if rel in headers:
                source_cache[rel] = (source_keys[rel], rows)
        for stale in source_cache.keys() - (needed.keys() & headers.keys()):
            del source_cache[stale]
    def line(sp):
        """페이즈 한 줄 요약."""
        return {"rank": sp.rank, "name": sp.name, "targets": phase._text(sp.targets), "left": len(remaining.get(sp.name, []))} if sp else None
    counts = Counter(i["code"] for i in items)
    tables = ds.row_counts()
    fresh = [{"code": f.code, "file": f.file, "line": f.line, "message": f.message} for f in (new or [])]
    return {"command": command, "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "base": base, "docs": len(ds.docs), "tables": dict(tables), "counts": dict(counts),
            "notes": list(notes), "findings": items, "rev": rev, "changes": changes, "new": fresh,
            "resolved": list(resolved or []), "phase_now": line(phase_current), "phase_next": line(following)}


def completion(findings, comparison=None, authority="code", rev=None):
    """같은 판의 화면 미해결과 차단 상태로 전체 완료를 판정한다. 재검사·SQL 조회는 하지 않는다."""
    rows = [f if isinstance(f, dict) else vars(f) for f in findings]
    codes = [f.get("code", "") for f in rows]
    # A mode change must never import the other direction's retained state.
    compared = (comparison or {}) if authority == "code" else {}
    retained = compared.get("items", [])
    missing = authority == "code" and ("remaining" not in compared or "blocked" not in compared
                                      or compared["remaining"] != len(retained))
    current = Counter(tuple(f.get(k, "" if k != "line" else 0) for k in ("code", "file", "line", "message", "rule")) for f in rows)
    saved = Counter(tuple(f.get(k, "" if k != "line" else 0) for k in ("code", "file", "line", "message", "rule")) for f in retained)
    pending = sum((saved - current).values())
    pending_rows = [dict(zip(("code", "file", "line", "message", "rule"), key))
                    for key, count in (saved - current).items() for _ in range(count)]
    blocked = missing or any(c.startswith(("D", "P")) for c in codes) or bool(compared.get("blocked"))
    remaining = None if missing else sum((current | saved).values())
    complete = rev is not None and not blocked and remaining == 0
    return {"rev": rev, "scope": "whole-project", "observedFindings": len(codes),
            "remaining": remaining, "blocked": blocked, "resolvedConfirmed": not blocked,
            "complete": complete, "decision": "allow" if complete else "block",
            "comparisonMissing": missing, "awaitingRecheck": pending, "authority": authority,
            "pendingFindings": pending_rows}


def text(data):
    """글 보고서."""
    document_rules_only = data["command"] == "docs"
    out = [("문서 형식·문서 규칙 검사" if document_rules_only else "문서·코드 대조") +
           " — %s (%s)" % (data["time"], data["command"]),
           "기준 스냅숏: %s" % (data["base"] or "없음"),
           "읽은 문서 %d개, 표 행 %s" % (data["docs"], " · ".join("%s %d" % kv for kv in sorted(data["tables"].items())) or "없음")]
    if document_rules_only:
        out.append("용도: 문서 형식·경로·본문 규칙만 검사. 코드 선언·계층·폴더 경계·미구현 계약은 검사하지 않음.")
        out.append("결과 사용: 전체 미해결 조회는 engine.py priority; 변경 반영·해소 확인은 engine.py check.")
    basis = data.get("executionBasis")
    if basis:
        pending = data.get("documentReview", {})
        out.append("승인 실행 기준: %s · %s · 승인 작업 지적 %d건" % (basis.get("id", ""), basis.get("status", ""), len(data.get("approvedFindings", []))))
        out.append("문서 검토: 대기 %d건 · 틀림 %d건 · 검토 지적 %d건" % (pending.get("waiting", 0), pending.get("wrong", 0), len(pending.get("findings", []))))
    assessment = data.get("completion")
    ranking = data.get('priority')
    if ranking and 'groupCount' in ranking:
        out.append('현재 판정: 원 발생 %d건 · 고유 지적 %d건 · 작업 묶음 %d개' %
                   (ranking['occurrences'],ranking['uniqueFindings'],ranking['groupCount']))
    if not document_rules_only and assessment:
        out.append("전체 완료 판정: %s · 화면 기준 미해결 %s건 · 현재 검사 지적 %d건 · 대조 차단 %s"
                   % ("완료" if assessment["complete"] else "미완료", assessment["remaining"] if assessment["remaining"] is not None else "미확정",
                      assessment["observedFindings"], "있음" if assessment["blocked"] else "없음"))
        if assessment["blocked"]:
            out.append("해소 확정 불가: 이전 미해결을 재검사 대기로 보존한다. 현재 지적 수나 부분 범위 0건으로 완료를 보고하지 않는다.")
    if data["counts"]:
        out.append(("문서 규칙 검사 지적: %d건 (%s)" if document_rules_only else "판정: 지적 %d건 (%s)") % (len(data["findings"]),
                                        ", ".join("%s %d" % (c, data["counts"][c]) for c in sorted(data["counts"], key=_rank))))
    else:
        out.append("문서 형식·규칙 검사 통과 — 전체 미해결은 이 명령에서 판정하지 않음" if document_rules_only else "현재 검사 지적: 0건 — 전체 완료는 completion 판정으로 확인")
    for n in data["notes"]:
        out.append("참고: " + n)
    for label, sp in (("지금 페이즈", data.get("phase_now")), ("다음 페이즈", data.get("phase_next"))):
        if sp:
            out.append("%s: 순위 %d · %s · %s · 남은 지적 %d건" % (label, sp["rank"], sp["name"], sp["targets"], sp["left"]))
    if data.get("rev") is not None:
        out.append("")
        out.append("== 판 %d · 장부 대비 변경 %d건 · 새 지적 %d건 · %s %d건"
                   % (data["rev"], data.get("changes", 0), len(data.get("new") or []),
                      "해소 후보(미확정)" if assessment and assessment["blocked"] else "해소", len(data.get("resolved") or [])))
        for i in sorted(data.get("new") or [], key=lambda x: (x["file"], x["line"], _rank(x["code"]))):
            out.append("  새  %s:%d %s %s" % (i["file"], i["line"], i["code"], i["message"]))
        for k in data.get("resolved") or []:
            out.append(("  재검사 후보  " if assessment and assessment["blocked"] else "  해소  ") + k)
    current = None
    file_counts = Counter(i["file"] for i in data["findings"])
    for i in data["findings"]:
        if i["file"] != current:
            current = i["file"]
            count = file_counts[current]
            out.append("")
            out.append("== %s (%d)" % (current, count))
        tag = " [순위 %d · %s]" % tuple(i["phase"]) if i.get("phase") else ""
        if i.get("origin"):
            tag += " [대기본 검토]" if i["origin"] == "documentReview" else " [승인본 기준]"
        if i.get("priority"):
            tag += " [처리순위 %d · %s]" % (i["priority"]["priorityRank"], i["priority"]["actionKind"])
        out.append("  L%-5d %-3s %s%s" % (i["line"], i["code"], i["message"], tag))
        if i["snippet"]:
            out.append("         > " + i["snippet"])
    return "\n".join(out) + "\n"


def write(root, data):
    """`Reports/latest.txt`·`latest.json`에 쓰고 글 보고서를 돌려준다."""
    folder = os.path.join(root, snapshot.REPORT_ROOT)
    os.makedirs(folder, exist_ok=True)
    body = text(data)
    with open(os.path.join(folder, "latest.txt"), "w", encoding="utf-8") as f:
        f.write(body)
    with open(os.path.join(folder, "latest.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
    return body
