# -*- coding: utf-8 -*-
"""문서 변경 체크(SPEC-36 2.12). 체크 기준본(`History/approved`)과 지금 문서를 줄 단위로 견줘 변경 단위를 만들고,
표 행이면 계획(신규·수정·삭제)을 붙인다. 사용자가 맞음으로 체크한 단위만 기준본에 옮기고, 틀림은 이유와 함께 적는다."""
import datetime
import difflib
import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass, field

from documents import docs as docmod
from documents import workflow
from parsing import parse_cs
from parsing import cache as cachemod
from storage import ledger
from storage import snapshot

APPROVED_ROOT = ledger.HISTORY_ROOT + "/approved"
STATE_FILE = ledger.HISTORY_ROOT + "/review.json"
LOG_FILE = ledger.HISTORY_ROOT + "/review.jsonl"
EXECUTION_FILE = ledger.HISTORY_ROOT + "/execution-basis.bin"
CONTEXT_LINES = 3
PLAN_TABLES = ("scope", "members", "constants", "changes", "body", "behaviors")
HEADING = re.compile(r"^\s{0,3}#{1,6}\s")
REMOVING = {"삭제중", "삭제완료"}
PLAN_WAITING = {"조사중", "조사완료", "설계중", "설계완료", "구현중", "수정중", "삭제중"}
SIGNATURE_NAME = re.compile(r"^`[^`]*?([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^`(]*>)?\s*\(.*`$")


@dataclass
class Unit:
    """변경 단위 하나(2.12): 문서·열쇠·종류·옛 줄·새 줄·자리·앞뒤 줄·계획·체크."""
    doc: str
    key: str
    kind: str
    old: str
    new: str
    old_line: int
    new_line: int
    heading: str
    before: list = field(default_factory=list)
    after: list = field(default_factory=list)
    plan: dict = field(default_factory=dict)
    verdict: str = ""
    memo: str = ""
    group: str = ""


def ensure(root):
    """기준본 폴더가 없으면 지금 문서로 뜬다. 돌려주는 값: 기준본 폴더(절대 경로)."""
    base = os.path.join(root, APPROVED_ROOT)
    if not os.path.isdir(base):
        for rel in docmod.doc_paths(root):
            target = os.path.join(base, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(os.path.join(root, rel), target)
    return base


def _lines(path):
    """줄 목록(줄바꿈 포함, `\\n`으로만 나눔 — 문서 표의 줄 번호와 같다). 파일이 없으면 None."""
    try:
        with open(path, encoding="utf-8", newline="") as f:
            text = f.read()
    except OSError:
        return None
    parts = text.split("\n")
    out = [p + "\n" for p in parts[:-1]]
    if parts[-1]:
        out.append(parts[-1])
    return out


def _bare(line):
    """줄바꿈을 뺀 줄."""
    return line.rstrip("\r\n")


def _row_key(line):
    """행 열쇠: 표 행이면 앞 네 칸(시그니처 칸은 멤버 이름만 — 시그니처가 바뀐 행도 같은 행), 아니면 줄 그대로(줄바꿈 뺌)."""
    text = _bare(line).strip()
    if text.startswith("|") and text.count("|") >= 3:
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", text)[1:-1]]
        return "|".join(SIGNATURE_NAME.sub(r"\1", c) for c in cells[:4])
    return _bare(line)




def _align(old, new):
    """줄 맞춤(2.12): (종류 `=`·추가·삭제·수정, 옛 줄 번호 또는 None, 새 줄 번호 또는 None) 목록."""
    steps = []
    outer = difflib.SequenceMatcher(None, old, new, autojunk=False)
    for tag, i1, i2, j1, j2 in outer.get_opcodes():
        if tag == "equal":
            steps.extend(("=", i1 + k, j1 + k) for k in range(i2 - i1))
            continue
        a, b = old[i1:i2], new[j1:j2]
        inner = difflib.SequenceMatcher(None, [_row_key(x) for x in a], [_row_key(x) for x in b], autojunk=False)
        for t, p1, p2, q1, q2 in inner.get_opcodes():
            if t == "equal" or (t == "replace" and p2 - p1 == q2 - q1):
                for k in range(p2 - p1):
                    same = a[p1 + k] == b[q1 + k]
                    steps.append(("=" if same else "수정", i1 + p1 + k, j1 + q1 + k))
            else:
                steps.extend(("삭제", i1 + p, None) for p in range(p1, p2))
                steps.extend(("추가", None, j1 + q) for q in range(q1, q2))
    return steps


def _rows(ds):
    """(문서, 줄) → 계획 표 행."""
    return {(r.doc, r.line): r for r in ds.rows if r.kind in PLAN_TABLES}


def _target(r):
    """표 행 → 대상(파일·형·이름·종류·시그니처·상태)."""
    c = r.cells
    if r.kind == "behaviors":
        file, _, qualified = c["구현 대상"].split(",", 1)[0].strip().partition("#")
        path, _, name = qualified.rpartition(".")
        return {"file": file, "path": path or "-", "name": name, "kind": "method",
                "behavior": c["동작 ID"], "sig": c["조건"] + " → " + c["보장"], "state": c["상태"]}
    if r.kind == "scope":
        return {"file": c["파일"], "path": "-", "name": "", "kind": "file", "sig": "", "state": c["상태"]}
    if r.kind == "constants":
        return {"file": c["파일"], "path": c["형"], "name": c["이름"], "kind": "const", "sig": c["이름"] + ": " + c["형식"] + " = " + c["값"], "state": ""}
    p = r.parsed or {}
    if r.kind == "body":
        return {"file": c["파일"], "path": p.get("path", c["형"]), "name": p.get("name", ""), "kind": "method",
                "sig": c["시그니처"], "state": c["본문 계약"]}
    if r.kind == "changes":
        return {"file": c["파일"], "path": p.get("path", c["형"]), "name": p.get("name", ""), "kind": p.get("kind", "file"),
                "sig": c["시그니처"].strip("`"), "state": c["변경"]}
    return {"file": c["파일"], "path": p.get("path", c["형"]), "name": p.get("name", ""), "kind": c["종류"],
            "sig": c["시그니처"].strip("`"), "state": c["상태"]}


def _plan(new_row, old_row):
    """표 행(지금·기준본) → 계획 dict(2.9.1 계획 표). 둘 다 없으면 `글`."""
    if new_row is None and old_row is None:
        return {"action": "글"}
    r = new_row or old_row
    now, was = (_target(new_row) if new_row else None), (_target(old_row) if old_row else None)
    t = dict(now or was)
    t["table"] = r.kind
    t["sig_old"] = was["sig"] if was else ""
    t["sig_new"] = now["sig"] if now else ""
    t["state_old"] = was["state"] if was else ""
    t["state_new"] = now["state"] if now else ""
    if new_row is None:
        t["action"] = "글" if r.kind == "changes" else "삭제"
    elif r.kind == "scope":
        t["action"] = {"추가": "신규", "변경": "수정", "삭제": "삭제"}.get(now["state"], "글")
    elif r.kind == "changes":
        t["action"] = "신규" if now["state"] in ("추가", "파일 추가") else "삭제" if now["state"] in ("삭제", "파일 삭제") else "수정"
    elif now["state"] in REMOVING:
        t["action"] = "삭제"
    else:
        t["action"] = "수정" if old_row is not None else "신규"
    return t


def implementation_plans(ds, cur, root=None, basis=None, only_files=None):
    """현재 미완성 선언과 설계 문서의 변경 계획을 승인 대기와 별개로 표시한다. 판정·승인 상태는 바꾸지 않는다."""
    if root is not None and workflow.state(root)["authority"] == "document":
        approved = os.path.abspath(os.path.join(root, APPROVED_ROOT))
        if basis is None:
            ds, basis = execution_basis(root)
        if basis["status"] != "ready" or os.path.abspath(getattr(ds, "source_root", "")) != approved:
            raise ValueError("승인 작업 입력 불일치")
        if getattr(ds, "execution_basis", {}).get("id") != basis["id"]:
            raise ValueError("승인 작업 버전 불일치")
    waiting = PLAN_WAITING
    design_docs = (ds._stored['design_docs'] if getattr(ds,'_stored',None) else
                   {doc for doc, lines in ds.texts.items()
                   if any(re.match(r"^\s*\|\s*상태\s*\|\s*(?:설계중|설계완료)(?:\s|—|·|\|)", line) for line in lines)})
    symbols = {}
    result = {}
    plan_rows = ds.selected_rows(only_files,('members','changes','scope','behaviors'))
    for row in plan_rows:
        c = row.cells
        if row.kind == "behaviors":
            if c["상태"] in waiting:
                for reference in c["구현 대상"].split(","):
                    rel, _, qualified = reference.strip().partition("#")
                    if only_files is not None and rel not in only_files:
                        continue
                    path, _, name = qualified.rpartition(".")
                    matches = [s for s in cur.get(rel, {}).get("symbols", [])
                               if s.get("path") == (path or "-") and s.get("name") == name]
                    for symbol in matches or [{"path": path or "-", "name": name, "kind": "method"}]:
                        target = dict(file=rel, path=symbol["path"], name=name, kind=symbol["kind"],
                                      params=symbol.get("params", ""), sig=symbol.get("signature", qualified),
                                      state=c["상태"], behavior=c["동작 ID"])
                        result[(row.doc, c["동작 ID"], reference, target["params"])] = {
                            "plan": dict(target, action="수정", table=row.kind, sig_new=target["sig"]),
                            "sources": [{"doc": row.doc, "line": row.line, "state": target["state"], "behavior": c["동작 ID"],
                                         "reason": c["조건"] + " → " + c["보장"]}],
                            "exists": bool(matches), "status": "동작 검증 미완료"}
            continue
        if row.kind == "members":
            if c["상태"] not in waiting:
                continue
        elif row.kind == "changes":
            # Completed-document change tables are history, not current intent.
            # A pending member must not resurrect its old add/delete operations.
            if row.doc not in design_docs:
                continue
        elif row.kind == "scope":
            if c["상태"] != "추가" or c["파일"] in cur:
                continue
        else:
            continue
        target = _target(row)
        if target["kind"] == "file":
            target["sig"] = ""
        rel = target["file"]
        if only_files is not None and rel not in only_files:
            continue
        entry = cur.get(rel)
        if rel not in symbols:
            symbols[rel] = {(s.get("path"), s.get("kind"), s.get("name"), s.get("params", "")): True
                            for s in (entry or {}).get("symbols", [])}
        exists = entry is not None if target["kind"] == "file" else (
            target["path"], target["kind"], target["name"], (row.parsed or {}).get("params", "")) in symbols[rel]
        unknown = bool(entry and entry.get("error"))
        deleting = target["state"] in {"삭제중", "삭제", "파일 삭제"}
        action = "삭제" if deleting else "수정" if exists else "신규"
        if row.kind == "changes":
            action = "삭제" if deleting else "수정" if exists else "신규" if target["state"] in {"추가", "파일 추가"} else "수정"
        elif target["state"] == "수정중":
            action = "수정"
        plan = dict(target, action=action, table=row.kind, sig_new=target["sig"],
                    params=(row.parsed or {}).get("params", ""))
        key = (rel, target["path"], target["kind"], target["name"], target["sig"], action)
        source = {"doc": row.doc, "line": row.line, "state": target["state"],
                  "reason": c.get("설명", c.get("이유", c.get("책임", "")))}
        if key not in result:
            result[key] = {"plan": plan, "sources": [], "exists": exists,
                           "status": "코드 확인 불가" if unknown else "구현 확인 필요" if exists else "코드 없음"}
        result[key]["sources"].append(source)
    # One concrete declaration per card; preserve every requirement and source.
    merged = {}
    for item in result.values():
        plan = item["plan"]
        identity = (plan["file"], plan["path"], plan["kind"], plan["name"],
                    re.sub(r"\s+", "", plan.get("params", "")))
        if identity not in merged:
            merged[identity] = item
            plan["behaviors"] = []
            item["actions"] = []
        current = merged[identity]
        if plan["action"] not in current["actions"]:
            current["actions"].append(plan["action"])
        behavior = plan.get("behavior")
        if behavior and behavior not in current["plan"]["behaviors"]:
            current["plan"]["behaviors"].append(behavior)
            current["plan"].setdefault("behavior", behavior)
            current["status"] = "동작 검증 미완료"
        if current is not item:
            for source in item["sources"]:
                if source not in current["sources"]:
                    current["sources"].append(source)
        if len(current["actions"]) > 1:
            current["status"] = "계획 충돌 · " + "/".join(current["actions"])
    result = merged
    source_files = {}
    for item in result.values():
        plan = item["plan"]
        rel = plan["file"]
        entry = cur.get(rel) or {}
        item["code"] = []
        if root is None:
            item["codeStatus"] = "코드 본문 미제공"
            continue
        if rel not in source_files:
            try:
                # Only read a watched project file, and never combine stale symbol spans with new bytes.
                base = os.path.realpath(root)
                full = os.path.realpath(os.path.join(base, rel))
                if rel not in cur or os.path.commonpath([base, full]) != base:
                    raise ValueError("감시 코드 없음")
                with open(full, "rb") as stream:
                    raw = stream.read()
                if hashlib.sha256(raw).hexdigest() != entry.get("sha256"):
                    raise ValueError("코드 갱신 중 — 재검사 후 표시")
                source_files[rel] = (raw.decode("utf-8-sig", errors="replace").splitlines(), "")
            except (OSError, ValueError) as error:
                source_files[rel] = ([], str(error))
        lines, error = source_files[rel]
        matches = [s for s in entry.get("symbols", []) if
                   (s.get("path"), s.get("kind"), s.get("name"), s.get("params", "")) ==
                   (plan["path"], plan["kind"], plan["name"], plan.get("params", ""))]
        if not matches and plan["action"] == "수정":
            matches = [s for s in entry.get("symbols", []) if
                       (s.get("path"), s.get("kind"), s.get("name")) ==
                       (plan["path"], plan["kind"], plan["name"])]
        if plan["kind"] == "file" and not error:
            matches = [{"line": 1, "end": len(lines), "signature": rel}]
        item["codeStatus"] = error or ("지적 대상의 현재 코드" if matches else "지적 대상 코드 없음 · 문서 선언")
        if len(matches) > 1:
            item["codeStatus"] = "대상 후보 여러 개 · 아래 오버로드 전체 확인 필요"
        if not error:
            item["code"] = [dict(line=s["line"], end=s["end"], signature=s.get("signature", ""),
                                 lines=lines[s["line"]-1:s["end"]]) for s in matches]
    changes_by_member, tests_by_behavior = {}, {}
    for row in (r for r in plan_rows if r.kind == 'changes'):
        key = (row.cells["파일"], row.parsed.get("path"), row.parsed.get("name"))
        changes_by_member.setdefault(key, []).append({"doc": row.doc, "line": row.line,
            "operation": row.cells["변경"], "signature": row.cells["시그니처"]})
    for order, row in enumerate(r for r in plan_rows if r.kind == 'behaviors'):
        tests_by_behavior.setdefault(row.cells["동작 ID"], []).append((order, row.cells["검사 연결"]))
    for item in result.values():
        item["basisId"] = (basis or {}).get("id")
        item["documentHashes"] = (basis or {}).get("documents", {})
        plan = item["plan"]
        item["changes"] = [dict(change) for change in changes_by_member.get((plan["file"], plan["path"], plan["name"]), ())]
        item["tests"] = [link for _, link in sorted(pair for identity in set(plan.get("behaviors", []))
                          for pair in tests_by_behavior.get(identity, ()))]
    return sorted(result.values(), key=lambda x: (x["plan"]["file"], x["plan"]["path"], x["plan"]["sig"]))


def cached_implementation_plans(ds, cur, root, basis, retained, work, only_files=None):
    """구현 카드의 파일 소유 입력을 공용 정책으로 비교하고 변경 파일만 한 번에 조립한다."""
    authority = workflow.state(root)['authority']
    if authority == 'document' and (basis is None or basis.get('status') != 'ready'
            or os.path.abspath(ds.source_root) != os.path.abspath(os.path.join(root, APPROVED_ROOT))
            or getattr(ds, 'execution_basis', {}).get('id') != basis.get('id')):
        raise ValueError('승인 작업 입력 불일치')
    scope = set(only_files) if only_files is not None and 'publication-plans' in retained else None
    rows = ds.selected_rows(scope, ('members','changes','scope','behaviors'))
    design_docs = (ds._stored['design_docs'] if getattr(ds,'_stored',None) else
                   {doc for doc,lines in ds.texts.items() if any(re.match(
                       r'^\s*\|\s*상태\s*\|\s*(?:설계중|설계완료)(?:\s|—|·|\|)',line) for line in lines)})
    owners, wanted = {}, set()
    for row in rows:
        files = {r.strip().partition('#')[0] for r in row.cells['구현 대상'].split(',')} if row.kind == 'behaviors' else {row.cells['파일']}
        active = (row.kind in ('members','behaviors') and row.cells['상태'] in PLAN_WAITING
                  or row.kind == 'changes' and row.doc in design_docs
                  or row.kind == 'scope' and row.cells['상태'] == '추가' and row.cells['파일'] not in cur)
        for file in files:
            if scope is not None and file not in scope:
                continue
            owners.setdefault(file,[]).append((row.doc,row.line,row.kind,row.cells,row.parsed,row.doc in design_docs))
            if active:
                wanted.add(file)
    inputs = {}
    for file,contracts in owners.items():
        if file not in wanted:
            continue
        try:
            stat = os.stat(os.path.join(root,file))
            stamp = (stat.st_mtime_ns,stat.st_ctime_ns,stat.st_size)
        except OSError:
            stamp = None
        source = cur.fingerprint(file) if isinstance(cur,ledger.SourceIndex) else (
            cachemod.POLICY.key('publication-source',cur[file]) if file in cur else None)
        inputs[file] = (root,authority,ds.source_root,basis,contracts,source,stamp)
    def build(changed):
        grouped = {file:[] for file in changed}
        for item in implementation_plans(ds,cur,root,basis,only_files=changed):
            grouped[item['plan']['file']].append(item)
        return grouped
    values = cachemod.POLICY.partition('publication-plans',inputs,retained,build,work,scope=scope)
    return sorted((item for items in values.values() for item in items),
                  key=lambda x:(x['plan']['file'],x['plan']['path'],x['plan']['sig']))


def _state(root):
    """틀림 기록(dict 열쇠 → 이유·시각). 없으면 빈 dict."""
    try:
        with open(os.path.join(root, STATE_FILE), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_state(root, state):
    """틀림 기록을 쓴다."""
    path = os.path.join(root, STATE_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".%d.tmp" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def _pairs(root):
    """문서마다 (경로, 기준본 줄, 지금 줄). 둘이 같은 문서는 뺀다."""
    base = ensure(root)
    rels = set(docmod.doc_paths(root))
    for dirpath, _, names in os.walk(base):
        for name in names:
            if name.endswith(".md"):
                rels.add(os.path.relpath(os.path.join(dirpath, name), base).replace("\\", "/"))
    for rel in sorted(rels):
        old = _lines(os.path.join(base, rel)) or []
        new = _lines(os.path.join(root, rel)) or []
        if old != new:
            yield rel, old, new


def _build(root, progress=None):
    """변경 단위(계획·체크 전)와 문서별 (기준본 줄, 지금 줄, 맞춤)."""
    pairs = list(_pairs(root))
    if progress:
        progress("대조 중", 0, len(pairs))
    if not pairs:
        return [], {}
    base = ensure(root)
    changed = [rel for rel, _, _ in pairs]
    now_rows = _rows(docmod.load(root, [r for r in changed if os.path.exists(os.path.join(root, r))]))
    old_rows = _rows(docmod.load(base, [r for r in changed if os.path.exists(os.path.join(base, r))]))
    first_scope = {}
    for rows in (old_rows, now_rows):
        for (doc, line), r in sorted(rows.items()):
            if r.kind == "scope":
                first_scope.setdefault(doc, r.cells["파일"])
    out, per_doc = [], {}
    for done, (rel, old, new) in enumerate(pairs, 1):
        steps = _align(old, new)
        per_doc[rel] = (old, new, steps)
        # Build neighbour positions once. Rewalking all alignment steps for each
        # inserted/deleted line becomes quadratic during large document edits.
        near_new, near_old = {}, {}
        last_old = last_new = -1
        for _, i, j in steps:
            if i is not None:
                near_new[i] = last_new + 1
            if j is not None:
                near_old[j] = last_old + 1
            if i is not None:
                last_old = i
            if j is not None:
                last_new = j
        headings = {}
        for label, lines in (("old", old), ("new", new)):
            current, before = "", []
            for line in lines:
                before.append(current)
                if HEADING.match(line):
                    current = _bare(line).strip()
            headings[label] = before + [current]
        seen, group, last = {}, "", "="
        for kind, i, j in steps:
            if kind == "=":
                last = kind
                continue
            if last == "=":
                group = "%s:%d" % (rel, (j if j is not None else near_new[i]) + 1)
            last = kind
            o = old[i] if i is not None else ""
            n = new[j] if j is not None else ""
            ident = (kind, o, n)
            seen[ident] = seen.get(ident, 0) + 1
            key = hashlib.sha1(("%s\0%s\0%s\0%s\0%d" % (rel, kind, o, n, seen[ident])).encode("utf-8")).hexdigest()[:12]
            at_new = j if j is not None else near_new[i]
            at_old = i if i is not None else near_old[j]
            lines = new if j is not None or not old else old
            at = at_new if lines is new else at_old
            heading = headings["new" if lines is new else "old"][min(at, len(lines))]
            unit = Unit(rel, key, kind, _bare(o), _bare(n), at_old + 1, at_new + 1, heading,
                        [_bare(x) for x in lines[max(0, at - CONTEXT_LINES):at]],
                        [_bare(x) for x in lines[at + 1:at + 1 + CONTEXT_LINES]], group=group)
            unit.plan = _plan(now_rows.get((rel, j + 1)) if j is not None else None,
                              old_rows.get((rel, i + 1)) if i is not None else None)
            if unit.plan["action"] == "글":
                unit.plan.update({"file": first_scope.get(rel, ""), "path": "-", "name": "", "kind": "file", "table": ""})
            out.append(unit)
        if progress:
            progress("대조 중", done, len(pairs))
    return out, per_doc


def units(root):
    """모든 문서의 변경 단위(체크 상태·계획 포함). 없어진 단위의 틀림 기록은 지운다."""
    found, _ = _build(root)
    state = _state(root)
    keys = {u.key for u in found}
    stale = [k for k in state if k not in keys]
    if stale:
        for k in stale:
            del state[k]
        _save_state(root, state)
    for u in found:
        got = state.get(u.key)
        if got:
            u.verdict, u.memo = "틀림", got.get("memo", "")
    return found


def check(root, items, verdict, memo="", progress=None):
    """변경 단위들(items = [(문서, 열쇠)])을 한 번에 체크한다(2.12). 맞음이면 기준본에 문서마다 한 번에 옮기고, 틀림이면 이유와 함께 기록한다.
    돌려주는 값: dict(체크 결과·체크한 수·없는 수·남은 대기·틀림 수)."""
    with ledger.locked(root):
        try:
            if verdict not in ("맞음", "틀림"):
                raise ValueError("판정은 맞음·틀림: %s" % verdict)
            if progress:
                progress("대조 중", 0, 0)
            found, per_doc = _build(root, progress=progress)
            index = {(u.doc, u.key): u for u in found}
            picked = [index[(d, k)] for d, k in dict.fromkeys(items) if (d, k) in index]
            missing = sum(1 for d, k in dict.fromkeys(items) if (d, k) not in index)
            if not picked:
                return {"ok": False, "error": "그 변경 단위가 없음(이미 체크했거나 문서가 다시 바뀜): %d건" % missing}
            state = _state(root)
            if verdict == "맞음":
                ledger.write_binary(root, EXECUTION_FILE, {"status": "publishing", "reason": "선택 승인 반영 중"})
                by_doc = {}
                for u in picked:
                    by_doc.setdefault(u.doc, set()).add(u.key)
                for done, (doc, keys) in enumerate(by_doc.items(), 1):
                    old, new, steps = per_doc[doc]
                    seen, out = {}, []
                    for kind, i, j in steps:
                        if kind == "=":
                            out.append(old[i])
                            continue
                        o = old[i] if i is not None else ""
                        n = new[j] if j is not None else ""
                        ident = (kind, o, n)
                        seen[ident] = seen.get(ident, 0) + 1
                        k = hashlib.sha1(("%s\0%s\0%s\0%s\0%d" % (doc, kind, o, n, seen[ident])).encode("utf-8")).hexdigest()[:12]
                        take_new = k in keys
                        if kind == "추가":
                            if take_new:
                                out.append(n)
                        elif kind == "삭제":
                            if not take_new:
                                out.append(o)
                        else:
                            out.append(n if take_new else o)
                    path = os.path.join(ensure(root), doc)
                    if not out and not os.path.exists(os.path.join(root, doc)):
                        if os.path.exists(path):
                            os.remove(path)
                    else:
                        os.makedirs(os.path.dirname(path), exist_ok=True)
                        with open(path, "w", encoding="utf-8", newline="") as f:
                            f.write("".join(out))
                    if progress:
                        progress("기준본 적용 중", done, len(by_doc))
                for u in picked:
                    state.pop(u.key, None)
            else:
                for u in picked:
                    state[u.key] = {"doc": u.doc, "memo": memo, "time": ledger.now(), "old": u.old, "new": u.new, "heading": u.heading}
            _save_state(root, state)
            if progress:
                progress("체크 기록 중", 0, 0)
            log = os.path.join(root, LOG_FILE)
            os.makedirs(os.path.dirname(log), exist_ok=True)
            with open(log, "a", encoding="utf-8") as f:
                for u in picked:
                    f.write(json.dumps({"time": ledger.now(), "doc": u.doc, "key": u.key, "verdict": verdict, "memo": memo,
                                        "kind": u.kind, "heading": u.heading, "plan": u.plan}, ensure_ascii=False) + "\n")
            if verdict == "맞음":
                hashes = {}
                base = os.path.join(root, APPROVED_ROOT)
                for rel in docmod.doc_paths(base):
                    with open(os.path.join(base, rel), "rb") as stream:
                        hashes[rel] = hashlib.sha256(stream.read()).hexdigest()
                identity = hashlib.sha256(json.dumps(sorted(hashes.items()), ensure_ascii=False).encode("utf-8")).hexdigest()
                ledger.write_binary(root, EXECUTION_FILE, {"id": identity, "documents": hashes, "status": "ready", "reason": ""})
            waiting, wrong = counts(root)
            return {"ok": True, "verdict": verdict, "checked": len(picked), "missing": missing, "waiting": waiting, "wrong": wrong}
        except Exception as error:
            if verdict == "맞음":
                ledger.write_binary(root, EXECUTION_FILE, {"status": "error", "reason": str(error)})
            raise


def findings(root):
    """A1·A2 지적 [(코드, 문서, 줄, 내용)]."""
    if workflow.state(root)["authority"] == "code":
        return []
    out = []
    for u in units(root):
        where = u.heading or "(제목 없음)"
        act = u.plan.get("action", "글")
        what = act if act == "글" else "%s %s %s" % (act, u.plan.get("table", ""), u.plan.get("name") or u.plan.get("file", ""))
        if u.verdict == "틀림":
            out.append(("A2", u.doc, u.new_line, "틀림으로 체크된 문서 변경(%s · %s): %s — 이유: %s" % (u.kind, what, where, u.memo or "-")))
        else:
            out.append(("A1", u.doc, u.new_line, "체크 대기 문서 변경(%s · %s): %s" % (u.kind, what, where)))
    return out


def counts(root):
    """(체크 대기 수, 틀림 수)."""
    if workflow.state(root)["authority"] == "code":
        return 0, 0
    found = units(root)
    wrong = sum(1 for u in found if u.verdict == "틀림")
    return len(found) - wrong, wrong


def words(a, b):
    """수정 줄의 낱말 단위 조각: (옛 [(같음·다름, 글)], 새 [(같음·다름, 글)])."""
    ta, tb = re.findall(r"\s+|[^\s|`·,()]+|.", a), re.findall(r"\s+|[^\s|`·,()]+|.", b)
    sm = difflib.SequenceMatcher(None, ta, tb, autojunk=False)
    left, right = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            left.append(["같음", "".join(ta[i1:i2])])
            right.append(["같음", "".join(tb[j1:j2])])
        else:
            if i2 > i1:
                left.append(["다름", "".join(ta[i1:i2])])
            if j2 > j1:
                right.append(["다름", "".join(tb[j1:j2])])
    return left, right


def as_dict(u):
    """변경 단위 → dict(API·지도용)."""
    d = {"doc": u.doc, "key": u.key, "kind": u.kind, "old": u.old, "new": u.new, "old_line": u.old_line,
         "new_line": u.new_line, "heading": u.heading, "before": u.before, "after": u.after, "plan": u.plan,
         "verdict": u.verdict, "memo": u.memo, "group": u.group}
    if u.kind == "수정":
        d["words"] = words(u.old, u.new)
    return d


def approved_members(root):
    """승인본(`History/approved`)의 members 표를 읽어 {멤버 열쇠: (상태, 파일, parsed)}(W11 판정용, SPEC-36 E19).
    멤버 열쇠는 코드 심볼의 열쇠(`파일|형|종류|이름|매개변수`)와 같은 꼴이라 코드 존재와 바로 맞댈 수 있다."""
    base = os.path.join(root, APPROVED_ROOT)
    if not os.path.isdir(base):
        return {}
    paths = [rel for rel in docmod.doc_paths(root) if os.path.exists(os.path.join(base, rel))]
    ds = docmod.load(base, paths)
    out = {}
    for r in ds.of("members"):
        if r.parsed and r.parsed.get("key"):
            out[r.parsed["key"]] = (r.cells["상태"], r.cells["파일"], r.parsed)
    return out


def regressions(root, doc):
    """그 문서의 members 표 가운데 승인본 대비 역행 수정(SPEC-36 E19): 승인본 상태가 착수 전(PLANNED)인데 그 멤버가
    코드에 실제로 있고 문서는 착수 이후로 올림(a), 또는 승인본이 삭제 상태가 아닌데 코드에서 지워지고 문서는 삭제 쪽으로
    물러남(b). 돌려주는 값: [(종류, 파일, parsed, 승인본 상태, 작업 상태)]."""
    base = os.path.join(root, APPROVED_ROOT)
    appr = {}
    if os.path.exists(os.path.join(base, doc)):
        for r in docmod.load(base, [doc]).of("members"):
            if r.parsed and r.parsed.get("key"):
                appr[r.parsed["key"]] = (r.cells["상태"], r.cells["파일"], r.parsed)
    work = {}
    for r in docmod.load(root, [doc]).of("members"):
        if r.parsed and r.parsed.get("key"):
            work[r.parsed["key"]] = (r.cells["상태"], r.cells["파일"], r.parsed)
    code_cache = {}

    def symbol(f, key):
        if f not in code_cache:
            try:
                code_cache[f] = {s.key: s for s in (parse_cs.Symbol.from_dict(d) for d in snapshot.index_file(root, f, "심볼").get("symbols", []))}
            except (OSError, ValueError):
                code_cache[f] = {}
        return code_cache[f].get(key)

    hits = []
    for key in set(appr) | set(work):
        a, w = appr.get(key), work.get(key)
        st_a = a[0] if a else None
        st_w = w[0] if w else None
        f = (a or w)[1]
        p = (a or w)[2]
        s = symbol(f, key)
        if st_a in docmod.PLANNED and st_w is not None and st_w not in docmod.PLANNED and s is not None:
            hits.append(("advance", f, p, st_a, st_w))
        elif st_a is not None and st_a not in docmod.PLANNED and st_a not in REMOVING \
                and (st_w is None or st_w in REMOVING) and s is None:
            hits.append(("delete", f, p, st_a, st_w))
    return hits


def guard(root, doc):
    """기존 역행 지적을 반환한다. 하네스는 문서를 덮어쓰거나 삭제하지 않는다."""
    if workflow.state(root)["authority"] == "code":
        return {"reverted": False, "regressions": [], "warning": False}
    hits = regressions(root, doc)
    return {"reverted": False, "regressions": hits, "warning": bool(hits)}


def workflow_state(root):
    """문서·코드 검증 방향과 에이전트 지침."""
    return workflow.state(root)


def set_workflow(root, mode, code_policy=None):
    """작업 방향만 전환하며 문서 생성·수정은 하지 않는다."""
    return workflow.set_mode(root, mode, code_policy)

def execution_basis(root, cache=None):
    """승인 문서만 같은 잠금 안에서 읽고 원문 지문과 발행 상태를 확인한다."""
    empty = docmod.DocSet()
    empty.root = root
    status = {"id": "", "documents": {}, "status": "error", "reason": ""}
    try:
        with ledger.locked(root):
            base = os.path.join(root, APPROVED_ROOT)
            if not os.path.isdir(base):
                raise ValueError("승인본 없음 — 사용자 검토 필요")
            published = ledger.read_binary(root, EXECUTION_FILE, None)
            if published is not None and published.get("status") != "ready":
                status.update(published)
                raise ValueError("승인 입력 발행 " + str(published.get("status")))
            paths = docmod.doc_paths(base)
            if not paths:
                raise ValueError("승인 문서 없음")
            hashes = {}
            for rel in paths:
                with open(os.path.join(base, rel), "rb") as stream:
                    hashes[rel] = hashlib.sha256(stream.read()).hexdigest()
            identity = hashlib.sha256(json.dumps(sorted(hashes.items()), ensure_ascii=False).encode("utf-8")).hexdigest()
            if published is not None and (published.get("documents") != hashes or published.get("id") != identity):
                raise ValueError("발행한 승인 입력과 현재 승인본 불일치·누락")
            saved = (cache or {}).get("_approved_ds")
            if saved is not None and saved[0] == identity:
                ds = saved[1]
            else:
                ds = docmod.load(root, paths, cache, source_root=base)
                if cache is not None:
                    cache["_approved_ds"] = (identity, ds)
            status = {"id": identity, "documents": hashes, "status": "ready", "reason": ""}
            status["contractErrors"] = [vars(i) for i in ds.issues]
            blocked = set()
            behavior_locations, file_locations, structure_files = {}, {}, {}
            for row in ds.rows:
                location = (row.doc, row.line)
                if row.kind == "behaviors":
                    behavior_locations.setdefault(location, []).append(row)
                if row.cells.get("파일"):
                    file_locations.setdefault(location, set()).add(row.cells["파일"])
                if row.kind in {"architecture", "architecture-graph"}:
                    structure_files.setdefault(row.doc, set()).update(row.parsed.get("affectedFiles", []))
            for issue in ds.issues:
                rows = behavior_locations.get((issue.file, issue.line), [])
                if issue.message.startswith("구조:") or "architecture" in issue.message:
                    targets = structure_files.get(issue.file, set()) | file_locations.get((issue.file, issue.line), set())
                    if rows:
                        for row in rows:
                            for column in ("구현 대상", "검사 연결"):
                                targets.update(ref.strip().split("#", 1)[0] for ref in row.cells[column].split(",") if "#" in ref)
                    blocked.update(targets or {"*"})
                elif issue.code == "D5" and len(rows) == 1:
                    # Behavior-link failures have explicit implementation/test
                    # targets; unrelated owners do not consume this behavior.
                    for column in ("구현 대상", "검사 연결"):
                        blocked.update(ref.strip().split("#", 1)[0] for ref in rows[0].cells[column].split(",") if "#" in ref)
                else:
                    blocked.add("*")
            status["blockedFiles"] = sorted(blocked)
            if ds.issues:
                status["reason"] = "승인본 문서 오류: " + "; ".join(i.message for i in ds.issues[:4])
            ds.execution_basis = status
            return ds, status
    except (OSError, ValueError, TypeError, AttributeError, EOFError) as error:
        status.update(status="error" if status.get("status") != "publishing" else "publishing", reason=str(error))
        empty.issues.append(docmod.Issue("D1", APPROVED_ROOT, 1, "승인 입력 오류: " + str(error)))
        empty.execution_basis = status
        return empty, status


def edit_decision(root, event, data):
    """실제 전후 변경 전부를 하나의 승인 버전의 정확한 선언과 대조한다."""
    from parsing import tool_inputs
    approval_cache = {}
    ds, basis = execution_basis(root, approval_cache)
    result = {"allowed": False, "basisId": basis["id"], "targets": [], "reason": ""}
    if basis["status"] != "ready":
        result["reason"] = basis["reason"] or "승인 입력 준비되지 않음"
        return result
    try:
        changes = tool_inputs.changed_members(root, event, data)
        from parsing import globs
        active = {(r.cells["파일"], r.parsed.get("path"), r.parsed.get("name"))
                  for r in ds.of("members") if r.cells["상태"] in docmod.PLANNED | docmod.DOING}
        latest = {}
        for row in ds.of("changes"):
            identity = (row.cells["파일"], row.parsed.get("path"), row.parsed.get("name"))
            if identity in active:
                latest[(row.doc, identity)] = row
        stages = {(r.doc, r.cells["단계"]) for r in latest.values()}
        declarations = [r for r in ds.of("changes") if (r.doc, r.cells["단계"]) in stages]
        for change in changes:
            if "*" in basis.get("blockedFiles", []) or change["file"] in basis.get("blockedFiles", []):
                raise ValueError("영향받는 승인 계약 오류: " + basis["reason"])
            watches = [r for r in ds.of("watch") if globs.matches(change["file"], globs.split(r.cells["경로"]))]
            if not any(r.cells["포함"] == "포함" for r in watches) or any(r.cells["포함"] == "제외" for r in watches):
                raise ValueError("승인 감시 범위 밖: " + change["file"])
            candidates = []
            for row in declarations:
                if row.cells["파일"] != change["file"]:
                    continue
                op = row.cells["변경"]
                symbol = change.get("after") or change.get("before")
                if change["kind"] == "file":
                    matches = op == {"add": "파일 추가", "delete": "파일 삭제", "modify": "파일 변경", "move": "이동"}[change["operation"]]
                else:
                    parsed = row.parsed
                    matches = bool(parsed) and all(parsed.get(k, "") == symbol.get(k, "") for k in ("path", "name"))
                    if matches:
                        matches = parsed.get("kind") == symbol.get("kind") or (
                            change["file"].endswith(".py") and {parsed.get("kind"), symbol.get("kind")} <= {"field", "const"})
                    if matches:
                        # Parameters and full normalized signature distinguish overloads.
                        signatures = {s["signature"] for s in (change.get("before"), change.get("after")) if s}
                        matches = parsed.get("signature") in signatures
                    expected = {"add": {"추가"}, "delete": {"삭제"}, "modify": {"본문 변경"},
                                "signature": {"시그니처 변경"}, "move": {"이동"}}[change["operation"]]
                    if change["operation"] in ("modify", "signature") and op == "추가":
                        constructing = any(r.cells["파일"] == change["file"] and r.parsed.get("name") == symbol.get("name")
                            and r.parsed.get("path") == symbol.get("path") and r.cells["상태"] in docmod.PLANNED | {"구현중"}
                            for r in ds.of("members"))
                        if constructing and change.get("after", {}).get("signature") == parsed.get("signature"):
                            expected.add("추가")
                    if (change["operation"] == "modify" and op == "시그니처 변경"
                            and (change["file"], symbol.get("path"), symbol.get("name")) in active
                            and change.get("after", {}).get("signature") == parsed.get("signature")):
                        # Completing the body after reaching the approved target
                        # signature remains part of that same unfinished change.
                        expected.add("시그니처 변경")
                    matches = matches and op in expected
                if matches:
                    candidates.append({"doc": row.doc, "line": row.line, "operation": op,
                                       "signature": row.cells["시그니처"], "sha256": basis["documents"][row.doc]})
            if not candidates:
                raise ValueError("승인 변경 선언 없음: %s %s %s" % (change["file"], change["operation"],
                                 (change.get("after") or change.get("before") or {}).get("signature", "파일")))
            result["targets"].append(dict(change, declarations=candidates))
        if not changes:
            raise ValueError("실제 코드 변경 없음 또는 변경 범위 불명")
        # A concurrent approval cannot validate a request against a stale basis.
        _, current = execution_basis(root, approval_cache)
        if current["status"] != "ready" or current["id"] != basis["id"]:
            raise ValueError("승인 기준 변경(stale) — 재판정 필요")
        result["allowed"] = True
    except (OSError, ValueError, TypeError, KeyError) as error:
        result["reason"] = str(error)
    return result
