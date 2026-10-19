# -*- coding: utf-8 -*-
"""우선순위·페이즈(SPEC-36 2.13)와 페이즈 탭 조작(2.9.2). 페이즈 표(SPEC-00 6.8.6)를 읽어 모든 지적에 순위를 매기고,
완료 이력을 보존하고 미완료 순서로만 진행한다. 탭 조작은 표를 고쳐 문서와 체크 기준본에 쓴다."""
import fnmatch
import json
import os
import re
import weakref
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache

from judging import check as checkmod
from documents import docs as docmod
from storage import ledger
from judging import meta as metamod
from documents import review
from storage import snapshot
from documents import workflow

LOG_FILE = ledger.HISTORY_ROOT + "/phases.jsonl"
STATE_FILE = ledger.HISTORY_ROOT + "/phase-progress.bin"
HEADER = re.compile(r"^\s*\|\s*순위\s*\|\s*페이즈\s*\|\s*대상\s*\|\s*이유\s*\|\s*$")


@dataclass
class Phase:
    """페이즈 표 행 하나: 순위·이름·대상·이유·문서·줄."""
    rank: int
    name: str
    targets: list = field(default_factory=list)
    reason: str = ""
    doc: str = ""
    line: int = 0


def parse_targets(text):
    """대상 칸 → 대상 목록. 형식이 틀리면 ValueError. 경로패턴 자리의 `@문서경로`는 그 문서가 건드리는 자리(2.13)."""
    out = []
    for item in [x.strip() for x in (text or "").split(",") if x.strip()]:
        m = re.match(r"^단계 (\S+)$", item)
        if m:
            out.append(("단계", m.group(1)))
            continue
        m = re.match(r"^([A-Z*][A-Za-z0-9*]*) (\S+)$", item)
        if not m:
            raise ValueError("대상 형식이 아님: %s" % item)
        if m.group(2) == "@":
            raise ValueError("문서 경로가 비었음: %s" % item)
        out.append(("지적", m.group(1), m.group(2)))
    if not out:
        raise ValueError("대상이 비었음")
    return out


def _text(targets):
    """대상 목록 → 대상 칸 글."""
    return ", ".join("단계 " + t[1] if t[0] == "단계" else t[1] + " " + t[2] for t in targets)


def rows(ds):
    """페이즈 표 행(순위순)."""
    out = []
    for r in ds.of("phases"):
        try:
            out.append(Phase(int(r.cells["순위"]), r.cells["페이즈"], parse_targets(r.cells["대상"]), r.cells["이유"], r.doc, r.line))
        except ValueError:
            continue
    return sorted(out, key=lambda s: s.rank)


def stage_files(ds, label):
    """단계 범위: 그 단계 changes 행의 파일과, 그 파일을 scope에 둔 문서·그 changes 행이 있는 문서."""
    found = ds.of("changes",cells={"단계":label})
    files = {r.cells["파일"] for r in found}
    return files | {r.doc for r in found} | {r.doc for r in ds.of("scope",files=files) if r.cells["파일"] in files}


_STAGES = weakref.WeakKeyDictionary()


@lru_cache(maxsize=8192)
def _path_match(pattern, path):
    """경로 패턴(`**` = 하위 전체, `*` = 한 단계)이 맞는가. 패턴이 폴더면 그 폴더 자신도 맞는다."""
    rx = "^" + re.escape(pattern).replace(r"\*\*", "\0").replace(r"\*", "[^/]*").replace("\0", ".*") + "$"
    return re.match(rx, path) is not None


def matches(sp, f, ds, places=None):
    """지적이 페이즈 대상에 맞는가(코드 패턴·경로 패턴, 단계 범위). `@문서경로`는 places(자리 → 문서)로 그 문서가 건드리는 자리인지 본다."""
    for t in sp.targets:
        if t[0] == "단계":
            stages = _STAGES.setdefault(ds, {})
            if t[1] not in stages:
                stages[t[1]] = stage_files(ds, t[1])
            if f.file in stages[t[1]]:
                return True
        elif not fnmatch.fnmatchcase(f.code, t[1]):
            continue
        elif t[2].startswith("@"):
            if places and t[2][1:] in (places.get(f.file) or ()):
                return True
        elif _path_match(t[2], f.file):
            return True
    return False


def assign(ds, findings, places=None):
    """지적마다 순위·페이즈, 페이즈마다 남은 지적, 지금·다음 페이즈(2.13).
    돌려주는 값: (지적 열쇠 → (순위, 이름), 이름 → 남은 지적, 지금 행, 다음 행)."""
    sps = rows(ds)
    completed = set(ledger.read_binary(getattr(ds, "root", ""), STATE_FILE, {}).get("completed", []))
    unfinished = [sp for sp in sps if sp.name not in completed]
    ranks, remaining = {}, {sp.name: [] for sp in sps}
    selected = {}
    for f in findings:
        owner = (f.code,f.file)
        if owner not in selected:
            candidates = [sp for sp in sps if matches(sp,f,ds,places)]
            selected[owner] = candidates[0] if len(candidates) == 1 else None
        sp = selected[owner]
        if sp is None:
            ranks[checkmod.finding_key(f)] = (len(sps) + 1, "미배정")
        else:
            ranks[checkmod.finding_key(f)] = (sp.rank,sp.name)
            remaining[sp.name].append(f)
    current = next((sp for sp in unfinished if remaining[sp.name]), None)
    following = next((sp for sp in unfinished if current is not None and sp.rank > current.rank and remaining[sp.name]), None)
    return ranks, remaining, current, following


def advance(root, ds, findings, places=None):
    """정상 전체 판정 뒤 빈 선행 페이즈만 완료로 확정한다. 완료 이름은 되돌리지 않는다."""
    state = ledger.read_binary(root, STATE_FILE, {"completed": []})
    completed = set(state["completed"])
    _, remaining, _, _ = assign(ds, findings, places)
    sps = rows(ds)
    conflicts = set()
    seen = set()
    for f in findings:
        owner = (f.code, f.file)
        if owner in seen:
            continue
        seen.add(owner)
        candidates = [sp.name for sp in sps if matches(sp,f,ds,places)]
        if len(candidates) > 1:
            conflicts.update(candidates)
    for sp in sps:
        if sp.name in completed:
            continue
        if sp.name in conflicts:
            break
        if remaining[sp.name]:
            break
        state["completed"].append(sp.name)
        completed.add(sp.name)
    if state != ledger.read_binary(root, STATE_FILE, {}):
        ledger.write_binary(root, STATE_FILE, state)


def as_dict(ds, findings, places=None, assigned=None):
    """페이즈 탭 자료: 행마다 순위·이름·대상·이유·상태·코드별 남은 수·남은 지적(앞 200건), 미배정 수."""
    ranks, remaining, current, following = assigned if assigned is not None else assign(ds, findings, places)
    completed = set(ledger.read_binary(getattr(ds, "root", ""), STATE_FILE, {}).get("completed", []))
    out = []
    sps = rows(ds)
    conflicts = []
    owners = {}
    for f in findings:
        identity = (f.code, f.file)
        if identity not in owners:
            owners[identity] = [sp.name for sp in sps if matches(sp,f,ds,places)]
        if len(owners[identity]) > 1:
            conflicts.append({"code":f.code,"file":f.file,"line":f.line,"message":f.message,"phases":owners[identity]})
    for sp in sps:
        left = remaining[sp.name]
        if sp.name in completed and left:
            state = "재발"
        elif any(sp.name in conflict["phases"] for conflict in conflicts):
            state = "배정 충돌"
        elif current is not None and sp.name == current.name:
            state = "지금"
        elif following is not None and sp.name == following.name:
            state = "다음"
        else:
            state = "끝남" if sp.name in completed else "대기"
        out.append({"rank": sp.rank, "name": sp.name, "targets": _text(sp.targets), "reason": sp.reason, "state": state,
                    "left": len(left), "counts": dict(Counter(f.code for f in left)),
                    "findings": [[f.code, f.file, f.line, f.message] for f in left[:200]]})
    return {"rows": out, "current": current.name if current else "", "next": following.name if following else "",
            "unassigned": sum(1 for f in findings if ranks[checkmod.finding_key(f)][1] == "미배정"),
            "ambiguous": conflicts, "followup": []}


def _rewrite(root, ds, rows):
    """페이즈 표 행을 새 순서로 문서와 체크 기준본에 쓴다(순위는 1부터 다시 매김)."""
    table = ds.of("phases")
    if not table:
        raise ValueError("페이즈 표가 없음")
    doc = table[0].doc
    body = ["| %d | %s | `%s` | %s |" % (k + 1, sp.name, _text(sp.targets), sp.reason) for k, sp in enumerate(rows)]

    def replace(path):
        """그 파일의 페이즈 표 몸(머리줄·구분줄 뒤 행들)을 새 행으로. 표가 없으면 False."""
        if not os.path.isfile(path):
            return False
        with open(path, encoding="utf-8", newline="") as f:
            text = f.read()
        nl = "\r\n" if "\r\n" in text else "\n"
        lines = text.split(nl)
        head = next((k for k, l in enumerate(lines) if HEADER.match(l)), None)
        if head is None:
            return False
        start = head + 2
        end = start
        while end < len(lines) and lines[end].strip().startswith("|"):
            end += 1
        lines[start:end] = body
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(nl.join(lines))
        return True

    replace(os.path.join(root, doc))
    replace(os.path.join(review.ensure(root), doc))
    return body


def _findings(root):
    """마지막 보고서의 지적(지금 페이즈를 정할 때)."""
    try:
        with open(os.path.join(root, snapshot.REPORT_ROOT, "latest.json"), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    return [checkmod.Finding(i["code"], i["file"], i["line"], i["message"], i.get("rule", "")) for i in data.get("findings", [])]


def _find(sps, name):
    """이름으로 페이즈 번호. 없으면 ValueError."""
    for k, sp in enumerate(sps):
        if sp.name == name:
            return k
    raise ValueError("그 페이즈가 없음: %s" % name)


def move(root, name, rank):
    """페이즈를 그 순위로 옮기고 사이 행을 민다."""
    ds = docmod.load(root)
    sps = rows(ds)
    completed = set(ledger.read_binary(root, STATE_FILE, {}).get("completed", []))
    if name in completed or int(rank) <= sum(sp.name in completed for sp in sps):
        raise ValueError("완료한 페이즈를 옮기거나 그 앞으로 되돌릴 수 없습니다")
    k = _find(sps, name)
    sp = sps.pop(k)
    to = max(0, min(len(sps), int(rank) - 1))
    sps.insert(to, sp)
    body = _rewrite(root, ds, sps)
    _log(root, "옮김", name, k + 1, to + 1)
    return body


def insert(root, name, targets, reason):
    """새 페이즈를 지금 페이즈 바로 다음 순위로 넣고 뒤를 한 칸씩 민다(지금이 없으면 1순위)."""
    name = (name or "").strip()
    if not name:
        raise ValueError("페이즈 이름이 비었음")
    if not re.fullmatch(r"PH[A-Za-z0-9_-]+", name):
        raise ValueError("페이즈 이름은 PH 접두와 영문·숫자·밑줄·하이픈을 사용합니다: " + name)
    parsed = parse_targets(targets)
    ds = docmod.load(root)
    sps = rows(ds)
    completed = set(ledger.read_binary(root, STATE_FILE, {}).get("completed", []))
    if name in completed or any(sp.name == name for sp in sps):
        raise ValueError("같은 이름의 페이즈가 있음: %s" % name)
    _, _, current, _ = assign(ds, _findings(root), metamod.load_places(root))
    at = sps.index(current) + 1 if current is not None else len(sps)
    sps.insert(at, Phase(0, name, parsed, (reason or "").strip() or "-"))
    body = _rewrite(root, ds, sps)
    _log(root, "넣음", name, None, at + 1)
    return body


def defer(root, name):
    """페이즈를 맨 뒤로 보낸다."""
    ds = docmod.load(root)
    sps = rows(ds)
    if name in ledger.read_binary(root, STATE_FILE, {}).get("completed", []):
        raise ValueError("완료한 페이즈는 보류할 수 없습니다")
    k = _find(sps, name)
    sps.append(sps.pop(k))
    body = _rewrite(root, ds, sps)
    _log(root, "보류", name, k + 1, len(sps))
    return body


def drop(root, name):
    """페이즈 행을 지운다."""
    ds = docmod.load(root)
    sps = rows(ds)
    if name in ledger.read_binary(root, STATE_FILE, {}).get("completed", []):
        raise ValueError("완료한 페이즈는 삭제할 수 없습니다")
    k = _find(sps, name)
    sps.pop(k)
    body = _rewrite(root, ds, sps)
    _log(root, "지움", name, k + 1, None)
    return body


def _log(root, op, name, before, after):
    """조작 이력 한 줄."""
    path = os.path.join(root, LOG_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"time": ledger.now(), "op": op, "name": name, "before": before, "after": after}, ensure_ascii=False) + "\n")
