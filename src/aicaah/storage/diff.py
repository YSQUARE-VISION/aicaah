# -*- coding: utf-8 -*-
"""스냅숏 ↔ 지금의 변경(SPEC-36 2.5): 파일 단위와 심볼 단위(추가·삭제·시그니처 변경·본문 변경·이동)."""
from dataclasses import dataclass
import difflib
import io
import tokenize
import re

from parsing.parse_cs import Symbol
from parsing import parse_cs


def line_edits(before, after):
    """앞뒤 동일 줄을 제외한 구간의 교체 범위. 0부터 시작하는 반열린 줄 범위 네 값."""
    old, new = before.splitlines(keepends=True), after.splitlines(keepends=True)
    start = 0
    while start < min(len(old), len(new)) and old[start] == new[start]:
        start += 1
    a, b = len(old), len(new)
    while a > start and b > start and old[a - 1] == new[b - 1]:
        a -= 1
        b -= 1
    return [(start+i,start+j,start+k,start+l)
            for tag,i,j,k,l in difflib.SequenceMatcher(None,old[start:a],new[start:b],autojunk=False).get_opcodes()
            if tag != "equal"]


def move_line(line, edits):
    """교체 범위 뒤의 줄은 누적 줄 차이만 적용한다. 교체 안의 자리는 새 범위에 대응한다."""
    if line <= 0:
        return line
    at, shift = line - 1, 0
    for a,b,c,d in edits:
        if at < a:
            break
        if at < b:
            return c + min(at - a, max(0,d-c-1)) + 1
        shift += (d-c) - (b-a)
    return line + shift


def position_only(before, after, ext, edits):
    """내용·문법 토큰이 같고 모든 토큰 줄이 교체식에 맞는 경우만 위치 교체를 허용한다."""
    if ext == ".py":
        ignored = {tokenize.COMMENT, tokenize.NL, tokenize.ENCODING, tokenize.ENDMARKER}
        def tokens(text):
            return [(t.type, "\n" if t.type == tokenize.NEWLINE else t.string, t.start[0])
                    for t in tokenize.generate_tokens(io.StringIO(text).readline) if t.type not in ignored]
    elif ext == ".cs":
        if re.findall(r"(?m)^\s*(?:///|#).*?$|/\*\*[\s\S]*?\*/", before) != re.findall(r"(?m)^\s*(?:///|#).*?$|/\*\*[\s\S]*?\*/", after):
            return False
        def tokens(text):
            return [(t.kind,t.text,t.line) for t in parse_cs.tokenize(text)[0]]
    else:
        return False
    try:
        old, new = tokens(before), tokens(after)
    except (tokenize.TokenError, IndentationError, SyntaxError, parse_cs.ParseError):
        return False
    return len(old) == len(new) and all(a[:2] == b[:2] and move_line(a[2],edits) == b[2]
                                       for a,b in zip(old,new))


@dataclass
class Change:
    """변경 하나. line은 지금 파일의 줄(삭제는 스냅숏의 줄)."""
    kind: str
    file: str
    path: str
    symkind: str
    name: str
    signature: str
    line: int
    detail: str = ""
    base_file: str = ""


def _symbols(entry):
    """색인 항목의 심볼을 키 → 심볼 사전으로."""
    return {s.key: s for s in (Symbol.from_dict(d) for d in entry.get("symbols", []))}


def _move_key(s):
    """이동 판정 키: 동일 소속 형·종류·이름·매개변수 형·선언 서명·본문."""
    return "%s|%s|%s|%s|%s|%s" % (s.path, s.kind, s.name, s.params, s.signature, s.body)


def compare(base_files, cur_files):
    """두 색인의 변경 목록."""
    changes = []
    added, removed = [], []
    for rel in sorted(set(base_files) | set(cur_files)):
        b, c = base_files.get(rel), cur_files.get(rel)
        if b and c and b["sha256"] == c["sha256"]:
            continue
        if c and not b:
            changes.append(Change("파일 추가", rel, "-", "file", rel, "-", 1))
            added.extend(_symbols(c).values())
            continue
        if b and not c:
            changes.append(Change("파일 삭제", rel, "-", "file", rel, "-", 1))
            removed.extend(_symbols(b).values())
            continue
        if c["unit"] != "심볼" or (not c["symbols"] and not b.get("symbols")):
            changes.append(Change("파일 변경", rel, "-", "file", rel, "-", 1))
            continue
        bs, cs = _symbols(b), _symbols(c)
        for key in sorted(set(bs) | set(cs)):
            x, y = bs.get(key), cs.get(key)
            if y and not x:
                added.append(y)
            elif x and not y:
                removed.append(x)
            elif x.signature != y.signature:
                changes.append(Change("시그니처 변경", rel, y.path, y.kind, y.name, y.signature, y.line,
                                      "이전: " + x.signature))
            elif x.body != y.body:
                changes.append(Change("본문 변경", rel, y.path, y.kind, y.name, y.signature, y.line,
                                      "L%d-%d" % (y.line, y.end)))
    pool = {}
    for s in removed:
        pool.setdefault(_move_key(s), []).append(s)
    for s in added:
        prev = pool.get(_move_key(s))
        if prev:
            old = prev.pop(0)
            changes.append(Change("이동", s.file, s.path, s.kind, s.name, s.signature, s.line,
                                  "이전: %s %s" % (old.file, old.path), old.file))
            continue
        changes.append(Change("추가", s.file, s.path, s.kind, s.name, s.signature, s.line))
    for group in pool.values():
        for s in group:
            changes.append(Change("삭제", s.file, s.path, s.kind, s.name, s.signature, s.line))
    return changes
