# -*- coding: utf-8 -*-
"""경로 패턴(SPEC-00 6.8.1): 프로젝트 루트 기준 `/` 경로. `**` = 하위 폴더 전체, `*` = 한 단계 이름, `?` = 한 글자, `[...]` = 글자 집합."""
import os
import re

_CACHE = {}


def to_regex(pattern):
    """패턴 하나를 정규식으로 바꾼다."""
    if pattern in _CACHE:
        return _CACHE[pattern]
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern[i:i + 3] == "**/":
                out.append("(?:.*/)?")
                i += 3
                continue
            if pattern[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i)
            if j < 0:
                out.append(re.escape(c))
            else:
                out.append("[" + pattern[i + 1:j] + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    compiled = re.compile("^" + "".join(out) + "$")
    _CACHE[pattern] = compiled
    return compiled


def split(cell):
    """표 칸의 경로 목록(`, ` 구분)을 나눈다. 빈 칸·`-`는 빈 목록."""
    if cell is None:
        return []
    items = [x.strip().strip("`").strip() for x in cell.split(",")]
    return [x for x in items if x and x != "-"]


def matches(path, patterns):
    """경로가 패턴 중 하나에 맞는가."""
    return any(to_regex(p).match(path) for p in patterns)


def prunes_dir(reldir, exclude):
    """그 폴더(루트 기준 경로)의 하위 전체가 제외인가 — os.walk가 안 내려가게(SPEC-36 6.16).
    두 겹 탐침: `reldir/\\0`와 `reldir/\\0/\\0`가 같은 제외 패턴에 둘 다 맞으면 임의 깊이까지 제외라 통째로 뺀다.
    `**`류(`.*`)는 두 탐침을 다 잡고, `/*`류(`[^/]*`)는 두 번째를 못 잡아 하위를 지우지 않는다."""
    a = reldir + "/\x00"
    b = reldir + "/\x00/\x00"
    return any(to_regex(p).match(a) and to_regex(p).match(b) for p in exclude)


def relative(root, path):
    """절대 경로를 루트 기준 `/` 경로로."""
    return os.path.relpath(path, root).replace(os.sep, "/")


def expand(root, include, exclude=()):
    """포함 패턴에 맞고 제외 패턴에 안 맞는 파일(루트 기준 경로)을 정렬해 돌려준다."""
    found = []
    tops = set()
    for p in include:
        head = p.split("*")[0].split("?")[0].split("[")[0]
        top = head.rsplit("/", 1)[0] if "/" in head else ""
        tops.add(top)
    # A parent traversal already applies every include pattern to its descendants.
    # Collapse overlapping roots before os.walk instead of merely deduplicating output.
    traversal_roots = []
    for top in sorted(tops):
        if not any(parent == "" or top == parent or top.startswith(parent + "/") for parent in traversal_roots):
            traversal_roots.append(top)
    seen = set()
    for top in traversal_roots:
        base = os.path.join(root, top) if top else root
        if os.path.isfile(base):
            rel = relative(root, base)
            if rel not in seen and matches(rel, include) and not matches(rel, exclude):
                seen.add(rel)
                found.append(rel)
            continue
        if not os.path.isdir(base):
            continue
        for folder, dirs, files in os.walk(base):
            relative_folder = relative(root, folder)
            prefix = "" if relative_folder == "." else relative_folder + "/"
            # 하위 전체가 제외인 폴더는 안 내려간다(SPEC-36 6.16) — os.walk 부하의 대부분(UniGLTF·VRM10·Library 등)
            dirs[:] = sorted(d for d in dirs if not prunes_dir(prefix + d, exclude))
            for name in sorted(files):
                rel = prefix + name
                if rel in seen:
                    continue
                if matches(rel, include) and not matches(rel, exclude):
                    seen.add(rel)
                    found.append(rel)
    return sorted(found)
