# -*- coding: utf-8 -*-
"""계층·연결 판정(SPEC-36 2.8.3·2.8.4). 참조 그래프와 계층·진입점·인터페이스 표로 닿음을 넓히고 L1~L5를 낸다.
계층 이름·진입점은 문서 표에서만 온다."""
import os
import marshal
import hashlib
import re
from dataclasses import dataclass, field

from parsing import globs
from graph import refs

TYPE_KINDS = {"class", "struct", "interface", "enum", "record", "delegate"}
SKIP_KINDS = {"enum-member", "module", "other"}
CONVERSIONS = {"op_Implicit", "op_Explicit"}
SCRIPT_GUID = re.compile(r"m_Script:\s*\{fileID:\s*-?\d+,\s*guid:\s*([0-9a-f]{32})")
META_GUID = re.compile(r"^guid:\s*([0-9a-f]{32})", re.MULTILINE)


@dataclass
class Analysis:
    """지도가 쓰는 판정 결과: 그래프, 계층 행, 파일의 계층, 위반 참조(출발, 대상), 선언별 상태(L3·L4)."""
    graph: refs.Graph
    rows: list
    file_layer: list
    bad_edges: set = field(default_factory=set)
    status: dict = field(default_factory=dict)


def _simple(name):
    """전체 이름의 마지막 이름(끝의 `Attribute`와 제네릭 인자는 뺀다)."""
    name = re.sub(r"<.*>$", "", name or "").split(".")[-1]
    return name[:-len("Attribute")] if name.endswith("Attribute") and len(name) > len("Attribute") else name


def _base_match(bases, target):
    """조상 목록에 대상 형이 있는가(전체 이름. 해석 못 한 형은 이름만)."""
    for b in bases:
        b = re.sub(r"<.*>$", "", b)
        if b == target or ("." not in b and b == _simple(target)):
            return True
    return False


class _Entries:
    """진입점 표를 계층별로 푼 것."""

    def __init__(self, ds):
        """종류별로 모은다."""
        self.attrs, self.messages, self.scenes, self.names, self.serial, self.scripts = {}, {}, {}, {}, {}, {}
        self.inherits = {}
        for r in ds.of("entries"):
            layer_names = [x.strip() for x in r.cells["계층"].split(",") if x.strip()]
            kind, target = r.cells["종류"], r.cells["대상"]
            for L in layer_names:
                if kind == "특성":
                    self.attrs.setdefault(L, set()).update(_simple(x) for x in globs.split(target))
                elif kind == "메시지":
                    base, _, names = target.partition(":")
                    self.messages.setdefault(L, []).append((base.strip(), set(globs.split(names))))
                elif kind == "상속":
                    self.inherits.setdefault(L, []).extend(globs.split(target))
                elif kind == "장면":
                    self.scenes.setdefault(L, []).extend(globs.split(target))
                elif kind == "이름":
                    self.names.setdefault(L, set()).update(globs.split(target))
                elif kind == "직렬화":
                    marks, _, fattrs = target.partition(";")
                    self.serial.setdefault(L, []).append((globs.split(marks), {_simple(x) for x in globs.split(fattrs)}))
                elif kind == "스크립트":
                    self.scripts.setdefault(L, []).extend(globs.split(target))


class _Graph:
    """판정용 색인: 나가는 참조, 형의 멤버, 재정의 관계, 문자열 호출, 이름별 멤버, 전체 이름별 형."""

    def __init__(self, graph):
        """그래프에서 색인을 만든다."""
        self.g = graph
        self.extras = {}
        n = len(graph.decls)
        self.out = [[] for _ in range(n)]
        for e in graph.edges:
            if tuple(e) in graph.execution_edges:
                continue
            self.out[e[0]].append((e[1], e[4]))
        self.members = [[] for _ in range(n)]
        self.by_name = {}
        self.types_by_full = {}
        for i, d in enumerate(graph.decls):
            if "kind" not in d:
                continue
            c = d.get("container", -1)
            if c is not None and c >= 0:
                self.members[c].append(i)
            if d["kind"] not in TYPE_KINDS:
                self.by_name.setdefault(d["name"], []).append(i)
            else:
                self.types_by_full.setdefault(self.full_name(i), []).append(i)
        self.overrides_of = [[] for _ in range(n)]
        self.overridden_by = [[] for _ in range(n)]
        self.external = set()
        for impl, target, ext in graph.overrides:
            if ext or target < 0:
                self.external.add(impl)
            else:
                self.overrides_of[impl].append(target)
                self.overridden_by[target].append(impl)
        self.strings = [[] for _ in range(n)]
        for s in graph.strings:
            self.strings[s[0]].append((s[4], s[5]))

    def full_name(self, i):
        """형의 전체 이름(문서 주석 id에서 앞 글자·제네릭 표시·파일을 뺀 것)."""
        key = self.g.decls[i]["key"]
        ident = key.rsplit("@", 1)[0]
        ident = ident[2:] if len(ident) > 2 and ident[1] == ":" else ident
        return re.sub(r"`\d+", "", ident)

    def string_targets(self, name, t, layer, decl_layer):
        """문자열 호출이 가리키는 멤버: 대상 형을 알면 그 형과 소스 조상 안, 모르면 부르는 코드와 같은 계층 안의 그 이름."""
        cands = self.by_name.get(name, [])
        if t is None or t < 0:
            return [c for c in cands if decl_layer[c] == layer]
        scope = {t}
        for b in self.g.decls[t].get("bases", []):
            scope.update(self.types_by_full.get(re.sub(r"<.*>$", "", b), []))
        return [c for c in cands if self.g.decls[c].get("container") in scope]


def _guid(root, rel, pattern, cache):
    """장면·스크립트 GUID는 파일 위치·수정 시각·크기가 변할 때만 다시 읽는다."""
    path = os.path.join(root, rel)
    try:
        stat = os.stat(path)
    except FileNotFoundError:
        cache.pop(path, None)
        return ()
    fingerprint = (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size, pattern.pattern)
    saved = cache.get(path)
    if saved is None or saved[0] != fingerprint:
        with open(path, encoding="utf-8", errors="replace") as stream:
            saved = (fingerprint, tuple(pattern.findall(stream.read())))
        cache[path] = saved
    return saved[1]


def _roots(root, ds, graph, ix, decl_layer, entries, cache=None):
    """계층별 뿌리(특성·장면·이름·스크립트). 메시지·직렬화는 형이 닿을 때 붙는다."""
    roots = {}
    cache = {} if cache is None else cache
    live = set()
    decls = graph.decls
    for i, d in enumerate(decls):
        L = decl_layer[i]
        if L is None or "kind" not in d:
            continue
        if entries.attrs.get(L) and any(_simple(a) in entries.attrs[L] for a in d.get("attrs", [])):
            roots.setdefault(L, set()).add(i)
        if d["kind"] == "method" and "static" in d.get("mods", []):
            owner = decls[d["container"]].get("name") if d.get("container", -1) >= 0 else None
            names = entries.names.get(L, ())
            if d["name"] in names or ("%s.%s" % (owner, d["name"])) in names:
                roots.setdefault(L, set()).add(i)
        if d["kind"] in TYPE_KINDS and any(_base_match(d.get("bases", []), b) for b in entries.inherits.get(L, [])):
            roots.setdefault(L, set()).add(i)
        if d["kind"] == "module" and globs.matches(graph.files[d["file"]], entries.scripts.get(L, [])):
            roots.setdefault(L, set()).add(i)
    for L, patterns in entries.scenes.items():
        guids = set()
        for rel in globs.expand(root, patterns):
            live.add(os.path.join(root, rel))
            guids.update(_guid(root, rel, SCRIPT_GUID, cache))
        for i, d in enumerate(decls):
            if decl_layer[i] != L or d.get("kind") not in TYPE_KINDS or d.get("container", -1) >= 0:
                continue
            rel = graph.files[d["file"]]
            if d["name"] != os.path.splitext(os.path.basename(rel))[0]:
                continue
            live.add(os.path.join(root, rel + ".meta"))
            marks = _guid(root, rel + ".meta", META_GUID, cache)
            if marks and marks[0] in guids:
                roots.setdefault(L, set()).add(i)
    for path in cache.keys() - live:
        del cache[path]
    return roots


def _type_extras(i, ix, decl_layer, entries):
    """형이 닿으면 함께 닿는 멤버: 정적·매개변수 없는 생성자, 메시지, 직렬화 필드, 외부 멤버 재정의·구현, 파이썬 `__이름__`."""
    if i in ix.extras:
        return ix.extras[i]
    decls = ix.g.decls
    d = decls[i]
    L = decl_layer[i]
    bases = d.get("bases", [])
    msgs = [names for base, names in entries.messages.get(L, []) if _base_match(bases, base)]
    serial = []
    attrs = {_simple(a) for a in d.get("attrs", [])}
    for marks, fattrs in entries.serial.get(L, []):
        if any(_simple(m) in attrs or _base_match(bases, m) for m in marks):
            serial.append(fattrs)
    python = d["key"].startswith("py:")
    out = []
    for m in ix.members[i]:
        md = decls[m]
        ident = md["key"].rsplit("@", 1)[0]
        if md["kind"] == "ctor" and (ident.endswith("#cctor") or ident.endswith("#ctor")):
            out.append(m)
        elif m in ix.external:
            out.append(m)
        elif md["kind"] == "method" and any(globs.matches(md["name"], names) for names in msgs):
            out.append(m)
        elif md["kind"] == "field" and serial and "static" not in md.get("mods", []) and "const" not in md.get("mods", []) and (
                md.get("access") == "public" or any(_simple(a) in fa for fa in serial for a in md.get("attrs", []))):
            out.append(m)
        elif python and md["name"].startswith("__") and md["name"].endswith("__"):
            out.append(m)
    ix.extras[i] = out
    return out


def _reach(roots, ix, decl_layer, entries):
    """뿌리에서 닿는 선언(2.8.3 규칙 1~4)과 쓰기만 받은 필드."""
    decls = ix.g.decls
    seen, written = set(), set()
    stack = list(roots)
    while stack:
        x = stack.pop()
        if x in seen:
            continue
        seen.add(x)
        d = decls[x]
        if "kind" not in d:
            continue
        c = d.get("container", -1)
        if c is not None and c >= 0 and c not in seen:
            stack.append(c)
        for to, w in ix.out[x]:
            if w and decls[to].get("kind") == "field":
                written.add(to)
            elif to not in seen:
                stack.append(to)
        for name, t in ix.strings[x]:
            stack.extend(m for m in ix.string_targets(name, t, decl_layer[x], decl_layer) if m not in seen)
        if d["kind"] in TYPE_KINDS:
            stack.extend(m for m in _type_extras(x, ix, decl_layer, entries) if m not in seen)
            for m in ix.members[x]:
                if m not in seen and any(o in seen for o in ix.overrides_of[m]):
                    stack.append(m)
        for impl in ix.overridden_by[x]:
            if impl not in seen and decls[impl].get("container", -1) in seen:
                stack.append(impl)
    return seen, written


def _display(decls, i):
    """선언 표시 이름: 종류 + 소속 형.이름."""
    d = decls[i]
    c = d.get("container", -1)
    owner = decls[c].get("name") if c is not None and c >= 0 and decls[c].get("kind") in TYPE_KINDS else None
    return "%s %s" % (d.get("kind"), ("%s.%s" % (owner, d.get("name"))) if owner else d.get("name"))


def _interface(ds):
    """쓰는 계층 → {형 이름: 멤버 이름 집합 또는 '*'}."""
    out = {}
    for r in ds.of("interface"):
        members = r.cells["멤버"].strip()
        for L in [x.strip() for x in r.cells["계층"].split(",") if x.strip()]:
            names = "*" if members == "*" else set(globs.split(members))
            out.setdefault(L, {})[_simple(r.cells["형"])] = names
    return out


def _allowed(decls, i, rules):
    """인터페이스 표가 이 선언을 허용하는가: 형이면 표에 있어야 하고, 멤버면 소속 형이 표에 있고 `*`(공개) 또는 이름이 적혀 있어야 한다."""
    d = decls[i]
    if d.get("kind") in TYPE_KINDS:
        return d["name"] in rules
    c = d.get("container", -1)
    while c is not None and c >= 0:
        owner = decls[c]
        names = rules.get(owner.get("name"))
        if names is not None:
            return (names == "*" and d.get("access") == "public") or (names != "*" and d.get("name") in names)
        c = owner.get("container", -1)
    return False


SHADER_EXT = (".shader", ".compute", ".cginc", ".hlsl")
INCLUDE_EXT = (".cginc", ".hlsl")


def _place(pattern):
    """셰이더 자리 표의 경로 패턴 → 정규식(`{기능}` = 한 단계 이상의 폴더, 이름 그룹 f)."""
    token = "QQFEATUREQQ"
    return re.compile(globs.to_regex(pattern.replace("{기능}", token)).pattern.replace(token, "(?P<f>.+)"))


def _common(folders):
    """폴더들(`/` 경로)의 공통 앞 폴더."""
    out = []
    for group in zip(*[f.split("/") for f in folders]):
        if len(set(group)) != 1:
            break
        out.append(group[0])
    return "/".join(out)


def _calls(literal, base, stem, declared):
    """코드의 글자 하나가 그 셰이더를 부르는가 — 확장자 뺀 이름, 선언 이름, 끝 이름이 파일 이름인 경로."""
    return literal == stem or (declared is not None and literal == declared) or literal.rsplit("/", 1)[-1] == base


def shaders(root, ds, cur, add):
    """L6(2.8.4): 셰이더 자리 표로 셰이더 파일의 자리·부르는 코드·기능 폴더를 본다. 참조 그래프 없이 글자로. 표가 없으면 하지 않는다."""
    rows = ds.of("shaders")
    if not rows:
        return
    places = [(_place(p), [_place(c) for c in globs.split(r.cells["부르는 코드"])]) for r in rows for p in globs.split(r.cells["자리"])]
    files = sorted(rel for rel in cur if os.path.splitext(rel)[1].lower() in SHADER_EXT)
    code = sorted(rel for rel in cur if rel.endswith((".cs", ".ps1")))
    texts, literals = {}, {}

    def text(rel):
        if rel not in texts:
            with open(os.path.join(root, rel), encoding="utf-8-sig", errors="replace") as f:
                texts[rel] = f.read()
        return texts[rel]

    def strings(rel):
        if rel not in literals:
            if rel.endswith(".ps1"):
                # Only actual asset-loader expressions (including C# generated
                # by the runner), never bundle input/file-name mentions alone.
                literals[rel] = set(re.findall(r'\bLoad(?:Compute|Resource(?:<[^>\n]+>)?)\s*\(\s*"([^"\n]+)"', text(rel)))
            else:
                literals[rel] = set(re.findall(r'"((?:[^"\\\n]|\\.)*)"', text(rel)))
        return literals[rel]

    placed = {}
    for rel in files:
        hit = next(((m, callers) for rx, callers in places for m in [rx.match(rel)] if m), None)
        if hit is None:
            add("L6", rel, 1, "셰이더 자리 밖 — 셰이더 자리 표(SPEC-00 3.4.4)의 어느 자리에도 없음")
            continue
        placed[rel] = (hit[0].group("f"), hit[1])
    for rel, (feature, callers) in sorted(placed.items()):
        base = rel.rsplit("/", 1)[-1]
        stem = os.path.splitext(base)[0]
        if rel.lower().endswith(INCLUDE_EXT):
            users = [(s, placed[s][0]) for s in placed if s != rel and not s.lower().endswith(INCLUDE_EXT)
                     and any(inc.rsplit("/", 1)[-1] == base for inc in re.findall(r'#include\s+"([^"]+)"', text(s)))]
            what = "들이는 셰이더"
        else:
            m = re.search(r'(?m)^\ufeff?\s*Shader\s+"([^"]+)"', text(rel))
            declared = m.group(1) if m else None
            users = [(c, f.group("f")) for c in code for rx in callers for f in [rx.match(c)]
                     if f and any(_calls(lit, base, stem, declared) for lit in strings(c))]
            what = "부르는 코드"
        if not users:
            add("L6", rel, 1, "%s가 없는 셰이더 — 이름·파일 이름을 쓰는 곳이 없음" % what)
            continue
        common = _common([f for _, f in users]) or "Shared"
        if common != feature:
            add("L6", rel, 1, "기능 폴더가 다름: 자리 %s, %s의 공통 폴더 %s(%s)"
                % (feature, what, common or "-", ", ".join(sorted({u for u, _ in users})[:4])))


def judge(root, ds, graph, cur, add, cache=None, unit_cache=None):
    """L1~L5를 add(코드, 파일, 줄, 내용)로 내고 지도용 판정 결과를 돌려준다. 계층 표가 없으면 None."""
    cache = {} if cache is None else cache
    rows = refs.layers(ds)
    if not rows:
        return None
    by_name = {L.name: L for L in rows}
    order = {L.name: k for k, L in enumerate(rows)}
    symbol_files = {rel for rel, e in cur.items() if e.get("unit") == "심볼" and os.path.splitext(rel)[1] in (".cs", ".py")}
    file_layer = []
    for rel in graph.files:
        layer = refs.layer_of(rel, rows)
        file_layer.append(layer.name if layer and rel in symbol_files else None)
    decls = graph.decls
    decl_layer = [file_layer[d["file"]] if "kind" in d else None for d in decls]
    ix = _Graph(graph)
    entries = _Entries(ds)
    roots = _roots(root, ds, graph, ix, decl_layer, entries, cache)
    reach, written = {}, set()
    for L in rows:
        seen, w = _reach(roots.get(L.name, set()), ix, decl_layer, entries)
        reach[L.name] = seen
        written |= w
    # PS1 컴파일마다 재결합된 본문을 독립 순회한 뒤 원천 선언의 닿음만 합친다.
    canonical = {d["key"]: i for i, d in enumerate(decls)}
    # Only reachability depends on these tables. Member descriptions and their lines do not.
    reach_contract = tuple((kind, tuple(tuple(sorted(r.cells.items())) for r in ds.of(kind)))
                           for kind in ("layers", "entries"))
    asset_signature = tuple(sorted((path, value[0]) for path, value in (cache or {}).items()))
    published_units = {} if unit_cache is None else unit_cache
    current_units = {}
    for compilation in graph.compilations:
        identity = (tuple(compilation["files"]), tuple(sorted(compilation["owners"])))
        fingerprint = (reach_contract, asset_signature, refs.compilation_fingerprint(compilation))
        saved = published_units.get(identity)
        if saved is not None and saved[0] == fingerprint:
            for layer_name, keys in saved[1]:
                reach[layer_name].update(canonical[key] for key in keys if key in canonical)
            written.update(canonical[key] for key in saved[2] if key in canonical)
            current_units[identity] = saved
            continue
        unit = refs.Graph()
        refs._Merger(unit).add(refs.compilation_data(compilation))
        unit_layers = [refs.layer_of(f, rows) for f in unit.files]
        local_layers = [unit_layers[d["file"]].name if "kind" in d and unit_layers[d["file"]] else None for d in unit.decls]
        local_ix = _Graph(unit)
        local_roots = _roots(root, ds, unit, local_ix, local_layers, entries)
        owners = set(compilation["owners"])
        reached_keys, written_keys = [], set()
        for L, candidates in local_roots.items():
            owned = {i for i in candidates if unit.files[unit.decls[i]["file"]] in owners}
            seen, writes = _reach(owned, local_ix, local_layers, entries)
            reach[L].update(canonical[unit.decls[i]["key"]] for i in seen if unit.decls[i]["key"] in canonical)
            written.update(canonical[unit.decls[i]["key"]] for i in writes if unit.decls[i]["key"] in canonical)
            reached_keys.append((L, frozenset(unit.decls[i]["key"] for i in seen)))
            written_keys.update(unit.decls[i]["key"] for i in writes)
        current_units[identity] = (fingerprint, tuple(reached_keys), frozenset(written_keys))
    # Bound residency to current compilations; never retain local graphs or decoded bodies.
    if unit_cache is not None:
        unit_cache.clear()
        unit_cache.update(current_units)
    a = Analysis(graph, rows, file_layer)

    # L1 ① 계층 밖 코드 파일
    for rel in sorted(symbol_files):
        if refs.layer_of(rel, rows) is None:
            add("L1", rel, 1, "어느 계층 경로에도 없는 코드 파일(SPEC-00 3.4.1)")
    # L1 ② 문서가 둔 파일과 다른 곳에 선언된 형
    documented = {}
    for r in ds.of("members"):
        if r.parsed and r.cells["종류"] in TYPE_KINDS:
            name = r.parsed["name"] if r.parsed["path"] == "-" else r.parsed["path"] + "." + r.parsed["name"]
            documented.setdefault(name, []).append((r.cells["파일"], r.doc, r.line))
    for r in ds.of("overview"):
        for span in re.findall(r"`([^`]+)`", r.cells["형"]) or [r.cells["형"]]:
            m = re.match(r"[A-Za-z_][\w.]*", span.strip())
            if m:
                documented.setdefault(m.group(0), []).append((r.cells["파일"], r.doc, r.line))
    code_types = {}
    for i, d in enumerate(decls):
        if d.get("kind") in TYPE_KINDS and decl_layer[i] is not None:
            chain, c = [d["name"]], d.get("container", -1)
            while c is not None and c >= 0 and decls[c].get("kind") in TYPE_KINDS:
                chain.insert(0, decls[c]["name"])
                c = decls[c].get("container", -1)
            code_types.setdefault(".".join(chain), []).append(i)
    for name, places in sorted(documented.items()):
        found = code_types.get(name, [])
        doc_files = {p[0] for p in places}
        if not found or any(graph.files[decls[i]["file"]] in doc_files for i in found):
            continue
        f0, doc, line = places[0]
        want = refs.layer_of(f0, rows)
        for i in found:
            rel = graph.files[decls[i]["file"]]
            add("L1", rel, decls[i]["line"], "형 %s — 문서(%s:%d)의 자리 %s(계층 %s), 코드의 자리 여기(계층 %s)"
                % (name, doc, line, f0, want.name if want else "없음", decl_layer[i]))
    # L2 참조·인터페이스 위반
    iface = _interface(ds)
    seen_l2 = set()
    published = {}
    for frm, to, f, line, w in graph.edges:
        A, B = file_layer[f], decl_layer[to]
        if A is None or B is None or A == B:
            continue
        la = by_name[A]
        message = None
        if B not in la.refs:
            message = "참조 금지 %s → %s(SPEC-00 3.4.1): %s" % (A, B, _display(decls, to))
        elif B in la.interface_only and not _allowed(decls, to, iface.get(A, {})):
            message = "인터페이스 밖 %s → %s(인터페이스 표에 없음): %s" % (A, B, _display(decls, to))
        if message:
            a.bad_edges.add((frm, to))
            if (f, line, to) not in seen_l2:
                seen_l2.add((f, line, to))
                add("L2", graph.files[f], line, message)
        elif (frm in reach.get(A, ()) and decls[to].get("access") == "public"
              and not (w and decls[to].get("kind") == "field")
              and decls[to].get("kind") not in TYPE_KINDS
              and decls[to].get("container", -1) >= 0
              and isinstance(iface.get(A, {}).get(decls[decls[to]["container"]].get("name")), set)
              and _allowed(decls, to, iface.get(A, {}))):
            # Explicitly published APIs belong to their producer. A real live
            # external consumer proves the connection; a table alone does not.
            published.setdefault(B, set()).add(to)
    for layer_name, targets in published.items():
        owned, writes = _reach(targets, ix, decl_layer, entries)
        reach[layer_name].update(owned)
        written.update(writes)
    type_layers = {}
    for i, d in enumerate(decls):
        if d.get("kind") in TYPE_KINDS and decl_layer[i] is not None:
            type_layers.setdefault(d["name"], set()).add(decl_layer[i])
    for frm, f, line, name in graph.unresolved:
        A = file_layer[f]
        if A is None or name not in type_layers or A in type_layers[name]:
            continue
        banned = sorted(B for B in type_layers[name] if B not in by_name[A].refs)
        if banned and (f, line, name) not in seen_l2:
            seen_l2.add((f, line, name))
            add("L2", graph.files[f], line, "참조 금지 %s → %s(이 계층 컴파일에서 해석되지 않는 이름): 형 %s" % (A, ", ".join(banned), name))
    for frm, f, line, api, name, t in graph.strings:
        A = file_layer[f]
        if A is None or t is None or t < 0:
            continue
        for m in ix.string_targets(name, t, A, decl_layer):
            B = decl_layer[m]
            if B is not None and B != A and decls[m].get("access") != "public" and (f, line, m) not in seen_l2:
                seen_l2.add((f, line, m))
                a.bad_edges.add((frm, m))
                add("L2", graph.files[f], line, "문자열 호출 %s로 다른 계층(%s)의 비공개 멤버: %s" % (api, B, _display(decls, m)))
    # Shared source libraries have consumers, not their own execution entry.
    shared = {r.cells["공유 계층"] for r in ds.of("shared_layers")}
    # L3·L4 따로 놂·다른 계층 전용
    for i, d in enumerate(decls):
        L = decl_layer[i]
        if L is None or d.get("kind") in SKIP_KINDS or d.get("name") in CONVERSIONS:
            continue
        if i in reach[L]:
            continue
        rel = graph.files[d["file"]]
        others = [M.name for M in rows if M.name != L and i in reach[M.name]]
        if others and L in shared:
            continue
        if others:
            a.status[i] = "L4"
            add("L4", rel, d["line"], "다른 계층 전용: 계층 %s의 %s — 쓰는 곳은 계층 %s뿐(그 계층에 있어야 한다)" % (L, _display(decls, i), ", ".join(others)))
        else:
            a.status[i] = "L3"
            what = "쓰기만 하고 읽지 않음" if i in written else "어느 진입점에서도 닿지 않음"
            add("L3", rel, d["line"], "따로 놂(%s): %s" % (what, _display(decls, i)))
    copies(graph,rows,file_layer,add)
    return a


def same_links(previous, current):
    """Only declaration body hashes/statement counts may differ; every link input stays equal."""
    for name,definition in refs.Graph.__dataclass_fields__.items():
        if definition.compare and name != "decls" and getattr(previous,name) != getattr(current,name):
            return False
    if len(previous.decls) != len(current.decls):
        return False
    for old,new in zip(previous.decls,current.decls):
        if old != new and ({key:value for key,value in old.items() if key not in ("hash","stmts")} !=
                           {key:value for key,value in new.items() if key not in ("hash","stmts")}):
            return False
    return True


def copies(graph, rows, file_layer, add):
    """Recheck body-copy groups independently of link reachability."""
    decls = graph.decls
    decl_layer = [file_layer[d["file"]] if "kind" in d else None for d in decls]
    order = {layer.name:i for i,layer in enumerate(rows)}
    groups = {}
    for i, d in enumerate(decls):
        if decl_layer[i] is not None and d.get("hash") and d.get("stmts", 0) >= 2:
            groups.setdefault(d["hash"], []).append(i)
    for items in groups.values():
        if len({decl_layer[i] for i in items}) < 2:
            continue
        top = min(items, key=lambda i: (order[decl_layer[i]], graph.files[decls[i]["file"]], decls[i]["line"]))
        for i in items:
            if decl_layer[i] != decl_layer[top]:
                add("L5", graph.files[decls[i]["file"]], decls[i]["line"],
                    "복사본: 본문이 계층 %s의 %s(%s:%d)과 같음 — 복사하지 말고 참조한다"
                    % (decl_layer[top], _display(decls, top), graph.files[decls[top]["file"]], decls[top]["line"]))
