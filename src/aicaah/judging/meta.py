# -*- coding: utf-8 -*-
"""참조 메타데이터(SPEC-36 2.14). 코드 전체를 폴더 → 파일 → 인터페이스·클래스 → 메서드 → 변수의 한 나무로 담는다.
마디는 모두 같은 꼴(열쇠·종류·이름·부모·파일·줄·계층·셈)이다. 참조·인터페이스는 참조 그래프에서, 문서가 건드리는 마디는 문서 표·글에서 푼다.
한도 판정(S1·S2·S4)·인터페이스 판정(I1·I2·I3)·페이즈의 `@문서` 대상·코드 구조 탭이 모두 이 한 벌만 읽는다."""
import ast
import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field

from graph import refs
from parsing import cache as cachemod
from parsing import languages
from storage import snapshot
from storage import ledger, metadata_store
from storage import diff as diffmod

PLACE_INDEX = ".spec-conformance/Cache/document-places"
FILE_RECORDS = ".spec-conformance/Cache/file-meta"
_WRITTEN_RECORDS = {}
CLASS_KINDS = {"class", "struct", "record", "enum", "delegate"}
METHOD_KINDS = {"method", "ctor", "operator", "indexer"}
VARIABLE_KINDS = {"field", "const", "property", "event", "enum-member"}


@dataclass
class Node:
    """나무 마디 하나. 폴더·파일·인터페이스·클래스·메서드·변수가 같은 꼴이다."""
    key: str
    kind: str
    name: str
    parent: str = ""
    file: str = ""
    line: int = 0
    layer: str = ""
    counts: dict = field(default_factory=dict)
    owner_type: str = ""
    folder: str = ""
    source_kind: str = ""
    modifiers: tuple = ()
    occurrence_id: str = ""
    symbol_id: str = ""
    alias: str = ""
    end: int = 0


@dataclass
class Meta:
    """참조 메타데이터 한 벌(2.14)."""
    nodes: dict = field(default_factory=dict)
    refs: list = field(default_factory=list)
    interfaces: dict = field(default_factory=dict)
    docs: dict = field(default_factory=dict)
    places: dict = field(default_factory=dict)
    file_records: dict = field(default_factory=dict, compare=False, repr=False)


def file_input(rel, entry, layer):
    """파일 소유 나무의 현재 입력 지문. 위치 교체와 전체 조립이 같은 규약을 사용한다."""
    return cachemod.POLICY.key('file-meta' + (os.path.splitext(rel)[1] if rel.endswith(('.cs', '.py')) else '.generic'),
        [rel, entry.get("sha256"), entry.get("parser"), entry.get("symbols"), entry.get("unit"), entry.get("error"), layer])


def move_positions(meta, cur, deltas, cache, relations):
    """변경 파일의 위치·저장 행만 교체한다. 소속·참조 대상·폴더 기여분과 문서 조회는 유지한다."""
    result = Meta(nodes=dict(meta.nodes), refs=list(meta.refs), interfaces=meta.interfaces,
                  docs=meta.docs, places=meta.places, file_records=dict(meta.file_records))
    for rel,edits in deltas.items():
        for row in meta.file_records[rel]["nodes"]:
            if row["file"] == rel:
                node = meta.nodes[row["key"]]
                result.nodes[node.key] = Node(**dict(vars(node),counts=dict(node.counts),
                    line=diffmod.move_line(node.line,edits),end=diffmod.move_line(node.end,edits)))
        shape,part = cache[rel]
        record = dict(meta.file_records[rel],input=file_input(rel,cur[rel],shape[1]))
        record["nodes"] = [dict(n,line=diffmod.move_line(n["line"],edits),end=diffmod.move_line(n["end"],edits))
                           if n["file"] == rel else n for n in record["nodes"]]
        if "outgoing" in record:
            record["outgoing"] = dict(record["outgoing"],edges=[(a,b,diffmod.move_line(line,edits),write,guess)
                for a,b,line,write,guess in record["outgoing"]["edges"]])
        result.file_records[rel] = record
        nodes = dict(part.nodes)
        for row in record["nodes"]:
            nodes[row["key"]] = Node(**dict(row,modifiers=tuple(row.get("modifiers",())),counts=dict(row["counts"])))
        cache[rel] = ((cur[rel],shape[1]),Meta(nodes=nodes,file_records={rel:record}))
        owned = relations.get("refs",{}).get("files",{}).get(rel)
        if owned is not None:
            raw = [(a,b,diffmod.move_line(line,edits),write,guess) for a,b,line,write,guess in owned[0]]
            linked = tuple((a,b,f,diffmod.move_line(line,edits),write,cross,iface,guess)
                           for a,b,f,line,write,cross,iface,guess in owned[2])
            relations["refs"]["files"][rel] = (raw,owned[1],linked)
            if "outgoing" in record:
                relations["refs"].setdefault("encoded",{})[rel] = (raw,record["outgoing"])
        start,end = relations["refs"]["spans"].get(rel,(0,0))
        for i in range(start,end):
            a,b,f,line,write,cross,iface,guess = meta.refs[i]
            result.refs[i] = (a,b,f,diffmod.move_line(line,edits),write,cross,iface,guess)
    return result


def refresh_body(root, ds, previous, cur, files, cache, deltas=None):
    """Refresh file-owned inputs/local counts only after proving the declaration tree unchanged."""
    prepared = {}
    layers = refs.layers(ds)
    if previous is None:
        previous = Meta(places=load_places(root))
        for rel in files:
            record = ledger.read_table(root,FILE_RECORDS + "/" + rel + ".row",None)
            if record is None:
                return None
            part = Meta(nodes={row["key"]:Node(**dict(row,modifiers=tuple(row.get("modifiers",())))) for row in record["nodes"]},
                        file_records={rel:record})
            previous.nodes.update(part.nodes)
            previous.file_records[rel] = record
            layer = refs.layer_of(rel,layers)
            cache[rel] = ((None,layer.name if layer else ""),part)
    if deltas:
        previous = move_positions(previous,cur,deltas,cache,{"refs":{"spans":{}}})
    for rel in files:
        saved = cache.get(rel)
        if saved is None or rel not in previous.file_records:
            return None
        part = Meta()
        _tree(part,{rel:cur[rel]},layers)
        if rel.endswith(".py"):
            locals_by_line = _python_locals(root,rel)
            for node in part.nodes.values():
                if node.kind == "메서드" and node.line in locals_by_line:
                    node.counts["지역 변수"] = locals_by_line[node.line]
        if part.nodes.keys() != saved[1].nodes.keys():
            return None
        for key,node in part.nodes.items():
            old = saved[1].nodes[key]
            shape = dict(vars(node),symbol_id="",counts={k:v for k,v in node.counts.items() if k != "지역 변수"})
            prior = dict(vars(old),symbol_id="",counts={k:v for k,v in old.counts.items() if k != "지역 변수"})
            if shape != prior:
                return None
        prepared[rel] = (saved,part)
    result = Meta(nodes=dict(previous.nodes),refs=previous.refs,interfaces=previous.interfaces,
                  docs=previous.docs,places=previous.places,file_records=dict(previous.file_records))
    for rel,(saved,part) in prepared.items():
        for key,node in part.nodes.items():
            if node.kind == "메서드" and "지역 변수" in node.counts:
                old = result.nodes[key]
                if old.counts.get("지역 변수") != node.counts["지역 변수"]:
                    result.nodes[key] = Node(**dict(vars(old),counts=dict(old.counts,**{"지역 변수":node.counts["지역 변수"]})))
            node.symbol_id = previous.nodes[key].symbol_id
        record = dict(previous.file_records[rel],input=file_input(rel,cur[rel],saved[0][1]))
        record["nodes"] = [dict(row,counts=dict(row["counts"],**{"지역 변수":result.nodes[row["key"]].counts["지역 변수"]}))
                           if "지역 변수" in result.nodes[row["key"]].counts else row for row in record["nodes"]]
        result.file_records[rel] = record
        part.file_records[rel] = record
    for rel,(saved,part) in prepared.items():
        cache[rel] = ((cur[rel],saved[0][1]),part)
    return result


def build(root, ds, cur, analysis=None, cache=None, relations=None, only_files=None):
    """메타데이터 한 벌: 나무와 셈(색인), 참조·인터페이스·C# 지역 변수(참조 그래프), 문서 참조(문서 표·글)."""
    meta = Meta()
    cache = {} if cache is None else cache
    rows = refs.layers(ds)
    relations = {} if relations is None else relations
    # Read all cold file records in one domain pass. In-process cached records
    # remain untouched; each restored record is still validated below.
    cold = []
    for rel, entry in cur.items():
        if os.path.splitext(rel)[1].lower() not in languages.EXTENSIONS or entry.get("error"):
            continue
        layer = refs.layer_of(rel, rows)
        shape = (entry, layer.name if layer else "")
        saved = cache.get(rel)
        if (saved is None or saved[0] != shape
                or saved[1].file_records[rel]['input'] != file_input(rel, entry, shape[1])):
            cold.append(FILE_RECORDS + "/" + rel + ".row")
    restored = ledger.read_tables(root, cold)
    old_place_types = set()
    same_place_files = only_files is not None and set(only_files) == set(cur)
    if same_place_files:
        for rel in only_files:
            saved = cache.get(rel)
            old = (saved[1].file_records.get(rel) if saved is not None else
                   restored.get(FILE_RECORDS + "/" + rel + ".row"))
            if not old:
                same_place_files = False
                break
            old_place_types.update((rel,n["key"],n["kind"]) for n in old["nodes"] if n["kind"] in ("클래스","인터페이스"))
    live = set()
    changed_targets = set()
    for rel, entry in sorted(cur.items()):
        if os.path.splitext(rel)[1].lower() not in languages.EXTENSIONS or entry.get("error"):
            continue
        live.add(rel)
        layer = refs.layer_of(rel, rows)
        shape = (entry, layer.name if layer else "")
        saved = cache.get(rel)
        previous_nodes = saved[1].nodes if saved is not None else {}
        if (saved is None or saved[0] != shape
                or saved[1].file_records[rel]['input'] != file_input(rel, entry, shape[1])):
            fingerprint = file_input(rel,entry,shape[1])
            path = FILE_RECORDS + "/" + rel + ".row"
            stored = restored.get(path, {})
            part = Meta()
            valid = isinstance(stored, dict) and stored.get("input") == fingerprint and stored.get("file") == rel
            try:
                if valid:
                    part.nodes = {n["key"]: Node(**dict(n, modifiers=tuple(n.get("modifiers", ())))) for n in stored["nodes"]}
                    expected = {r[2] for r in refs.source_records(rel, entry)
                                if r[0].get("kind") in CLASS_KINDS | METHOD_KINDS | VARIABLE_KINDS | {"interface"}}
                    if rel not in part.nodes or {n.occurrence_id for n in part.nodes.values() if n.occurrence_id} != expected:
                        raise ValueError("incomplete file metadata")
                    if any(n.owner_type and n.owner_type not in part.nodes for n in part.nodes.values()):
                        raise ValueError("invalid declaration owner")
                    record = stored.get("outgoing")
                    if record:
                        names = record["names"]
                        raw = [(names[a], names[b], line, write, guess) for a, b, line, write, guess in record["edges"]]
                        relation = relations.setdefault("refs", {})
                        relation.setdefault("files", {})[rel] = (raw, {}, ())
            except (KeyError, TypeError, ValueError, IndexError):
                valid = False
            record_path = os.path.join(root, FILE_RECORDS, rel + ".row")
            if valid:
                _WRITTEN_RECORDS[record_path] = stored
            else:
                _WRITTEN_RECORDS.pop(record_path, None)
            if not valid:
                part = Meta()
                _tree(part, {rel: entry}, rows)
            if not valid and rel.endswith(".py"):
                got = _python_locals(root, rel)
                for n in part.nodes.values():
                    if n.kind == "메서드" and n.line in got:
                        n.counts["지역 변수"] = got[n.line]
            if not valid and not rel.endswith(('.py', '.cs')):
                got = languages.locals_by_line(snapshot.read_text(root, rel), rel)
                for symbol, key, _, _ in refs.source_records(rel, entry):
                    local_key = (symbol['line'], symbol['name'], symbol['params'])
                    if key in part.nodes and part.nodes[key].kind == '메서드' and local_key in got:
                        part.nodes[key].counts['지역 변수'] = got[local_key]
            saved = (shape, part)
            part.file_records[rel] = {"file": rel, "input": fingerprint,
                                      "nodes": stored["nodes"] if valid else [asdict(n) for n in part.nodes.values()]}
            cache[rel] = saved
            if previous_nodes:
                current_nodes = part.nodes
                for key in set(previous_nodes) | set(current_nodes):
                    old, new = previous_nodes.get(key), current_nodes.get(key)
                    if old is None or new is None or (old.folder,old.owner_type,old.kind) != (new.folder,new.owner_type,new.kind):
                        changed_targets.add(key)
        meta.file_records[rel] = dict(saved[1].file_records[rel])
        for key, node in saved[1].nodes.items():
            if node.kind == "폴더" and key in meta.nodes:
                for name, count in node.counts.items():
                    counts = meta.nodes[key].counts
                    counts[name] = counts.get(name, 0) + count
            else:
                meta.nodes[key] = Node(**dict(vars(node), counts=dict(node.counts)))
    for rel in cache.keys() - live:
        changed_targets.update(cache[rel][1].nodes)
        del cache[rel]
    if analysis is not None:
        if changed_targets:
            relations.setdefault("refs", {}).setdefault("affected", set()).update(
                ledger.table_users(root, FILE_RECORDS, changed_targets, "target"))
        _refs(meta, analysis, relations.setdefault("refs", {}), refs.bind_sources(analysis.graph, cur))
        for record in meta.file_records.values():
            rows = []
            for row in record["nodes"]:
                node = meta.nodes[row["key"]]
                counts = row["counts"]
                locals = node.counts.get("지역 변수")
                if row.get("symbol_id") != node.symbol_id or (locals is not None and counts.get("지역 변수") != locals):
                    counts = dict(counts)
                    if locals is not None:
                        counts["지역 변수"] = locals
                    row = dict(row,symbol_id=node.symbol_id,counts=counts)
                rows.append(row)
            record["nodes"] = rows
        encoded = relations["refs"].setdefault("encoded", {})
        for rel in encoded.keys() - meta.file_records.keys():
            del encoded[rel]
        for rel, record in relations["refs"].get("files", {}).items():
            if rel in meta.file_records:
                prior = encoded.get(rel)
                if prior is None or prior[0] != record[0]:
                    names, edges = {}, []
                    for a, b, line, write, guess in record[0]:
                        edges.append((names.setdefault(a, len(names)), names.setdefault(b, len(names)), line, write, guess))
                    prior = (record[0], {"names": list(names), "edges": edges})
                    encoded[rel] = prior
                meta.file_records[rel]["outgoing"] = prior[1]
    if only_files is not None:
        # Folder checks aggregate sibling counts in SQL; their declarations and
        # source records are not restored into this pass.
        for file in only_files:
            folder = os.path.dirname(file)
            while folder not in meta.nodes:
                parent = os.path.dirname(folder)
                meta.nodes[folder] = Node(folder,"폴더",os.path.basename(folder),parent)
                if not folder: break
                folder = parent
        folders = {key for key, node in meta.nodes.items() if node.kind == "폴더"}
        counts, siblings = metadata_store.sibling_counts(root, folders, only_files)
        for key in folders:
            node = meta.nodes[key]
            for name, value in counts.get(key, {}).items():
                node.counts[name] = node.counts.get(name, 0) + value
            for file, name, value in siblings.get(key, ()):
                sibling = meta.nodes.setdefault(file, Node(file, "파일", os.path.basename(file), key, file))
                sibling.counts[name] = value
    current_place_types = {(n.file,n.key,n.kind) for n in meta.nodes.values() if n.kind in ("클래스","인터페이스")}
    if same_place_files and old_place_types == current_place_types:
        meta.places = load_places(root)
    else:
        _docs(meta, ds, relations.setdefault("docs", {}))
    return meta


def _tree(meta, cur, rows):
    """색인에서 폴더 → 파일 → 형 → 멤버 나무와 셈. rows = 계층 표 행(마디의 계층)."""
    def folder(path):
        """폴더 마디와 그 위 폴더 마디들."""
        while path not in meta.nodes:
            parent = os.path.dirname(path)
            meta.nodes[path] = Node(path, "폴더", path.rsplit("/", 1)[-1], parent if path else "")
            if not path:
                break
            path = parent

    def params(text):
        """매개변수 글(쉼표 목록)의 수. 괄호·꺾쇠 안의 쉼표는 나누지 않는다."""
        depth, items, cur_item = 0, [], ""
        for c in text:
            if c in "<([{":
                depth += 1
            elif c in ">)]}":
                depth -= 1
            if c == "," and depth == 0:
                items.append(cur_item)
                cur_item = ""
            else:
                cur_item += c
        items.append(cur_item)
        return [x.strip() for x in items if x.strip() and x.strip() not in ("self", "cls", "*", "/")]

    for rel in sorted(cur):
        entry = cur[rel]
        if os.path.splitext(rel)[1].lower() not in languages.EXTENSIONS or entry.get("error"):
            continue
        layer = refs.layer_of(rel, rows) if rows else None
        lname = layer.name if layer else ""
        here = os.path.dirname(rel)
        folder(here)
        meta.nodes[rel] = Node(rel, "파일", rel.rsplit("/", 1)[-1], here, rel, 0, lname)
        owners = {}
        for s, key, occurrence, alias in sorted(refs.source_records(rel, entry), key=lambda r: r[0].get("line", 0)):
            k = s.get("kind")
            kind = ("인터페이스" if k == "interface" else "클래스" if k in CLASS_KINDS else "메서드" if k in METHOD_KINDS
                    else "변수" if k in VARIABLE_KINDS else None)
            if kind is None:
                continue
            path = s.get("path") or "-"
            parent = rel if path == "-" else owners.get(path, "%s#%s" % (rel, path))
            if parent not in meta.nodes:
                parent = rel
            node = Node(key, kind, s["name"], parent, rel, s.get("line", 0), lname)
            node.folder = here
            node.source_kind = k
            node.modifiers = tuple(s.get("modifiers") or ())
            node.occurrence_id, node.alias, node.end = occurrence, alias, s.get("end", 0)
            node.owner_type = key if kind in ("인터페이스", "클래스") else meta.nodes[parent].owner_type
            if kind == "메서드":
                if rel.endswith(".py"):
                    sig = s.get("signature", "")
                    inner = sig[sig.find("(") + 1:sig.rfind(")")] if "(" in sig else ""
                    node.counts["매개변수"] = len(params(inner))
                else:
                    node.counts["매개변수"] = len(params(s.get("params") or ""))
            meta.nodes[key] = node
            if kind in ("인터페이스", "클래스"):
                owners[s["name"] if path == "-" else path + "." + s["name"]] = key
    # 셈: 폴더는 바로 든 것, 파일은 그 안 전부, 인터페이스·클래스는 바로 든 멤버
    for n in list(meta.nodes.values()):
        if n.kind == "폴더":
            continue
        if n.kind == "파일":
            c = meta.nodes[n.parent].counts
            c["바로 든 파일"] = c.get("바로 든 파일", 0) + 1
            continue
        fc = meta.nodes[n.file].counts
        fc[n.kind] = fc.get(n.kind, 0) + 1
        if n.kind in ("인터페이스", "클래스"):
            c = meta.nodes[os.path.dirname(n.file)].counts
            c["바로 든 형"] = c.get("바로 든 형", 0) + 1
            c["바로 든 " + n.kind] = c.get("바로 든 " + n.kind, 0) + 1
        owner = meta.nodes.get(n.parent)
        if owner is not None and owner.kind in ("인터페이스", "클래스") and n.kind in ("메서드", "변수"):
            name = "멤버" if owner.kind == "인터페이스" else n.kind
            owner.counts[name] = owner.counts.get(name, 0) + 1


def _python_locals(root, rel):
    """파이썬 파일의 함수마다 지역 변수 수(구문 트리의 대입·for·with·except 이름, 매개변수 제외). 돌려주는 값: def 줄 → 수."""
    try:
        tree = ast.parse(snapshot.read_text(root, rel))
    except (SyntaxError, ValueError, OSError):
        return {}
    scopes = []
    pending = [(tree, ())]
    while pending:
        node, owners = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = node.args
            given = {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs}
            given.update(x.arg for x in (a.vararg, a.kwarg) if x is not None)
            scope = (node.lineno, given, set())
            scopes.append(scope)
            owners = owners + (scope,)
        name = node.id if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) else (
            node.name if isinstance(node, ast.ExceptHandler) else None)
        if name:
            for _, _, names in owners:
                names.add(name)
        pending.extend((child, owners) for child in ast.iter_child_nodes(node))
    return {line: len(names - given) for line, given, names in scopes}



def _refs(meta, analysis, cache=None, bindings=None):
    """참조 그래프의 선·상속을 마디 사이 참조와 인터페이스 구현으로. C# 메서드의 지역 변수 수를 채운다."""
    g = analysis.graph
    cache = {} if cache is None else cache
    to_key = {}
    bound = set()
    for i, records in (bindings or {}).items():
        d = g.decls[i]
        for _, key, occurrence, alias in records:
            node = meta.nodes.get(key)
            if node is None:
                continue
            if node.occurrence_id != occurrence:
                continue
            node.symbol_id = d["key"] if d["key"].startswith("py:") else d["key"].rsplit("@", 1)[0]
            bound.add(key)
            to_key.setdefault(i, key)
            if d.get("locals") is not None and node.kind == "메서드":
                node.counts["지역 변수"] = d["locals"]
    for key,node in meta.nodes.items():
        if key not in bound:
            node.symbol_id = ""

    # 인터페이스: 멤버 이름과 구현한 형(조상 목록의 프로젝트 안 인터페이스)
    children = {}
    for node in meta.nodes.values():
        children.setdefault(node.parent, []).append(node.name)
    for key, n in meta.nodes.items():
        if n.kind == "인터페이스":
            meta.interfaces[key] = (children.get(key, []), [])
    full = {}
    for i, d in enumerate(g.decls):
        if i in to_key and d.get("kind") in ("class", "struct", "interface", "enum", "record", "delegate"):
            ident = d["key"].rsplit("@", 1)[0]
            ident = ident[2:] if len(ident) > 2 and ident[1] == ":" else ident
            full.setdefault(re.sub(r"<.*>$", "", re.sub(r"`\d+", "", ident)), i)
    for i, d in enumerate(g.decls):
        if i not in to_key:
            continue
        for b in d.get("bases") or []:
            t = full.get(re.sub(r"<.*>$", "", b))
            if t is not None and t != i and to_key.get(t) in meta.interfaces:
                impls = meta.interfaces[to_key[t]][1]
                # One compiled partial type has several source owners. Preserve
                # its real interface implementation on every bound declaration.
                for _, part_key, occurrence, _ in (bindings or {}).get(i, ()):
                    part = meta.nodes.get(part_key)
                    if part is not None and part.occurrence_id == occurrence and part_key not in impls:
                        impls.append(part_key)
    for key, (names, impls) in meta.interfaces.items():
        meta.nodes[key].counts["구현"] = len({meta.nodes[c].symbol_id or c for c in impls})
    # 파일별 원본 참조와 대상 속성이 같은 관계는 그대로 유지한다.
    groups = {}
    for e in g.edges:
        rel = g.files[e[2]] if 0 <= e[2] < len(g.files) else ""
        a, b = to_key.get(e[0]), to_key.get(e[1])
        if a is None or b is None or a == b:
            continue
        rel = rel or meta.nodes[a].file
        groups.setdefault(rel, []).append((a, b, e[3], bool(e[4]), (e[0], e[1], e[2], e[3]) in g.guessed))
    records = cache.setdefault("files", {})
    incoming = cache.setdefault("incoming", {})
    attributes = {key: (n.file,n.owner_type,meta.nodes[n.owner_type].kind if n.owner_type else "")
                  for key,n in meta.nodes.items()}
    previous = cache.get("attributes")
    affected = cache.pop("affected", set())
    if previous is None:
        affected.update(records)
    else:
        for key in previous.keys() | attributes.keys():
            if previous.get(key) != attributes.get(key):
                affected.update(incoming.get(key, ()))
    cache["attributes"] = attributes
    cache["checked"], cache["reused"] = 0, 0
    cache["spans"] = {}
    for rel in sorted(set(records) | set(groups)):
        start = len(meta.refs)
        saved = records.get(rel)
        raw = groups.get(rel, [])
        if saved is not None and saved[0] == raw and rel not in affected:
            cache["reused"] += 1
            meta.refs.extend(saved[2])
            cache["spans"][rel] = (start,len(meta.refs))
            continue
        keys = {key for row in raw for key in row[:2]}
        targets = {key: attributes[key] for key in keys}
        if saved is not None and saved[0] == raw and saved[1] == targets:
            cache["reused"] += 1
            meta.refs.extend(saved[2])
            cache["spans"][rel] = (start,len(meta.refs))
            continue
        if saved is not None:
            for key in saved[1]:
                users = incoming[key]
                users.discard(rel)
                if not users:
                    del incoming[key]
        if rel not in groups:
            del records[rel]
            continue
        cache["checked"] += 1
        seen, linked = set(), []
        source_folder = os.path.dirname(rel)
        for a, b, line, write, guess in raw:
            mark = (a, b, line)
            if mark in seen:
                continue
            seen.add(mark)
            _, owner, kind = targets[b]
            # Partial types have one canonical declaration, which may live in a
            # different folder from this edge. Ownership follows the edge file.
            folder = meta.nodes[b].folder
            linked.append((a, b, rel, line, write, source_folder != folder,
                           owner if kind == "인터페이스" else "", guess))
        records[rel] = (raw, targets, tuple(linked))
        for key in keys:
            incoming.setdefault(key, set()).add(rel)
        meta.refs.extend(linked)
        cache["spans"][rel] = (start,len(meta.refs))


def _docs(meta, ds, cache=None):
    """문서별 이름 조회 입력과 결과를 유지한다. 새 형·삭제된 형도 조회 결과 변화로 감지한다."""
    cache = {} if cache is None else cache
    paths = {}
    aliases = {}
    for key, n in meta.nodes.items():
        aliases.setdefault(n.alias or key, set()).add(key)
        if n.kind in ("인터페이스", "클래스"):
            paths.setdefault(key.split("#", 1)[1].split("@")[0], []).append(key)
    rows = {}
    for row in ds.rows:
        if row.kind in ("scope", "members", "overview", "constants", "changes", "behaviors"):
            rows.setdefault(row.doc, []).append(row)
    resolved = {}
    places = {}
    for doc in sorted(set(ds.texts) | set(rows)):
        inputs = (rows.get(doc, []), ds.texts.get(doc, []))
        fingerprint = hashlib.sha256(repr(inputs).encode('utf-8')).digest()
        saved = cache.get(doc)
        if saved is None or saved[0] != fingerprint:
            direct, chains, files = set(), set(), set()
            for row in inputs[0]:
                if row.kind == "behaviors":
                    for col in ("구현 대상", "검사 연결"):
                        for target in row.cells[col].split(","):
                            target = target.strip()
                            if "#" in target:
                                rel = target.partition("#")[0]
                                direct.update((rel, target))
                                files.add(rel)
                    continue
                rel = row.cells.get("파일", "")
                if not rel or rel == "-":
                    continue
                files.add(rel)
                direct.add(rel)
                typ = row.cells.get("형", "-")
                names = re.findall(r"`([^`]+)`", typ) or ([typ] if typ not in ("", "-") else [])
                direct.update("%s#%s" % (rel, name.strip()) for name in names)
                name = (row.parsed or {}).get("name") or (row.cells.get("이름") if row.kind == "constants" else "")
                path = (row.parsed or {}).get("path") or typ
                if name:
                    direct.add("%s#%s" % (rel, name if path in ("", "-") else path + "." + name))
            for line in inputs[1]:
                for span in re.findall(r"`([^`]+)`", line):
                    if "/" not in span:
                        chains.update(re.findall(r"(?<![A-Za-z0-9_.])[A-Z][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", span))
            saved = (fingerprint, direct, chains, files)
            cache[doc] = saved
        _, direct, chains, files = saved
        touched = set().union(*(aliases.get(key, ()) for key in direct)) if direct else set()
        linked_files = set(files)
        for chain in chains:
            if chain not in resolved:
                parts = chain.split(".")
                resolved[chain] = next((paths[".".join(parts[:k])] for k in range(len(parts), 0, -1)
                                        if ".".join(parts[:k]) in paths), ())
            for key in resolved[chain]:
                touched.add(key)
                linked_files.add(meta.nodes[key].file)
        if touched:
            meta.docs[doc] = sorted(touched)
        for rel in linked_files:
            places.setdefault(rel, set()).add(doc)
            places.setdefault(os.path.dirname(rel), set()).add(doc)
    for doc in cache.keys() - (set(ds.texts) | set(rows)):
        del cache[doc]
    meta.places = {place: sorted(docs) for place, docs in places.items()}


def write(root, meta, only_files=None):
    """완료한 파일 소유 레코드와 문서별 자리 목록을 변경 조각만 원자적으로 저장한다."""
    record_folder = os.path.join(root, FILE_RECORDS)
    os.makedirs(record_folder, exist_ok=True)
    expected_files = set()
    selected = meta.file_records.items() if only_files is None else ((rel,meta.file_records[rel]) for rel in only_files if rel in meta.file_records)
    for rel, record in selected:
        name = rel + ".row"
        expected_files.add(FILE_RECORDS + "/" + name)
        path = os.path.join(record_folder, name)
        if _WRITTEN_RECORDS.get(path) == record:
            continue
        # build() already validated and cached this SQL row. Do not fetch the
        # same record again during this publication; cold rows still use SQL.
        stored = (_WRITTEN_RECORDS[path] if path in _WRITTEN_RECORDS
                  else ledger.read_table(root, FILE_RECORDS + "/" + name, {}))
        payload = record
        if stored != payload:
            ledger.write_table(root, FILE_RECORDS + "/" + name, payload)
        _WRITTEN_RECORDS[path] = record
    if only_files is not None:
        removed = set(only_files) - meta.file_records.keys()
        ledger.remove_sources(root, FILE_RECORDS, removed)
        for file in removed:
            _WRITTEN_RECORDS.pop(os.path.join(record_folder, file + ".row"), None)
        return
    ledger.prune_tables(root, FILE_RECORDS, expected_files)
    for path in list(_WRITTEN_RECORDS):
        if path.startswith(record_folder + os.sep) and os.path.relpath(path, root).replace("\\", "/") not in expected_files:
            del _WRITTEN_RECORDS[path]
    by_doc = {}
    for place, docs in meta.places.items():
        for doc in docs: by_doc.setdefault(doc, []).append(place)
    expected = set()
    for doc, places in sorted(by_doc.items()):
        rel = PLACE_INDEX + "/" + doc + ".row"
        expected.add(rel)
        payload = {"file": doc, "doc": doc, "places": sorted(set(places))}
        if ledger.read_table(root, rel, {}) != payload:
            ledger.write_table(root, rel, payload)
    ledger.prune_tables(root, PLACE_INDEX, expected)


def load_places(root):
    """문서 폴더 소유 바이너리 행을 읽어 자리 → 문서 지도를 조합한다."""
    return metadata_store.places(root)
