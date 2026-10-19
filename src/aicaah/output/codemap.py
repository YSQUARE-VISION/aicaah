# -*- coding: utf-8 -*-
"""통합 지도(SPEC-36 2.9). 실시간 서버는 판 사이 변경 자료를 전달하고 정적 내보내기는 `Reports/map.html`에 담는다.
전체 오버뷰(전체(계층) → 계층(모듈) → 모듈(형) → 형(멤버) 네 층의 지적 지도)와 코드 구조(2.9.1: 전체 코드 → 모듈 → 인터페이스·클래스 →
메서드·변수, 인터페이스 대응 문제, 문서 계획 겹치기와 체크). 정적 지도는 `Reports/map-stamp.js`로 새 판정을 확인한다."""
import datetime
import hashlib
import json
import os
import re
from collections import defaultdict

from storage import ledger, map_store
from storage import snapshot
from storage import diff as diffmod
from graph import refs as refmod
from output import localization

MERMAID_URL = "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"


def _innermost(spans, line):
    """그 줄을 품은 가장 안쪽 선언(없으면 -1)."""
    best, size = -1, None
    for k, start, end in spans:
        if start <= line <= end and (size is None or end - start < size):
            best, size = k, end - start
    return best


def _full(key):
    """형의 전체 이름(선언 열쇠에서 앞 글자·제네릭 표시·파일을 뺀 것)."""
    ident = key.rsplit("@", 1)[0]
    ident = ident[2:] if len(ident) > 2 and ident[1] == ":" else ident
    return re.sub(r"`\d+", "", ident)


def data(analysis, findings, notes, stamp, first_seen=None, rev=0, cur=None, units=None, phases=None, meta=None):
    """실제 코드 구조를 기본 지도로 만들고 문서 지적·계획은 별도로 연결한다. first_seen은 지적 열쇠 → 처음 본 판.
    cur = 색인(시그니처·형식), units = 문서 변경 단위(2.12), phases = 페이즈 탭 자료(2.9.2), meta = 참조 메타데이터(2.14, 폴더 셈).
    선언마다 시그니처·조상, 참조선의 쓰기는 한 번이라도 쓰면 1. 참조선의 인터페이스 우회 표시는 엔진 I1 지적(자리·대상 이름)에서 온다."""
    from judging import check as checkmod
    out = {"stamp": stamp, "rev": rev, "layers": [], "mods": [], "files": [], "decls": [], "edges": [], "finds": [],
           "notes": list(notes), "sig": [], "bases": [], "variables": [], "modifiers": [], "units": list(units or []),
           "phases": phases, "folders": {},
           "sourceFiles": [{"file": rel, "symbolCount": len(entry.get("symbols") or []), "error": entry.get("error", "")}
                           for rel, entry in sorted((cur or {}).items())]}
    if meta is not None:
        for key, n in meta.nodes.items():
            if n.kind == "폴더":
                out["folders"][key] = dict(n.counts)
        for key, n in meta.nodes.items():
            if n.kind == "파일" and n.parent in out["folders"]:
                c = out["folders"][n.parent]
                for name in ("메서드", "변수"):
                    c[name] = c.get(name, 0) + n.counts.get(name, 0)
    file_index, decl_index, mod_index, bindings = {}, {}, {}, {}
    if analysis is not None:
        g = analysis.graph
        out["layers"] = [L.name for L in analysis.rows]
        layer_no = {name: k for k, name in enumerate(out["layers"])}
        for f, rel in enumerate(g.files):
            L = analysis.file_layer[f] or "미분류"
            if L not in layer_no:
                layer_no[L] = len(out["layers"])
                out["layers"].append(L)
            folder = os.path.dirname(rel)
            if (folder, L) not in mod_index:
                mod_index[(folder, L)] = len(out["mods"])
                out["mods"].append([folder, layer_no[L]])
            file_index[f] = len(out["files"])
            out["files"].append([rel, mod_index[(folder, L)]])
        for i, d in enumerate(g.decls):
            if "kind" in d and d["file"] in file_index:
                decl_index[i] = len(decl_index)
        bindings = refmod.bind_sources(g, cur)
        types_by_full = {}
        for i in decl_index:
            d = g.decls[i]
            if d["kind"] in ("class", "struct", "interface", "enum", "record", "delegate"):
                types_by_full.setdefault(re.sub(r"<.*>$", "", _full(d["key"])), decl_index[i])
        for i, k in decl_index.items():
            d = g.decls[i]
            c = d.get("container", -1)
            out["decls"].append([d["name"], d["kind"], file_index[d["file"]], d.get("line", 0), d.get("end", 0),
                                 decl_index.get(c, -1) if c is not None and c >= 0 else -1, d.get("access", ""),
                                 analysis.status.get(i, "")])
            rel = g.files[d["file"]]
            source = bindings[i][0][0] if i in bindings else None
            got = (source.get("signature", ""), source.get("type", "")) if source else None
            out["sig"].append([got[0], got[1]] if got else [d.get("type", "") or "", d.get("type", "") or ""])
            out["variables"].append(d.get("variables") or [])
            out["modifiers"].append(d.get("mods") or [])
            inner, outer = [], []
            for b in d.get("bases") or []:
                t = types_by_full.get(re.sub(r"<.*>$", "", b))
                if t is not None and t != k:
                    inner.append(t)
                elif b not in ("object", "System.Object"):
                    outer.append(b)
            out["bases"].append([inner, outer] if inner or outer else 0)
        # 엔진 I1 지적(자리 → (대상 형.멤버, 인터페이스 이름)): 그 자리의 참조선 가운데 대상이 맞는 것을 우회로 표시한다
        bypass = {}
        for f in findings:
            m = re.match(r"^인터페이스 우회: .* → ([^ ]+)\.([^ .]+) — ([^ ]+)\.[^ .]+로 쓴다$", f.message) if f.code == "I1" else None
            if m:
                bypass.setdefault((f.file, f.line), []).append((m.group(1), m.group(2), m.group(3)))
        iface_by_name = {}
        for i, k in decl_index.items():
            if g.decls[i]["kind"] == "interface":
                iface_by_name.setdefault(g.decls[i]["name"], k)
        where = {}
        for e in g.edges:
            a, b = decl_index.get(e[0]), decl_index.get(e[1])
            if a is None or b is None or a == b:
                continue
            rel = g.files[e[2]] if 0 <= e[2] < len(g.files) else ""
            hit = -1
            for owner_name, member, iface in bypass.get((rel, e[3]), []):
                c = g.decls[e[1]].get("container", -1)
                if g.decls[e[1]]["name"] == member and c is not None and c >= 0 and g.decls[c].get("name") == owner_name:
                    hit = iface_by_name.get(iface, -2)
                    break
            key = (a, b)
            if key in where:
                x = out["edges"][where[key]]
                x[2] = 1 if (x[2] or e[4]) else 0
                x[3] = 1 if (x[3] or (e[0], e[1]) in analysis.bad_edges) else 0
                if hit != -1 and x[4] == -1:
                    x[4] = hit
                continue
            where[key] = len(out["edges"])
            out["edges"].append([a, b, 1 if e[4] else 0, 1 if (e[0], e[1]) in analysis.bad_edges else 0, hit])
    # Approved contracts and reference failures cannot remove source facts.
    # Bind by source occurrence so partial types and overloads are not duplicated.
    present = {r[2]: decl_index[i] for i, records in bindings.items() if i in decl_index for r in records}
    paths = {row[0]: i for i, row in enumerate(out["files"])}
    modules_by_file = {d[2]: i for i, d in enumerate(out["decls"]) if d[1] == "module"}
    types = {"class", "struct", "interface", "enum", "record", "delegate"}
    for rel, entry in sorted((cur or {}).items()):
        if rel not in paths:
            if "미분류" not in out["layers"]:
                out["layers"].append("미분류")
            folder, layer = os.path.dirname(rel), "미분류"
            if (folder, layer) not in mod_index:
                mod_index[(folder, layer)] = len(out["mods"])
                out["mods"].append([folder, out["layers"].index(layer)])
            paths[rel] = len(out["files"])
            out["files"].append([rel, mod_index[(folder, layer)]])
        records = refmod.source_records(rel, entry)
        owners, added = defaultdict(list), []
        for s, key, occurrence, alias in records:
            k = present.get(occurrence)
            if k is None:
                k = len(out["decls"])
                out["decls"].append([s["name"], s["kind"], paths[rel], s.get("line", 0), s.get("end", 0), -1, s.get("access", ""), ""])
                out["sig"].append([s.get("signature", ""), s.get("type", "")])
                out["bases"].append(0)
                out["variables"].append(s.get("variables") or [])
                out["modifiers"].append(list(s.get("modifiers") or s.get("mods") or []))
                added.append((k, s))
            owners[alias.partition("#")[2]].append(k)
        module = modules_by_file.get(paths[rel], -1)
        for k, s in added:
            candidates = [i for i in owners.get(s.get("path"), ()) if i != k and out["decls"][i][3] <= s.get("line", 0) <= out["decls"][i][4]]
            if candidates:
                out["decls"][k][5] = min(candidates, key=lambda i: out["decls"][i][4] - out["decls"][i][3])
            elif s["kind"] not in types:
                if module < 0:
                    module = len(out["decls"])
                    out["decls"].append([os.path.basename(rel), "module", paths[rel], 1, max((r[0].get("end", 1) for r in records), default=1), -1, "", ""])
                    out["sig"].append(["", ""])
                    out["bases"].append(0)
                    out["variables"].append([])
                    out["modifiers"].append([])
                out["decls"][k][5] = module
    spans = defaultdict(list)
    rel_index = {out["files"][k][0]: k for k in range(len(out["files"]))}
    for k, d in enumerate(out["decls"]):
        spans[d[2]].append((k, d[3], d[4]))
    for f in findings:
        fk = rel_index.get(f.file, -1)
        dk = _innermost(spans[fk], f.line) if fk >= 0 else -1
        seen = (first_seen or {}).get(checkmod.finding_key(f), 0)
        out["finds"].append([f.code, f.file, f.line, f.message, dk, fk, seen])
    return refresh_body(None,findings,cur,(),stamp,first_seen or {},rev,replacement=out)


def document_links(ds, findings):
    """Connect DOC22 to declared source ownership without inventing a module destination."""
    selected = [f for f in findings if f.rule == "DOC22"]
    if not selected:
        return []
    by_doc, by_line = defaultdict(list), defaultdict(list)
    for row in ds.selected_rows(None, ("scope", "members", "body", "constants", "document_folders")):
        by_doc[row.doc].append(row)
        by_line[(row.doc, row.line)].append(row)
    mappings = ds.of("document_folders")
    links = []
    for finding in selected:
        match = re.match(r"^(Docs/04_Specifications/[0-9]{2}-[^/]+?)(?:\.md$|/)", finding.file)
        package = match[1] if match else ""
        whole_document = any(reason in finding.message for reason in (
            "총괄에 상세 scope·members·body·constants 계약이 있음",
            "상세 문서의 총괄 패키지 문서 없음", "상세 계약은 동명 패키지 안의 모듈 폴더에 배치해야 함"))
        rows = by_doc[finding.file] if whole_document else by_line[(finding.file, finding.line)]
        sources = sorted({r.cells["파일"] for r in rows if r.kind != "document_folders" and r.cells.get("파일") not in (None, "", "-")})
        folders = {source.rpartition("/")[0] for source in sources}
        folders.update("" if r.cells["소스 폴더"] == "." else r.cells["소스 폴더"] for r in rows if r.kind == "document_folders")
        expected = set()
        for source in sources:
            candidates = [r for r in mappings if package and (r.doc == package + ".md" or r.doc.startswith(package + "/"))
                          and (r.cells["소스 폴더"] == "." or source.startswith(r.cells["소스 폴더"] + "/"))
                          and r.cells["문서 폴더"].startswith(package + "/")]
            if candidates:
                depth = max(len(r.cells["소스 폴더"]) for r in candidates)
                expected.update(r.cells["문서 폴더"] for r in candidates if len(r.cells["소스 폴더"]) == depth)
        links.append({"finding": [finding.code, finding.file, finding.line, finding.message],
                      "sources": sources, "sourceFolders": sorted(folders),
                      "expectedFolders": sorted(expected), "packageFolder": package})
    return links


def publish_sql(root, map_data, findings, previous=None, source_snippets=None):
    """Persist the prepared projection through its storage owner."""
    map_store.publish_sql(root, map_data, findings, previous, source_snippets)


def load_sql(root, rev, cur, structure=True):
    """Restore the published projection, then construct the finding value objects."""
    stored = map_store.load_sql(root, rev, cur, structure=structure)
    if stored is None:
        return None
    from judging.check import Finding
    projection, findings = stored
    findings=[Finding(*row) for row in findings]
    if structure:
        from judging.check import finding_key
        projection.pop('sourceSnippets',None)
        seen={finding_key(f):r[6] for f,r in zip(findings,projection['finds'])}
        projection=refresh_body(None,findings,{},(),projection['stamp'],seen,rev,replacement=projection)
    return projection, findings


def position_index(map_data):
    """지도 파일 번호·선언 소속·범위의 메모리 색인. 화면 자료에는 저장하지 않는다."""
    declarations, spans = defaultdict(list),defaultdict(list)
    for i,row in enumerate(map_data["decls"]):
        declarations[row[2]].append(i)
        spans[row[2]].append((i,row[3],row[4]))
    return {"files":{f[0]:i for i,f in enumerate(map_data["files"])},
            "sources":{r["file"]:i for i,r in enumerate(map_data["sourceFiles"])},
            "decls":dict(declarations),"spans":dict(spans)}


def move_positions(previous, findings, cur, deltas, stamp, first_seen, rev, positions=None):
    """소속 색인으로 변경 파일 선언·변수·지적 위치만 교체한다. 참조선·폴더 셈은 유지한다."""
    from judging import check as checkmod
    positions = position_index(previous) if positions is None else positions
    moved = any(deltas.values())
    out = dict(previous,stamp=stamp,rev=rev,
               decls=list(previous["decls"]) if moved else previous["decls"],
               variables=list(previous["variables"]) if moved else previous["variables"],
               sourceFiles=list(previous["sourceFiles"]) if deltas else previous["sourceFiles"],finds=[])
    rel_index = positions["files"]
    spans = dict(positions["spans"]) if moved else positions["spans"]
    for rel,edits in deltas.items():
        fk = rel_index.get(rel)
        if fk is not None and edits:
            for i in positions["decls"].get(fk,[]):
                row = list(previous["decls"][i])
                row[3],row[4] = diffmod.move_line(row[3],edits),diffmod.move_line(row[4],edits)
                if row[1] == "module": row[3] = 1
                out["decls"][i] = row
                out["variables"][i] = [dict(v,line=diffmod.move_line(v["line"],edits),
                    end=diffmod.move_line(v.get("end",v["line"]),edits)) for v in previous["variables"][i]]
            spans[fk] = [(i,out["decls"][i][3],out["decls"][i][4]) for i in positions["decls"].get(fk,[])]
        i = positions["sources"].get(rel)
        if i is not None:
            entry = cur[rel]
            out["sourceFiles"][i] = dict(file=rel,symbolCount=len(entry.get("symbols") or []),error=entry.get("error", ""))
    owners = {}
    for row in previous["finds"]:
        line = diffmod.move_line(row[2],deltas[row[1]]) if row[1] in deltas else row[2]
        owners[(row[0],row[1],line,row[3])] = row[4]
    for finding in findings:
        fk = rel_index.get(finding.file,-1)
        key = (finding.code,finding.file,finding.line,finding.message)
        dk = owners[key] if key in owners else (_innermost(spans.get(fk,[]),finding.line) if fk >= 0 else -1)
        out["finds"].append([finding.code,finding.file,finding.line,finding.message,dk,fk,
                           first_seen.get(checkmod.finding_key(finding),0)])
    positions["spans"] = spans
    return out


def refresh_body(previous, findings, cur, files, stamp, first_seen, rev, positions=None, deltas=None, replacement=None):
    """Reuse proven unchanged ownership while replacing current body source rows and findings."""
    if replacement is not None:
        from judging import check as checkmod
        out = dict(previous or replacement,stamp=stamp,rev=rev)
        affected = set(files)
        parts = ([previous] if previous else []) + [replacement]
        layers = list(replacement["layers"])
        modules, paths, declarations, sources = {}, {}, [], {}
        mappings = []
        folders = dict((previous or {}).get("folders",{}))
        folders.update(replacement["folders"])
        for part in parts:
            keep = lambda file:part is replacement or file not in affected
            for source in part["sourceFiles"]:
                if keep(source["file"]): sources[source["file"]] = source
            for path,module in part["files"]:
                if keep(path):
                    folder,layer = part["mods"][module]
                    name = part["layers"][layer]
                    modules[(folder,name)] = None
                    paths[path] = (folder,name)
            mapping = {}
            for i,row in enumerate(part["decls"]):
                file = part["files"][row[2]][0]
                if keep(file):
                    mapping[i] = len(declarations)
                    declarations.append((part,i,file,row))
            mappings.append(mapping)
        mods = sorted(modules,key=lambda p:(layers.index(p[1]),p[0]))
        file_names = sorted(paths,key=lambda f:(0 if f.endswith(".cs") else 1,f))
        file_ids = {f:i for i,f in enumerate(file_names)}
        order = sorted(range(len(declarations)),key=lambda n:(file_ids[declarations[n][2]],
            declarations[n][3][3],declarations[n][3][4],declarations[n][3][0],declarations[n][3][1],
            declarations[n][0]["sig"][declarations[n][1]][0]))
        remap = {old:new for new,old in enumerate(order)}
        mapping_by_part = {id(part):{i:remap[n] for i,n in mapping.items()} for part,mapping in zip(parts,mappings)}
        out.update(layers=layers,mods=[[f,layers.index(l)] for f,l in mods],
            files=[[f,mods.index(paths[f])] for f in file_names],decls=[],sig=[],bases=[],variables=[],modifiers=[],edges=[],finds=[],
            sourceFiles=[sources[f] for f in sorted(sources)],folders=folders)
        live_folders = set()
        for source in sources.values():
            if source.get("error") or not source["file"].endswith((".cs",".py")): continue
            folder = os.path.dirname(source["file"])
            while folder not in live_folders:
                live_folders.add(folder)
                if not folder: break
                folder = os.path.dirname(folder)
        out["folders"] = {key:value for key,value in folders.items() if previous is None or key in live_folders}
        for old in order:
            part,i,file,row = declarations[old]
            mapping = mapping_by_part[id(part)]
            out["decls"].append([*row[:2],file_ids[file],*row[3:5],mapping.get(row[5],-1),*row[6:]])
            for name in ("sig","variables","modifiers"):
                out[name].append(part[name][i])
            base = part["bases"][i]
            out["bases"].append([[mapping[b] for b in base[0] if b in mapping],base[1]] if base else 0)
        edges = set()
        for part in parts:
            mapping = mapping_by_part[id(part)]
            for a,b,w,bad,bypass in part["edges"]:
                if a in mapping and b in mapping:
                    edges.add((mapping[a],mapping[b],w,bad,mapping.get(bypass,bypass) if bypass >= 0 else bypass))
        out["edges"] = [list(e) for e in sorted(edges)]
        spans = defaultdict(list)
        for i,row in enumerate(out["decls"]): spans[row[2]].append((i,row[3],row[4]))
        for f in findings:
            fk = file_ids.get(f.file,-1)
            out["finds"].append([f.code,f.file,f.line,f.message,_innermost(spans[fk],f.line),fk,
                                 first_seen.get(checkmod.finding_key(f),0)])
        return out
    return move_positions(previous,findings,cur,deltas or dict.fromkeys(files,()),stamp,first_seen,rev,positions)


def live_data(map_data):
    """실시간 화면이 소비하는 자료. 상세 해결 본문은 기존 comparison 입구에서 받는다."""
    if map_data and 'decls' not in map_data: map_data['decls']
    shown = {key:value for key,value in map_data.items() if key != "priority"}
    ranking = map_data.get('priority',{})
    shown['prioritySummary'] = {key:ranking.get(key,0) for key in ('uniqueFindings','occurrences','groupCount')}
    shown['priorityGroups'] = [{key:value for key,value in group.items() if key != 'findingIds'} for group in ranking.get('groups',[])]
    shown["sourceFiles"] = [{"file": f["file"], "symbolCount": len(f.get("symbols") or []) if "symbols" in f else f.get("symbolCount", 0),
                            "error": f.get("error", "")} for f in map_data.get("sourceFiles", [])]
    if "comparison" in map_data:
        comparison = dict(map_data["comparison"])
        comparison["resolved"] = [{"key": item["key"], "file": item["file"], "line": item["line"],
                                   "source": {"line": (item.get("source") or {}).get("line", item["line"])}}
                                  for item in comparison.get("resolved", [])]
        comparison["resolvedDeferred"] = True
        shown["comparison"] = comparison
    return shown


def delta(previous, current):
    """기존 판 사이의 변경 필드와 배열 자리만 전달한다. 빠진 판은 전체 자료로 연결한다."""
    if previous is None:
        return {"full": live_data(current)}
    old, new = live_data(previous), live_data(current)
    def difference(old, new):
        out = {"set": {}, "arrays": {}, "objects": {}, "remove": sorted(old.keys() - new.keys())}
        for key, value in new.items():
            before = old.get(key)
            if key in old and before == value:
                continue
            if isinstance(before, list) and isinstance(value, list):
                out["arrays"][key] = {"length": len(value), "items": [[i, row] for i, row in enumerate(value)
                                                                        if i >= len(before) or before[i] != row]}
            elif isinstance(before, dict) and isinstance(value, dict):
                out["objects"][key] = difference(before, value)
            else:
                out["set"][key] = value
        return out
    out = difference(old, new)
    out.update(base=old.get("rev"), rev=new.get("rev"))
    return out


def page(map_data, live=False, locale="ko"):
    """지도 HTML. 실시간 화면은 다음 판부터 변경 자료를 받는다."""
    if live:
        # Keep the HTML shell small so the loading state can paint before the large map arrives.
        payload = "null"
    else:
        shown = live_data(map_data)
        if "comparison" in map_data:
            shown["comparison"] = map_data["comparison"]
        payload = json.dumps(shown, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    return (localization.shell(PAGE, locale).replace("__LOCALE__", json.dumps(locale)).replace("__UI_MESSAGES__", json.dumps(localization.map_catalog(locale), ensure_ascii=False).replace("</", "<\\/")).replace("__MESSAGES__", json.dumps(localization.catalog(locale), ensure_ascii=False).replace("</", "<\\/")).replace("__MERMAID__", MERMAID_URL).replace("__DATA__", payload)
            .replace("__LIVE__", "true" if live else "false")
            .replace("__UI_VERSION__", json.dumps(hashlib.sha256(PAGE.encode("utf-8")).hexdigest())))


def write(root, map_data, live_url=None):
    """`Reports/map.html`과 `Reports/map-stamp.js`를 쓰고 지도 경로(루트 기준)를 돌려준다. 감시 서버가 떠 있으면 실시간 주소를 `map-stamp.js`에 적는다."""
    folder = os.path.join(root, snapshot.REPORT_ROOT)
    os.makedirs(folder, exist_ok=True)
    target = os.path.join(folder, "map.html")
    content = ('<!doctype html><meta charset="utf-8"><title>하네스</title>'
               '<p>실시간 하네스를 여는 중입니다.</p><script>location.replace(' + json.dumps(live_url) +
               '+location.hash)</script>') if live_url else page(map_data)
    previous = None
    if live_url and os.path.isfile(target):
        with open(target, encoding="utf-8") as f:
            previous = f.read()
    if previous != content:
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
    live = ""
    try:
        with open(os.path.join(root, ledger.HISTORY_ROOT, "server.json"), encoding="utf-8") as f:
            live = "http://127.0.0.1:%d/" % json.load(f)["port"]
    except (OSError, ValueError, KeyError):
        pass
    with open(os.path.join(folder, "map-stamp.js"), "w", encoding="utf-8") as f:
        f.write("window.MAP_STAMP = %s;\nwindow.MAP_LIVE_URL = %s;\n" % (json.dumps(map_data["stamp"]), json.dumps(live)))
    return snapshot.REPORT_ROOT + "/map.html"


PAGE = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>코드 통합 지도</title>
<style>
:root { --bg:#ffffff; --fg:#1f2328; --muted:#59636e; --line:#d1d9e0; --panel:#f6f8fa; --accent:#0969da;
        --s0:#2e7d32; --s1:#b58100; --s2:#d35400; --s3:#c62828; --s4:#6a1b9a; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.45 "Segoe UI","Malgun Gothic",sans-serif; }
header { position:sticky; top:0; z-index:5; background:var(--bg); border-bottom:1px solid var(--line); padding:10px 16px; }
h1 { font-size:17px; margin:0 12px 0 0; display:inline-block; }
.meta { color:var(--muted); font-size:12px; }
.tabs { display:flex; gap:4px; margin-top:8px; border-bottom:1px solid var(--line); }
.tabs a { padding:5px 14px; border:1px solid var(--line); border-bottom:none; border-radius:6px 6px 0 0; cursor:pointer; background:var(--panel); color:var(--fg); text-decoration:none; font-weight:600; }
.tabs a.on { background:var(--bg); color:var(--accent); position:relative; top:1px; }
.bar { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-top:8px; }
.crumb a { color:var(--accent); cursor:pointer; text-decoration:none; }
.crumb span.sep { color:var(--muted); margin:0 4px; }
button, label.tog { font:inherit; font-size:13px; border:1px solid var(--line); background:var(--panel); border-radius:6px; padding:3px 9px; cursor:pointer; }
label.tog input { margin-right:4px; }
.chip { display:inline-block; border-radius:10px; padding:1px 8px; font-size:12px; font-weight:600; color:#fff; cursor:pointer; user-select:none; }
.chip.off { opacity:.35; }
.c1 { background:var(--s1); } .c2 { background:var(--s2); } .c3 { background:var(--s3); } .c4 { background:var(--s4); } .c0 { background:var(--s0); }
.cn { background:#2e7d32; } .cm { background:#d35400; } .cd { background:#c62828; } .ct { background:#78909c; } .cw { background:#8c959f; }
main { display:grid; grid-template-columns:minmax(0,1fr) 483px; gap:0; min-height:calc(100vh - 130px); }
body.code main { grid-template-columns:minmax(0,1fr) 690px; }
#view { overflow:auto; padding:12px; border-right:1px solid var(--line); max-height:calc(100vh - 130px); }
#graph svg { display:block; }
.module-sequence { width:100%; }
.module-section { padding:8px 0; }
.module-section + .module-section { border-top:1px solid var(--line); margin-top:8px; }
.lazy-module > summary { cursor:pointer; padding:6px; font-size:13px; }
.lazy-module[open] > summary { font-weight:600; }
.lazy-module > .module-body { padding:0 6px; }
.module-body, .bundle-body { content-visibility:auto; contain-intrinsic-size:auto 400px; }
.varlist { margin-top:6px; }
.variable-family > summary { cursor:pointer; }
.variable-summary { float:right; margin-left:12px; color:var(--muted); font-weight:normal; }
.variable-divider { border-top:1px dashed var(--line); margin-top:10px; padding-top:4px; }
.cgroup.class-family { background:#f3f8ff; border:1px solid #0969da; }
.variable-family { border:1px solid; border-radius:6px; padding:4px 6px; }
.global-family { background:#fff8e1; border-color:#b58100; }
.field-family { background:#f3f8ff; border-color:#0969da; }
.local-family { background:#e8f5e9; border-color:#2e7d32; }

.varrow { display:grid; grid-template-columns:58px minmax(0,1fr); gap:6px; align-items:center; padding:2px 0; font-size:12px; cursor:pointer; }
.varrow .chip { text-align:center; padding:1px 4px; }


#side { overflow:auto; max-height:calc(100vh - 130px); padding:10px 12px; background:var(--panel); }
#side h2 { font-size:14px; margin:8px 0 8px; }
.find { border-bottom:1px solid var(--line); padding:6px 0; cursor:pointer; }
.find:hover { background:#eaeef2; }
.find .where { color:var(--muted); font-size:12px; word-break:break-all; }
.find .msg { font-size:13px; }
.legend span { margin-right:10px; font-size:12px; }
.legend i { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:4px; vertical-align:-1px; }
#status { color:var(--muted); font-size:12px; }
#status.err { color:#c62828; font-weight:600; }
#down { display:none; background:#c62828; color:#fff; padding:6px 16px; font-weight:600; }
#down.on { display:block; }
.cmod.i3 { border:3px solid #c62828; }
.note { color:var(--muted); font-size:12px; margin:4px 0; }
.code-summary {border:1px solid var(--line);border-radius:6px;padding:8px;margin-bottom:8px;}
.code-summary h2 {margin-top:0;}
.finding-rules,.finding-pages {display:flex;align-items:center;flex-wrap:wrap;gap:6px;margin:8px 0;}
.finding-rules button[aria-pressed="true"] {background:#ddf4ff;border-color:#0969da;}
.finding-pages button:disabled {opacity:.45;cursor:default;}
.document-issue {background:#fff8e1;border:1px solid #b58100;border-radius:6px;padding:5px 9px;margin:5px;}
.document-problem {border-color:#b58100 !important;}
.document-unlinked {border:1px solid #b58100;padding:10px;margin-bottom:12px;}
.summary-states {display:flex;flex-wrap:wrap;gap:6px;}
.document-check {border:1px solid var(--line);border-radius:6px;padding:10px;margin-bottom:16px;}
.document-check > h2, #current-findings > h2 {margin-top:0;}
.review-diffs > h3 {margin:12px 0 6px;}
#current-findings {border:1px solid var(--line);border-radius:6px;padding:10px;margin-bottom:12px;}
.unit { background:var(--bg); border:1px solid var(--line); border-radius:6px; padding:6px 8px; margin:6px 0; }
.unit.wrong { border-color:#c62828; box-shadow:0 0 0 1px #c62828 inset; }
.unit .head { cursor:pointer; }
.unit .where { color:var(--muted); font-size:12px; word-break:break-all; }
.unit .target { font-size:12px; margin-top:2px; word-break:break-all; }
pre.diff { margin:6px 0; padding:4px 0; background:#fbfcfd; border:1px solid var(--line); border-radius:4px; font:12px/1.4 Consolas,"Malgun Gothic",monospace; white-space:pre-wrap; word-break:break-all; }
pre.diff div { padding:0 6px; }
pre.diff .ctx { color:#6e7781; }
pre.diff .del { background:#ffebe9; }
pre.diff .ins { background:#dafbe1; }
pre.diff .planned-line { background:#fff8e1; border-left:3px solid #b58100; }
pre.diff .del b { background:#ff818266; font-weight:normal; }
pre.diff .ins b { background:#4ac26b66; font-weight:normal; }
.checks { display:flex; gap:6px; align-items:center; margin:6px 0; }
.checks.bulk { flex-wrap:wrap; }
.checks.bulk > b { flex-basis:100%; overflow-wrap:anywhere; }
.checks button { font-size:15px; font-weight:700; padding:6px 22px; }
.sel { background:#ddf4ff; border:1px solid #0969da; border-radius:6px; padding:6px 8px; margin:4px 0 8px; }
details.prose > summary { cursor:pointer; font-weight:600; margin:10px 0 6px; }
.bulk { background:#f6f8fa; border:1px dashed #8c959f; border-radius:6px; padding:6px 8px; flex-wrap:wrap; }
.review-dialog { width:min(520px,calc(100vw - 28px)); border:1px solid var(--line); border-radius:12px; padding:22px; box-shadow:0 18px 48px #1f232844; color:var(--fg); }
.review-dialog::backdrop { background:#1f232880; }
.review-dialog h2 { margin:0 0 10px; font-size:19px; }
.review-dialog p { margin:8px 0; }
.review-meter { display:flex; align-items:center; gap:12px; margin:14px 0 8px; }
.review-meter progress { flex:1; width:100%; height:16px; }
.review-meter strong { min-width:3.5em; text-align:right; font-variant-numeric:tabular-nums; }
.review-dialog .actions { display:flex; justify-content:flex-end; gap:8px; margin-top:18px; }
.review-dialog .actions button { padding:7px 16px; font-weight:600; }
.review-dialog .error { color:#c62828; white-space:pre-wrap; }
.cmap { display:flex; }
.clayer { border:2px solid #b58100; border-radius:8px; background:#fffde7; padding:8px 10px; }
.clayer > h3 { font-size:15px; margin:0 0 8px; }
.cmods { display:flex; flex-wrap:wrap; gap:10px; align-items:flex-start; }
.cmod { border:2px solid #8c959f; border-radius:8px; background:#ffffff; padding:6px 8px; max-width:100%; }
.cmod.changed { flex-basis:100%; border-color:#0969da; background:#f3f8ff; }
.chead { font-weight:700; font-size:13px; cursor:pointer; margin-bottom:6px; }
.chead .pstate, .thead .pstate { margin-left:6px; }
a.open { font-weight:400; font-size:12px; color:#0969da; cursor:pointer; margin-left:6px; }
.cgroup { border:1px dashed #8c959f; border-radius:6px; padding:4px 6px; margin:4px 0; }
.glabel { font-size:11px; font-weight:700; color:#59636e; margin-bottom:4px; }
.gitems { display:flex; flex-wrap:wrap; gap:6px; align-items:flex-start; }
.tnode { border:1px solid #8c959f; border-radius:5px; padding:3px 7px; font-size:12px; cursor:pointer; background:#fff; }
.tnode .pstate { display:block; }
.review-tree { font-size:13px; max-width:100%; }
.review-tree ul { list-style:none; margin:0; padding-left:20px; border-left:1px solid var(--line); }
.review-tree > ul { padding-left:0; border:0; }
.review-folder > summary { cursor:pointer; padding:3px 0; }
.review-select { color:inherit; background:transparent; border:0; border-radius:4px; text-align:left; padding:5px 8px; cursor:pointer; font:inherit; overflow-wrap:anywhere; }
.review-select:hover { background:#eef5fc; }
.review-select[aria-current="page"] { background:#dbeafe; outline:2px solid #0969da; }
.review-select .review-count { color:var(--muted); font-size:12px; margin-left:8px; }
.review-selection { overflow-wrap:anywhere; padding:8px; background:#eef5fc; border-radius:4px; }
.tnode.s0 { background:#e8f5e9; border-color:#2e7d32; } .tnode.s1 { background:#fff8e1; border-color:#b58100; } .tnode.s2 { background:#fff3e0; border-color:#d35400; }
.tnode.s3 { background:#ffebee; border-color:#c62828; } .tnode.s4 { background:#f3e5f5; border-color:#6a1b9a; }
.tnode.by { border:3px solid #c62828; } .tnode.noimpl { border:3px solid #d35400; }
.ptype { border:2px solid #0969da; border-radius:6px; background:#fff; padding:6px; min-width:320px; max-width:720px; }
.ptype.ghost { border:2px solid #b58100; background:#fff8e1; }
.thead { font-weight:700; font-size:13px; cursor:pointer; margin-bottom:4px; }
.prow { border:2px solid #8c959f; border-radius:4px; margin:4px 0; padding:4px 6px; font:13px/1.4 Consolas,"Malgun Gothic",monospace; cursor:pointer; word-break:break-all; }
.prow.pn { background:#e8f5e9; border-color:#2e7d32; border-style:dashed; } .prow.pm { background:#fff3e0; border-color:#d35400; } .prow.pd { background:#ffebee; border-color:#c62828; border-style:dashed; }
.prow.implementation-issue { background:#fff8e1; border-color:#b58100; }
.prow.wrong { border:4px solid #c62828; }
.picked { outline:4px solid #0969da; outline-offset:2px; }
.pstate { color:#59636e; font-size:11px; font-family:"Segoe UI","Malgun Gothic",sans-serif; }
.bundle { background:#fff; border:1px solid #8c959f; border-radius:6px; padding:6px 8px; margin:8px 0; }
.bundle.hasWrong { border:2px solid #c62828; }
.bundle > summary { cursor:pointer; font-size:12px; padding:4px; }
.bundle-page { display:flex; align-items:center; justify-content:center; gap:8px; margin:7px 0; }
.bundle .head { font-size:12px; margin-bottom:4px; }
div.diff { font:12px/1.4 Consolas,"Malgun Gothic",monospace; border:1px solid #d1d9e0; border-radius:4px; background:#fbfcfd; }
div.diff > div { display:flex; gap:4px; padding:0 4px; }
div.diff .cb { flex:0 0 22px; text-align:center; }
div.diff .cb input { width:16px; height:16px; margin-top:2px; cursor:pointer; }
div.diff .rl { flex:1; white-space:pre-wrap; word-break:break-all; min-width:0; }
div.diff .ctx { color:#6e7781; }
div.diff .del { background:#ffebe9; } div.diff .ins { background:#dafbe1; }
div.diff .del b { background:#ff818266; font-weight:normal; } div.diff .ins b { background:#4ac26b66; font-weight:normal; }
div.diff .row:hover { background:#f6f8fa; } div.diff .row.flagged { box-shadow:inset 3px 0 0 #c62828; }
.cgroup.over { border:2px solid #c62828; background:#ffebee; }
.phases { display:flex; flex-direction:column; gap:6px; }
.sadd { border:1px dashed #8c959f; border-radius:6px; padding:6px 8px; background:#f6f8fa; margin-bottom:6px; }
.sadd .checks input { min-width:180px; }
.srow { border:1px solid #d1d9e0; border-radius:6px; background:#fff; }
.srow.s-지금 { border:3px solid #0969da; } .srow.s-다음 { border:2px dashed #2e7d32; } .srow.s-끝남 { opacity:.55; }
.shead { padding:6px 8px; cursor:pointer; font-size:13px; display:flex; flex-wrap:wrap; gap:6px; align-items:center; }
.shead code { background:#f6f8fa; padding:0 4px; border-radius:3px; }
.srank { display:inline-block; min-width:26px; text-align:center; font-weight:700; background:#eaeef2; border-radius:10px; }
.sbtns { margin-left:auto; display:flex; gap:4px; } .sbtns button { padding:2px 8px; }
.sfinds { border-top:1px solid #d1d9e0; padding:4px 8px; max-height:420px; overflow:auto; }
.cgroup.over .glabel { color:#c62828; font-size:13px; margin:0; }
.checks input { flex:1; font:inherit; font-size:12px; padding:3px 6px; border:1px solid var(--line); border-radius:4px; }
button.ok { background:#dafbe1; border-color:#2e7d32; } button.ng { background:#ffebe9; border-color:#c62828; }
.doc { margin:8px 0 2px; font-weight:600; font-size:13px; word-break:break-all; }
.uline { font-size:12px; padding:2px 0; cursor:pointer; border-bottom:1px dotted var(--line); }
.uline:hover { background:#eaeef2; }
@media (max-width: 900px) { main { grid-template-columns:1fr; } #view { border-right:none; } #side { max-height:none; } }
</style>
</head>
<body>
<div id="down"></div>
<header>
  <h1>코드 통합 지도</h1><label>표시 언어 <select id="displayLanguage"><option value="en">English</option><option value="ko">한국어</option><option value="zh">中文</option><option value="ja">日本語</option></select></label><a id="structureSettings" href="/settings">구조 설정</a><span class="meta" id="stamp"></span>
  <div id="judgmentState" class="note" role="status">표시 판정의 최신 여부 확인 중…</div>
  <nav class="tabs"><a id="tabAll">전체 오버뷰</a><a id="tabPhase">페이즈 <span id="phaseCount"></span></a><a id="tabCode">지적</a><a id="tabImplementation">구현 <span id="tabCount"></span></a><a id="tabReview">문서 변경 검토</a></nav>
  <div class="bar"><span class="crumb" id="crumb"></span></div>
  <div class="bar">
    <label class="tog"><input type="checkbox" id="onlyProblems">문제만</label>
    <label class="tog"><input type="checkbox" id="allEdges">모든 참조선</label>
    <button id="zoomOut">−</button><button id="zoomIn">＋</button><button id="zoomFit">맞춤</button>
    <span id="chips"></span>
    <span class="legend" id="legend"></span>
    <span id="status"></span>
    <label class="tog">작업 모드
      <select id="workflowMode" aria-label="작업 모드 전환">
        <option value="" disabled selected>현재 모드 확인 중…</option>
        <option value="document-to-code">문서 → 코드</option>
        <option value="code-to-document">코드 → 문서</option>
      </select>
    </label>
    <label class="tog">코드 수정
      <select id="codePolicy" aria-label="코드 수정 정책">
        <option value="deny">문서만 수정</option>
        <option value="allow">코드 수정 허용</option>
        <option value="request">필요 시 수락 요청</option>
      </select>
    </label>
    <span id="workflowStatus" role="status" aria-live="polite"></span>
  </div>
</header>
<main>
  <section id="view"><div id="graph"></div></section>
  <aside id="side"></aside>
</main>
<dialog id="reviewDialog" class="review-dialog" aria-labelledby="reviewTitle">
  <h2 id="reviewTitle">문서 변경 체크</h2>
  <p id="reviewMessage"></p>
  <p id="reviewStage" role="status" aria-live="polite"></p>
  <div class="review-meter"><progress id="reviewProgress" max="100" value="0" aria-label="체크 진행률"></progress><strong id="reviewPercent">0%</strong></div>
  <p class="note" id="reviewDetail"></p>
  <p class="error" id="reviewError"></p>
  <div class="actions"><button id="reviewCancel">취소</button><button id="reviewConfirm" class="ok">실행</button><button id="reviewClose" hidden>닫기</button></div>
</dialog>
<script>const uiMessages=__UI_MESSAGES__; const ui=s=>uiMessages[s]??s; const messages = __MESSAGES__; const tr = (key, values={}) => (messages[key] || key).replace(/\{(\w+)\}/g, (_, name) => values[name] ?? '');
const displayLanguage = document.getElementById('displayLanguage'); displayLanguage.value = __LOCALE__;
displayLanguage.onchange = () => { const target = new URL(location.href); target.searchParams.set('lang', displayLanguage.value); location.href = target.href; };
document.getElementById('structureSettings').href='/settings?lang='+__LOCALE__;
window.MAP_DATA = __DATA__; window.MAP_LIVE = __LIVE__; window.MAP_UI = __UI_VERSION__;</script>
<script src="__MERMAID__"></script>
<script>
function localizedFinding(file, line, raw) {
  const item = (window.MAP_DATA?.standardFindings || []).find(row => row.file === file && row.line === line && raw.includes(row.unavailable ? '('+row.rule+')' : '('+row.depth+'; '+row.rule+')'));
  return item ? tr(item.unavailable ? 'finding.unavailable' : 'finding.limit', {...item, metric:tr('metric.'+item.metric), depth:tr('depth.'+item.depth)}) : raw;
}
function mountMap(state) {
  if (!state) {
    try {
      const saved = JSON.parse(sessionStorage.getItem('mapReloadState') || 'null');
      sessionStorage.removeItem('mapReloadState');
      if (saved && saved.hash === location.hash) state = saved;
    } catch (e) {}
  }
  const D = window.MAP_DATA;
  const $ = (id) => document.getElementById(id);
  const SEV = (code) => code[0] === "D" || code[0] === "P" ? 4 : (code === "L1" || code === "L2" || code === "L6") ? 3 : code[0] === "L" ? 2 : 1;
  const KIND_TYPES = new Set(["class", "struct", "interface", "enum", "record", "delegate", "module"]);
  let zoom = state ? state.zoom : 1, renderNo = 0, hidden = new Set(state ? state.hidden : []);
  side.findingState = state?.findingState;
  side.tab = state?.sideTab || 'findings';
  let seenRev = D.rev;
  try { const v = localStorage.getItem("mapSeenRev"); if (v !== null) seenRev = Math.min(+v, D.rev); localStorage.setItem("mapSeenRev", String(D.rev)); } catch (e) {}
  if (state) seenRev = state.seenRev;
  const isNew = (f) => f[6] > seenRev;
  let U = D.units || [];
  let reviewSubmitting = 0;
  let codeFirst = !!(D.workflow && D.workflow.authority === "code");
  let reviewViewActive = false, reviewLoading = null;
  if (codeFirst) U = [];
  const wrongCount = U.filter(u => u.verdict === "틀림").length;
  const whole = D.completion || {}, totalText = whole.remaining == null ? ui("미확정") : whole.remaining + ui("건");
  $("stamp").textContent = ui("판 ") + D.rev + ui(" · 판정 ") + D.stamp.slice(0, 19) + (window.MAP_LIVE ? ui(" · 실시간") : "") + ui(" · 파일 ") + (D.sourceFiles || D.files).length + ui(" · 선언 ") + (D.sourceFiles ? D.sourceFiles.reduce((n,f)=>n+(f.symbolCount ?? f.symbols.length),0) : D.decls.length) + ui(" · 참조 ") + D.edges.length + ui(" · 전체 미해결 ") + totalText + ui(" · 표시 판 지적 발생 ") + D.finds.length + ui("건");
  $("tabCount").textContent = ui("· 미구현·검증 미완료 코드 대상 ") + (D.implementationPlans || []).length + ui("개");
  if (D.rev == null) {
    $("stamp").textContent = ui("코드 대조 결과 미확정 · 문서 검토 가능");
    $("tabCount").textContent = ui("· 판정 대기");
  }
  $("tabReview").textContent = ui("문서 변경 검토") + (U.length ? " · " + U.length + ui("줄") : "");

  // 색인: 선언의 주인(가장 가까운 형·모듈·최상위 선언), 파일·모듈별 선언, 선언별 지적
  const owner = D.decls.map((d, i) => {
    let k = i;
    while (k >= 0) {
      const x = D.decls[k];
      if (KIND_TYPES.has(x[1]) || x[5] < 0) return k;
      k = x[5];
    }
    return i;
  });
  const members = D.decls.map(() => []);
  D.decls.forEach((d, i) => { if (d[5] >= 0) members[d[5]].push(i); });
  const modOfDecl = (i) => D.files[D.decls[i][2]][1];
  const findsByDecl = new Map(), findsByFile = new Map();
  D.finds.forEach((f, k) => {
    if (f[4] >= 0) { if (!findsByDecl.has(f[4])) findsByDecl.set(f[4], []); findsByDecl.get(f[4]).push(k); }
    if (f[5] >= 0) { if (!findsByFile.has(f[5])) findsByFile.set(f[5], []); findsByFile.get(f[5]).push(k); }
  });
  // 문서 행에서 발생한 W8/W12도 그 계약의 실제 코드 위치에 같은 지적으로 연결한다.
  const implementationDecls = new Map(D.decls.map((d,i)=>[JSON.stringify([D.files[d[2]][0],d[3],d[0],d[1]]),i]));
  (D.implementationPlans || []).forEach(item=>{
    const p=item.plan, related=implementationFindingIndices(item);
    (item.code || []).forEach(block=>{
      const i=implementationDecls.get(JSON.stringify([p.file,block.line,p.name,p.kind]));
      if(i===undefined)return;
      findsByDecl.set(i,[...new Set([...(findsByDecl.get(i)||[]),...related])]);
      const fi=D.decls[i][2];findsByFile.set(fi,[...new Set([...(findsByFile.get(fi)||[]),...related])]);
    });
  });
  // 형 마디에 그 형 안(멤버·중첩)의 지적을 모은다
  const inside = (t) => { const out = [t]; for (let q = 0; q < out.length; q++) for (const m of members[out[q]]) out.push(m); return out; };
  const findsUnder = (t) => { const ks = new Set(); for (const i of inside(t)) (findsByDecl.get(i) || []).forEach(k => ks.add(k)); return [...ks]; };
  const visible = (ks) => ks.filter(k => !hidden.has(D.finds[k][0]));
  const worst = (ks) => ks.reduce((s, k) => Math.max(s, SEV(D.finds[k][0])), 0);
  const tally = (ks) => { const c = {}; ks.forEach(k => { const x = D.finds[k][0]; c[x] = (c[x] || 0) + 1; });
    return Object.keys(c).sort().map(x => x + "×" + c[x]).join(" · "); };
  const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/"/g, "#quot;").replace(/</g, "#lt;").replace(/>/g, "#gt;");
  const html = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const declName = (i) => { const d = D.decls[i]; const c = d[5] >= 0 && KIND_TYPES.has(D.decls[d[5]][1]) && D.decls[d[5]][1] !== "module" ? D.decls[d[5]][0] + "." : ""; return c + d[0]; };
  // 격자: 마디 ids를 cols칸마다 다음 순위로 잇는 보이지 않는 선(실제 선 뒤에 붙여 linkStyle 번호를 흔들지 않는다).
  const grid = (ids, cols) => { const out = []; for (let i = 0; i + cols < ids.length; i++) out.push(`${ids[i]} ~~~ ${ids[i + cols]}`); return out; };
  // 열 수: 화면 너비에 마디 너비(px)로 들어가는 만큼, 마디 수의 제곱근을 넘지 않게
  const colsFor = (n, width) => Math.max(1, Math.min(Math.ceil(Math.sqrt(n)), Math.floor(($("view").clientWidth - 40) / width)));
  // 모듈 이름: 그 계층 모듈들의 공통 앞부분을 뺀다
  const modPrefix = D.layers.map((L, li) => {
    const names = D.mods.filter(m => m[1] === li).map(m => m[0].split("/"));
    if (names.length < 2) return 0;
    let k = 0; while (names.every(p => p.length > k + 1 && p[k] === names[0][k])) k++;
    return k;
  });
  const modName = (m) => { const p = D.mods[m][0].split("/"); const k = modPrefix[D.mods[m][1]]; return p.slice(k).join("/") || D.mods[m][0] || "(루트)"; };
  const CLASSDEF = [
    "classDef s0 fill:#e8f5e9,stroke:#2e7d32,color:#1b1b1b",
    "classDef s1 fill:#fff8e1,stroke:#b58100,color:#1b1b1b",
    "classDef s2 fill:#fff3e0,stroke:#d35400,stroke-width:2px,color:#1b1b1b",
    "classDef s3 fill:#ffebee,stroke:#c62828,stroke-width:3px,color:#1b1b1b",
    "classDef s4 fill:#f3e5f5,stroke:#6a1b9a,stroke-width:3px,color:#1b1b1b",
    "classDef ext fill:#eceff1,stroke:#78909c,stroke-dasharray:4 3,color:#37474f",
    "classDef gn fill:#fff8e1,stroke:#b58100,stroke-width:2px,color:#1b1b1b"];

  const modFinds = D.mods.map(() => []);
  D.files.forEach((f, fi) => (findsByFile.get(fi) || []).forEach(k => modFinds[f[1]].push(k)));
  const documentLinkIndex = new Map((D.documentLinks||[]).map(link=>[JSON.stringify(link.finding),link]));
  const documentFindsByModule = D.mods.map(()=>[]), unlinkedDocumentFinds=[];
  const sourceModules = new Map(D.files.map(f=>[f[0],f[1]])), folderModules=new Map();
  D.mods.forEach((m,k)=>{if(!folderModules.has(m[0]))folderModules.set(m[0],[]);folderModules.get(m[0]).push(k);});
  D.finds.forEach((f,k)=>{
    if(!/^규칙 DOC22\s/.test(f[3]))return;
    const link=documentLinkIndex.get(JSON.stringify(f.slice(0,4))), targets=new Set();
    (link?.sources||[]).forEach(file=>{if(sourceModules.has(file))targets.add(sourceModules.get(file));});
    (link?.sourceFolders||[]).forEach(folder=>(folderModules.get(folder)||[]).forEach(m=>targets.add(m)));
    if(!targets.size)unlinkedDocumentFinds.push(k);
    targets.forEach(m=>{modFinds[m].push(k);documentFindsByModule[m].push(k);});
  });
  modFinds.forEach((ks,i)=>modFinds[i]=[...new Set(ks)]);
  const fileCount = D.mods.map(() => 0); D.files.forEach(f => fileCount[f[1]]++);
  const layerOfMod = (m) => D.mods[m][1];
  const docFinds = D.finds.map((f, k) => k).filter(k => D.finds[k][5] < 0 && D.finds[k][1].startsWith("Docs/"));
  const strayFinds = D.finds.map((f, k) => k).filter(k => D.finds[k][5] < 0 && !D.finds[k][1].startsWith("Docs/"));
  const layerFinds = D.layers.map((L, li) => { const ks = []; D.mods.forEach((m, mi) => { if (m[1] === li) modFinds[mi].forEach(k => ks.push(k)); }); return [...new Set(ks)]; });

  // ===== 전체 오버뷰 탭: 지적 지도 네 층(2.9) =====
  // 보기 1: 전체 — 계층 마디, 계층 사이 참조(허용 파랑, 위반 빨강)
  function viewAll() {
    const lines = ["flowchart LR"], click = {};
    D.layers.forEach((L, li) => {
      const mods = D.mods.filter(m => m[1] === li).length;
      if (!mods) return;
      const files = D.files.filter(f => D.mods[f[1]][1] === li).length;
      const ks = visible(layerFinds[li]);
      lines.push(`L${li}${ui("[\"계층 ")}${esc(L)}${ui("<br/>파일 ")}${files}${ui(" · 모듈 ")}${mods}${ui("<br/>지적 ")}${ks.length}${ks.length ? "<br/>" + esc(tally(ks)) : ""}"]:::s${worst(ks)}`);
      click["L" + li] = "layer:" + li;
    });
    const dks = visible(docFinds), sks = visible(strayFinds);
    if (dks.length) { lines.push(`${ui("DOC[\"문서<br/>지적 ")}${dks.length}<br/>${esc(tally(dks))}"]:::s${worst(dks)}`); click["DOC"] = "docs"; }
    if (sks.length) { lines.push(`${ui("OUT[\"계층 밖 파일<br/>지적 ")}${sks.length}<br/>${esc(tally(sks))}"]:::s${worst(sks)}`); click["OUT"] = "stray"; }
    const agg = new Map();
    D.edges.forEach(e => {
      const a = layerOfMod(modOfDecl(e[0])), b = layerOfMod(modOfDecl(e[1]));
      if (a === b) return;
      const key = a + ">" + b; const x = agg.get(key) || { a, b, n: 0, bad: 0 }; x.n++; x.bad += e[3]; agg.set(key, x);
    });
    const styles = []; let n = 0;
    for (const x of agg.values()) {
      lines.push(`L${x.a}${ui(" -->|\"참조 ")}${x.n}${x.bad ? ui(" · 위반 ") + x.bad : ""}"| L${x.b}`);
      styles.push(`linkStyle ${n} stroke:${x.bad ? "#c62828" : "#0969da"},stroke-width:${x.bad ? 3 : 2}px`);
      n++;
    }
    return { text: lines.concat(CLASSDEF, styles).join("\n"), click, crumbs: [[ui("전체"), "all"]],
             list: D.finds.map((f, k) => k), title: ui("전체 지적"), extra: "" };
  }

  // 보기 1-2: 문서·계층 밖 지적(그림 없이 목록)
  function viewList(which) {
    const list = which === "docs" ? docFinds : strayFinds;
    return { text: null, click: {}, crumbs: [[ui("전체"), "all"], [which === "docs" ? ui("문서") : ui("계층 밖 파일"), which]],
             list, title: which === "docs" ? ui("문서 지적") : ui("계층 밖 파일 지적"), extra: "" };
  }

  // 보기 1-5: 계층 — 그 계층의 모듈, 다른 계층은 계층 마디 하나로
  function viewLayer(li) {
    const only = $("onlyProblems").checked, all = $("allEdges").checked;
    const mods = D.mods.map((m, i) => i).filter(i => D.mods[i][1] === li);
    const agg = new Map(), ext = new Set();
    D.edges.forEach(e => {
      const ma = modOfDecl(e[0]), mb = modOfDecl(e[1]);
      if (ma === mb) return;
      const ia = layerOfMod(ma) === li, ib = layerOfMod(mb) === li;
      if (!ia && !ib) return;
      const ka = ia ? "m" + ma : "L" + layerOfMod(ma), kb = ib ? "m" + mb : "L" + layerOfMod(mb);
      if (!ia) ext.add(layerOfMod(ma)); if (!ib) ext.add(layerOfMod(mb));
      const key = ka + ">" + kb; const x = agg.get(key) || { a: ka, b: kb, n: 0, bad: 0, inner: ia && ib }; x.n++; x.bad += e[3]; agg.set(key, x);
    });
    let keep = new Set(mods.filter(i => !only || visible(modFinds[i]).length).map(i => "m" + i));
    ext.forEach(L => keep.add("L" + L));
    const lines = ["flowchart TB"], click = {};
    const shown = mods.filter(i => keep.has("m" + i)).sort((a, b) => D.mods[a][0].localeCompare(D.mods[b][0]));
    lines.push(`${ui("subgraph LL[\"계층 ")}${esc(D.layers[li])}"]`);
    shown.forEach(i => {
      const ks = visible(modFinds[i]);
      lines.push(`m${i}["${esc(modName(i))}${ui("<br/>파일 ")}${fileCount[i]}${ui(" · 지적 ")}${ks.length}${ks.length ? "<br/>" + esc(tally(ks)) : ""}"]:::s${worst(ks)}`);
      click["m" + i] = "mod:" + i;
    });
    lines.push("end");
    ext.forEach(L => { lines.push(`L${L}${ui("[\"계층 ")}${esc(D.layers[L])}"]:::ext`); click["L" + L] = "layer:" + L; });
    const styles = []; let n = 0;
    for (const x of agg.values()) {
      if (!keep.has(x.a) || !keep.has(x.b)) continue;
      if (x.inner && !all && !x.bad) continue;
      lines.push(`${x.a} -->|${x.n}${x.bad ? ui(" · 위반 ") + x.bad : ""}| ${x.b}`);
      if (x.bad) styles.push(`linkStyle ${n} stroke:#c62828,stroke-width:3px`);
      else if (!x.inner) styles.push(`linkStyle ${n} stroke:#0969da,stroke-width:2px`);
      n++;
    }
    return { text: lines.concat(grid(shown.map(i => "m" + i), colsFor(shown.length, 250)), CLASSDEF, styles).join("\n"), click, crumbs: [[ui("전체"), "all"], [ui("계층 ") + D.layers[li], "layer:" + li]],
             list: layerFinds[li], title: ui("계층 ") + D.layers[li] + ui(" 지적"), extra: ui("모듈 ") + mods.length + (all ? "" : ui(" · 계층 안 참조선은 '모든 참조선'으로 켠다")) };
  }

  // 보기 2: 모듈 — 파일 subgraph 안의 형(최상위·중첩), 다른 모듈은 모듈 마디 하나로
  function viewModule(mi) {
    const only = $("onlyProblems").checked;
    const files = D.files.map((f, i) => i).filter(i => D.files[i][1] === mi);
    const typeNodes = D.decls.map((d, i) => i).filter(i => files.includes(D.decls[i][2]) && owner[i] === i);
    const agg = new Map(), ext = new Set();
    D.edges.forEach(e => {
      const a = owner[e[0]], b = owner[e[1]];
      if (a === b) return;
      const am = modOfDecl(a) === mi, bm = modOfDecl(b) === mi;
      if (!am && !bm) return;
      const ka = am ? "n" + a : "x" + modOfDecl(a), kb = bm ? "n" + b : "x" + modOfDecl(b);
      if (!am) ext.add(modOfDecl(a)); if (!bm) ext.add(modOfDecl(b));
      const key = ka + ">" + kb; const x = agg.get(key) || { a: ka, b: kb, n: 0, bad: 0, w: 1 }; x.n++; x.bad |= e[3]; x.w &= e[2]; agg.set(key, x);
    });
    let keep = new Set(typeNodes.filter(t => !only || visible(findsUnder(t)).length).map(t => "n" + t));
    if (only) { const base = new Set(keep); for (const x of agg.values()) { if (base.has(x.a)) keep.add(x.b); if (base.has(x.b)) keep.add(x.a); } }
    else ext.forEach(m => keep.add("x" + m));
    const lines = ["flowchart TB"], click = {};
    const shown = typeNodes.filter(t => keep.has("n" + t)).sort((a, b) => D.decls[a][2] - D.decls[b][2] || D.decls[a][3] - D.decls[b][3]);
    lines.push(`subgraph MM["${esc(D.mods[mi][0] || "(루트)")}"]`);
    shown.forEach(t => {
      const ks = visible(findsUnder(t)), d = D.decls[t];
      lines.push(`n${t}["${esc(d[1])} ${esc(declName(t))}<br/>${esc(D.files[d[2]][0].split("/").pop())}${ui(" · 멤버 ")}${members[t].length}${ks.length ? "<br/>" + esc(tally(ks)) : ""}"]:::s${worst(ks)}`);
      click["n" + t] = "type:" + t;
    });
    lines.push("end");
    ext.forEach(m => { if (keep.has("x" + m)) { lines.push(`x${m}["→ ${esc(modName(m))}${ui("<br/>계층 ")}${esc(D.layers[D.mods[m][1]])}"]:::ext`); click["x" + m] = "mod:" + m; } });
    const styles = []; let n = 0;
    for (const x of agg.values()) {
      if (!keep.has(x.a) || !keep.has(x.b)) continue;
      lines.push(`${x.a} ${x.w ? "-.->" : "-->"}|${x.n}| ${x.b}`);
      if (x.bad) styles.push(`linkStyle ${n} stroke:#c62828,stroke-width:3px`);
      n++;
    }
    const list = []; files.forEach(fi => (findsByFile.get(fi) || []).forEach(k => list.push(k)));
    return { text: lines.concat(grid(shown.map(t => "n" + t), colsFor(shown.length, 240)), CLASSDEF, styles).join("\n"), click, crumbs: [[ui("전체"), "all"], [ui("계층 ") + D.layers[D.mods[mi][1]], "layer:" + D.mods[mi][1]], [D.mods[mi][0] || "(루트)", "mod:" + mi]],
             list, title: ui("모듈 지적"), extra: "" };
  }

  // 보기 3: 형 — 그 형의 멤버, 참조를 주고받는 다른 형(쓰인 멤버 이름을 함께)
  function viewType(t) {
    const only = $("onlyProblems").checked, all = $("allEdges").checked;
    const own = members[t].slice();
    const ownSet = new Set(own.concat([t]));
    const outside = new Map(), links = new Map();
    const node = (i) => ownSet.has(i) ? "n" + i : "o" + owner[i];
    D.edges.forEach(e => {
      const a = ownSet.has(e[0]), b = ownSet.has(e[1]);
      if (!a && !b) return;
      if (a && b && e[0] === t) return;
      [[a, e[0]], [b, e[1]]].forEach(([mine, i]) => {
        if (mine) return;
        const o = owner[i]; if (!outside.has(o)) outside.set(o, new Set()); if (i !== o) outside.get(o).add(D.decls[i][0]);
      });
      const ka = node(e[0]), kb = node(e[1]);
      if (ka === kb) return;
      const key = ka + ">" + kb; const x = links.get(key) || { a: ka, b: kb, n: 0, bad: 0, w: 1 }; x.n++; x.bad |= e[3]; x.w &= e[2]; links.set(key, x);
    });
    let keep = new Set(own.filter(i => !only || visible(findsByDecl.get(i) || []).length).map(i => "n" + i));
    if (only) { const base = new Set(keep); for (const x of links.values()) { if (base.has(x.a)) keep.add(x.b); if (base.has(x.b)) keep.add(x.a); } }
    else outside.forEach((v, o) => keep.add("o" + o));
    const d = D.decls[t], lines = ["flowchart TB"], click = {};
    const tks = visible(findsByDecl.get(t) || []);
    lines.push(`subgraph T["${esc(d[1])} ${esc(declName(t))} · ${esc(D.files[d[2]][0])}${tks.length ? " · " + esc(tally(tks)) : ""}"]`, "direction TB");
    const shownOwn = own.filter(i => keep.has("n" + i)).sort((a, b) => D.decls[a][3] - D.decls[b][3]);
    shownOwn.forEach(i => {
      const m = D.decls[i], ks = visible(KIND_TYPES.has(m[1]) ? findsUnder(i) : (findsByDecl.get(i) || []));
      lines.push(`n${i}["${esc(m[1])} ${esc(m[0])}<br/>${esc(m[6])} · L${m[3]}${ks.length ? " · " + esc(tally(ks)) : ""}"]:::s${worst(ks)}`);
      if (KIND_TYPES.has(m[1])) click["n" + i] = "type:" + i;
    });
    lines.push("end");
    outside.forEach((names, o) => {
      if (!keep.has("o" + o)) return;
      const od = D.decls[o], list = Array.from(names).slice(0, 8);
      const more = names.size > 8 ? " …" + (names.size - 8) : "";
      lines.push(`o${o}["${esc(od[1])} ${esc(declName(o))}<br/>${esc(list.join(", "))}${more}<br/>${esc(D.layers[D.mods[modOfDecl(o)][1]])} · ${esc(D.files[od[2]][0].split("/").pop())}"]:::ext`);
      click["o" + o] = "type:" + o;
    });
    const styles = []; let n = 0;
    for (const x of links.values()) {
      if (!keep.has(x.a) || !keep.has(x.b)) continue;
      if (!all && !x.bad && x.a[0] === "n" && x.b[0] === "n") continue;
      lines.push(`${x.a} ${x.w ? "-.->" : "-->"}${x.n > 1 ? "|" + x.n + "|" : ""} ${x.b}`);
      if (x.bad) styles.push(`linkStyle ${n} stroke:#c62828,stroke-width:3px`);
      n++;
    }
    const list = findsUnder(t);
    const mi = modOfDecl(t);
    return { text: lines.concat(grid(shownOwn.map(i => "n" + i), colsFor(shownOwn.length, 190)), CLASSDEF, styles).join("\n"), click,
             crumbs: [[ui("전체"), "all"], [ui("계층 ") + D.layers[D.mods[mi][1]], "layer:" + D.mods[mi][1]], [D.mods[mi][0] || "(루트)", "mod:" + mi], [declName(t), "type:" + t]],
             list, title: ui("형 지적"), extra: ui("멤버 ") + own.length + ui(" · 바깥 형 ") + outside.size + (all ? "" : ui(" · 형 안 참조선은 '모든 참조선'으로 켠다")) };
  }

  // ===== 코드 구조 탭(2.9.1): 전체 코드 → 모듈 → 인터페이스·클래스 → 메서드·변수, 인터페이스 대응, 문서 계획·체크 =====
  const METHOD_KINDS = new Set(["method", "ctor", "operator"]);
  const VAR_KINDS = new Set(["field", "property", "const", "event", "enum-member", "indexer"]);
  const TYPE_ONLY = new Set(["class", "struct", "interface", "enum", "record", "delegate"]);
  const SIG = D.sig || [], BASES = D.bases || [];
  const outE = D.decls.map(() => []), inE = D.decls.map(() => []);
  D.edges.forEach((e, k) => { outE[e[0]].push(k); inE[e[1]].push(k); });
  const isType = (i) => TYPE_ONLY.has(D.decls[i][1]);
  const TRIM = /\b(public|private|protected|internal|static|override|virtual|abstract|sealed|readonly|async|extern|unsafe|partial|const)\s+/g;
  const sigOf = (i) => ((SIG[i] && SIG[i][0]) || (D.decls[i][1] + " " + D.decls[i][0])).replace(TRIM, "").trim();
  const clip = (s, n) => s.length > n ? s.slice(0, n - 1) + "…" : s;
  const typeText = (i) => (SIG[i] && SIG[i][1]) || "";
  const varLabel = (i) => D.decls[i][0] + (typeText(i) ? " : " + typeText(i) : "") + (D.decls[i][1] !== "field" ? " (" + D.decls[i][1] + ")" : "");
  // 구현·상속(조상 목록의 프로젝트 안 형)
  const implOf = D.decls.map(() => []), baseOf = D.decls.map(() => -1), implementers = D.decls.map(() => []), outerBases = D.decls.map(() => []);
  BASES.forEach((b, i) => {
    if (!b) return;
    b[0].forEach(t => { if (D.decls[t][1] === "interface") { implOf[i].push(t); implementers[t].push(i); } else if (baseOf[i] < 0) baseOf[i] = t; });
    outerBases[i] = b[1];
  });
  // I1·I2·I3은 엔진 판정(2.6)을 그린다 — 지도에서 따로 셈하지 않는다. I1 = 엔진이 표시한 참조선(e[4] ≠ -1, 0 이상이면 거쳐야 할 인터페이스)
  const bypass = [];
  D.edges.forEach((e, k) => { if (e.length > 4 && e[4] !== -1) bypass.push({ k, from: e[0], to: e[1], t: owner[e[1]], iface: e[4] }); });
  const bypassEdge = new Set(bypass.map(x => x.k));
  const noImpl = new Set(); D.finds.forEach(f => { if (f[0] === "I2" && f[4] >= 0) noImpl.add(owner[f[4]]); });
  // 폴더 자리 지적(S1·I3 — 파일이 아니라 폴더에 놓인다)
  const folderFinds = new Map(); D.finds.forEach((f, k) => { if (f[5] < 0) { if (!folderFinds.has(f[1])) folderFinds.set(f[1], []); folderFinds.get(f[1]).push(k); } });
  const modFolderFinds = (m) => folderFinds.get(D.mods[m][0]) || [];
  const typesOfMod = D.mods.map(() => []);
  D.decls.forEach((d, i) => { if ((isType(i) || d[1] === "module") && owner[i] === i) typesOfMod[D.files[d[2]][1]].push(i); });
  const modCounts = D.mods.map(() => ({ i: 0, c: 0, f: 0, v: 0 }));
  D.decls.forEach((d, i) => { const c = modCounts[D.files[d[2]][1]]; if (d[1] === "interface") c.i++; else if (isType(i)) c.c++; else if (METHOD_KINDS.has(d[1])) c.f++; else if (VAR_KINDS.has(d[1])) c.v++; });
  // 참조 메타데이터(2.14)의 폴더 셈이 있으면 그것을 쓴다
  D.mods.forEach((m, mi) => { const fc = (D.folders || {})[m[0]]; if (fc) modCounts[mi] = { i: fc["바로 든 인터페이스"] || 0, c: fc["바로 든 클래스"] || 0, f: fc["메서드"] || 0, v: fc["변수"] || 0 }; });

  // 문서 계획 → 맵 자리(없으면 신설 마디)
  const fileIdx = new Map(D.files.map((f, i) => [f[0], i]));
  const typesByName = new Map(); D.decls.forEach((d, i) => { if (isType(i)) { if (!typesByName.has(d[0])) typesByName.set(d[0], []); typesByName.get(d[0]).push(i); } });
  const G = { mods: [], types: [], mems: [] };
  const folderOf = (rel) => rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "";
  function modKeyOf(rel) {
    const fi = fileIdx.get(rel); if (fi !== undefined) return "m" + D.files[fi][1];
    const folder = folderOf(rel), real = D.mods.findIndex(m => m[0] === folder); if (real >= 0) return "m" + real;
    let g = G.mods.findIndex(x => x.folder === folder); if (g < 0) { g = G.mods.length; G.mods.push({ folder, files: new Set() }); }
    G.mods[g].files.add(rel); return "gm" + g;
  }
  function ghostType(name, rel, modKey, kind) { let g = G.types.findIndex(x => x.name === name && x.rel === rel); if (g < 0) { g = G.types.length; G.types.push({ name, rel, modKey, kind }); } return "gt" + g; }
  function findType(rel, path) {
    const last = path.split(".").pop(), cands = typesByName.get(last) || [], fi = fileIdx.get(rel);
    const inFile = cands.filter(i => D.decls[i][2] === fi);
    const pick = (list) => list.find(i => { const up = path.split("."); let c = D.decls[i][5]; for (let k = up.length - 2; k >= 0 && c >= 0; k--) { if (D.decls[c][0] !== up[k]) return false; c = D.decls[c][5]; } return true; });
    const got = pick(inFile);
    return got === undefined ? -1 : got;
  }
  function typeKeyOf(rel, path, modKey) {
    if (!path || path === "-") {
      const fi = fileIdx.get(rel);
      if (fi !== undefined) { const m = D.decls.findIndex(d => d[1] === "module" && d[2] === fi); if (m >= 0) return "t" + m; }
      return ghostType(rel.split("/").pop(), rel, modKey, "module");
    }
    const t = findType(rel, path); return t >= 0 ? "t" + t : ghostType(path, rel, modKey, "class");
  }
  function memberKeyOf(typeKey, name, kind, sig) {
    if (typeKey[0] === "t") { const t = +typeKey.slice(1), candidates = members[t].filter(k => D.decls[k][0] === name && D.decls[k][1] === kind); const m = candidates.find(k => (SIG[k] || [])[0] === sig) ?? (candidates.length === 1 ? candidates[0] : undefined); if (m !== undefined) return "d" + m; }
    let g = G.mems.findIndex(x => x.typeKey === typeKey && x.name === name); if (g < 0) { g = G.mems.length; G.mems.push({ typeKey, name, kind, sig }); } return "gd" + g;
  }
  const plannedDeclIndex = new Map(D.decls.map((d, i) => [JSON.stringify([D.files[d[2]][0], d[3], d[0], d[1]]), i]));
  const chainFor = (u) => {
    const p = u.plan || {}; if (!p.file) return [];
    const mk = modKeyOf(p.file);
    const span = (u.code || [])[0];
    if (span && p.kind !== "file") {
      const di = plannedDeclIndex.get(JSON.stringify([p.file, span.line, p.name, p.kind]));
      if (di !== undefined) return TYPE_ONLY.has(p.kind) ? [mk, "t" + di] : [mk, "t" + owner[di], "d" + di];
    }
    if (p.kind === "file" || !p.name) return [mk];
    if (TYPE_ONLY.has(p.kind)) return [mk, typeKeyOf(p.file, p.path && p.path !== "-" ? p.path + "." + p.name : p.name, mk)];
    const tk = typeKeyOf(p.file, p.path, mk);
    return [mk, tk, memberKeyOf(tk, p.name, p.kind, p.sig_new || p.sig_old)];
  };
  let chainOf = U.map(chainFor);
  const unitsUnder = (key) => U.map((u, k) => k).filter(k => chainOf[k].includes(key));
  const unitsAt = (key) => U.map((u, k) => k).filter(k => chainOf[k][chainOf[k].length - 1] === key);
  function planLine(key) {
    const plans = (D.implementationPlans || []).filter(p => chainFor(p).includes(key));
    return plans.length ? ui("<br/>미구현·검증 미완료 ") + plans.length + ui("곳") : "";
  }
  function planStyle(id, key) {
    // 실제 마디는 이미 전체 지적의 최고 등급을 사용한다. 구현 대상 표시로 덮어쓰지 않는다.
    if (!key.startsWith('g')) return [];
    const plans = (D.implementationPlans || []).filter(p => chainFor(p).includes(key));
    if (!plans.length) return [];
    const severity=Math.max(1,worst(plans.flatMap(implementationFindingIndices)));
    return [`style ${id} fill:${['#e8f5e9','#fff8e1','#fff3e0','#ffebee','#f3e5f5'][severity]},stroke:${['#2e7d32','#b58100','#d35400','#c62828','#6a1b9a'][severity]},stroke-width:2px`];
  }
  const planTag = (key) => { const at = (D.implementationPlans || []).find(p => chainFor(p).slice(-1)[0] === key); return at ? "[" + implementationLabel([at]) + "] " : ""; };
  const typeTitle = (i) => D.decls[i][1] + " " + declName(i);
  const ghostTypeKey = (g) => "gt" + g, ghostMemKey = (g) => "gd" + g;
  const codeClick = (key) => "c:" + key;

  // 코드 1(첫 화면): 전체 코드 맵 — 서브그래프 구조(계층 틀 → 모듈 틀 → 인터페이스·클래스 틀 → 마디)를 상자 배치(HTML)로 그린다.
  // 모듈 틀은 안에 든 인터페이스·클래스를 이름으로 모두 보인다. 체크할 계획이 있는 형은 그 자리에서 펼쳐 계획 줄을 보인다.
  // 계획 줄·펼친 틀을 누르면 골라지고 곁에 그 체크 묶음이 나온다. 형 마디를 누르면 그 형 보기로 간다
  function codeAll(sel) {
    const only = $("onlyProblems").checked;
    const documentBadge = m => {
      const count=(documentFindsByModule[m]||[]).length;
      return count?`<button class="document-issue" data-go="c:dm${m}${ui("\">W6 · 문서 분리 ")}${count}${ui("건</button>")}`:'';
    };
    const scheduled = D.implementationPlans || [];
    // 표시 순위는 승인 units와 분리한다. 현재 지도 색인만 사용한다.
    const priorityFiles = new Set(), priorityMods = new Set();
    const priorityDecls = new Set(), priorityTypes = new Set(), wholeFiles = new Set(), targets = new Map();
    scheduled.forEach(item => {
      const p=item.plan;
      if(p.action!=='신규' && p.action!=='수정') return;
      const fi=fileIdx.get(p.file);
      if(fi===undefined) return;
      priorityFiles.add(fi); priorityMods.add(D.files[fi][1]);
      if(p.kind==='file') wholeFiles.add(fi);
      else { if(!targets.has(fi)) targets.set(fi,[]); targets.get(fi).push(p); }
    });
    D.decls.forEach((d,i) => {
      if(!priorityFiles.has(d[2])) return;
      if(wholeFiles.has(d[2]) || (targets.get(d[2])||[]).some(p => p.name===d[0] && p.kind===d[1])) {
        priorityDecls.add(i);
        let parent=TYPE_ONLY.has(d[1])?i:d[5];
        while(parent>=0) { if(TYPE_ONLY.has(D.decls[parent][1])) priorityTypes.add(parent); parent=D.decls[parent][5]; }
      }
    });
    const plannedFirst = (a,b) => Number(priorityDecls.has(b)||priorityTypes.has(b))-Number(priorityDecls.has(a)||priorityTypes.has(a));
    const tree = new Map();   // 모듈 → 형(없으면 "") → 마디(멤버 또는 "") → [단위]
    // Document review units never create implementation tasks or approval rows here.
    const scheduledAt = new Map(), scheduledUnder = new Map();
    scheduled.forEach(item => {
      const chain=chainFor(item), key=chain[chain.length-1];
      if(!key) return;
      if(!scheduledAt.has(key)) scheduledAt.set(key,[]);
      scheduledAt.get(key).push(item);
      chain.forEach(k=>{if(!scheduledUnder.has(k)) scheduledUnder.set(k,new Set());scheduledUnder.get(k).add(item);});
      const [mk,tk,dk]=chain;
      if(!tree.has(mk)) tree.set(mk,new Map());
      if(tk && !tree.get(mk).has(tk) && tk.startsWith('gt')) tree.get(mk).set(tk,new Map());
      if(!mk.startsWith('gm')) priorityMods.add(+mk.slice(1));
    });
    const scheduledBadge = key => scheduledUnder.has(key) ? `<span class="chip c1">${html(implementationLabel([...scheduledUnder.get(key)]))}</span>` : '';
    const scheduledRows = (tk, missingOnly=false) => [...scheduledAt].filter(([key,items])=>key===tk || items.some(item=>chainFor(item)[1]===tk)).filter(([key])=>!missingOnly || key.startsWith("gd")).map(([key,items])=>`<div class="prow implementation-issue" data-key="${html(key)}" data-go="c:@${html(key)}">${scheduledBadge(key)} ${html(items[0].plan.sig||items[0].plan.file)}</div>`).join('');
    const ACT = { "신규": "pn", "수정": "pm", "삭제": "pd" };
    const bypassOf = new Map(); bypass.forEach(x => bypassOf.set(x.t, (bypassOf.get(x.t) || 0) + 1));
    let first = null;
    const state = (ks) => { const w = ks.filter(k => U[k].verdict === "틀림").length; return ui("체크 대기 ") + (ks.length - w) + (w ? ui(" · 틀림 ") + w : ""); };
    const row = (key, ks, text) => {
      if (!first) first = key;
      const wrong = ks.some(k => U[k].verdict === "틀림");
      return `<div class="prow ${ACT[(U[ks[0]].plan || {}).action] || ""}${wrong ? " wrong" : ""}${sel === key ? " picked" : ""}" data-go="c:@${html(key)}" data-key="${html(key)}">${scheduledBadge(key)} ${html(text)} <span class="pstate">${state(ks)}</span></div>`;
    };
    // 계획이 없는 형 마디: 이름 · 멤버 수 · 지적
    const statusOf = ks => {
      const codes=ks.map(k=>D.finds[k][0]);
      return codes.includes('W2') ? ['문서 누락','c1'] : codes.includes('W9') ? ['문서 미등록','c1'] : codes.includes('W8') ? ['미구현','c1'] :
        codes.includes('W12') ? ['검증 미완료','c1'] : codes.some(c=>c==='W3'||c==='W4') ? [ui("불일치"),'c1'] : codes.length ? [ui("지적"),'c'+worst(ks)] : ['', ''];
    };
    const stateHtml = ks => {const [name,tone]=statusOf(ks);return name ? `<span class="chip ${tone}">${name}</span>` : "";};
    const variableRows = ids => ids.map(i=>`<div class="varrow" data-go="c:@d${i}" data-key="d${i}">${scheduledBadge("d"+i)||stateHtml(visible(findsByDecl.get(i)||[]))}<span>${html(D.decls[i][0])}</span></div>`).join('');
    const methodVariables = i => {
      const groups=new Map();
      (D.variables[i]||[]).forEach(variable=>{const label=[variable.scope,variable.kind].filter(Boolean).join(' · ');if(!groups.has(label)) groups.set(label,[]);groups.get(label).push(variable);});
      let h='';
      groups.forEach((values,label)=>{h+=`<details class="varlist variable-family local-family"><summary class="glabel">${html(label)} ${values.length}${ui("개<span class=\"variable-summary\">미확인 ")}${values.length}${ui("개</span></summary>")}${values.map(variable=>`<div class="varrow" data-go="c:@d${i}${ui("\"><span class=\"chip cw\" title=\"지역 변수 자체의 문서 대조는 미확인\">미확인</span><span>")}${html(variable.name)}</span></div>`).join('')}</details>`;});
      return h;
    };
    const typeNode = t => {
      const d=D.decls[t], own=visible(findsByDecl.get(t)||[]), children=[...members[t]].sort(plannedFirst);
      const methods=children.filter(i=>METHOD_KINDS.has(D.decls[i][1]));
      const nested=children.filter(i=>TYPE_ONLY.has(D.decls[i][1]));
      const variables=children.filter(i=>VAR_KINDS.has(D.decls[i][1]));
      const globals=variables.filter(i=>d[1]==='module'||(D.modifiers[i]||[]).some(m=>m==='static'||m==='const'));
      const fields=variables.filter(i=>!globals.includes(i));
      const methodHtml = i => {
        const ms=D.decls[i], ks=visible(findsByDecl.get(i)||[]);
        let h=`<div class="tnode s${worst(ks)}${sel==='d'+i?' picked':''}" data-key="d${i}"><div data-go="c:@d${i}">${scheduledBadge("d"+i)||stateHtml(ks)} ${html(ms[0])}</div>`;
        if ((D.variables[i]||[]).length) h+=`<details data-variable-owner="${i}${ui("\"><summary>변수 ")}${(D.variables[i]||[]).length}${ui("개</summary><div ")}${sel==='d'+i?'':'data-variable-pending="true"'}>${sel==='d'+i?methodVariables(i):''}</div></details>`;
        return h+'</div>';
      };
      let h=`<div class="ptype${sel==='t'+t?' picked':''}" data-key="t${t}"><div class="thead" data-go="c:@t${t}">${scheduledBadge("t"+t)||stateHtml(own)} ${html(d[0])}</div>`;
      h+=scheduledRows("t"+t,true);
      if(globals.length) {const ks=visible([...new Set(globals.flatMap(i=>findsByDecl.get(i)||[]))]);h+=`${ui("<details class=\"varlist variable-family global-family\"><summary class=\"glabel\">전역·정적 변수 ")}${globals.length}${ui("개<span class=\"variable-summary\">지적 ")}${ks.length}${ui("개")}${ks.length?' · '+html(tally(ks)):''}</span></summary>${variableRows(globals)}</details>`;}
      if(fields.length) {const ks=visible([...new Set(fields.flatMap(i=>findsByDecl.get(i)||[]))]);h+=`${ui("<details class=\"varlist variable-family field-family\"><summary class=\"glabel\">클래스 변수 ")}${fields.length}${ui("개<span class=\"variable-summary\">지적 ")}${ks.length}${ui("개")}${ks.length?' · '+html(tally(ks)):''}</span></summary>${variableRows(fields)}</details>`;}
      if(variables.length && (methods.length || nested.length)) h+='<div class="variable-divider" aria-hidden="true"></div>';
      if(methods.length) h+=`<div class="gitems">${methods.map(methodHtml).join('')}</div>`;
      if(nested.length) h+=`<div class="gitems">${nested.map(typeNode).join('')}</div>`;
      return h+'</div>';
    };
    // 계획이 있는 형 틀: 형 이름 → 계획 줄
    const planType = (tk, mems) => {
      const ghost = tk.startsWith("gt");
      let h = `<div class="ptype${sel === tk ? " picked" : ""}${ghost ? " ghost" : ""}" data-key="${html(tk)}"><div class="thead" data-go="c:@${html(tk)}">${scheduledBadge(tk)}${ghost && !scheduledUnder.has(tk) ? ui("[코드 없음] ") : ""}${html(nodeName(tk))}${ghost ? "" : ` <a class="open" data-go="c:${html(tk)}${ui("\">형 보기 →</a>")}`}</div>`;
      mems.forEach((ks, dk) => { if (!dk) ks.forEach(k => h += row(tk, [k], planText(k))); else h += row(dk, ks, ks.length > 1 ? planText(ks[0]) + ui(" 외 ") + (ks.length - 1) : planText(ks[0])); });
      h += scheduledRows(tk);
      return h + "</div>";
    };
    const group = (label, items) => items.length ? `<div class="cgroup${label==='클래스'?' class-family':''}"><div class="glabel">${label}</div><div class="gitems">${items.join("")}</div></div>` : "";
    const probType = (t) => visible(findsUnder(t)).length || bypassOf.has(t) || noImpl.has(t);
    // 모듈 틀(서브그래프): 인터페이스 틀 · 클래스 틀 · 파일 틀
    const moduleFrame = (mk) => {
      const ghost = mk.startsWith("gm"), m = ghost ? -1 : +mk.slice(1), plan = tree.get(mk) || new Map();
      const ts = ghost ? [] : typesOfMod[m].filter(t => {
        const parent=D.decls[t][5];
        if(parent>=0 && TYPE_ONLY.has(D.decls[parent][1]) && modOfDecl(parent)===m) return false;
        return priorityTypes.has(t) || plan.has("t"+t) || !only || probType(t);
      });
      const byName = (a, b) => plannedFirst(a,b) || (plan.has("t" + b) - plan.has("t" + a)) || D.decls[a][0].localeCompare(D.decls[b][0]);
      const ifaces = ts.filter(t => D.decls[t][1] === "interface").sort(byName), classes = ts.filter(t => D.decls[t][1] !== "interface").sort(byName);
      const shown = new Set(ts.map(t => "t" + t));
      const extra = Array.from(plan.keys()).filter(tk => tk && !shown.has(tk)).map(tk => planType(tk, plan.get(tk)));
      const loose = []; if (plan.has("")) plan.get("").forEach(ks => ks.forEach(k => loose.push(row(mk, [k], planText(k)))));
      const ks = ghost ? [] : visible(modFinds[m]);
      const fks = ghost ? [] : modFolderFinds(m), s1 = fks.map(k => D.finds[k]).find(f => f[0] === "S1"), i3 = fks.map(k => D.finds[k]).find(f => f[0] === "I3");
      let h = `<section class="module-section${plan.size ? " changed" : ""}${sel === mk ? " picked" : ""}${i3 ? " i3" : ""}" data-key="${html(mk)}">`;
      h += `<div class="chead" data-go="${plan.size ? "c:@" + html(mk) : "c:" + html(mk)}">${scheduledBadge(mk)}${ghost ? "" : ui("모듈 ")}${html(nodeName(mk))} <span class="pstate">${ghost ? "" : ui("인터페이스 ") + modCounts[m].i + ui(" · 클래스 ") + modCounts[m].c + ui(" · 메서드 ") + modCounts[m].f + ui(" · 변수 ") + modCounts[m].v}${ks.length ? ui(" · 지적 ") + html(tally(ks)) : ""}</span>${ghost ? "" : ` <a class="open" data-go="c:${html(mk)}${ui("\">모듈 보기 →</a>")}`}</div>`;
      // 구조 한도 지적은 표시하되 클래스·메서드·변수는 생략하지 않는다.
      const typeCount = ghost ? 0 : typesOfMod[m].filter(t => D.decls[t][1] !== "module").length;
      if (s1) h += `${ui("<div class=\"cgroup over\"><div class=\"glabel\">형 ")}${typeCount}${ui("개 — S1 ")}${html(s1[3])}</div></div>`;
      if (i3) h += `<div class="cgroup over"><div class="glabel">I3 ${html(i3[3])}</div></div>`;
      h += group(ui("인터페이스"), ifaces.map(t => plan.has("t" + t) ? planType("t" + t, plan.get("t" + t)) : typeNode(t)));
      h += group(ui("클래스"), extra.concat(classes.map(t => plan.has("t" + t) ? planType("t" + t, plan.get("t" + t)) : typeNode(t))));
      h += group(ui("파일"), loose);
      return h + "</section>";
    };
    const probMod = (m) => priorityMods.has(m) || visible(modFinds[m]).length || modFolderFinds(m).length || tree.has("m" + m) || typesOfMod[m].some(probType);
    const ordered=D.mods.map((m,i)=>i).filter(i=>!only||probMod(i)).sort((a,b)=>{
      const priority=Number(priorityMods.has(b))-Number(priorityMods.has(a)); if(priority) return priority;
      const pa=D.mods[a][0].split('/'),pb=D.mods[b][0].split('/');
      for(let k=0;k<Math.min(pa.length,pb.length);k++){const order=pa[k].localeCompare(pb[k]);if(order) return order;}
      return pa.length-pb.length;
    });
    const ghosts=Array.from(tree.keys()).filter(k=>k.startsWith('gm'));
    const folders=new Set(D.mods.map(m=>m[0]));
    const rootFolder = path => {
      let root=path, parent=path;
      while(parent.includes('/')) {
        parent=parent.slice(0,parent.lastIndexOf('/'));
        if(folders.has(parent)) root=parent;
      }
      return root;
    };
    const families=new Map();
    ordered.forEach(m=>{const root=rootFolder(D.mods[m][0]);if(!families.has(root)) families.set(root,[]);families.get(root).push('m'+m);});
    ghosts.forEach(mk=>{const path=G.mods[+mk.slice(2)].folder,root=rootFolder(path);if(!families.has(root)) families.set(root,[]);families.get(root).push(mk);});
    
    const modulePriority = key => key.startsWith('gm') ? 1 : Number(priorityMods.has(+key.slice(1)));
    families.forEach(keys => keys.sort((a,b)=>modulePriority(b)-modulePriority(a)));
    const orderedFamilies=[...families].sort((a,b)=>Number(b[1].some(modulePriority))-Number(a[1].some(modulePriority)));
    // A priority family must not carry all its unchanged modules ahead of another family's plans.
    const sections = [true,false].flatMap(planned => orderedFamilies.map(([root,keys]) =>
      [root,keys.filter(key=>Boolean(modulePriority(key))===planned),planned]).filter(([,keys])=>keys.length));
    // The full declaration tree is large; materialize a module only when opened.
    const selectedModule = sel && (sel.startsWith('gm') || sel.startsWith('m') ? sel : scheduled.map(item=>chainFor(item)).find(c => c.includes(sel))?.[0] || chainOf.find(c => c.includes(sel))?.[0]);
    const allModules = sections.flatMap(([, keys]) => keys);
    const initialModules = new Set(allModules.slice(0, Math.ceil(allModules.length * 0.1)));
    const moduleShell = key => {
      const ghost = key.startsWith('gm'), m = ghost ? -1 : +key.slice(1);
      const path = ghost ? G.mods[+key.slice(2)].folder : D.mods[m][0];
      const changed = tree.has(key), open = key === selectedModule || initialModules.has(key);
      const count = ghost ? '' : `${ui(" · 선언 ")}${typesOfMod[m].length}`;
      return `<details class="module-section lazy-module${changed ? ' changed' : ''}${!ghost&&documentFindsByModule[m].length?' document-problem':''}" data-module="${html(key)}" data-key="${html(key)}"${open ? ' open' : ''}><summary>${scheduledBadge(key)}${html(path || '(루트)')}${count}${ghost?'':documentBadge(m)}</summary><div class="module-body"></div></details>`;
    };
    let h=`<div class="cmap"><div class="cmods">`+sections.map(([root,keys,planned])=>`<div class="cmod module-sequence" data-key="family:${html(root)}:${planned?'planned':'rest'}" data-folder-root="${html(root)}">${keys.map(moduleShell).join('')}</div>`).join('')+'</div></div>';
    const documentCount=D.finds.filter(f=>/^규칙 DOC22\s/.test(f[3])).length;
    if(documentCount)h=ui("<div class=\"note\"><button class=\"document-issue\" data-go=\"c:docs\">문서 분리 지적 ")+documentCount+ui("건 전체 보기</button> 폴더의 문서 분리 표식을 누르면 우측에 원인과 문서 위치가 표시됩니다.</div>")+h;
    if(unlinkedDocumentFinds.length) {
      const docs=[...new Set(unlinkedDocumentFinds.map(k=>D.finds[k][1]))];
      h=ui("<section class=\"document-unlinked\"><h3>소스 폴더 미연결 · ")+unlinkedDocumentFinds.length+ui("건</h3><p>문서의 소유 선언으로 코드맵 폴더를 찾지 못했습니다.</p>")+docs.map(doc=>`<button class="document-issue" data-go="c:doc:${encodeURIComponent(doc)}">${html(doc)}</button>`).join('')+'</section>'+h;
    }

    return { html: h, click: {}, crumbs: [[ui("전체 코드 맵"), "c:"]].concat(sel ? [[nodeName(sel), "c:@" + sel]] : []),
             list: [], title: ui("지적"), units: sel ? unitsUnder(sel) : [], plan: true, sel, focusKey: selectedModule, populateVariables: methodVariables, populateModule: moduleFrame,
             problems: sel ? [] : bypass.map(x => ({ kind: "I1", k: x })).concat(Array.from(noImpl).map(i => ({ kind: "I2", i })))
               .concat(D.finds.map((f, k) => k).filter(k => D.finds[k][0] === "I3" || D.finds[k][0] === "I4").map(k => ({ kind: D.finds[k][0], f: k }))),
             extra: ui("문서 변경 ") + planUnits.length + ui(" · 설명 글 ") + proseUnits.length + ui(" · I1 인터페이스 우회 ") + bypass.length + ui(" · I2 구현 없는 인터페이스 ") + noImpl.size
               + ui(" · I3 인터페이스 없는 폴더 경계 ") + D.finds.filter(f => f[0] === "I3").length + ui(" · I4 파이프라인 위반 ") + D.finds.filter(f => f[0] === "I4").length };
  }

  // 코드 2: 모듈 — 인터페이스(C# 인터페이스·밖에서 쓰는 형)와 클래스, 쓰는 다른 모듈
  function codeModule(key) {
    const only = $("onlyProblems").checked, all = $("allEdges").checked;
    const lines = ["flowchart LR"], click = {}, styles = [], links = [];
    const ghost = key.startsWith("gm");
    const m = ghost ? -1 : +key.slice(1);
    const ts = ghost ? [] : typesOfMod[m];
    const users = new Map();   // 형 → 다른 모듈 → {n, names, bad}
    const extMods = new Set();
    ts.forEach(t => {
      const u = new Map();
      inside(t).forEach(i => inE[i].forEach(k => {
        const e = D.edges[k], fm = modOfDecl(e[0]); if (fm === m) return;
        const x = u.get(fm) || { n: 0, names: new Set(), bad: 0 }; x.n++; if (i !== t) x.names.add(D.decls[i][0]); if (bypassEdge.has(k)) x.bad++; u.set(fm, x); extMods.add(fm);
      }));
      users.set(t, u);
    });
    const ifaces = ts.filter(t => D.decls[t][1] === "interface");
    const exposed = ts.filter(t => D.decls[t][1] !== "interface" && users.get(t).size);
    const rest = ts.filter(t => D.decls[t][1] !== "interface" && !users.get(t).size);
    const gts = G.types.map((g, i) => i).filter(i => G.types[i].modKey === key);
    const problemT = (t) => visible(findsUnder(t)).length || unitsUnder("t" + t).length || noImpl.has(t) || Array.from(users.get(t).values()).some(x => x.bad);
    const keepT = (t) => !only || problemT(t);
    const label = (t) => {
      const ks = visible(findsUnder(t)), d = D.decls[t];
      let s = esc(planTag("t" + t)) + esc(typeTitle(t));
      if (d[1] === "interface") s += ui("<br/>멤버 ") + esc(clip(members[t].map(k => D.decls[k][0]).join(", "), 60)) + ui("<br/>구현 ") + implementers[t].length + (noImpl.has(t) ? ui(" · I2 구현 없음") : "");
      else {
        const u = users.get(t), names = new Set(); let bad = 0; u.forEach(x => { x.names.forEach(nm => names.add(nm)); bad += x.bad; });
        if (u.size) s += ui("<br/>밖에서 쓰는 멤버 ") + esc(clip(Array.from(names).join(", "), 60));
        s += ui("<br/>메서드 ") + members[t].filter(k => METHOD_KINDS.has(D.decls[k][1])).length + ui(" · 변수 ") + members[t].filter(k => VAR_KINDS.has(D.decls[k][1])).length;
        if (implOf[t].length) s += ui("<br/>구현 ") + esc(clip(implOf[t].map(I => D.decls[I][0]).join(", "), 50));
        if (bad) s += ui("<br/>I1 우회 ") + bad;
      }
      if (ks.length) s += ui("<br/>지적 ") + esc(tally(ks));
      return s + planLine("t" + t);
    };
    const sev = (t) => { const w = worst(visible(findsUnder(t))); const bad = Array.from(users.get(t).values()).some(x => x.bad); return bad ? Math.max(3, w) : noImpl.has(t) ? Math.max(2, w) : w; };
    const title = ghost ? ui("[코드 없음] ") + (G.mods[+key.slice(2)].folder || "(루트)") : D.mods[m][0] || "(루트)";
    lines.push(`${ui("subgraph MI[\"인터페이스 — ")}${esc(title)}"]`, "direction TB");
    ifaces.concat(exposed).filter(keepT).forEach(t => { lines.push(`t${t}["${label(t)}"]:::s${sev(t)}`); click["t" + t] = codeClick("t" + t); styles.push(...planStyle("t" + t, "t" + t)); });
    lines.push("end", ui("subgraph MC[\"클래스\"]"), "direction TB");
    rest.filter(keepT).forEach(t => { lines.push(`t${t}["${label(t)}"]:::s${sev(t)}`); click["t" + t] = codeClick("t" + t); styles.push(...planStyle("t" + t, "t" + t)); });
    gts.forEach(g => { lines.push(`gt${g}${ui("[\"[코드 없음] ")}${esc(G.types[g].kind)} ${esc(G.types[g].name)}<br/>${esc(G.types[g].rel.split("/").pop())}${planLine("gt" + g)}"]:::gn`); click["gt" + g] = codeClick("gt" + g); styles.push(...planStyle("gt" + g, "gt" + g)); });
    lines.push("end");
    const shownT = new Set(ifaces.concat(exposed, rest).filter(keepT));
    let n = 0;
    // 쓰는 다른 모듈 → 인터페이스·형
    extMods.forEach(fm => {
      let any = false;
      users.forEach((u, t) => { const x = u.get(fm); if (!x || !shownT.has(t)) return; if (only && !x.bad && !all) return; any = true; links.push(`x${fm} -->|"${x.bad ? ui("I1 우회 ") + x.bad : x.n}"| t${t}`); styles.push(`linkStyle ${n} stroke:${x.bad ? "#c62828" : "#0969da"},stroke-width:${x.bad ? 3 : 1}px`); n++; });
      if (any) { lines.push(`x${fm}["→ ${esc(modName(fm))}${ui("<br/>계층 ")}${esc(D.layers[D.mods[fm][1]])}"]:::ext`); click["x" + fm] = codeClick("m" + fm); }
    });
    // 구현·상속
    const extI = new Set();
    shownT.forEach(t => {
      implOf[t].forEach(I => { if (!shownT.has(I)) extI.add(I); links.push(`t${t}${ui(" -.->|구현| ")}${shownT.has(I) ? "t" : "i"}${I}`); n++; });
      const b = baseOf[t]; if (b >= 0) { if (!shownT.has(b)) extI.add(b); links.push(`t${t}${ui(" -->|상속| ")}${shownT.has(b) ? "t" : "i"}${b}`); n++; }
    });
    extI.forEach(I => { lines.push(`i${I}["${esc(typeTitle(I))}<br/>${esc(modName(modOfDecl(I)))}"]:::ext`); click["i" + I] = codeClick("t" + I); });
    const list = []; if (!ghost) D.files.forEach((f, fi) => { if (f[1] === m) (findsByFile.get(fi) || []).forEach(k => list.push(k)); });
    const probs = bypass.filter(x => modOfDecl(x.to) === m || modOfDecl(x.from) === m).map(x => ({ kind: "I1", k: x })).concat(ifaces.filter(t => noImpl.has(t)).map(i => ({ kind: "I2", i })))
      .concat(modFolderFinds(m).filter(k => D.finds[k][0] === "I3").map(k => ({ kind: "I3", f: k })))
      .concat((modFinds[m] || []).filter(k => D.finds[k][0] === "I4").map(k => ({ kind: "I4", f: k })));
    return { text: lines.concat(links, grid(Array.from(shownT).map(t => "t" + t), colsFor(shownT.size, 260)), CLASSDEF, styles).join("\n"), click,
             crumbs: [[ui("전체 코드 맵"), "c:"], [title, codeClick(key)]], list, title: ui("모듈 지적"), units: unitsUnder(key), unitMode: "full", problems: probs,
             extra: ui("인터페이스 ") + ifaces.length + ui(" · 밖에서 쓰는 형 ") + exposed.length + ui(" · 클래스 ") + rest.length + (gts.length ? ui(" · 코드 없는 형 ") + gts.length : "") };
  }

  // 코드 3: 클래스 — 메서드·변수, 메서드 → 변수 읽기·쓰기, 메서드 → 메서드 호출, 구현·상속
  function codeType(key) {
    const only = $("onlyProblems").checked, all = $("allEdges").checked;
    const lines = ["flowchart TB"], click = {}, styles = [], links = [];
    const ghost = key.startsWith("gt"), t = ghost ? -1 : +key.slice(1);
    const own = ghost ? [] : members[t];
    const meths = own.filter(i => METHOD_KINDS.has(D.decls[i][1])), vars = own.filter(i => VAR_KINDS.has(D.decls[i][1])), nested = own.filter(i => isType(i));
    const gms = G.mems.map((g, i) => i).filter(i => G.mems[i].typeKey === key);
    const keep = (i) => !only || visible(findsByDecl.get(i) || []).length || unitsUnder("d" + i).length;
    const node = (i, text) => { const ks = visible(findsByDecl.get(i) || []); lines.push(`d${i}["${esc(planTag("d" + i))}${esc(text)}<br/>L${D.decls[i][3]}${ks.length ? " · " + esc(tally(ks)) : ""}${planLine("d" + i)}"]:::s${worst(ks)}`); click["d" + i] = codeClick("d" + i); styles.push(...planStyle("d" + i, "d" + i)); };
    const ghostNode = (g) => { const x = G.mems[g]; lines.push(`gd${g}["[${esc(((U[unitsAt("gd" + g)[0]] || {}).plan || {}).action || "신규")}] ${esc(clip(x.sig || x.name, 80))}${planLine("gd" + g)}"]:::gn`); click["gd" + g] = codeClick("gd" + g); styles.push(...planStyle("gd" + g, "gd" + g)); };
    const title = ghost ? ui("[코드 없음] ") + G.types[+key.slice(2)].name : typeTitle(t) + " · " + D.files[D.decls[t][2]][0];
    if (!ghost) {
      implOf[t].forEach(I => { lines.push(`i${I}${ui("[\"구현 ")}${esc(typeTitle(I))}"]:::ext`); click["i" + I] = codeClick("t" + I); });
      if (baseOf[t] >= 0) { const b = baseOf[t]; lines.push(`i${b}${ui("[\"상속 ")}${esc(typeTitle(b))}"]:::ext`); click["i" + b] = codeClick("t" + b); }
    }
    lines.push(`subgraph TT["${esc(title)}${!ghost && outerBases[t].length ? ui(" · 밖의 조상 ") + esc(clip(outerBases[t].join(", "), 60)) : ""}"]`, "direction LR");
    lines.push(ui("subgraph TF[\"메서드\"]"), "direction TB");
    meths.filter(keep).forEach(i => node(i, clip(sigOf(i), 90)));
    gms.filter(g => METHOD_KINDS.has(G.mems[g].kind) || !VAR_KINDS.has(G.mems[g].kind)).forEach(ghostNode);
    lines.push("end", ui("subgraph TV[\"변수\"]"), "direction TB");
    vars.filter(keep).forEach(i => node(i, clip(varLabel(i), 80)));
    gms.filter(g => VAR_KINDS.has(G.mems[g].kind)).forEach(ghostNode);
    lines.push("end");
    if (nested.length) { lines.push(ui("subgraph TN[\"안의 형\"]"), "direction TB"); nested.forEach(i => { lines.push(`d${i}["${esc(typeTitle(i))}${planLine("t" + i)}"]:::s${worst(visible(findsUnder(i)))}`); click["d" + i] = codeClick("t" + i); }); lines.push("end"); }
    lines.push("end");
    let n = 0;
    if (!ghost) {
      implOf[t].forEach(I => { links.push(`${ui("TT -.->|구현| i")}${I}`); n++; });
      if (baseOf[t] >= 0) { links.push(`${ui("TT -->|상속| i")}${baseOf[t]}`); n++; }
      const mine = new Set(meths.concat(vars).filter(keep));
      const dense = own.length > 60 && !all;
      if (!dense) meths.forEach(i => { if (!mine.has(i)) return; outE[i].forEach(k => { const e = D.edges[k]; if (!mine.has(e[1]) || e[1] === i) return;
        const v = VAR_KINDS.has(D.decls[e[1]][1]);
        links.push(`d${i} ${v ? (e[2] ? "==>" : "-->") : "-.->"} d${e[1]}`);
        if (v && e[2]) styles.push(`linkStyle ${n} stroke:#d35400,stroke-width:3px`); n++; }); });
    }
    const list = ghost ? [] : findsUnder(t);
    const probs = ghost ? [] : bypass.filter(x => x.t === t).map(x => ({ kind: "I1", k: x })).concat(noImpl.has(t) ? [{ kind: "I2", i: t }] : []);
    const mk = ghost ? G.types[+key.slice(2)].modKey : "m" + modOfDecl(t);
    const mt = mk.startsWith("gm") ? ui("[코드 없음] ") + G.mods[+mk.slice(2)].folder : D.mods[+mk.slice(1)][0];
    return { text: lines.concat(links, CLASSDEF, styles).join("\n"), click, crumbs: [[ui("전체 코드 맵"), "c:"], [mt || "(루트)", codeClick(mk)], [ghost ? G.types[+key.slice(2)].name : declName(t), codeClick(key)]],
             list, title: ui("클래스 지적"), units: unitsUnder(key), unitMode: "full", problems: probs,
             extra: ui("메서드 ") + meths.length + ui(" · 변수 ") + vars.length + (gms.length ? ui(" · 코드 없는 멤버 ") + gms.length : "") + (own.length > 60 && !all ? ui(" · 멤버가 많아 참조선은 '모든 참조선'으로 켠다") : ui(" · 실선 = 읽기, 굵은 주황 = 쓰기, 점선 = 호출")) };
  }

  // 코드 4·5: 메서드(부르는 쪽·부르는 대상·읽고 쓰는 변수) · 변수(읽는 쪽·쓰는 쪽)
  function codeMember(key) {
    const lines = ["flowchart LR"], click = {}, styles = [], links = [];
    if (key.startsWith("gd")) {
      const g = G.mems[+key.slice(2)];
      lines.push(`gd${key.slice(2)}${ui("[\"[코드 없음] ")}${esc(clip(g.sig || g.name, 100))}"]:::gn`);
      const tk = g.typeKey;
      return { text: lines.concat(CLASSDEF).join("\n"), click, crumbs: [[ui("전체 코드 맵"), "c:"], [tk.startsWith("gt") ? G.types[+tk.slice(2)].name : declName(+tk.slice(1)), codeClick(tk)], [g.name, codeClick(key)]],
               list: [], title: ui("지적"), units: unitsUnder(key), unitMode: "full", problems: [], extra: ui("문서에 선언됐으나 코드에 없는 멤버") };
    }
    const i = +key.slice(1), d = D.decls[i], isVar = VAR_KINDS.has(d[1]);
    const ks = visible(findsByDecl.get(i) || []);
    lines.push(`c${i}["${esc(planTag(key))}${esc(clip(isVar ? varLabel(i) : sigOf(i), 110))}<br/>${esc(D.files[d[2]][0].split("/").pop())}:${d[3]}${ks.length ? "<br/>" + esc(tally(ks)) : ""}${planLine(key)}"]:::s${worst(ks)}`);
    styles.push(...planStyle("c" + i, key));
    const name = (j) => (owner[j] !== j && owner[j] !== owner[i] ? D.decls[owner[j]][0] + "." : "") + D.decls[j][0];
    let n = 0; const seen = new Set();
    const add = (j, text, cls) => { if (seen.has(j)) return; seen.add(j); lines.push(`d${j}["${esc(clip(text, 80))}"]${cls}`); click["d" + j] = codeClick(VAR_KINDS.has(D.decls[j][1]) || METHOD_KINDS.has(D.decls[j][1]) ? "d" + j : "t" + j); };
    inE[i].slice(0, 60).forEach(k => { const e = D.edges[k], j = e[0]; add(j, name(j), modOfDecl(j) !== modOfDecl(i) ? ":::ext" : ""); links.push(`d${j} ${isVar && e[2] ? ui("==>|쓰기|") : isVar ? ui("-->|읽기|") : ui("-.->|부름|")} c${i}`); styles.push(`linkStyle ${n} stroke:${bypassEdge.has(k) ? "#c62828" : isVar && e[2] ? "#d35400" : "#0969da"},stroke-width:${bypassEdge.has(k) || e[2] ? 3 : 1}px`); n++; });
    if (!isVar) outE[i].slice(0, 80).forEach(k => { const e = D.edges[k], j = e[1]; if (isType(j)) return; const v = VAR_KINDS.has(D.decls[j][1]); add(j, v ? name(j) + (typeText(j) ? " : " + typeText(j) : "") : name(j), modOfDecl(j) !== modOfDecl(i) ? ":::ext" : "");
      links.push(`c${i} ${v ? (e[2] ? ui("==>|쓰기|") : ui("-->|읽기|")) : ui("-.->|부름|")} d${j}`); styles.push(`linkStyle ${n} stroke:${bypassEdge.has(k) ? "#c62828" : v && e[2] ? "#d35400" : "#0969da"},stroke-width:${bypassEdge.has(k) || e[2] ? 3 : 1}px`); n++; });
    const t = owner[i], mk = "m" + modOfDecl(i);
    const probs = bypass.filter(x => x.to === i || x.from === i).map(x => ({ kind: "I1", k: x }));
    return { text: lines.concat(links, CLASSDEF, styles).join("\n"), click,
             crumbs: [[ui("전체 코드 맵"), "c:"], [D.mods[modOfDecl(i)][0] || "(루트)", codeClick(mk)], [declName(t), codeClick("t" + t)], [d[0], codeClick(key)]],
             list: (findsByDecl.get(i) || []).slice(), title: (isVar ? ui("변수") : ui("메서드")) + ui(" 지적"), units: unitsUnder(key), unitMode: "full", problems: probs,
             extra: isVar ? ui("읽는 쪽 · 쓰는 쪽(굵은 주황)") : ui("부르는 쪽(왼쪽) → 이 메서드 → 부르는 대상·읽고 쓰는 변수(오른쪽). 빨강 = I1 인터페이스 우회") };
  }

  // 코드 0: 계획 맵(첫 화면, 2.9.1) — 문서가 고치겠다고 한 인터페이스·클래스·메서드·변수·파일만. 마디를 누르면 곁 맨 위에 맞음·틀림
  let planUnits = U.map((u, k) => k).filter(k => ((U[k].plan || {}).action || "글") !== "글" && chainOf[k].length);
  let planSet = new Set(planUnits);
  let proseUnits = U.map((u, k) => k).filter(k => !planSet.has(k));
  const nodeName = (key) => {
    if (key.startsWith("gm")) return ui("[코드 없음] ") + (G.mods[+key.slice(2)].folder || "(루트)");
    if (key.startsWith("m")) return D.mods[+key.slice(1)][0] || "(루트)";
    if (key.startsWith("gt")) return G.types[+key.slice(2)].kind + " " + G.types[+key.slice(2)].name;
    if (key.startsWith("t")) return typeTitle(+key.slice(1));
    if (key.startsWith("gd")) return G.mems[+key.slice(2)].name;
    return declName(+key.slice(1));
  };
  const planText = (k) => {
    const p = U[k].plan || {}, kind = p.table === "scope" ? ui("파일") : p.table === "changes" ? ui("변경(") + (p.state_new || p.state_old) + ")" : (p.kind || "");
    const what = p.table === "scope" || (p.table === "changes" && (!p.sig_new || p.sig_new === "-") && (!p.sig_old || p.sig_old === "-")) ? p.file.split("/").pop() : (p.sig_old && p.sig_new && p.sig_old !== p.sig_new ? p.sig_old + " → " + p.sig_new : (p.sig_new || p.sig_old || p.name || ""));
    const body = what.replace(TRIM, "");
    const hasKind = p.table === "scope" || p.table === "changes" ? false : /\(|^(def|class|struct|interface|enum|record|delegate)\b/.test(body);
    return "[" + p.action + "] " + (hasKind ? "" : kind + " ") + clip(body, 150);
  };
  function implementationFindingIndices(item) {
    return (D.finds || []).map((f,k)=>k).filter(k=>{
      const f=D.finds[k];
      return item.sources.some(s=>s.doc===f[1] && s.line===f[2]) ||
        f[1]===item.plan.file && (item.code || []).some(block=>f[2]>=block.line && f[2]<=block.end);
    });
  }
  function implementationLabel(items) {
    const codes = new Set(items.flatMap(implementationFindingIndices).map(k=>D.finds[k][0]));
    const labels = [];
    if (codes.has('W8')) labels.push(ui("미구현"));
    if (codes.has('W12')) labels.push(ui("검증 미완료"));
    return labels.join('·') || (codes.size ? ui("지적") : ui("구현 확인 필요"));
  }
  function plannedCodeHtml(v) {
    if (!v.implementation || !v.view.startsWith("c:")) return "";
    const key = (v.sel || v.view.slice(2)).replace(/^@/, "");
    const all = !key || key === "all";
    const selected = (D.implementationPlans || []).filter(item => all || chainFor(item).includes(key));
    if (!selected.length) return "";
    return `${ui("<section class=\"planned-code\"><h3>미구현·검증 미완료 — ")}${selected.length}${ui("곳</h3><div class=\"note\">문서 계약과 현재 코드의 미해결 지적입니다. 지적 사유와 대조 기준, 해당 코드 본문을 함께 표시합니다.</div>")}` + selected.map((item, index) => {
      const p = item.plan;
      const behaviors = p.behaviors || (p.behavior ? [p.behavior] : []);
      const label = `<span class="chip c1">${html(implementationLabel([item]))}</span> <b>${html(p.sig || p.name || p.file)}</b>${behaviors.length ? ' · ' + html(behaviors.join(' · ')) : ''}`;
      let h = all ? `<details class="unit planned-target" data-key="planned:${index}"${index < 3 ? ' open' : ''}><summary class="head">${label}</summary>` : `<article class="unit planned-target"><div class="head">${label}</div>`;
      h += `<div class="where">${html(p.file)}</div>`;
      h += `<div class="note">${html(item.status || '')}</div>`;
      if (item.basisId) h += `${ui("<div class=\"note\">승인본 기준 ")}${html(item.basisId)}<br/>${item.sources.map(s => html(s.doc) + ':' + s.line + ' · SHA256 ' + html((item.documentHashes || {})[s.doc] || '')).join('<br/>')}</div>`;
      const related=implementationFindingIndices(item).filter(k=>['W8','W12'].includes(D.finds[k][0]));
      h += related.map(k=>{const f=D.finds[k];return `<div class="find" data-k="${k}"><span class="chip c${SEV(f[0])}">${html(f[0])}</span> <span class="where">${html(f[1])}:${f[2]}</span><div class="msg">${html(localizedFinding(f[1], f[2], f[3]))}</div></div>`;}).join('');
      h += ui("<div class=\"target\"><b>대조 기준 · 문서 계약</b></div>") + item.sources.map(s => `<div class="note">${s.behavior ? '<b>' + html(s.behavior) + '</b> · ' : ''}${html(s.reason || '계약 설명 미등록')}<br/>${html(s.doc)}:${s.line} · ${html(s.state)}</div>`).join('');
      h += `<div class="target"><b>${html(item.codeStatus || '코드 본문 미제공')}</b></div>`;
      h += (item.code || []).map(block => '<pre class="diff planned-source">' + block.lines.map((line, i) => `<div class="planned-line"><span class="where">${block.line+i}</span>  ${html(line)}</div>`).join('') + '</pre>').join('');
      if (!(item.code || []).length) h += `<pre class="diff">${html(p.sig_new || p.sig || p.name || p.file)}</pre>`;
      return h + (all ? '</details>' : '</article>');
    }).join('') + '</section>';
  }
  function comparisonSide(v) {
    const C = D.comparison || {}, scope = C.scope || {changes:[],requests:[]};
    let h = plannedCodeHtml(v) + ui("<h2>문서 반영 진행 상태</h2>");
    h += `${ui("<div class=\"sel\">전체 미해결 ")}${totalText}${ui(" · 표시 판 지적 발생 ")}${D.finds.length}${ui("건 · 재검사 대기 ")}${whole.awaitingRecheck || 0}${ui("건 · 해소 ")}${C.resolvedCount || 0}${ui("건</div>")}`;
    h += ui("<div class=\"note\">선언 누락·문서 불일치·코드 품질·구조·규칙·승인·파싱 지적을 모두 미해결에 포함합니다.</div>");
    if ((C.validation || []).length) h += `${ui("<details><summary>지적 발생 건수에 포함된 대조 차단 오류 ")}${C.validation.length}${ui("건 — 펼쳐 보기</summary>")}` + C.validation.map(f => `<div class="find">${html(f.code)} · ${html(f.file)}:${f.line} ${html(f.message)}</div>`).join('') + '</details>';
    if (C.blocked) h += ui("<div class=\"note\">문서 형식·파싱 문제로 코드 대조가 완료되지 않았습니다. 이전 지적은 해소로 계산하지 않습니다.</div>");
    h += `${ui("<h2>코드 유지 검사</h2><div class=\"sel\">기준 ")}${html(scope.started || "확인 중")}${ui(" · 감시 코드 ")}${scope.tracked || 0}${ui("개<br/>")}${scope.unchanged ? ui("코드 변경 없음 — 문서만 수정 중") : ui("코드 변경 ") + (scope.changes || []).length + ui("개 · 허용되지 않은 변경 ") + (scope.violations || 0) + ui("개")}</div>`;
    const permittedChanges = (scope.changes || []).filter(change => change.permitted);
    const violatingChanges = (scope.changes || []).filter(change => !change.permitted);
    const changeRow = change => `<div class="find"><span class="chip ${change.permitted ? "ct" : "cd"}">${change.permitted ? ui("허용된 변경") : ui("작업 범위 위반")}</span> ${html(change.change)} · ${html(change.file)}</div>`;
    h += violatingChanges.map(changeRow).join('');
    if (permittedChanges.length) h += `${ui("<details><summary>허용된 수정 ")}${permittedChanges.length}${ui("건 — 전체 펼쳐 보기</summary>")}${permittedChanges.map(changeRow).join('')}</details>`;
    const pending = (scope.requests || []).filter(r => r.status === "pending");
    if (pending.length) h += `${ui("<h2>코드 수정 수락 요청 ")}${pending.length}${ui("건</h2>")}`;
    pending.forEach(request => {
      h += `<div class="unit"><b>${html(request.file)}</b><div class="note">${html(request.reason)}</div>`;
      if (window.MAP_LIVE) h += `<div class="checks"><button data-request="${request.id}${ui("\" data-accept=\"true\">이 코드 수정 수락</button><button data-request=\"")}${request.id}${ui("\" data-accept=\"false\">거절</button></div>")}`;
      h += '</div>';
    });
    const key = (v.sel || v.view.slice(2)).replace(/^@/, "");
    const identity = (code,file,line,message) => JSON.stringify([code,file,line,message]);
    let related = null, files = null, span = null;
    if (/^m\d+$/.test(key)) {
      files = new Set(D.files.filter(f => f[1] === +key.slice(1)).map(f => f[0]));
      related = modFinds[+key.slice(1)] || [];
    } else if (/^t\d+$/.test(key)) { related = findsUnder(+key.slice(1)); span = D.decls[+key.slice(1)]; }
    else if (/^d\d+$/.test(key)) { related = findsByDecl.get(+key.slice(1)) || []; span = D.decls[+key.slice(1)]; }
    const identifiers = related && new Set(related.map(k => { const f = D.finds[k]; return identity(f[0],f[1],f[2],f[3]); }));
    const selectedSource = v.sourceSelection;
    const matches = item => selectedSource ?
      (selectedSource.folder !== undefined ? (!selectedSource.folder || item.file.startsWith(selectedSource.folder + '/')) :
       item.file === selectedSource.file && (!selectedSource.line || ((item.source || {}).line || item.line) >= selectedSource.line && ((item.source || {}).line || item.line) <= selectedSource.end)) :
      related === null || (files && files.has(item.file)) ||
      (span && item.file === D.files[span[2]][0] && item.line >= span[3] && item.line <= span[4]) ||
      identifiers.has(identity(item.code,item.file,item.line,item.message));
    if (selectedSource) h += `<div class="sel"><b>${html(selectedSource.signature || selectedSource.file || selectedSource.folder || '감시 코드')}${ui("</b> · 선택한 위치의 미해결</div>")}`;
    if (related !== null) h += `<div class="sel"><b>${html(nodeName(key))}${ui("</b> · 선택한 코드에 관련된 문서 지적</div>")}`;
    const items = (C.items || []).filter(matches).filter(item => !hidden.has(item.code));
    h += `<h2>${html(related === null ? ui("전체 위치의 필터 후 표시") : ui("선택한 위치의 필터 후 표시"))} ${items.length}${ui("건</h2>")}`;
    const symbolName = item => {
      const source = item.source || {};
      return [source.path && source.path !== "-" ? source.path : "",source.name].filter(Boolean).join(".");
    };
    const groupAtCode = list => {
      const groups = new Map();
      list.forEach(item => {
        const codeKey = JSON.stringify([item.file,(item.source || {}).line || item.line]);
        if (!groups.has(codeKey)) groups.set(codeKey,[]);
        groups.get(codeKey).push(item);
      });
      return [...groups.values()];
    };
    const groupHtml = group => {
      const first = group[0], source = first.source || {}, symbol = symbolName(first);
      const codeLine = source.line || Math.min(...group.map(item => item.line));
      const status = group.every(item => item.status === "해소") ? ui("해소") : group.some(item => item.status === "미해결") ? ui("미해결") : ui("재검사 대기");
      let text = `<div class="bundle unit" data-comparison="${html(first.key)}" data-code-file="${html(first.file)}" data-code-symbol="${html(symbol)}"><div class="head"><b>${html(symbol || source.signature || first.file.split("/").pop())}</b><br/><span class="where">${html(first.file)}:${codeLine}</span></div>`;
      text += `<div class="target"><span class="chip ${status === "해소" ? "ct" : "cw"}">${html(status)}${ui("</span> 지적 ")}${group.length}${ui("건</div>")}`;
      const row = (kind,mark,content) => `<div class="${kind}"><span class="cb">${mark}</span><span class="rl">${content}</span></div>`;
      text += '<div class="diff">' + row('ctx','', ui("<b>코드 · 현재 기준</b>"));
      const signatures = [...new Set(group.map(item => {const s=item.source || {};return s.signature || s.text;}).filter(Boolean))];
      signatures.forEach(signature => text += row('ins','+',html(signature)));
      text += '</div>';
      const documents = new Map(), unlinked = [];
      group.forEach(item => {
        if (!item.documents.length) unlinked.push(item);
        item.documents.forEach(doc => {
          if (!documents.has(doc.file)) documents.set(doc.file,{locations:new Map(),items:new Map()});
          const target = documents.get(doc.file);
          target.locations.set(doc.line,doc); target.items.set(item.key,item);
        });
      });
      const issuesHtml = list => '<div class="diff">' + list.map(item => row('del','−',`<b>${html(item.code)}</b> · ${html(item.message)}`)).join('') + '</div>';
      text += `${ui("<div class=\"target\"><b>대응 문서 ")}${documents.size ? documents.size + ui("개") : ui("없음")}</b></div>`;
      documents.forEach((doc,file) => {
        text += `<div class="unit" data-document="${html(file)}"><div class="head"><b>${html(file)}</b></div><div class="diff">`;
        [...doc.locations.values()].sort((a,b)=>a.line-b.line).forEach(location => {
          text += row('ctx','',`L${location.line}${location.precise ? "" : ui(" · 관련 파일의 등록 위치")}`);
          if (location.text) text += row('ctx','',html(location.text));
        });
        text += ui("</div><div class=\"target\"><b>이 문서의 누락·차이</b></div>") + issuesHtml([...doc.items.values()]) + '</div>';
      });
      if (unlinked.length) text += ui("<div class=\"unit\"><div class=\"head\"><b>대응 문서가 없는 지적</b></div>") + issuesHtml(unlinked) + '</div>';
      return text + '</div>';
    };
    const groups = groupAtCode(items);
    h += `${ui("<div class=\"note\">코드 위치 ")}${groups.length}${ui("곳 · 지적 ")}${items.length}${ui("건. 같은 코드 위치의 지적과 대응 문서를 한 카드로 묶었습니다.</div>")}`;
    h += '<div id="comparison-items">' + groups.slice(0,100).map(groupHtml).join('') + '</div>';
    if (groups.length > 100) h += `${ui("<button id=\"comparison-more\">다음 100곳 보기 (100 / ")}${groups.length})</button>`;
    const resolved = groupAtCode((C.resolved || []).filter(matches));
    if (resolved.length) h += `${ui("<details id=\"resolved-details\"><summary>해소된 코드 위치 ")}${resolved.length}${ui("곳</summary><div class=\"resolved-items\"></div></details>")}`;
    patchHtml($("side"), h);
    const resolvedDetails = $("resolved-details");
    if (resolvedDetails) resolvedDetails.ontoggle = async () => {
      if (!resolvedDetails.open || resolvedDetails.dataset.loading || resolvedDetails.dataset.loaded) return;
      resolvedDetails.dataset.loading = "true";
      const content = resolvedDetails.querySelector(".resolved-items");
      content.textContent = ui("해소 내역 불러오는 중…");
      try {
        if (C.resolvedDeferred) {
          const response = await fetch("/comparison");
          if (!response.ok) throw new Error(ui("해소 내역을 불러오지 못했습니다."));
          const fresh = await response.json();
          if (fresh.rev !== D.rev) throw new Error(ui("판정이 갱신되었습니다. 최신 화면에서 다시 펼쳐 주세요."));
          C.resolved = fresh.resolved || []; C.resolvedDeferred = false;
        }
        const rows = groupAtCode(C.resolved.filter(matches));
        content.innerHTML = rows.slice(-100).map(groupHtml).join('');
        resolvedDetails.dataset.loaded = "true";
      } catch (error) { content.textContent = error.message; }
      finally { delete resolvedDetails.dataset.loading; }
    };
    const more = $("comparison-more");
    if (more) {
      let shown = 100;
      more.onclick = () => {
        const next = Math.min(shown + 100, groups.length);
        $("comparison-items").insertAdjacentHTML('beforeend', groups.slice(shown,next).map(groupHtml).join(''));
        shown = next;
        if (shown === groups.length) more.remove();
        else more.textContent = `${ui("다음 100곳 보기 (")}${shown} / ${groups.length})`;
      };
    }
    $("side").querySelectorAll("button[data-request]").forEach(button => button.onclick = async () => {
      button.disabled = true;
      try {
        const response = await fetch('/workflow/decision',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:button.dataset.request,accept:button.dataset.accept === 'true'})});
        const result = await response.json(); if (!response.ok) throw new Error(result.error);
        $("status").textContent = result.status === 'approved' ? ui("이 편집 요청만 수락했습니다. 에이전트가 재시도하면 한 번 허용됩니다.") : ui("코드 수정 요청을 거절했습니다.");
      } catch(error) { failed(error.message); button.disabled = false; }
    });
  }
  function codeView(rest) {
    if(/^dm\d+$/.test(rest))return {...codeAll('m'+rest.slice(2)),documentScope:true,documentModule:+rest.slice(2)};
    if(rest==='docs'||rest.startsWith('doc:')) return {...codeAll(null),documentScope:true,documentPath:rest.startsWith('doc:')?rest.slice(4):'',crumbs:[[ui("전체 코드 맵"),'c:'],[ui("문서 분리"),'c:docs']]};
    if (!rest || rest === "all") return codeAll(null);
    if (rest.startsWith("@")) return codeAll(rest.slice(1));
    if (rest.startsWith("m") || rest.startsWith("gm")) return codeModule(rest);
    if (rest.startsWith("t") || rest.startsWith("gt")) return codeType(rest);
    return codeMember(rest);
  }

  function documentReviewView(doc) {
    const counts = new Map();
    U.forEach(u => counts.set(u.doc, (counts.get(u.doc) || 0) + 1));
    const docs = [...counts.keys()].sort();
    const folder = doc && doc.endsWith('/') ? doc : '';
    const units = U.map((u,k) => k).filter(k => !doc || (folder ? U[k].doc.startsWith(folder) : U[k].doc === doc));
    const documentCount = new Set(units.map(k=>U[k].doc)).size;
    const root = {folders:new Map(), docs:[], count:U.length, documents:docs.length};
    docs.forEach(path=>{
      const parts=path.split('/'); let branch=root, prefix='';
      parts.slice(0,-1).forEach(name=>{
        prefix+=name+'/';
        if(!branch.folders.has(name)) branch.folders.set(name,{path:prefix,folders:new Map(),docs:[],count:0,documents:0});
        branch=branch.folders.get(name); branch.count+=counts.get(path); branch.documents++;
      });
      branch.docs.push(path);
    });
    const select = (path,label,count,documents,isFolder) => `<button type="button" class="review-select" data-go="review${path?':'+html(path):''}"${isFolder?'':` data-review-doc="${html(path)}"`}${(doc||'')===path?' aria-current="page"':''}><b>${html(label)}</b><span class="review-count">${isFolder?documents+ui("문서 · "):''}${count}${ui("줄</span></button>")}`;
    const branchHtml = (branch,depth) => '<ul>'+[...branch.folders].map(([name,child])=>
      `<li><details class="review-folder" data-review-folder="${html(child.path)}"${depth<2||(doc||'').startsWith(child.path)?' open':''}><summary>${select(child.path,name,child.count,child.documents,true)}</summary>${branchHtml(child,depth+1)}</details></li>`).join('')+
      branch.docs.map(path=>`<li>${select(path,path.split('/').pop(),counts.get(path),1,false)}</li>`).join('')+'</ul>';
    return {review:true, list:[], units, title:ui("문서 변경 검토"),
      reviewFolder:folder, reviewDoc:folder?'':doc||'', documentCount,
      crumbs:[[ui("문서 변경 검토"),'review'], ...(doc ? [[doc,'review:'+doc]] : [])],
      html:ui("<div class=\"note\">폴더를 선택하면 모든 하위 폴더의 문서 변경을 재귀적으로 모읍니다. 우측 ‘하위 전체 승인’ 한 번으로 선택 범위를 처리합니다.</div><nav class=\"review-tree\" aria-label=\"문서 변경 폴더 트리\">")+
        select('',ui("전체 문서"),U.length,docs.length,true)+branchHtml(root,0)+'</nav>'};
  }

  function codeContext(v) {
    const key = (v.sel || v.view.slice(2)).replace(/^@/, ''), all = !key || key === 'all';
    const plans = (D.implementationPlans || []).filter(p => all || chainFor(p).includes(key));
    let list = v.list || [];
    if(v.documentScope) list=v.documentModule!==undefined ? documentFindsByModule[v.documentModule]||[] : D.finds.map((f,k)=>k).filter(k=>/^규칙 DOC22\s/.test(D.finds[k][3])&&(!v.documentPath||D.finds[k][1]===v.documentPath));
    else if (all) list = D.finds.map((f,k)=>k);
    else if (/^m\d+$/.test(key)) list = modFinds[+key.slice(1)] || [];
    else if (/^t\d+$/.test(key)) list = findsUnder(+key.slice(1));
    else if (/^d\d+$/.test(key)) list = findsByDecl.get(+key.slice(1)) || [];
    const sources = plans.flatMap(p=>p.sources);
    const units = U.map((u,k)=>k).filter(k => all || chainOf[k].includes(key) || sources.some(s => {
      const u=U[k]; return u.doc===s.doc && s.line>=u.new_line && s.line<u.new_line+Math.max(1,(u.new||'').split('\n').length);
    }));
    return {...v, list:[...new Set([...list,...plans.flatMap(implementationFindingIndices)])], units, plans, allTargets:all, plan:false, review:true, codePanel:true};
  }

  function codeSummary(v) {
    const total=v.list.length, shown=v.list.filter(k=>!hidden.has(D.finds[k][0])).length;
    return `<section class="code-summary"><h2>${v.allTargets?ui("전체"):ui("선택 대상")}${ui(" 요약</h2>")}` +
      (D.executionBasis ? `${ui("<div class=\"small\">승인 실행 기준 ")}${html(D.executionBasis.id)} · ${html(D.executionBasis.status)}</div>` : '') +
      `<div class="summary-states"><b class="chip ${'c'+worst(v.list)}" data-issue-count="${total}">${total?ui("지적 있음 · ")+total+ui("건"):ui("지적 없음")}</b>` +
      (v.units.length || v.implementation ? '' : ui("<span class=\"small\">문서 변경 없음</span>")) + '</div>' +
      (shown!==total?`${ui("<div class=\"note\">필터 표시 ")}${shown}${ui("건 / 전체 지적 ")}${total}${ui("건</div>")}`:'') +
      (v.allTargets && D.prioritySummary ? `${ui("<div class=\"small\">현재 판정: 원 발생 ")}${D.prioritySummary.occurrences}${ui("건 · 고유 지적 ")}${D.prioritySummary.uniqueFindings}${ui("건 · 작업 묶음 ")}${D.prioritySummary.groupCount}${ui("개</div>")}` : '') +
      (v.allTargets && window.MAP_LIVE ? (D.priorityGroups||[]).filter(g=>g.uniqueFindings>1 && Boolean(v.implementation)===['W8','W12'].includes(g.code)).map(g=>`<details data-priority-group="${html(g.id)}"><summary>${html(g.behaviorId||g.code)} · ${g.uniqueFindings}${ui("개 지적 · ")}${g.occurrences}${ui("건 발생</summary><div class=\"group-findings\">펼치면 원 지적을 조회합니다.</div></details>")}`).join('') : '') +
      '</section>';
  }

  // 문서 변경 단위(2.12) — diff와 맞음·틀림
  const deepest = (k) => { const c = chainOf[k]; return c.length ? codeClick(c[c.length - 1]) : "c:"; };
  function wordsHtml(parts) { return parts.map(([s, t]) => s === "다름" ? "<b>" + html(t) + "</b>" : html(t)).join(""); }
  function unitHtml(k) {
    const u = U[k], p = u.plan || {}, act = p.action || "글";
    const kindChip = { "추가": "cn", "삭제": "cd", "수정": "cm" }[u.kind] || "ct";
    const actChip = { "신규": "cn", "수정": "cm", "삭제": "cd" }[act] || "ct";
    let h = `<div class="unit${u.verdict === "틀림" ? " wrong" : ""}" data-u="${k}"><div class="head"><span class="chip ${kindChip}">${html(u.kind)}</span> <span class="chip ${actChip}${ui("\">계획 ")}${html(act)}</span> ${u.verdict === "틀림" ? ui("<span class=\"chip cd\">틀림</span>") : ui("<span class=\"chip cw\">체크 대기</span>")}`;
    h += ` <span class="where">${html(u.doc)}:${u.new_line} · ${html(u.heading)}</span></div>`;
    if (p.table) h += `<div class="target">${html(p.table)} · ${html(p.file || "")}${p.path && p.path !== "-" ? " · " + html(p.path) : ""}${p.name ? " · " + html(p.name) : ""}${p.sig_old && p.sig_new && p.sig_old !== p.sig_new ? ui("<br/>시그니처 ") + html(p.sig_old) + " → " + html(p.sig_new) : ""}${p.state_old !== p.state_new && p.state_old && p.state_new ? ui("<br/>상태 ") + html(p.state_old) + " → " + html(p.state_new) : ""}</div>`;
    if (window.MAP_LIVE) h += `<div class="checks"><button class="ok" data-u="${k}${ui("\">맞음</button><button class=\"ng\" data-u=\"")}${k}${ui("\">틀림</button><input class=\"memo\" data-u=\"")}${k}${ui("\" placeholder=\"틀림 이유(한 줄)\" value=\"")}${html(u.memo || "")}"></div>`;
    else h += ui("<div class=\"note\">체크 단추는 실시간 지도(감시 서버 주소)에서 나온다</div>");
    h += '<pre class="diff">';
    u.before.forEach(x => h += `<div class="ctx">  ${html(x)}</div>`);
    if (u.kind === "수정" && u.words) { h += `<div class="del">- ${wordsHtml(u.words[0])}</div><div class="ins">+ ${wordsHtml(u.words[1])}</div>`; }
    else { if (u.old) h += `<div class="del">- ${html(u.old)}</div>`; if (u.new) h += `<div class="ins">+ ${html(u.new)}</div>`; }
    u.after.forEach(x => h += `<div class="ctx">  ${html(x)}</div>`);
    h += "</pre>";
    if (u.verdict === "틀림") h += `${ui("<div class=\"note\">틀림 이유: ")}${html(u.memo || "-")}</div>`;
    return h + "</div>";
  }
  function unitLine(k) {
    const u = U[k], p = u.plan || {};
    return `<div class="uline" data-go="${html(deepest(k))}"><span class="chip ${u.verdict === "틀림" ? "cd" : "cw"}">${u.verdict === "틀림" ? ui("틀림") : ui("대기")}</span> ${html(u.kind)}${ui(" · 계획 ")}${html(p.action || "글")} · L${u.new_line} ${html(clip(p.name || p.file || u.heading, 60))}</div>`;
  }
  // 체크 묶음(2.12): 한 문서의 연속한 변경 단위들. 줄마다 왼쪽 틀림 체크 칸, 묶음마다 제출 한 번(체크한 줄 틀림, 나머지 맞음)
  const groups = new Map();
  const fillGroups = () => { groups.clear(); U.map((u, k) => k).sort((a, b) => U[a].doc.localeCompare(U[b].doc) || U[a].new_line - U[b].new_line || U[a].old_line - U[b].old_line || a - b)
    .forEach(k => { const g = U[k].group || (U[k].doc + ":" + U[k].new_line); if (!groups.has(g)) groups.set(g, []); groups.get(g).push(k); }); };
  fillGroups();
  // 체크 뒤(2.12): 페이지를 다시 받지 않고 변경 단위만 다시 받아 색인을 새로 만들고 그 자리에서 다시 그린다
  // 체크 실패는 빨간 글자로 남기고(다음 성공 때까지), 서버에 닿지 않으면 맨 위 빨간 띠(2.11)
  function failed(text) { $("status").textContent = text; $("status").classList.add("err"); }
  function down(on) {
    const el = $("down"); el.classList.toggle("on", on);
    if (on) el.textContent = ui("서버 연결 끊김 — 체크가 전달되지 않음(이 주소 ") + location.host + ui("). 서버가 같은 포트로 다시 뜨면 저절로 다시 붙는다. 안 붙으면 .spec-conformance/Reports/map.html을 다시 연다");
  }
  function refreshUnits(redraw=true) {
    if (reviewLoading) return reviewLoading;
    $("status").classList.remove("err");
    $("status").textContent = ui("체크 목록 다시 받는 중…");
    reviewLoading = fetch("/review").then(async r => {
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || '문서 검토 목록 조회 실패');
      return d;
    }).then(d => {
      if (!mounted) return;
      D.workflow = d.workflow || D.workflow;
      codeFirst = !!(D.workflow && D.workflow.authority === 'code');
      U = d.units || [];
      G.mods.length = 0; G.types.length = 0; G.mems.length = 0;
      chainOf = U.map(chainFor);
      planUnits = U.map((u, k) => k).filter(k => ((U[k].plan || {}).action || "글") !== "글" && chainOf[k].length);
      planSet = new Set(planUnits);
      proseUnits = U.map((u, k) => k).filter(k => !planSet.has(k));
      fillGroups();
      groupNames = Array.from(groups.keys());
      const w = U.filter(u => u.verdict === "틀림").length;
      $("tabCount").textContent = ui("· 미구현·검증 미완료 코드 대상 ") + (D.implementationPlans || []).length + ui("개");
      if (D.rev == null) $("tabCount").textContent = ui("· 판정 대기");
      $("tabReview").textContent = ui("문서 변경 검토") + (U.length ? " · " + U.length + ui("줄") : "");
    }).then(() => {
      if (!mounted) return;
      $("status").textContent = "";
      if (!redraw) return;
      $("graph").replaceChildren(); $("side").replaceChildren();
      delete $("graph")._mapMarkup; delete $("side")._mapMarkup;
      render();
    }).finally(() => { reviewLoading = null; });
    return reviewLoading;
  }
  let reviewActive = false;
  $("reviewDialog").oncancel = ev => { if (reviewActive) ev.preventDefault(); };
  $("reviewCancel").onclick = () => $("reviewDialog").close();
  $("reviewClose").onclick = () => $("reviewDialog").close();
  const reviewJson = async (path, body) => {
    const response = await fetch(path, body === undefined ? undefined : {
      method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)
    });
    let data;
    try { data = await response.json(); } catch (_) { throw new Error(ui("체크 응답 오류 (HTTP ") + response.status + ")"); }
    if (!response.ok) throw new Error(data.error || ("HTTP " + response.status));
    return data;
  };
  function requestReview(ks, verdict, memo, label) {
    if (reviewActive) return;
    const items = ks.map(k => U[k].doc + "|" + U[k].key);
    if (!items.length) return;
    const dialog = $("reviewDialog"), progress = $("reviewProgress");
    let shownPercent = 0;
    const setProgress = percent => {
      shownPercent = Math.max(shownPercent, Math.min(100, Math.round(percent)));
      progress.value = shownPercent;
      $("reviewPercent").textContent = shownPercent + "%";
    };
    $("reviewTitle").textContent = label + " · " + verdict;
    $("reviewMessage").textContent = items.length + ui("건을 ") + verdict + ui("으로 체크합니다.");
    $("reviewStage").textContent = ui("실행을 누르면 ") + Math.ceil(items.length / 400) + ui("개 묶음으로 전달합니다.");
    $("reviewDetail").textContent = ui("전달이 끝나면 서버가 문서별로 반영하고 지도를 한 번 갱신합니다.");
    $("reviewError").textContent = "";
    shownPercent = 0; setProgress(0);
    $("reviewCancel").hidden = false; $("reviewConfirm").hidden = false; $("reviewConfirm").disabled = false; $("reviewClose").hidden = true;
    $("reviewConfirm").onclick = async () => {
      reviewActive = true; reviewSubmitting++;
      $("reviewCancel").hidden = true; $("reviewConfirm").disabled = true;
      let batchId = "", committed = false, submitted = false;
      try {
        const start = await reviewJson("/review/batch/start", {total:items.length, verdict, memo});
        batchId = start.id;
        for (let offset = 0; offset < items.length; offset += 400) {
          const chunk = items.slice(offset, offset + 400);
          const sent = await reviewJson("/review/batch/chunk", {batch:batchId, index:offset / 400, items:chunk});
          setProgress(25 * sent.uploaded / items.length);
          $("reviewStage").textContent = ui("묶음 전달 중 · ") + sent.uploaded + "/" + items.length + ui("건 (") + Math.ceil(sent.uploaded / 400) + "/" + Math.ceil(items.length / 400) + ui("묶음)");
          await new Promise(resolve => setTimeout(resolve, 0));
        }
        submitted = true;
        await reviewJson("/review/batch/finish", {batch:batchId});
        setProgress(25);
        let retries = 0;
        while (true) {
          await new Promise(resolve => setTimeout(resolve, 500));
          let state;
          try { state = await reviewJson("/review/batch/status?batch=" + encodeURIComponent(batchId)); retries = 0; }
          catch (error) {
            if (++retries > 5) throw error;
            $("reviewStage").textContent = ui("서버 연결을 다시 확인하는 중…");
            continue;
          }
          committed = !!state.result;
          setProgress(state.percent ?? shownPercent);
          $("reviewStage").textContent = state.stage + (state.stageTotal ? " · " + state.done + "/" + state.stageTotal + ui("개 문서") : "");
          if (state.stage === "실패") throw new Error(state.error || "체크 실패");
          if (state.stage === "완료") {
            const got = state.result || {};
            $("reviewStage").textContent = ui("화면 갱신 중…");
            await refreshUnits();
            setProgress(100);
            $("reviewStage").textContent = ui("완료 · ") + got.checked + ui("건 체크");
            $("reviewDetail").textContent = ui("남은 대기 ") + got.waiting + ui("건") + (got.wrong ? ui(" · 틀림 ") + got.wrong + ui("건") : "") + (got.missing ? ui(" · 문서 변경으로 사라진 단위 ") + got.missing + ui("건") : "");
            $("status").textContent = $("reviewStage").textContent;
            break;
          }
        }
      } catch (error) {
        $("reviewStage").textContent = committed ? ui("체크 반영 후 화면 갱신 실패") : submitted ? ui("결과 확인 실패 · 서버에서 계속 처리 중일 수 있습니다") : ui("체크를 완료하지 못했습니다");
        $("reviewError").textContent = String(error) + (submitted ? ui("\n작업 ID: ") + batchId : "");
        failed($("reviewStage").textContent + ": " + error);
      } finally {
        reviewActive = false; reviewSubmitting--;
        $("reviewConfirm").hidden = true; $("reviewClose").hidden = false;
      }
    };
    if (!dialog.open) dialog.showModal();
  }
  const groupsOf = (ks) => { const want = new Set(ks.map(k => U[k].group || (U[k].doc + ":" + U[k].new_line))); return Array.from(groups.keys()).filter(g => want.has(g)); };
  let groupNames = Array.from(groups.keys());
  const PAGE_ROWS = 80;
  function bundleSummary(g, eager=false, allowed=null) {
    const ks = (groups.get(g)||[]).filter(k=>!allowed || allowed.has(k)), u0 = U[ks[0]], wrong = ks.filter(k => U[k].verdict === "틀림").length;
    return `<details class="bundle${wrong ? " hasWrong" : ""}" data-gi="${groupNames.indexOf(g)}"${eager ? " open" : ""}><summary><b>${html(u0.doc.split("/").pop())}:${u0.new_line}</b> · ${html(u0.heading)} · ${ks.length}${ui("줄")}${wrong ? ui(" · 틀림 ") + wrong : ""}</summary><div class="bundle-body"></div></details>`;
  }
  function bundleHtml(g, page, flags, allowed=null) {
    const ks = (groups.get(g)||[]).filter(k=>!allowed || allowed.has(k)), u0 = U[ks[0]], ul = U[ks[ks.length - 1]];
    const acts = {}; ks.forEach(k => { const a = U[k].kind; acts[a] = (acts[a] || 0) + 1; });
    const start = page * PAGE_ROWS, end = Math.min(start + PAGE_ROWS, ks.length);
    let h = `<div class="bundle-content"><div class="head">${Object.keys(acts).map(a => ui("문서 ") + html(a) + " " + acts[a]).join(" · ")}</div>`;
    h += '<div class="diff">';
    if (!page) u0.before.forEach(x => h += `<div class="ctx"><span class="cb"></span><span class="rl">  ${html(x)}</span></div>`);
    ks.slice(start, end).forEach(k => {
      const u = U[k], p = u.plan || {};
      const tag = `<span class="chip ${{ "추가": "cn", "수정": "cm", "삭제": "cd" }[u.kind] || "ct"}${ui("\">문서 ")}${html(u.kind)}</span> `;
      const box = `${ui("<label class=\"cb\" title=\"틀린 줄이면 체크\"><input type=\"checkbox\" class=\"flag\" data-u=\"")}${k}"${flags.has(k) ? " checked" : ""}${window.MAP_LIVE ? "" : " disabled"}></label>`;
      let body;
      if (u.kind === "수정" && u.words) body = `<div class="del">- ${wordsHtml(u.words[0])}</div><div class="ins">+ ${tag}${wordsHtml(u.words[1])}</div>`;
      else body = (u.old ? `<div class="del">- ${tag}${html(u.old)}</div>` : "") + (u.new ? `<div class="ins">+ ${tag}${html(u.new)}</div>` : "");
      h += `<div class="row${u.verdict === "틀림" ? " flagged" : ""}">${box}<span class="rl">${body}${u.verdict === "틀림" && u.memo ? `${ui("<div class=\"note\">틀림 이유: ")}${html(u.memo)}</div>` : ""}</span></div>`;
    });
    if (end === ks.length) ul.after.forEach(x => h += `<div class="ctx"><span class="cb"></span><span class="rl">  ${html(x)}</span></div>`);
    h += "</div>";
    if (ks.length > PAGE_ROWS) h += `<div class="bundle-page"><button class="page-prev"${page ? "" : " disabled"}${ui(">이전</button>")}${start + 1}–${end} / ${ks.length}${ui("줄<button class=\"page-next\"")}${end < ks.length ? "" : " disabled"}${ui(">다음</button></div>")}`;
    if (window.MAP_LIVE) h += ui("<div class=\"checks\"><input class=\"memo bmemo\" placeholder=\"체크한 줄이 틀린 이유\"><button class=\"ng bwrong\">틀림 제출 — 체크한 줄만</button><button class=\"ok brest\">나머지 맞음</button></div>");
    return h + "</div>";
  }
  function problemHtml(p) {
    if (p.kind === "I3") { const f = D.finds[p.f], mi = D.mods.findIndex(m => m[0] === f[1]);
      return `<div class="find" data-go="${mi >= 0 ? "c:m" + mi : ""}"><span class="chip c3">I3</span> <span class="where">${html(f[1])}</span><div class="msg">${html(localizedFinding(f[1], f[2], f[3]))}</div></div>`; }
    if (p.kind === "I4") { const f = D.finds[p.f];
      return `<div class="find" data-go="${f[4] >= 0 ? html(codeClick("d" + f[4])) : ""}"><span class="chip c3">I4</span> <span class="where">${html(f[1])}:${f[2]}</span><div class="msg">${html(localizedFinding(f[1], f[2], f[3]))}</div></div>`; }
    if (p.kind === "I2") return `<div class="find" data-go="${html(codeClick("t" + p.i))}"><span class="chip c2">I2</span> <span class="where">${html(D.files[D.decls[p.i][2]][0])}:${D.decls[p.i][3]}${ui("</span><div class=\"msg\">구현 없는 인터페이스 ")}${html(typeTitle(p.i))}</div></div>`;
    const x = p.k;
    return `<div class="find" data-go="${html(codeClick("d" + x.from))}"><span class="chip c3">I1</span> <span class="where">${html(D.files[D.decls[x.from][2]][0])}:${D.decls[x.from][3]}</span><div class="msg">${html(declName(x.from))} → ${html(declName(x.t))}.${html(D.decls[x.to][0])}${ui(" (인터페이스 ")}${html(x.iface >= 0 ? D.decls[x.iface][0] : "?")}.${html(D.decls[x.to][0])}${ui("로)</div></div>")}`;
  }

  function chips() {
    const c = {}; D.finds.forEach(f => c[f[0]] = (c[f[0]] || 0) + 1);
    $("chips").innerHTML = Object.keys(c).sort().map(x => `<span class="chip c${SEV(x)}${hidden.has(x) ? " off" : ""}" data-code="${x}">${x} ${c[x]}</span>`).join(" ");
    $("chips").querySelectorAll(".chip").forEach(el => el.onclick = () => {
      const x = el.dataset.code; hidden.has(x) ? hidden.delete(x) : hidden.add(x); chips(); render();
    });
  }

  function side(v) {
    if (v.unavailable) { patchHtml($("side"), ui("<div class=\"note\">코드 대조 결과가 아직 없습니다. 문서 변경 검토 탭에서 검토 목록을 확인할 수 있습니다.</div>")); return; }
    if (v.view.startsWith("c:")) v = codeContext(v);
    if (v.codePanel) {
      side.lastView=v;
      const implementation=side.tab==='implementation';
      v={...v,implementation,list:v.list.filter(k=>implementation===['W8','W12'].includes(D.finds[k][0])),
        units:implementation?[]:v.units,review:implementation?false:v.review};
    }
    if (codeFirst && v.review && !v.codePanel) { comparisonSide(v); return; }
    const findingState = side.findingState?.view === v.view ? side.findingState : (side.findingState = {view:v.view, rule:'', page:0});
    const ruleOf = f => /^규칙 ([A-Za-z][A-Za-z0-9_-]*)\s/.exec(f[3])?.[1] || '';
    const ruleCounts = new Map();
    v.list.forEach(k => { const rule=ruleOf(D.finds[k]); if(rule) ruleCounts.set(rule,(ruleCounts.get(rule)||0)+1); });
    if (findingState.rule && !ruleCounts.has(findingState.rule)) { findingState.rule=''; findingState.page=0; }
    const ks = v.list.filter(k => !hidden.has(D.finds[k][0]) && (!findingState.rule || ruleOf(D.finds[k]) === findingState.rule)).sort((a, b) => (isNew(D.finds[b]) - isNew(D.finds[a])) || SEV(D.finds[b][0]) - SEV(D.finds[a][0]) || D.finds[a][1].localeCompare(D.finds[b][1]) || D.finds[a][2] - D.finds[b][2]);
    const limit = 100, pages = Math.max(1, Math.ceil(ks.length / limit));
    findingState.page = Math.min(findingState.page, pages - 1);
    const start = findingState.page * limit;
    const rulesHtml = ruleCounts.size ? ui("<nav class=\"finding-rules\" aria-label=\"규칙별 지적 바로 보기\"><b>규칙별 바로 보기</b> ") +
      `<button data-finding-rule="" aria-pressed="${!findingState.rule}${ui("\">전체</button> ")}` +
      [...ruleCounts].sort(([a],[b])=>a.localeCompare(b)).map(([rule,count])=>`<button data-finding-rule="${html(rule)}" aria-pressed="${findingState.rule===rule}">${rule==='DOC22'?ui("문서 분리 (DOC22)"):html(rule)} ${count}${ui("건</button>")}`).join(' ') + '</nav>' : '';
    const pagination = v.list.length ? `<div class="finding-pages"><span>${findingState.rule?html(findingState.rule)+' · ':''}${ks.length?start+1:0}–${Math.min(start+limit,ks.length)} / ${ks.length}${ui("건</span> <button data-finding-page=\"prev\"")}${findingState.page===0?' disabled':''}${ui(">이전</button> <button data-finding-page=\"next\"")}${findingState.page===pages-1?' disabled':''}${ui(">다음</button></div>")}` : '';
    let h = v.codePanel ? codeSummary(v) : "";
    if (v.phase) {
      const S = D.phases || { rows: [] }, now = S.rows.find(r => r.state === "지금"), next = S.rows.find(r => r.state === "다음");
      h += ui("<h2>우선순위·페이즈</h2>");
      h += ui("<div class=\"note\">PH별 대상과 지적은 독립적으로 표시합니다. 재발은 원래 PH에 남고, 배정이 겹치면 미배정으로 유지합니다. 전체 완료·필수 오류 판정은 별도 전체 집계를 사용합니다.</div>");
      if (v.selectedPhase) {
        const selected = S.rows.find(r => r.name === v.selectedPhase);
        if (selected) h += `<div class="sel"><b>${html(selected.name)}</b> · ${html(selected.state)} · ${html(selected.targets)}${ui(" · 남은 지적 ")}${selected.left}</div>`;
        else h += ui("<div class=\"note\">선택한 PH가 없습니다.</div>");
      } else {
        if (now) h += `${ui("<div class=\"sel\"><b>지금</b> · ")}${now.rank} ${html(now.name)} · ${html(now.targets)}${ui(" · 남은 지적 ")}${now.left}</div>`;
        if (next) h += `${ui("<div class=\"sel\"><b>다음</b> · ")}${next.rank} ${html(next.name)} · ${html(next.targets)}${ui(" · 남은 지적 ")}${next.left}</div>`;
      }
      patchHtml($("side"), h);
      $("side").querySelectorAll("[data-go]").forEach(el => el.onclick = () => go(el.dataset.go));
      return;
    }
    // 묶음 체크(한 번에 맞음·틀림) — 누르기 전에 건수를 묻는다
    const bulk = (ks, label) => window.MAP_LIVE && ks.length ? `<div class="checks bulk" data-label="${html(label)}"><b>${html(label)} ${ks.length}${ui("건</b><button class=\"ok bulkok\">")}${v.reviewFolder?ui("하위 전체 승인"):ui("모두 맞음")}${ui("</button><button class=\"ng bulkng\">모두 틀림</button><input class=\"memo bulkmemo\" placeholder=\"틀림 이유(한 줄)\"></div>")}` : "";

    if (v.plan) {
      const wrongAll = U.filter(u => u.verdict === "틀림").length;
      h += `${ui("<h2>문서 변경 체크 — 대기 ")}${U.length - wrongAll}${wrongAll ? ui(" · 틀림 ") + wrongAll : ""}</h2>`;
      if (!window.MAP_LIVE) h += ui("<div class=\"note\">파일로 연 지도라 체크 단추가 없다 — 감시 서버 주소(engine.py ask status)로 연다</div>");
      if (v.sel) h += `<div class="sel"><b>${html(nodeName(v.sel))}${ui("</b> · 변경 ")}${v.units.length}${ui("줄 · 체크 묶음 ")}${groupsOf(v.units).length}${ui("개 · <a data-go=\"")}${html(codeClick(v.sel))}${ui("\" style=\"cursor:pointer;color:#0969da\">코드 구조에서 보기 →</a> · <a data-go=\"c:\" style=\"cursor:pointer;color:#0969da\">고르기 풀기</a></div>")}`;
      else h += bulk(U.map((u, k) => k), ui("전체")) + ui("<div class=\"note\">체크 묶음마다 틀린 줄의 왼쪽 칸을 체크하고 제출한다(체크한 줄 틀림, 나머지 맞음). 왼쪽 맵에서 코드 항목을 누르면 연결된 문서 변경만 보인다</div>");
    }
    const us = v.review ? (v.units || []).slice() : [];
    const reviewScope = new Set(us);
    if (v.review && (us.length || !v.codePanel)) {
      const waiting = us.filter(k=>U[k].verdict !== "틀림").length;
      const wrong = us.length - waiting;
      if (!v.codePanel) h += `<div class="review-selection"><b>${html(v.reviewFolder || v.reviewDoc || '전체 문서')}</b><div>${v.documentCount ?? new Set(us.map(k=>U[k].doc)).size}${ui("문서 · 변경 ")}${us.length}${ui("줄")}${v.reviewFolder?ui(" · 모든 하위 폴더 포함"):''}</div></div>`;
      h += `${ui("<section id=\"current-documents\" class=\"document-check\"><h2>문서 변경 체크 — 대기 ")}${waiting}${wrong ? ui(" · 틀림 ")+wrong : ''}</h2>`;
      if (us.length) {
        h += bulk(us, v.codePanel ? (v.allTargets ? ui("전체") : ui("선택 대상")) : v.reviewFolder ? v.reviewFolder+ui(" 하위 전체") : v.reviewDoc || '전체 문서');
        h += v.reviewFolder ? ui("<div class=\"note\">하위 전체 승인은 이 폴더 아래의 모든 하위 폴더·문서를 한 번에 처리합니다. 기존 틀림 판정은 제외하며, 개별 수정은 아래 변경 내역에서 할 수 있습니다.</div>") : ui("<div class=\"note\">체크 묶음마다 틀린 줄의 왼쪽 칸을 체크하고 제출한다(체크한 줄 틀림, 나머지 맞음). 왼쪽에서 선택한 범위의 변경만 보인다.</div>");
        const shownGroups=groupsOf(us);
        h += `${ui("<section class=\"review-diffs\"><h3>문서 변경 내역 — ")}${us.length}${ui("건 · ")}${shownGroups.length}${ui("묶음</h3><div class=\"note\">− 변경 전 문서 · + 변경 후 문서. 아래 문서 내용에 대해 맞음/틀림을 체크합니다.</div>")}`;
        shownGroups.forEach(g=>h+=bundleSummary(g,true,reviewScope));
        h += '</section>';
      } else h += ui("<div class=\"note\">현재 대상의 문서 변경 체크 대기가 없습니다.</div>");
      h += '</section>';
    }
    if (v.codePanel) {
      h += `<section id="current-findings"><h2>${v.implementation?ui("구현·검증"):ui("문서·구조 지적")}</h2>`;
      h += rulesHtml;
      if(v.implementation)h += plannedCodeHtml(v);
      h += `${ui("<details class=\"finding-list\" open><summary>지적 전체 목록 · ")}${v.list.length}${ui("건</summary>")}`;
    }
    if (v.problems && v.problems.length) {
      h += `${ui("<h2>인터페이스 대응 문제 ")}${v.problems.length}${ui("건</h2>")}`;
      v.problems.slice(0, 300).forEach(p => h += problemHtml(p));
    }
    if (!v.plan && !v.review) h += `<h2>${html(v.title)} ${ks.length}${ui("건</h2>")}`;

    if (v.extra && !v.codePanel) h += `<div class="note">${html(v.extra)}</div>`;
    if (v.view === "all") D.notes.forEach(n => h += `${ui("<div class=\"note\">참고: ")}${html(n)}</div>`);
    if (!v.codePanel) h += rulesHtml;
    h += pagination;
    ks.slice(start, start + limit).forEach(k => {
      const f = D.finds[k];
      h += `<div class="find" data-k="${k}"><span class="chip c${SEV(f[0])}">${f[0]}</span>${isNew(f) ? ui(" <span class=\"chip c3\">새</span>") : ""} <span class="where">${html(f[1])}:${f[2]}</span><div class="msg">${html(localizedFinding(f[1], f[2], f[3]))}</div></div>`;
      const link=(D.documentLinks||[]).find(item=>JSON.stringify(item.finding)===JSON.stringify(f.slice(0,4)));
      if(link)h+=`${ui("<div class=\"note\">소스 폴더: ")}${link.sourceFolders.length?link.sourceFolders.map(p=>html(p||'(루트)')).join(', '):ui("소유 연결 없음")}${ui("<br/>분리 위치: ")}${link.expectedFolders.length?link.expectedFolders.map(html).join(', '):ui("등록된 모듈 폴더 연결 없음")+(link.packageFolder?' · '+html(link.packageFolder)+ui("/ 아래의 모듈 폴더 연결 필요"):'')}</div>`;
    });
    h += pagination;
    if (v.codePanel) h += "</details></section>";
    patchHtml($("side"), h);
    const panels = selector => $("side").querySelectorAll(selector);
    $('side').querySelectorAll('details[data-priority-group]').forEach(details=>details.ontoggle=async()=>{
      if(!details.open || details.dataset.loaded) return;
      const target=details.querySelector('.group-findings'), revision=D.rev;
      target.textContent=ui("조회 중");
      try {
        const response=await fetch('/priority?group='+encodeURIComponent(details.dataset.priorityGroup)+'&limit=0');
        const result=await response.json();
        if(!response.ok || result.rev!==revision || D.rev!==revision) throw new Error(result.error||'판이 변경됐습니다. 다시 펼쳐 확인하세요.');
        target.replaceChildren(...result.findings.map(item=>{
          const row=document.createElement('p');
          row.textContent=`${item.id} · ${item.code} · ${(item.locations||[item]).map(p=>p.file+':'+p.line).join(', ')} · ${item.message}`;
          return row;
        }));
        details.dataset.loaded='true';
      } catch(error) { target.textContent=String(error); }
    });
    const showFindings = () => {
      side(v);
      panels('.finding-list').forEach(el => { el.open=true; });
      panels('.finding-pages')[0]?.scrollIntoView({block:'start'});
    };
    panels('[data-finding-rule]').forEach(el => el.onclick = () => {
      findingState.rule=el.dataset.findingRule; findingState.page=0;
      if (findingState.rule) {
        v.list.forEach(k => { if(ruleOf(D.finds[k])===findingState.rule) hidden.delete(D.finds[k][0]); });
        chips();
      }
      showFindings();
    });
    panels('[data-finding-page]').forEach(el => el.onclick = () => {
      findingState.page += el.dataset.findingPage==='next'?1:-1;
      showFindings();
    });
    const code = v.view.startsWith("c:");
    panels(".find[data-k]").forEach(el => el.onclick = () => {
      const f = D.finds[+el.dataset.k];
      if(code && /^규칙 DOC22\s/.test(f[3])) {go('c:doc:'+encodeURIComponent(f[1]));return;}
      if (code) { go(f[4] >= 0 ? codeClick((METHOD_KINDS.has(D.decls[f[4]][1]) || VAR_KINDS.has(D.decls[f[4]][1]) ? "d" : "t") + f[4]) : f[5] >= 0 ? codeClick("m" + D.files[f[5]][1]) : "c:"); return; }
      if (f[4] >= 0) go("type:" + owner[f[4]]);
      else if (f[5] >= 0) go("mod:" + D.files[f[5]][1]);
      else go(f[1].startsWith("Docs/") ? "docs" : "stray");
    });
    panels("[data-go]").forEach(el => el.onclick = () => go(el.dataset.go));
    panels(".unit[data-u] .head").forEach(el => el.onclick = () => go("c:@" + (chainOf[+el.parentNode.dataset.u].slice(-1)[0] || "")));
    // 체크 요청은 모두 같은 다이얼로그에서 확인하고 묶음별로 전달한다.
    const sendMany = (ks, verdict, memo, label=ui("선택")) => requestReview(ks, verdict, memo, label);
    const memoOf = (k) => (panels(`.memo[data-u="${k}"]`)[0] || {}).value || "";
    panels("button.ok:not(.bulkok)").forEach(el => el.onclick = () => sendMany([+el.dataset.u], "맞음", ""));
    panels("button.ng:not(.bulkng)").forEach(el => el.onclick = () => sendMany([+el.dataset.u], "틀림", memoOf(+el.dataset.u)));
    panels(".bundle[data-gi]").forEach(b => {
      const g = groupNames[+b.dataset.gi], ks = (groups.get(g)||[]).filter(k=>reviewScope.has(k));
      if (!ks.length) return;
      const scopeKey = g + ':' + ks.join(',');
      if (b._scope !== scopeKey) { b._scope = scopeKey; b._flags = new Set(ks.filter(k => U[k].verdict === "틀림")); b._page = 0; b._manualClosed = false; b._bodyRev = null; }
      if (b._page === undefined) b._page = 0;
      b.querySelector(':scope > summary').onclick = () => { b._manualClosed = b.open; };
      const show = () => {
        const body = b.querySelector(".bundle-body");
        if (!b.open) { body.replaceChildren(); return; }
        const memo = body.querySelector(".bmemo")?.value || "";
        body.innerHTML = bundleHtml(g, b._page, b._flags, reviewScope);
        b._bodyRev = D.rev;
        body.querySelectorAll(".flag").forEach(box => box.onchange = () => {
          const k = +box.dataset.u;
          if (box.checked) b._flags.add(k); else b._flags.delete(k);
        });
        const prev = body.querySelector(".page-prev"), next = body.querySelector(".page-next");
        if (prev) prev.onclick = () => { b._page--; show(); };
        if (next) next.onclick = () => { b._page++; show(); };
        const wbtn = body.querySelector(".bwrong"), rbtn = body.querySelector(".brest");
        if (wbtn) wbtn.onclick = () => {
          const wrong = ks.filter(k => b._flags.has(k));
          if (!wrong.length) { $("status").textContent = ui("틀린 줄의 왼쪽 칸을 먼저 체크하세요"); return; }
          sendMany(wrong, "틀림", body.querySelector(".bmemo").value || "", ui("묶음"));
        };
        if (rbtn) rbtn.onclick = () => {
          const right = ks.filter(k => !b._flags.has(k));
          if (!right.length) { $("status").textContent = ui("맞음으로 낼 줄이 없습니다(모두 체크됨)"); return; }
          sendMany(right, "맞음", "", ui("묶음"));
        };
        if (body.querySelector(".bmemo")) body.querySelector(".bmemo").value = memo;
      };
      b.ontoggle = show;
      if (b.open && (!b.querySelector('.bundle-body').firstElementChild || b._bodyRev !== D.rev)) show();
    });
    panels(".bulk").forEach(box => {
      const ks = v.review ? (v.units || []).slice() : U.map((u, k) => k), label = box.dataset.label, memo = () => box.querySelector(".bulkmemo").value || "";
      // 모두 맞음은 이미 틀림으로 체크된 줄을 덮지 않는다(2.9.1) — 틀림 줄을 맞음으로 바꾸려면 그 묶음에서 체크를 풀고 제출한다
      box.querySelector(".bulkok").onclick = () => {
        const ok = ks.filter(k => U[k].verdict !== "틀림"), kept = ks.length - ok.length;
        if (!ok.length) { $("status").textContent = ui("맞음으로 낼 줄이 없다(모두 틀림 줄)"); return; }
        sendMany(ok, "맞음", "", label + (kept ? ui(" (틀림 ") + kept + ui("건 제외)") : ""));
      };
      box.querySelector(".bulkng").onclick = () => sendMany(ks, "틀림", memo(), label);
    });
  }

  // The first 10% is already open at first paint. Open the remainder one at a
  // time after that paint, yielding between items so controls stay responsive.
  let expandHandle = null, expandGeneration = 0, mounted = true;
  function stopExpansion() {
    expandGeneration++;
    if (expandHandle !== null) {
      if (window.cancelIdleCallback) cancelIdleCallback(expandHandle);
      else clearTimeout(expandHandle);
      expandHandle = null;
    }
  }
  function queueExpansion() {
    const generation = expandGeneration;
    requestAnimationFrame(() => requestAnimationFrame(() => {
      if (!mounted || generation !== expandGeneration) return;
      const modules = Array.from($("graph").querySelectorAll('details[data-module]')).filter(x => !x.open && !x._manualClosed);
      const bundles = Array.from($("side").querySelectorAll('.bundle[data-gi]')).filter(x => !x.open && !x._manualClosed);
      let turn = 0;
      if (!modules.length && !bundles.length) return;
      const schedule = () => {
        if (!mounted || generation !== expandGeneration) return;
        if (window.requestIdleCallback) expandHandle = requestIdleCallback(step, {timeout: 250});
        else expandHandle = setTimeout(step, 16);
      };
      const step = () => {
        if (!mounted || generation !== expandGeneration) return;
        expandHandle = null;
        const first = turn++ % 2 ? bundles : modules, second = first === modules ? bundles : modules;
        let item = first.shift() || second.shift();
        while (item && !item.isConnected) item = first.shift() || second.shift();
        if (!item) return;
        if (!item._manualClosed && !item.open) item.open = true;
        if (modules.length || bundles.length) setTimeout(schedule, 0);
      };
      schedule();
    }));
  }

  function go(view) { if(view.startsWith('c:dm')||view.startsWith('c:doc'))side.tab='findings'; location.hash = view; }

  // 페이즈 탭(2.9.2): 순위대로 한 줄씩, 줄을 누르면 남은 지적, 조작은 실시간 지도에서만(▲▼ 보류 지우기, 새 작업 넣기)
  const STATE_CHIP = { "지금": "cm", "다음": "cn", "대기": "cw", "끝남": "ct" };
  const findGo = (file) => {
    const fi = fileIdx.get(file); if (fi !== undefined) return "c:m" + D.files[fi][1];
    const m = D.mods.findIndex(x => x[0] === file); return m >= 0 ? "c:m" + m : "c:";
  };
  function phaseView(open) {
    const S = D.phases;
    if (!S) return { html: ui("<p class=\"note\">페이즈 표가 없거나 문서 형식 오류로 계산하지 못했다</p>"), crumbs: [[ui("페이즈"), "ph:"]], list: [], title: "", phase: true };
    let h = '<div class="phases">';
    if (window.MAP_LIVE && !open) h += ui("<div class=\"sadd\"><b>새 작업 넣기</b> <span class=\"pstate\">지금 페이즈 바로 다음 순위로 들어가고 뒤는 한 칸씩 밀린다</span><div class=\"checks\"><input id=\"sName\" placeholder=\"페이즈 이름(예: PH10)\"><input id=\"sTargets\" placeholder=\"대상: 단계 E12 또는 S1 Assets/Scripts/Character (쉼표로 여럿)\"><input id=\"sReason\" placeholder=\"이유\"><button class=\"ok\" id=\"sAdd\">넣기</button></div></div>");
    else if (!window.MAP_LIVE) h += ui("<p class=\"note\">파일로 연 지도라 조작 단추가 없다 — 감시 서버 주소로 연다</p>");
    S.rows.forEach((r, k) => {
      if (open && r.name !== open) return;
      const counts = Object.keys(r.counts).sort().map(c => c + " " + r.counts[c]).join(" · ");
      h += `<div class="srow s-${r.state}" data-name="${html(r.name)}" data-rank="${r.rank}"><div class="shead" data-go="ph:${html(open === r.name ? "" : r.name)}"><span class="srank">${r.rank}</span> <b>${html(r.name)}</b> <span class="chip ${STATE_CHIP[r.state] || "cw"}">${html(r.state)}</span> <code>${html(r.targets)}</code> · ${html(r.reason)}${ui(" · 남은 지적 <b>")}${r.left}</b>${counts ? " (" + html(counts) + ")" : ""}`;
      if (window.MAP_LIVE && !["끝남","재발"].includes(r.state)) h += `<span class="sbtns"><button data-op="up"${k === 0 ? " disabled" : ""}>▲</button><button data-op="down"${k === S.rows.length - 1 ? " disabled" : ""}${ui(">▼</button><button data-op=\"defer\">보류</button><button data-op=\"drop\" class=\"ng\">지우기</button></span>")}`;
      h += "</div>";
      if (open === r.name) {
        h += '<div class="sfinds">';
        r.findings.forEach(f => h += `<div class="find" data-go="${html(findGo(f[1]))}"><span class="chip c${SEV(f[0])}">${html(f[0])}</span> <span class="where">${html(f[1])}:${f[2]}</span><div class="msg">${html(localizedFinding(f[1], f[2], f[3]))}</div></div>`);
        if (r.left > r.findings.length) h += `${ui("<div class=\"note\">앞의 ")}${r.findings.length}${ui("건만</div>")}`;
        h += "</div>";
      }
      h += "</div>";
    });
    if (!open) {
      h += `${ui("<div class=\"note\">미배정 ")}${S.unassigned}${ui("건 · 배정 충돌 ")}${(S.ambiguous || []).length}${ui("건</div>")}`;
      h += (S.ambiguous || []).map(f => `<div class="find">${html(f.code)} · ${html(f.file)}:${f.line} · ${html(f.phases.join(' / '))} · ${html(f.message)}</div>`).join('');
    } else if (!S.rows.some(r => r.name === open)) h += ui("<div class=\"note\">선택한 PH가 없습니다.</div>");
    h += '</div>';
    return { html: h, crumbs: [[ui("페이즈"), "ph:"]].concat(open ? [[open, "ph:" + open]] : []), list: [], title: "", phase: true,
             selectedPhase: open, extra: open || ui("지금 ") + (S.current || "-") + ui(" · 다음 ") + (S.next || "-") };
  }
  function wirePhases() {
    const call = (path) => {
      $("status").textContent = ui("페이즈 고치는 중…");
      fetch(path, { method: "POST" }).then(r => r.json()).then(got => {
        if (got.ok) { D.phases = got.phases; $("status").textContent = ""; render(); }
        else failed(got.error || "페이즈 조작 실패");
      }).catch(err => { failed(ui("페이즈 조작 실패: ") + err); down(true); });
    };
    const enc = encodeURIComponent;
    $("graph").querySelectorAll(".srow").forEach(row => {
      const name = row.dataset.name, rank = +row.dataset.rank;
      row.querySelectorAll("button[data-op]").forEach(b => b.onclick = (ev) => {
        ev.stopPropagation();
        const op = b.dataset.op;
        if (op === "up") call(`/phases/move?name=${enc(name)}&rank=${rank - 1}`);
        else if (op === "down") call(`/phases/move?name=${enc(name)}&rank=${rank + 1}`);
        else if (op === "defer") call(`/phases/defer?name=${enc(name)}`);
        else if (op === "drop" && confirm(name + ui(" 페이즈를 지울까요?"))) call(`/phases/drop?name=${enc(name)}`);
      });
    });
    const add = $("sAdd");
    if (add) add.onclick = () => call(`/phases/add?name=${enc($("sName").value)}&targets=${enc($("sTargets").value)}&reason=${enc($("sReason").value)}`);
  }

  const LEGEND_ALL = ui("<span><i style=\"background:var(--s4)\"></i>문서·파싱(D·P)</span><span><i style=\"background:var(--s3)\"></i>위치·참조 위반(L1·L2·L6)</span><span><i style=\"background:var(--s2)\"></i>따로 놂·다른 계층 전용·복사본(L3·L4·L5)</span><span><i style=\"background:var(--s1)\"></i>미구현(W8)·검증 미완료(W12)·그 밖의 W</span><span><i style=\"background:var(--s0)\"></i>지적 없음</span>");
  const LEGEND_CODE = LEGEND_ALL + ui("<span><i style=\"background:#c62828\"></i>I1 인터페이스 우회</span>");
  $("tabAll").onclick = () => go("all");
  const selectCodeTab = tab => {
    side.tab=tab; side.findingState=undefined;
    if(location.hash.startsWith('#c:') && side.lastView) {
      side(side.lastView);
      $("tabCode").classList.toggle('on',tab==='findings');
      $("tabImplementation").classList.toggle('on',tab==='implementation');
      $("side").scrollTop=0;
    } else go('c:');
  };
  $("tabCode").onclick = () => selectCodeTab('findings');
  $("tabImplementation").onclick = () => selectCodeTab('implementation');
  $("tabReview").onclick = () => go("review");
  $("tabPhase").onclick = () => go("ph:");
  if (D.phases) $("phaseCount").textContent = ui("· 지금 ") + (D.phases.current || "-");

  function patchHtml(container, markup) {
    if (container._mapMarkup === markup) return;
    const template = document.createElement('template'); template.innerHTML = markup;
    const keyOf = n => n.nodeType === 1 ? n.getAttribute('data-key') || n.getAttribute('data-folder-root') || n.id : null;
    function update(parent, incoming) {
      const keyed = new Map(Array.from(parent.childNodes).map(n => [keyOf(n), n]).filter(x => x[0]));
      Array.from(incoming.childNodes).forEach((next, i) => {
        const key = keyOf(next); let old = key ? keyed.get(key) : parent.childNodes[i];
        if (!old || old.nodeType !== next.nodeType || old.nodeName !== next.nodeName || (!key && keyOf(old))) {
          parent.insertBefore(next.cloneNode(true), parent.childNodes[i] || null); return;
        }
        if (parent.childNodes[i] !== old) parent.insertBefore(old, parent.childNodes[i] || null);
        if (old.nodeType !== 1) { if (old.nodeValue !== next.nodeValue) old.nodeValue = next.nodeValue; return; }
        if (old.isEqualNode(next)) return;
        Array.from(old.attributes).forEach(a => { if (!next.hasAttribute(a.name) && !(old.tagName === 'DETAILS' && a.name === 'open')) old.removeAttribute(a.name); });
        Array.from(next.attributes).forEach(a => { if (old.getAttribute(a.name) !== a.value && !(old.tagName === 'DETAILS' && a.name === 'open')) old.setAttribute(a.name, a.value); });
        update(old, next);
      });
      while (parent.childNodes.length > incoming.childNodes.length) parent.lastChild.remove();
    }
    update(container, template.content);
    container._mapMarkup = markup;
  }

  let lastSideView = null;
  async function render() {
    stopExpansion();
    if (document.querySelectorAll('#graph details[data-module][open], #side .bundle[open]').length > 100) {
      $("graph").replaceChildren(); $("side").replaceChildren();
      delete $("graph")._mapMarkup; delete $("side")._mapMarkup;
    }
    const view = decodeURIComponent(location.hash.slice(1)) || "all";
    const code = view.startsWith("c:"), phases = view.startsWith("ph:"), reviewing = view === 'review' || view.startsWith('review:');
    const loadReview = reviewing && !reviewViewActive;
    reviewViewActive = reviewing;
    if (window.MAP_LIVE && loadReview && !reviewSubmitting) {
      try { await refreshUnits(false); } catch (error) { failed(error.message); }
      if (!mounted || view !== (decodeURIComponent(location.hash.slice(1)) || 'all')) return;
    }
    $("tabAll").classList.toggle("on", !code && !phases && !reviewing); $("tabCode").classList.toggle("on", code&&side.tab!=='implementation'); $("tabImplementation").classList.toggle("on", code&&side.tab==='implementation'); $("tabPhase").classList.toggle("on", phases); $("tabReview").classList.toggle("on", reviewing);
    document.body.classList.toggle("code", code);
    $("legend").innerHTML = code ? LEGEND_CODE : LEGEND_ALL;
    if (D.phases) $("phaseCount").textContent = phases && view.slice(3) ? ui("· 선택 ") + view.slice(3) : ui("· 지금 ") + (D.phases.current || "-");
    let v;
    if (D.rev == null && !reviewing) v = {unavailable:true,list:[],crumbs:[],html:ui("<div class=\"note\">코드 대조 결과를 기다리는 중입니다. 문서 변경 검토 탭은 사용할 수 있습니다.</div>")};
    else if (phases) v = phaseView(view.slice(3));
    else if (code) v = codeView(view.slice(2));
    else if (reviewing) v = documentReviewView(view.startsWith('review:') ? view.slice(7) : '');
    else if (view.startsWith("layer:")) v = viewLayer(+view.slice(6));
    else if (view === "docs" || view === "stray") v = viewList(view);
    else if (view.startsWith("mod:")) v = viewModule(+view.slice(4));
    else if (view.startsWith("type:")) v = viewType(+view.slice(5));
    else v = viewAll();
    v.view = view;
    $("crumb").innerHTML = v.crumbs.map(([name, target]) => `<a data-v="${html(target)}">${html(name)}</a>`).join('<span class="sep">›</span>');
    $("crumb").querySelectorAll("a").forEach(a => a.onclick = () => go(a.dataset.v));
    side(v);
    if (lastSideView !== view) $("side").scrollTop = 0;
    lastSideView = view;
    queueExpansion();
    if (v.html) {
      delete $("graph").dataset.diagram;
      patchHtml($("graph"), v.html);
      const wireLinks = root => root.querySelectorAll('[data-go]').forEach(el => el.onclick = ev => { ev.stopPropagation(); go(el.dataset.go); });
      const wireVariables = root => root.querySelectorAll('details[data-variable-owner]').forEach(details => details.ontoggle = () => {
        const pending = details.querySelector(':scope > div');
        if (!details.open || !pending || !v.populateVariables) return;
        patchHtml(pending, v.populateVariables(+details.dataset.variableOwner));
        pending.removeAttribute('data-variable-pending');
        wireLinks(pending);
      });
      wireLinks($("graph"));
      if (v.populateModule) $("graph").querySelectorAll('details[data-module]').forEach(details => {
        details.querySelector(':scope > summary').onclick = () => { details._manualClosed = details.open; };
        const populate = () => {
          const body = details.querySelector(':scope > .module-body');
          if (!details.open) { body.replaceChildren(); return; }
          if (body.firstElementChild && details._bodyRev === D.rev && details._bodyOnly === $("onlyProblems").checked) return;
          body.innerHTML = v.populateModule(details.dataset.module);
          details._bodyRev = D.rev; details._bodyOnly = $("onlyProblems").checked;
          wireLinks(body);
          wireVariables(body);
          body.querySelectorAll('details[data-variable-owner][open]').forEach(item => item.ontoggle());
        };
        details.ontoggle = populate;
        if (details.open) populate();
      });
      // 지도 칸만 스크롤한다(페이지는 그대로): 고른 것, 없으면 첫 계획을 칸 위쪽 1/3에
      const target = v.focusKey && $("graph").querySelector(`[data-key="${CSS.escape(v.focusKey)}"]`);
      if (target) { const box = $("view"); box.scrollTop = Math.max(0, target.getBoundingClientRect().top - box.getBoundingClientRect().top + box.scrollTop - box.clientHeight / 3); }
      else if (v.plan && !v.sel) $("view").scrollTop = 0;
      $("status").textContent = "";
      if (v.phase) wirePhases();
      wireVariables($('graph'));
      $('graph').querySelectorAll('details[data-variable-owner][open]').forEach(details => details.ontoggle());
      return;
    }
    if (!v.text) { $("graph").innerHTML = ""; delete $("graph")._mapMarkup; return; }
    if (!window.mermaid) { $("graph").innerHTML = ui("<p class=\"note\">머메이드를 읽지 못해 그림을 그릴 수 없습니다(인터넷 연결). 오른쪽 목록은 그대로 보입니다.</p>"); return; }
    if ($( "graph").dataset.diagram === v.text) return;
    $("status").textContent = ui("그리는 중…");
    const no = ++renderNo;
    try {
      const { svg } = await mermaid.render("g" + no, v.text);
      if (no !== renderNo) return;
      $("graph").innerHTML = svg;
      delete $("graph")._mapMarkup;
      $("graph").dataset.diagram = v.text;
      $("graph").querySelectorAll("g.node, g.cluster").forEach(el => {
        const m = /^(?:flowchart-)?([A-Za-z]+\d+[a-z]?)(?:-\d+)?$/.exec(el.id);
        const target = m && v.click[m[1]];
        if (target) { el.style.cursor = "pointer"; el.addEventListener("click", () => go(target)); }
      });
      if (v.readable) {
        // 전체 코드 맵은 줄이지 않는다(배율 1). 고른 마디, 없으면 첫 계획 마디로 스크롤
        zoom = 1; applyZoom();
        const target = v.focus && ($("graph").querySelector(`[id^="flowchart-${v.focus}-"]`) || $("graph").querySelector(`[id="${v.focus}"]`));
        if (target) target.scrollIntoView({ block: "center", inline: "center" });
      } else fit();
      $("status").textContent = "";
    } catch (err) {
      $("graph").innerHTML = '<pre class="note">' + html(String(err && err.message || err)) + "</pre>";
      $("status").textContent = ui("그리기 실패");
    }
  }

  function natural() { const svg = $("graph").querySelector("svg"); if (!svg || !svg.viewBox || !svg.viewBox.baseVal) return null; return [svg, svg.viewBox.baseVal.width, svg.viewBox.baseVal.height]; }
  function applyZoom() { const n = natural(); if (!n) return; n[0].style.maxWidth = "none"; n[0].setAttribute("width", n[1] * zoom); n[0].setAttribute("height", n[2] * zoom); }
  function fit() { const n = natural(); if (!n) return; zoom = Math.max(0.15, Math.min(1, ($("view").clientWidth - 30) / n[1])); applyZoom(); }
  $("zoomIn").onclick = () => { zoom = Math.min(4, zoom * 1.25); applyZoom(); };
  $("zoomOut").onclick = () => { zoom = Math.max(0.1, zoom / 1.25); applyZoom(); };
  $("zoomFit").onclick = fit;
  $("onlyProblems").onchange = render;
  $("allEdges").onchange = render;
  window.addEventListener("hashchange", render);
  if (window.mermaid) mermaid.initialize({ startOnLoad: false, securityLevel: "loose", maxTextSize: 50000000, maxEdges: 200000,
                                          flowchart: { htmlLabels: true, useMaxWidth: false, curve: "basis" } });
  chips();
  Promise.resolve(render()).then(() => { if (state) { $("view").scrollTop = state.scroll; $("side").scrollTop = state.sideScroll; } });

  // 새 판정 알아채기: 실시간이면 1초마다 서버의 판을, 파일이면 5초마다 map-stamp.js를 본다
  let changingMode = false;
  let confirmedMode = "document-to-code";
  let confirmedPolicy = "deny";
  const showMode = mode => {
    confirmedMode = mode;
    $("workflowMode").value = confirmedMode;
  };
  $("workflowMode").disabled = true;
  $("codePolicy").disabled = true;
  const changeWorkflow = async () => {
    changingMode = true;
    $("workflowMode").disabled = true;
    $("codePolicy").disabled = true;
    $("workflowStatus").textContent = ui("모드 전환 중…");
    try {
      const r = await fetch("/workflow", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({mode:$("workflowMode").value,codePolicy:$("codePolicy").value})});
      const result = await r.json(); if (!r.ok) throw new Error(result.error);
      showMode(result.mode);
      confirmedPolicy = result.codePolicy;
      $("codePolicy").value = confirmedPolicy;
      $("workflowStatus").textContent = result.authority === "code" ? ui("코드 기준 검증 · 불일치 반복 지적") : ui("문서 기준 검증");
    } catch(e) {
      $("workflowMode").value = confirmedMode;
      $("codePolicy").value = confirmedPolicy;
      $("workflowStatus").textContent = e.message;
    } finally { changingMode = false; $("workflowMode").disabled = !window.MAP_LIVE; $("codePolicy").disabled = !window.MAP_LIVE || confirmedMode !== "code-to-document"; }
  };
  $("workflowMode").onchange = changeWorkflow;
  $("codePolicy").onchange = changeWorkflow;
  let updating = false;
  const timer = window.MAP_LIVE ? setInterval(async () => {
    if (updating) return;
    updating = true;
    try {
      const s = await fetch('/status').then(r => r.json()); down(false);
      const stale = !!s.error || (s.completion || {}).stateCurrent === false;
      const judgment = $("judgmentState");
      judgment.hidden = !stale && (s.completion || {}).stateCurrent === true;
      judgment.textContent = stale ? `${D.rev == null ? ui("코드 대조 결과 미확정") : ui("이전 판 ")+D.rev+ui("의 지적·코드 대상 수를 표시 중")} — ${s.error ? ui("최신 대조 실패") : ui("최신 대조 대기")}${ui(". 문서 검토 목록은 별도로 조회합니다.")}` : ui("표시 판정의 최신 여부 확인 중…");
      if (!changingMode) { showMode(s.workflow.mode); confirmedPolicy = s.workflow.codePolicy; $("codePolicy").value = confirmedPolicy; $("codePolicy").disabled = confirmedMode !== "code-to-document"; $("workflowMode").disabled = false; }
      if (changingMode || reviewSubmitting) return;
      if (s.uiVersion && window.MAP_UI && s.uiVersion !== window.MAP_UI) {
        try { sessionStorage.setItem('mapReloadState', JSON.stringify({hash:location.hash, zoom, hidden:Array.from(hidden), seenRev, findingState:side.findingState, sideTab:side.tab, scroll:$("view").scrollTop, sideScroll:$("side").scrollTop})); } catch (e) {}
        location.reload(); return;
      }
      if (s.workflow.mode !== (D.workflow || {}).mode) {
        try { await refreshUnits(false); render(); } catch (error) { failed(error.message); }
      }
      if (s.rev == null || s.rev === D.rev || s.busy) return;
      if (s.presentation && s.presentation.readyRev !== s.rev) return;
      const change = await fetch('/data?since=' + encodeURIComponent(D.rev)).then(r => { if (!r.ok) throw Error(ui("지도 갱신 실패")); return r.json(); });
      let next;
      if (change.full) next = change.full;
      else {
        if (change.base !== D.rev) throw Error(ui("지도 기준 불일치"));
        const apply = (before, edits) => {
          const value = Object.assign({}, before, edits.set);
          (edits.remove || []).forEach(key => delete value[key]);
          Object.entries(edits.arrays || {}).forEach(([key, patch]) => {
            const rows = (before[key] || []).slice(0, patch.length); rows.length = patch.length;
            patch.items.forEach(([i, row]) => rows[i] = row); value[key] = rows;
          });
          Object.entries(edits.objects || {}).forEach(([key, patch]) => value[key] = apply(before[key], patch));
          return value;
        };
        next = apply(D, change);
      }
      const keep = {zoom, hidden:Array.from(hidden), seenRev, findingState:side.findingState, sideTab:side.tab, scroll:$("view").scrollTop, sideScroll:$("side").scrollTop};
      clearInterval(timer); window.removeEventListener('hashchange', render); renderNo++;
      mounted = false; stopExpansion();
      $("graph").replaceChildren(); $("side").replaceChildren();
      delete $("graph")._mapMarkup; delete $("side")._mapMarkup;
      window.MAP_DATA = next; mountMap(keep);
    } catch (error) { down(true); }
    finally { updating = false; }
  }, 1000) : null;
  if (!window.MAP_LIVE) {
    const stamp = (first) => {
      const s = document.createElement("script");
      s.src = "map-stamp.js?t=" + Date.now();
      s.onload = () => {
        s.remove();
        // 감시 서버가 떠 있으면 실시간 지도로(체크 단추는 거기만 있다)
        if (window.MAP_LIVE_URL) fetch(window.MAP_LIVE_URL + "status", { mode: "no-cors" }).then(() => location.replace(window.MAP_LIVE_URL + location.hash)).catch(() => {});
        if (!first && window.MAP_STAMP && window.MAP_STAMP !== D.stamp) location.reload();
      };
      s.onerror = () => s.remove();
      document.head.appendChild(s);
    };
    stamp(true);
    setInterval(() => stamp(false), 5000);
  }
}
if (window.MAP_LIVE && !window.MAP_DATA) {
  document.getElementById("status").textContent = ui("지도 자료를 받는 중…");
  fetch("/data").then(r => { if (!r.ok) throw Error("HTTP " + r.status); return r.json(); })
    .then(data => { window.MAP_DATA = data; mountMap(); })
    .catch(error => { document.getElementById("status").textContent = ui("지도 자료를 받지 못했습니다: ") + error; });
} else mountMap();
</script>
</body>
</html>
"""
