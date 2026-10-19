# -*- coding: utf-8 -*-
"""스냅숏 = 현 상태 백업(SPEC-36 5.1). 감시 대상(`codedoc:watch`)을 그대로 복사하고, 파일 해시·수정 시각·심볼 색인을 매니페스트에 적는다."""
import datetime
import hashlib
import os
import shutil
import marshal

from parsing import globs
from parsing import parse_cs
from parsing import parse_py
from parsing import languages, settings
from storage import ledger
from storage import diff as diffmod
from parsing import cache as cachemod

SNAPSHOT_ROOT = ".spec-conformance/Snapshots"
CACHE_ROOT = ".spec-conformance/Cache/index"
REPORT_ROOT = ".spec-conformance/Reports"
ENGINE_DATA = [SNAPSHOT_ROOT + "/**", ".spec-conformance/Cache/**", REPORT_ROOT + "/**",
               ".spec-conformance/History/**"]
PARSERS = {ext: languages.parse for ext in languages.EXTENSIONS}
PARSERS.update({".cs": parse_cs.parse, ".py": parse_py.parse})
PARSER_VERSION = 2
_MIGRATED_INDEX = {}
_SOURCES = {}
_MANIFESTS = {}


def parser_input(rel):
    """언어별 파서 구현 지문. 비심볼 확장자는 자료 입력만 사용한다."""
    ext = os.path.splitext(rel)[1].lower()
    if ext in languages.EXTENSIONS and ext not in ('.cs', '.py'):
        return int(cachemod.POLICY.key('parse.generic', languages.runtime_version(languages.language(rel)))[:15], 16)
    version = cachemod.POLICY.versions.get('parse' + ext)
    return int(version[:15], 16) if version else PARSER_VERSION


def watch_set(root, ds):
    """감시 대상 파일 → 단위(심볼/파일). 엔진 자신의 자료 폴더(스냅숏·캐시·보고서)는 늘 뺀다."""
    include = {}
    exclude = list(ENGINE_DATA)
    for row in ds.of("watch"):
        patterns = globs.split(row.cells["경로"])
        if row.cells["포함"] == "제외":
            exclude.extend(patterns)
        else:
            for p in patterns:
                include[p] = row.cells["단위"]
    config = settings.load(root)
    if config:
        exclude.extend(config.get('exclude', []))
        for folder in config['sources']:
            prefix = '' if folder == '.' else folder.rstrip('/') + '/'
            for selected in config['languages']:
                for ext in settings.EXTENSIONS[selected]: include[prefix + '**/*' + ext] = '심볼'
    # 톱 폴더를 한 번만 순회한다(패턴마다 반복하지 않는다, SPEC-36 6.16). 파일마다 맞는 패턴의 단위를 정한다(심볼 우선).
    patterns = list(include)
    files = {}
    for rel in globs.expand(root, patterns, exclude):
        for p in patterns:
            if globs.to_regex(p).match(rel):
                unit = include[p]
                if files.get(rel) != "심볼":
                    files[rel] = unit
                if unit == "심볼":
                    break
    return files


def read_text(root, rel):
    """파일 글자(BOM 제거)."""
    with open(os.path.join(root, rel), encoding="utf-8-sig", errors="replace") as f:
        return f.read()


def index_file(root, rel, unit, previous=None):
    """파일 하나의 해시·수정 시각·심볼."""
    path = os.path.join(root, rel)
    for attempt in range(3):
        before = os.stat(path)
        with open(path, "rb") as f:
            data = f.read()
        stat = os.stat(path)
        if ((before.st_mtime_ns,before.st_ctime_ns,before.st_size) ==
                (stat.st_mtime_ns,stat.st_ctime_ns,stat.st_size) and len(data) == stat.st_size):
            break
    else:
        raise OSError("저장이 계속 진행 중인 원천: " + rel)
    entry = {"sha256": hashlib.sha256(data).hexdigest(), "mtime": stat.st_mtime,"ctime":stat.st_ctime_ns, "size": len(data),
             "unit": unit, "parser": parser_input(rel), "symbols": [], "error": None}
    parser = PARSERS.get(os.path.splitext(rel)[1].lower())
    text = data.decode("utf-8-sig", errors="replace")
    prior = _SOURCES.get(path)
    edits = diffmod.line_edits(prior[1], text) if prior is not None and previous is not None and prior[0] == previous.get("sha256") else None
    positional = (edits is not None and parser is not None and not previous.get("error")
                  and previous.get('parser') == parser_input(rel)
                  and previous.get("unit") == unit == "심볼"
                  and (not rel.endswith(".cs") or "contextHash" in previous)
                  and diffmod.position_only(prior[1], text, os.path.splitext(rel)[1].lower(), edits))
    if edits is not None:
        entry["delta"] = {"previous": previous["sha256"], "edits": edits, "positionOnly": positional}
    if unit == "심볼" and parser:
        try:
            if positional:
                if "contextHash" in previous:
                    entry["contextHash"] = previous["contextHash"]
                entry["symbols"] = [dict(s,line=diffmod.move_line(s["line"],edits),end=diffmod.move_line(s["end"],edits))
                                    for s in previous.get("symbols", [])]
            else:
                ranged = parse_range(prior[1],text,rel,previous,edits) if edits and rel.endswith(".py") else None
                if ranged is not None:
                    entry["symbols"],entry["delta"]["parseRange"] = ranged
                else:
                    if rel.endswith(".cs"):
                        symbols, entry["contextHash"] = parse_cs.parse_with_context(text, rel)
                        entry["symbols"] = [s.to_dict() for s in symbols]
                    else:
                        entry["symbols"] = [s.to_dict() for s in parser(text, rel)]
        except parse_cs.ParseError as e:
            entry["error"] = "L%d %s" % (e.line, e)
    _SOURCES[path] = (entry["sha256"], text)
    return entry


def parse_range(before, after, rel, previous, edits):
    """Python 최상위 선언 안의 변경만 해당 선언 범위에서 파싱한다. 경계·장식자는 전체 파서로 넘긴다."""
    if previous.get("error") or previous.get("parser") != parser_input(rel):
        return None
    rows = previous.get("symbols",[])
    first,last = edits[0][0],edits[-1][1]
    owner = next((s for s in rows if s["path"] == "-" and s["kind"] in ("method","class")
                  and s["line"]-1 <= first and last <= s["end"]),None)
    if owner is None:
        return None
    old = before.splitlines(keepends=True)
    start,end = owner["line"]-1,owner["end"]
    previous_end = max((s["end"] for s in rows if s["end"] < start+1),default=0)
    if any(line.startswith("@") for line in old[previous_end:start]):
        return None
    # 선언 앞·뒤가 변경 구간에 포함되면 토큰 소속이 달라질 수 있다.
    if any(a < start or b > end or (a == b and a in (start,end)) for a,b,_,_ in edits):
        return None
    new = after.splitlines(keepends=True)
    new_start = diffmod.move_line(start+1,edits)-1
    new_end = end + sum((d-c)-(b-a) for a,b,c,d in edits)
    try:
        parsed = [dict(s.to_dict(),line=s.line+new_start,end=s.end+new_start)
                  for s in parse_py.parse("".join(new[new_start:new_end]),rel)]
    except parse_cs.ParseError as error:
        raise parse_cs.ParseError(str(error),error.line+new_start) from error
    result = [dict(s,line=diffmod.move_line(s["line"],edits),end=diffmod.move_line(s["end"],edits))
              for s in rows if not (start < s["line"] <= end)]
    result.extend(parsed)
    result.sort(key=lambda s:(s["line"],s["end"]))
    return result,(start,end,new_start,new_end)


def current(root, ds, cache=True, previous=None, watched=None, changed_paths=None):
    """파일별 색인 조각. 같은 원천 입력은 재사용하고 변경·추가 파일의 조각만 원자적으로 교체한다."""
    scoped = cache and isinstance(previous,ledger.SourceIndex) and changed_paths is not None
    out, live = (previous.copy() if scoped else {}), set()
    folder = os.path.join(root, CACHE_ROOT)
    if cache:
        os.makedirs(folder, exist_ok=True)
    watched = watch_set(root, ds) if watched is None else watched
    if scoped:
        for rel in set(out) - set(watched):
            del out[rel]
    selected = ((rel,watched[rel]) for rel in changed_paths if rel in watched) if scoped else watched.items()
    for rel, unit in selected:
        shard = CACHE_ROOT + "/" + rel + ".row"
        if (cache and changed_paths is not None and rel not in changed_paths and rel in (previous or {})
                and previous[rel].get("unit") == unit and previous[rel].get("parser") == parser_input(rel)
                and (not rel.endswith(".cs") or "contextHash" in previous[rel])):
            out[rel] = previous[rel]
            live.add(shard)
            continue
        try:
            st = os.stat(os.path.join(root, rel))
        except FileNotFoundError:
            if scoped and rel in out:
                del out[rel]
            continue
        live.add(shard)
        prev = (previous or {}).get(rel) if cache else None
        if cache and prev is None:
            saved = ledger.read_table(root, shard, {})
            if isinstance(saved, dict) and saved.get("file") == rel:
                prev = saved.get("entry")
                if isinstance(saved.get("source"), str):
                    _SOURCES[os.path.join(root,rel)] = (prev.get("sha256"),saved["source"])
        reusable = (isinstance(prev, dict) and prev.get("mtime") == st.st_mtime
                    and prev.get("ctime") == st.st_ctime_ns
                    and prev.get("size") == st.st_size and prev.get("unit") == unit
                    and prev.get("parser") == parser_input(rel)
                    and (not rel.endswith(".cs") or "contextHash" in prev)
                    and (changed_paths is None or rel not in changed_paths))
        if cache and not reusable and prev is not None and os.path.join(root, rel) not in _SOURCES:
            saved = ledger.read_table(root, shard, {})
            if (saved.get("file") == rel and saved.get("entry", {}).get("sha256") == prev.get("sha256")
                    and isinstance(saved.get("source"), str)):
                _SOURCES[os.path.join(root, rel)] = (prev["sha256"], saved["source"])
        out[rel] = prev if reusable else index_file(root, rel, unit, prev)
        path = os.path.join(root,rel)
        missing_source = path not in _SOURCES
        if missing_source:
            with open(path, "rb") as stream:
                source = stream.read()
            if hashlib.sha256(source).hexdigest() != out[rel]["sha256"]:
                out[rel] = index_file(root,rel,unit,prev)
                reusable = False
            else:
                _SOURCES[path] = (out[rel]["sha256"],source.decode("utf-8-sig",errors="replace"))
        if cache and (not reusable or missing_source):
            ledger.write_table(root, shard, {"file": rel, "entry": out[rel], "source": _SOURCES[path][1]})
    if cache and (changed_paths is None or previous is None or out.keys() != previous.keys()):
        ledger.prune_tables(root, CACHE_ROOT, live)
    return out


def release(root):
    """닫힌 프로젝트의 원천 텍스트와 캡처 파서 캐시를 반환한다."""
    prefix = os.path.abspath(root) + os.sep
    for path in list(_SOURCES):
        if os.path.abspath(path).startswith(prefix):
            del _SOURCES[path]
    for key in list(_MIGRATED_INDEX):
        if os.path.abspath(key[0]).startswith(prefix):
            del _MIGRATED_INDEX[key]
    for path in list(_MANIFESTS):
        if os.path.abspath(path).startswith(prefix):
            del _MANIFESTS[path]


def take(root, ds, label):
    """스냅숏을 뜬다. 돌려주는 값: 스냅숏 폴더 이름."""
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    name = stamp + ("-" + label if label else "")
    folder = os.path.join(root, SNAPSHOT_ROOT, name)
    os.makedirs(os.path.join(folder, "files"), exist_ok=False)
    files = current(root, ds, cache=False)
    for rel in files:
        target = os.path.join(folder, "files", rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(os.path.join(root, rel), target)
    manifest = {"name": name, "label": label, "created": stamp, "files": files}
    ledger.write_binary(root, SNAPSHOT_ROOT + "/" + name + "/manifest.bin", manifest)
    return name


def record(root, name, keys):
    """스냅숏 매니페스트에 그때의 지적 열쇠 목록을 적는다."""
    rel = SNAPSHOT_ROOT + "/" + name + "/manifest.bin"
    manifest = ledger.read_binary(root, rel, None)
    if manifest is None: raise FileNotFoundError(rel)
    manifest["findings"] = sorted(set(keys))
    ledger.write_binary(root, rel, manifest)


def names(root):
    """스냅숏 이름 목록(오래된 것부터). 이름의 시각(초까지)이 같으면 매니페스트를 쓴 시각으로 가른다 — 이름표 글자 순서로 가르지 않는다."""
    base = os.path.join(root, SNAPSHOT_ROOT)
    if not os.path.isdir(base):
        return []
    found = [d for d in os.listdir(base) if os.path.isfile(os.path.join(base, d, "manifest.bin"))]
    return sorted(found, key=lambda d: (d[:15], os.path.getmtime(os.path.join(base, d, "manifest.bin")), d))


def load(root, name=None):
    """스냅숏 매니페스트. 이름이 없으면 가장 최근. 없으면 None."""
    all_names = names(root)
    if not all_names:
        return None
    if name is None:
        name = all_names[-1]
    elif name not in all_names:
        matches = [n for n in all_names if n.endswith("-" + name) or n.startswith(name)]
        if not matches:
            raise SystemExit("스냅숏을 찾지 못함: %s" % name)
        name = matches[-1]
    folder = os.path.join(root, SNAPSHOT_ROOT, name)
    path = os.path.join(folder,"manifest.bin")
    stat = os.stat(path)
    shape = (stat.st_mtime_ns,stat.st_ctime_ns,stat.st_size,PARSER_VERSION, parser_input('x.cs'), parser_input('x.py'))
    saved = _MANIFESTS.get(path)
    if saved is not None and saved[0] == shape:
        return marshal.loads(saved[1])
    manifest = ledger.read_binary(root, SNAPSHOT_ROOT + "/" + name + "/manifest.bin", None)
    # 저장 당시 파서의 결함을 코드 변경으로 오인하지 않는다. 캡처한 원본을
    # 현재 파서로 다시 읽되, 스냅숏·기준 파일·승인 이력은 수정하지 않는다.
    captured = os.path.join(folder, "files")
    for rel, entry in manifest.get("files", {}).items():
        if (entry.get("unit") != "심볼" or entry.get("parser") == parser_input(rel)
                or os.path.splitext(rel)[1].lower() not in PARSERS):
            continue
        path = os.path.join(captured, rel)
        st = os.stat(path)
        key = (path, st.st_mtime_ns, st.st_size, entry["sha256"], PARSER_VERSION, parser_input(rel))
        if key not in _MIGRATED_INDEX:
            cache_path = '.spec-conformance/Cache/snapshot-index/' + name + '/' + rel + '.row'
            stored = ledger.read_table(root, cache_path, {})
            parsed = stored.get('entry', {}) if stored.get('file') == rel else {}
            valid = (parsed.get('sha256') == entry['sha256'] and parsed.get('parser') == parser_input(rel)
                     and parsed.get('unit') == entry['unit'] and isinstance(parsed.get('symbols'), list)
                     and parsed.get('mtime') == st.st_mtime and parsed.get('ctime') == st.st_ctime_ns
                     and parsed.get('size') == st.st_size)
            if not valid:
                parsed = index_file(captured, rel, entry["unit"])
            if parsed["sha256"] != entry["sha256"]:
                raise ValueError("기준 스냅숏 원본 해시가 다릅니다: " + rel)
            if not valid:
                ledger.write_table(root, cache_path, {'file':rel, 'entry':parsed})
            _MIGRATED_INDEX[key] = {k: parsed[k] for k in ("parser", "symbols", "error", "contextHash") if k in parsed}
        manifest["files"][rel] = dict(entry, **_MIGRATED_INDEX[key])
    _MANIFESTS[path] = (shape,marshal.dumps(manifest))
    return manifest
