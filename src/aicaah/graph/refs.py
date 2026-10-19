# -*- coding: utf-8 -*-
"""참조 그래프(SPEC-36 2.8.1·2.8.2·2.8.5). 계층·환경·진입점 표로 컴파일 단위 작업 파일을 만들고, C# 추출기(RefGraph.cs)를
빌드·실행·캐시한다. 파이썬은 ast로 같은 형식의 선언·참조를 만든다. 판정은 하지 않는다(layers.py)."""
import ast
import marshal
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

from parsing import globs
from parsing import cache as cachemod
from storage import ledger, wire, reference_store
from storage import diff as diffmod

HERE = os.path.dirname(os.path.abspath(__file__))
UNITY_DEFAULT = "C:/Program Files/Unity/Hub/Editor/2022.3.62f3/Editor"
TOOL_ENV = "닷넷"
TOOL_VERSION = 1
TOOL_SOURCE = os.path.join(HERE, "RefGraph", "RefGraph.cs")
TOOL_DIR = ".spec-conformance/Cache/refgraph"
PYTHON_RECORDS = reference_store.PYTHON_RECORDS
_SOURCE_RECORDS = {}


def source_records(rel, entry):
    """원천 선언의 안정된 자리 ID와 문서 별칭. 줄 이동은 ID를 바꾸지 않는다."""
    symbols = entry.get("symbols") or []
    fingerprint = cachemod.POLICY.key('source-records',
        [rel, entry.get("sha256"), symbols, entry.get("unit"), entry.get("error")])
    saved = _SOURCE_RECORDS.get(rel)
    if saved is not None and saved[0] == fingerprint:
        return saved[1]
    totals, seen, result = {}, {}, []
    for s in symbols:
        path = s.get("path") or "-"
        alias = rel + "#" + (s["name"] if path == "-" else path + "." + s["name"])
        totals[alias] = totals.get(alias, 0) + 1
    for s in symbols:
        path = s.get("path") or "-"
        alias = rel + "#" + (s["name"] if path == "-" else path + "." + s["name"])
        generic = next((m.group(2) for m in re.finditer(r"\b(\w+)\s*(<[^>]+>)", s.get("signature", ""))
                        if m.group(1) == s["name"]), "")
        modes = tuple(re.findall(r"\b(ref|out|in)\s+", s.get("signature", "")))
        identity = (path, s.get("kind"), s.get("name"), s.get("params", ""), generic, modes)
        digest = hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()[:20]
        ordinal = seen.get(digest, 0)
        seen[digest] = ordinal + 1
        occurrence = rel + "#" + digest + ":" + str(ordinal)
        key = alias if totals[alias] == 1 else alias + "@" + digest + ":" + str(ordinal)
        result.append((s, key, occurrence, alias))
    _SOURCE_RECORDS[rel] = (fingerprint, result)
    return result


def bind_sources(graph, cur):
    """의미 선언을 같은 파일·종류·이름·선언 범위의 원천에 연결한다. 모호하면 연결하지 않는다."""
    inputs = tuple((rel, entry.get("sha256") or json.dumps(entry.get("symbols", []), sort_keys=True),
                    entry.get("unit"), entry.get("error")) for rel, entry in sorted((cur or {}).items()))
    if getattr(graph, "_binding_inputs", None) == inputs:
        return graph._bindings
    candidates, result = {}, {}
    for rel in _SOURCE_RECORDS.keys() - (cur or {}).keys():
        del _SOURCE_RECORDS[rel]
    for rel, entry in (cur or {}).items():
        for record in source_records(rel, entry):
            s = record[0]
            candidates.setdefault((rel, s.get("kind"), s.get("name")), []).append(record)
    for i, d in enumerate(graph.decls):
        if "kind" not in d or not 0 <= d.get("file", -1) < len(graph.files):
            continue
        occurrences = d.get("occurrences") or [{"file": graph.files[d["file"]], "line": d.get("line", 0), "end": d.get("end", 0)}]
        bound = []
        for part in occurrences:
            name = d.get("source_name", d["name"])
            if "source_name" not in d and d["kind"] == "ctor" and d.get("container", -1) >= 0:
                name = graph.decls[d["container"]].get("name", name)
            if d["kind"] == "indexer":
                name = "this"
            kind = "enum-member" if d["kind"] == "field" and d.get("container", -1) >= 0 and graph.decls[d["container"]].get("kind") == "enum" else d["kind"]
            hits = [r for r in candidates.get((part["file"], kind, name), ())
                    if part["line"] <= r[0].get("line", 0) <= part["end"]
                    and r[0].get("end", 0) == part["end"]]
            if "source_params" in d:
                params = re.sub(r"(^|,)\s*(?:ref|out|in)\s+", r"\1", d["source_params"])
                hits = [r for r in hits if re.sub(r"\s+", "", r[0].get("params", "")) == re.sub(r"\s+", "", params)]
                if len(hits) > 1:
                    modes = re.findall(r"\b(ref|out|in)\s+", d["source_params"])
                    hits = [r for r in hits if re.findall(r"\b(ref|out|in)\s+", r[0].get("signature", "")) == modes]
            if len(hits) > 1:
                arity = re.search(r"`+(\d+)$", d["key"].split("@", 1)[0].split("(", 1)[0])
                count = int(arity.group(1)) if arity else 0
                hits = [r for r in hits if (lambda generic: generic.group(1).count(",") + 1 if generic else 0)(
                    re.search(r"\b" + re.escape(name) + r"\s*<([^>]+)>", r[0].get("signature", ""))) == count]
            if len(hits) == 1:
                bound.append(hits[0])
        if bound:
            result[i] = tuple(bound)
    graph._binding_inputs, graph._bindings = inputs, result
    return result


@dataclass
class Layer:
    """계층 표 한 행(SPEC-00 6.8.1 layers)."""
    name: str
    paths: list
    refs: list
    interface_only: set
    unit: str
    env: str
    doc: str
    line: int


@dataclass
class Graph:
    """선언·참조. decls는 dict(key·name·kind·file·line·end·container·access·mods·attrs·bases·hash·stmts·type),
    edges는 [출발, 대상, 파일, 줄, 쓰기], overrides는 [구현, 대상(-1 = 외부), 외부], strings는 [출발, 파일, 줄, API, 이름, 받는 형],
    unresolved는 해석되지 않은 형 이름 꼴 [출발, 파일, 줄, 이름]."""
    files: list = field(default_factory=list)
    lookup_users: dict = field(default_factory=dict)
    compilations: list = field(default_factory=list)
    execution_edges: set = field(default_factory=set)
    decls: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    overrides: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    unresolved: list = field(default_factory=list)
    units: list = field(default_factory=list)
    diagnostics: list = field(default_factory=list)
    error: str = ""
    guessed: set = field(default_factory=set)
    positions: dict = field(default_factory=dict, compare=False, repr=False)


def unity_path(value=None):
    """Unity 에디터 폴더: 인자, 환경 변수 AIKA_UNITY_EDITOR, UNITY_DEFAULT 순."""
    return (value or os.environ.get("AIKA_UNITY_EDITOR") or UNITY_DEFAULT).replace("\\", "/").rstrip("/")


def layers(ds):
    """계층 표 행(표 순서 = 우선순위). 참조 칸의 `이름(인터페이스)`는 인터페이스만 쓰는 계층."""
    out = []
    for r in ds.of("layers"):
        names, only = [], set()
        for item in [x.strip() for x in r.cells["참조"].split(",") if x.strip() and x.strip() != "-"]:
            if item.endswith("(인터페이스)"):
                item = item[:-len("(인터페이스)")].strip()
                only.add(item)
            names.append(item)
        out.append(Layer(r.cells["계층"], globs.split(r.cells["경로"]), names, only, r.cells["단위"],
                         r.cells["환경"], r.doc, r.line))
    return out


def layer_of(rel, rows):
    """파일의 계층(위에서부터 처음 경로가 맞는 행). 없으면 None."""
    for layer in rows:
        if globs.matches(rel, layer.paths):
            return layer
    return None


def environments(ds):
    """환경 이름 → (참조 경로 목록, 정의 기호 목록)."""
    out = {}
    for r in ds.of("env"):
        defines = [x.strip() for x in r.cells["정의"].replace(",", ";").split(";") if x.strip() and x.strip() != "-"]
        out[r.cells["환경"]] = (globs.split(r.cells["참조"]), defines)
    return out


def expand_refs(root, unity, patterns):
    """참조 경로를 파일로 푼다. `{unity}`는 Unity 폴더, `!`로 시작하면 뺀다. 순서를 지키고 겹침은 뺀다."""
    def resolve(p):
        p = p.replace("{unity}", unity)
        return p if os.path.isabs(p) else os.path.join(root, p)

    def norm(p):
        return os.path.normcase(os.path.normpath(p))
    drop = set()
    for p in patterns:
        if p.startswith("!"):
            drop.update(norm(x) for x in glob.glob(resolve(p[1:])))
    keep, seen = [], set()
    for p in patterns:
        if p.startswith("!"):
            continue
        for x in sorted(glob.glob(resolve(p))):
            if norm(x) not in drop and norm(x) not in seen and is_managed(x):
                seen.add(norm(x))
                keep.append(os.path.normpath(x))
    return keep


def is_managed(path):
    """관리 어셈블리인가(PE 선택 헤더의 CLR 런타임 헤더 디렉터리가 비어 있지 않음). 네이티브 DLL은 참조에서 뺀다."""
    try:
        with open(path, "rb") as f:
            data = f.read(4096)
        pe = int.from_bytes(data[0x3C:0x40], "little")
        if data[pe:pe + 4] != b"PE\0\0":
            return False
        opt = pe + 24
        magic = int.from_bytes(data[opt:opt + 2], "little")
        dirs = opt + (96 if magic == 0x10B else 112)
        clr = dirs + 14 * 8
        return int.from_bytes(data[clr:clr + 4], "little") != 0
    except (OSError, ValueError):
        return False


def _fixed_head(pattern):
    """경로 패턴의 고정 머리(첫 와일드카드 앞 마지막 `/`까지)."""
    head = pattern.split("*")[0].split("?")[0].split("[")[0]
    return head.rsplit("/", 1)[0] + "/" if "/" in head else ""


def _units(rows, files_by_layer):
    """계층마다 단위(하나·폴더·파일)로 걷는 C# 파일을 나눈다."""
    out = []
    for layer in rows:
        own = [f for f in files_by_layer.get(layer.name, []) if f.endswith(".cs")]
        if not own:
            continue
        if layer.unit == "하나":
            out.append((layer, layer.name, own))
        elif layer.unit == "폴더":
            groups = {}
            for f in own:
                head = next((_fixed_head(p) for p in layer.paths if globs.matches(f, [p])), "")
                rest = f[len(head):]
                groups.setdefault(rest.split("/", 1)[0] if "/" in rest else "", []).append(f)
            for g in sorted(groups):
                out.append((layer, "%s/%s" % (layer.name, g), groups[g]))
        else:
            for f in own:
                out.append((layer, "%s/%s" % (layer.name, f), [f]))
    return out


def job(root, ds, cur, unity, only_files=None):
    """작업 파일(dict). 문맥 파일을 그 계층 환경과 다른 환경에서 처음 만나면 그 단위에서 걷는다(2.8.2)."""
    rows = layers(ds)
    envs = environments(ds)
    files_by_layer = {}
    for rel, entry in sorted(cur.summaries() if isinstance(cur,ledger.SourceIndex) else cur.items()):
        if entry.get("unit") != "심볼":
            continue
        layer = layer_of(rel, rows)
        if layer is not None:
            files_by_layer.setdefault(layer.name, []).append(rel)
    strings = {}
    for r in ds.of("entries"):
        if r.cells["종류"] == "문자열":
            receiver, _, apis = r.cells["대상"].partition(":")
            strings.setdefault(receiver.strip(), set()).update(globs.split(apis))
    walked = {(f, layer.env) for layer in rows for f in files_by_layer.get(layer.name, [])}
    units = []
    expanded_refs = {}
    explicit = {r.cells["검사 파일"]: globs.split(r.cells["컴파일 입력"])
                for r in ds.of("compilation")}
    units_by_owner = []
    for layer, name, own in _units(rows, files_by_layer):
        selected = [rel for rel in own if rel in explicit]
        for rel in selected:
            units_by_owner.append((layer, layer.name + "/" + rel, [rel]))
        remaining = [rel for rel in own if rel not in explicit]
        if remaining:
            units_by_owner.append((layer, name, remaining))
    for layer, name, own in units_by_owner:
        if layer.env not in envs:
            continue
        refs, defines = envs[layer.env]
        if layer.env not in expanded_refs:
            expanded_refs[layer.env] = expand_refs(root, unity, refs)
        context, extra = [], []
        if len(own) == 1 and own[0] in explicit:
            patterns = explicit[own[0]]
            inputs = sorted(f for f in cur if f.endswith(".cs") and globs.matches(f, patterns))
            missing = [p for p in patterns if not any(globs.matches(f, [p]) for f in inputs)]
            if missing or own[0] not in inputs:
                raise ValueError("검사 컴파일 입력 누락: " + own[0] + ": " + ", ".join(missing))
            units.append({"name": name, "defines": defines, "refs": expanded_refs[layer.env],
                          "walk": inputs, "context": [], "owners": own})
            continue
        for ref in layer.refs:
            for f in files_by_layer.get(ref, []):
                if not f.endswith(".cs"):
                    continue
                if (f, layer.env) not in walked:
                    walked.add((f, layer.env))
                    extra.append(f)
                else:
                    context.append(f)
        units.append({"name": name, "defines": defines, "refs": expanded_refs[layer.env],
                      "walk": own + extra, "context": context})
    if only_files is not None:
        import copy
        variant_inputs = {r.cells["검사 파일"]:set(globs.split(r.cells["변환 입력"])) |
                          {r.cells["실행 입구"],r.cells["변환기"]} for r in ds.of("compile_variant")}
        units = [u for u in units if (set(u["walk"] + u["context"]) |
                 set().union(*(variant_inputs.get(f,set()) for f in u["walk"]))) & set(only_files)]
        selected_ds = copy.copy(ds)
        owners = {f for u in units for f in u["walk"]}
        selected_ds.rows = [r for r in ds.of('compile_variant') if r.cells["검사 파일"] in owners]
    else:
        selected_ds = ds
    units = compile_variants(root, selected_ds, cur, units)
    return {"root": root, "strings": [{"receiver": k, "apis": sorted(v)} for k, v in sorted(strings.items())], "units": units}


def python_inputs(root, script):
    root = os.path.realpath(root)
    pending = [os.path.realpath(os.path.join(root, script))]
    visited = set()
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        if os.path.commonpath([root, path]) != root or not os.path.isfile(path):
            raise ValueError("Python transform input outside project or missing: " + path)
        visited.add(path)
        tree = ast.parse(open(path, encoding="utf-8-sig").read(), filename=path)
        for node in ast.walk(tree):
            names = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                     else [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            for name in names:
                candidate = os.path.realpath(os.path.join(os.path.dirname(path), name.replace(".", os.sep) + ".py"))
                if os.path.commonpath([root, candidate]) == root and os.path.isfile(candidate):
                    pending.append(candidate)
    return sorted(os.path.relpath(path, root).replace(os.sep, "/") for path in visited)


def compile_variants(root, ds, cur, units):
    """실제 러너의 변환 입력을 별도 분석 단위로 재현한다. 원본·운영 컴파일은 수정하지 않는다."""
    result = [dict(unit, sourceOverrides=[], variantKey="") for unit in units]
    for row in ds.of("compile_variant"):
        owner, runner, script = (row.cells[key] for key in ("검사 파일", "실행 입구", "변환기"))
        sources = globs.split(row.cells["변환 입력"])
        base = next((u for u in units if owner in u["walk"]), None)
        if base is None:
            raise ValueError("변환 검사 소유 컴파일 단위 없음: " + owner)
        for rel in [runner, script] + sources:
            absolute = os.path.realpath(os.path.join(root, rel))
            if os.path.commonpath([os.path.realpath(root), absolute]) != os.path.realpath(root) or not os.path.isfile(absolute):
                raise ValueError("변환 검사 입력 없음 또는 프로젝트 밖: " + rel)
        runner_text = open(os.path.join(root, runner), encoding="utf-8-sig").read()
        if (not runner.endswith(".ps1") or not script.endswith(".py")
                or not re.search(r"&\s+python\s+[^\n]*" + re.escape(os.path.basename(script)), runner_text)
                or any(os.path.basename(rel) not in runner_text for rel in sources)):
            raise ValueError("실행 입구에 변환기·대상 입력 근거 없음: " + runner)
        defines = globs.split(row.cells["정의"])
        if any(define not in runner_text for define in defines):
            raise ValueError("실행 입구에 변환 정의 근거 없음: " + runner)
        if any(rel not in base["walk"] + base["context"] for rel in sources):
            raise ValueError("변환 대상이 원래 컴파일 입력에 없음: " + owner)
        hashes = []
        for rel in list(dict.fromkeys([runner] + python_inputs(root, script) + sources)):
            hashes.append((rel, hashlib.sha256(open(os.path.join(root, rel), "rb").read()).hexdigest()))
        digest = hashlib.sha256(json.dumps([hashes, defines], sort_keys=True).encode()).hexdigest()
        identity = hashlib.sha256((root + "|" + owner).encode()).hexdigest()
        folder = os.path.join(root, TOOL_DIR, "variants", identity)
        os.makedirs(folder, exist_ok=True)
        overrides = []
        for i, rel in enumerate(sources):
            copy = os.path.join(folder, str(i) + ".cs")
            ready = copy + ".ready"
            stamp = open(ready, encoding="ascii").read() if os.path.isfile(ready) else ""
            if stamp != digest or not os.path.isfile(copy):
                shutil.copyfile(os.path.join(root, rel), copy)
                transform_env = dict(os.environ)
                transform_env.pop("AIKA_FIELD_ONLY", None)
                code, text = _run([sys.executable, os.path.join(root, script), copy, os.path.basename(rel)], env=transform_env)
                if code:
                    raise ValueError("시험 변환 실패: " + rel + ": " + text[-400:])
                with open(ready, "w", encoding="ascii") as stream:
                    stream.write(digest)
            overrides.append({"file": rel, "source": copy})
        variant = dict(base, name=base["name"] + "/variant/" + hashlib.sha256(owner.encode()).hexdigest()[:12],
                       defines=list(dict.fromkeys(base["defines"] + defines)), sourceOverrides=overrides,
                       variantKey=digest, walk=list(dict.fromkeys(base["walk"] + base["context"])),
                       context=[], reachOnly=True)
        variant.pop("owners", None)
        result.append(variant)
    return result


def _run(cmd, env=None):
    """명령을 돌려 (종료 코드, 출력). Windows의 분석 자식 프로세스는 콘솔 창을 만들지 않는다."""
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                       creationflags=flags, env=env)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def build_tool(root, ds, unity):
    """추출기를 `닷넷` 환경으로 컴파일한다(원본 해시가 같으면 건너뜀). 참조 DLL 중 런타임 폴더(System.Runtime.dll이 있는 곳)
    밖의 것은 곁에 복사한다. 돌려주는 값: (dll 경로, 원본 해시, 오류 글자)."""
    envs = environments(ds)
    if TOOL_ENV not in envs:
        return None, "", "환경 표에 '%s' 행이 없음" % TOOL_ENV
    with open(TOOL_SOURCE, "rb") as f:
        digest = hashlib.sha256(f.read() + str(TOOL_VERSION).encode()).hexdigest()
    os.makedirs(os.path.join(root, TOOL_DIR), exist_ok=True)
    dll = os.path.join(root, TOOL_DIR, "RefGraph.dll")
    stamp = os.path.join(root, TOOL_DIR, "tool.hash")
    if os.path.exists(dll) and os.path.exists(stamp):
        with open(stamp) as f:
            if f.read().strip() == digest:
                return dll, digest, ""
    refs = expand_refs(root, unity, envs[TOOL_ENV][0])
    if not refs:
        return None, "", "추출기 참조 DLL을 찾지 못함(Unity 폴더: %s)" % unity
    dotnet = os.path.join(unity, "Data", "NetCoreRuntime", "dotnet.exe")
    csc = os.path.join(unity, "Data", "DotNetSdkRoslyn", "csc.dll")
    rsp = os.path.join(root, TOOL_DIR, "build.rsp")
    lines = ["-nologo", "-nostdlib+", "-preferreduilang:en-US", "-target:exe", "-langversion:latest", "-optimize+",
             '-out:"%s"' % dll] + ['-r:"%s"' % r for r in refs] + ['"%s"' % TOOL_SOURCE]
    with open(rsp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    code, out = _run([dotnet, csc, "@" + rsp])
    if code != 0:
        return None, "", "추출기 컴파일 실패: " + " ".join(out.split())[:400]
    runtime = next((os.path.dirname(r) for r in refs if os.path.basename(r).lower() == "system.runtime.dll"), None)
    version = os.path.basename(runtime) if runtime else "6.0.0"
    with open(os.path.join(root, TOOL_DIR, "RefGraph.runtimeconfig.json"), "w", encoding="utf-8") as f:
        json.dump({"runtimeOptions": {"tfm": "net6.0", "framework": {"name": "Microsoft.NETCore.App", "version": version}}}, f)
    for r in refs:
        if runtime is None or os.path.normcase(os.path.dirname(r)) != os.path.normcase(runtime):
            shutil.copy2(r, os.path.join(root, TOOL_DIR, os.path.basename(r)))
    with open(stamp, "w") as f:
        f.write(digest)
    return dll, digest, ""


def declaration_hash(entry):
    """파일의 선언 시그니처(본문 제외) 해시. 문맥 파일은 선언만 해석에 쓰므로 본문이 바뀌어도 단위를 다시 돌리지 않는다."""
    items = sorted("%s|%s|%s|%s" % (s.get("path"), s.get("kind"), s.get("name"), s.get("signature"))
                   for s in (entry or {}).get("symbols", []))
    items.append("context:" + (entry or {}).get("contextHash", (entry or {}).get("sha256", "")))
    return hashlib.sha256("\n".join(items).encode("utf-8")).hexdigest()


def unit_key(unit, cur, tool_hash, strings, memo=None):
    """단위 결과 캐시 열쇠: 추출기 해시·정의·문자열 API·참조 DLL(크기·시각)·걷는 파일 해시·문맥 파일 선언 해시."""
    memo = {} if memo is None else memo
    h = hashlib.sha256()
    h.update(json.dumps([tool_hash, unit["name"], unit["defines"], strings], ensure_ascii=False).encode("utf-8"))
    h.update(unit.get("variantKey", "").encode("ascii"))
    for r in unit["refs"]:
        key = ("ref", r)
        if key not in memo:
            try:
                st = os.stat(r)
                memo[key] = ("%s|%d|%d" % (r, st.st_size, int(st.st_mtime))).encode("utf-8")
            except OSError:
                memo[key] = r.encode("utf-8")
        h.update(memo[key])
    for rel in unit["walk"]:
        entry = dict.get(cur,rel,{}) if isinstance(cur,ledger.SourceIndex) else cur.get(rel,{})
        h.update(("W|%s|%s" % (rel, entry.get("sha256", ""))).encode("utf-8"))
    for rel in unit["context"]:
        key = ("decl", rel)
        if key not in memo:
            memo[key] = declaration_hash(cur.get(rel))
        h.update(("C|%s|%s" % (rel, memo[key])).encode("utf-8"))
    return h.hexdigest()


def csharp(root, ds, cur, unity, cache=None, only_files=None):
    """C# 참조 그래프. 단위마다 결과를 캐시하고, 열쇠가 바뀐 단위만 추출기로 다시 돌린 뒤 열쇠로 합친다."""
    graph = Graph()
    cache = {} if cache is None else cache
    if cache.get("scope") != (root, unity):
        cache.clear()
        cache["scope"] = (root, unity)
    if not ds.of("layers") or not ds.of("env"):
        return cache.setdefault("empty", graph)
    try:
        work = job(root, ds, cur, unity,only_files)
    except (ValueError, OSError) as exc:
        graph.error = str(exc)
        return graph
    if not work["units"]:
        return cache.setdefault("empty", graph)
    dll, tool_hash, error = build_tool(root, ds, unity)
    if error:
        graph.error = error
        return graph
    units_folder = ".spec-conformance/Cache/refgraph/units"
    results, stale, memo, live = {}, [], {}, set()
    previous = cache.get("units", {})
    keys = []
    for u in work["units"]:
        key = unit_key(u, cur, tool_hash, work["strings"], memo)
        keys.append((u["name"], key))
        rel = units_folder + "/" + u["name"] + ".row"
        live.add(rel)
        saved = previous.get(u["name"])
        if saved is not None and saved[0] == key:
            results[u["name"]] = saved[1]
            continue
        stored = reference_store.compilation_input(root, rel, u["name"])
        if stored == key:
            results[u["name"]] = {"root": root, "record": rel, "input": key}
            continue
        output = os.path.join(root, TOOL_DIR, hashlib.sha1((root + "|" + u["name"]).encode("utf-8")).hexdigest() + ".tmp")
        stale.append(dict(u, out=output, key=key, path=rel))
    if stale:
        job_path = os.path.join(root, TOOL_DIR, "job.bin")
        try:
            wire.write(job_path, dict(work, units=stale))
            dotnet = os.path.join(unity, "Data", "NetCoreRuntime", "dotnet.exe")
            code, text = _run([dotnet, dll, job_path])
            if code != 0:
                graph.error = "추출기 실행 실패: " + " ".join(text.split())[:400]
                return graph
            for u in stale:
                data = wire.read(u["out"])
                data["inputKey"] = u["key"]
                ledger.write_table(root, u["path"], {"file": u["name"], "input": u["key"], "data": data})
                results[u["name"]] = {"root": root, "record": u["path"], "input": u["key"]}
                del data
        finally:
            for path in [job_path] + [u["out"] for u in stale]:
                if os.path.isfile(path): os.remove(path)
    if cache.get("keys") == keys and "graph" in cache:
        return cache["graph"]
    if only_files is None:
        ledger.prune_tables(root, units_folder, live)
    merger = _Merger(graph)
    for u in work["units"]:
        packed = results[u["name"]]
        data = compilation_data({"data": packed},owners=u.get("owners"),summary=bool(u.get("reachOnly")))
        if u.get("reachOnly"):
            # 시험 복사본 호출은 해당 컴파일 안에서 도달 여부를 판정한다.
            # 원본 앱 그래프에 주입해 앱→시험 계층의 허위 의존을 만들지 않는다.
            graph.compilations.append({"owners": list(u["walk"]), "files": list(data["files"]),
                                       "inputKey": data.get("inputKey"), "data": packed,
                                       "variant": u["name"]})
            graph.diagnostics.extend(data.get("diagnostics", []))
        else:
            merger.add(data, u.get("owners"), packed)
    cache.update(units={name: (key, results[name]) for name, key in keys}, keys=keys, graph=graph)
    return graph


def compilation_data(compilation, owners=None, summary=False):
    """Restore one compilation on demand from its owned DB; validate the captured input."""
    source = compilation["data"]
    if isinstance(source, bytes):
        data=marshal.loads(source)
        return {key:data.get(key,[]) for key in ("inputKey","files","diagnostics")} if summary else data
    if summary:
        return reference_store.compilation_summary(source["root"], source["record"], source["input"])
    record = ledger.read_table(source["root"], source["record"], {},owners=owners)
    data = record.get("data")
    if record.get("input") != source["input"] or not isinstance(data, dict) or data.get("inputKey") != source["input"]:
        raise ValueError("Compilation record changed or missing: " + source["record"])
    return data


def compilation_fingerprint(compilation):
    """Use the extraction input key; relocated transient records use their exact payload hash."""
    source = compilation["data"]
    return hashlib.sha256(source).digest() if isinstance(source, bytes) else source["input"]


class _Merger:
    """단위 결과를 열쇠로 합친다. 같은 열쇠의 선언은 먼저 채운 것을 쓰고, 참조는 겹치지 않게 더한다."""

    def __init__(self, graph):
        """빈 그래프와 번호 표."""
        self.graph = graph
        self.decl_no, self.file_no, self.edge_set = {}, {}, set()

    def _file(self, rel):
        """전체 파일 번호."""
        if rel not in self.file_no:
            self.file_no[rel] = len(self.graph.files)
            self.graph.files.append(rel)
        return self.file_no[rel]

    def _decl(self, key):
        """전체 선언 번호(처음 보는 열쇠는 자리만 만든다)."""
        if key not in self.decl_no:
            self.decl_no[key] = len(self.graph.decls)
            self.graph.decls.append({"key": key})
        return self.decl_no[key]

    def add(self, data, owners=None, packed=None):
        """단위 결과 하나(파일·선언 번호는 그 결과 안의 번호)."""
        g = self.graph
        if owners is not None:
            g.compilations.append({"owners": list(owners), "files": list(data["files"]),
                                   "inputKey": data.get("inputKey"),
                                   "data": packed if packed is not None else marshal.dumps(data)})
        files = [self._file(f) for f in data["files"]]
        local = [self._decl(d["key"]) for d in data["decls"]]
        for k, d in enumerate(data["decls"]):
            i = local[k]
            if "kind" in d and "kind" not in g.decls[i]:
                info = dict(d)
                info["file"] = files[d["file"]]
                info["container"] = local[d["container"]] if d["container"] >= 0 else -1
                g.decls[i] = info
            elif "kind" in d:
                g.decls[i]["bases"] = list(dict.fromkeys(g.decls[i].get("bases", []) + d.get("bases", [])))
                parts = g.decls[i].setdefault("occurrences", [])
                for part in d.get("occurrences", []):
                    if part not in parts:
                        parts.append(part)
        for e in data["edges"]:
            if owners is not None and data["files"][e[2]] not in owners:
                continue
            t = (local[e[0]], local[e[1]], files[e[2]], e[3], e[4])
            if t not in self.edge_set:
                self.edge_set.add(t)
                g.edges.append(list(t))
            if owners is not None:
                g.execution_edges.add(t)
        for o in data["overrides"]:
            if owners is not None and data["files"][data["decls"][o[0]].get("file", -1)] not in owners:
                continue
            g.overrides.append([local[o[0]], local[o[1]] if o[1] >= 0 else -1, o[2]])
        for s in data["strings"]:
            if owners is not None and data["files"][s[1]] not in owners:
                continue
            g.strings.append([local[s[0]], files[s[1]], s[2], s[3], s[4], local[s[5]] if s[5] >= 0 else -1])
        for u in data.get("unresolved", []):
            if owners is not None and data["files"][u[1]] not in owners:
                continue
            g.unresolved.append([local[u[0]], files[u[1]], u[2], u[3]])
        g.units.extend(data["units"])
        g.diagnostics.extend(data.get("diagnostics", []))


class _PyFile:
    """파이썬 파일 하나: 경로·구문 트리·모듈 선언 번호와 이름 표(모듈 수준 정의, from 가져오기, 모듈 별칭)."""

    def __init__(self, rel, tree, module):
        """파일 경로·구문 트리·모듈 선언 번호."""
        self.rel, self.tree, self.module = rel, tree, module
        self.names = {}
        self.imports = {}
        self.modules = {}
        self.occurrences = {}


def python(root, cur, rows, graph, cache=None, only_files=None):
    """파이썬 선언·참조를 graph에 더한다(2.8.5). 모듈 수준 코드는 모듈 선언에서 출발한다."""
    entries = dict(cur.summaries()) if isinstance(cur,ledger.SourceIndex) else cur
    files = [rel for rel, e in sorted(entries.items()) if e.get("unit") == "심볼" and rel.endswith(".py") and layer_of(rel, rows)]
    if only_files is not None:
        from storage import snapshot
        available, selected = set(files), set(files) & set(only_files)
        dependencies = set(selected)
        names_by_layer = {}
        for rel in selected:
            try:
                tree = ast.parse(snapshot.read_text(root,rel))
            except (SyntaxError,ValueError):
                continue
            folder = os.path.dirname(rel)
            names_by_layer.setdefault(layer_of(rel,rows).name,set()).update(n.attr for n in ast.walk(tree) if isinstance(n,ast.Attribute))
            for node in ast.walk(tree):
                dotted = ([a.name for a in node.names] if isinstance(node,ast.Import) else
                          [node.module] + [node.module + "." + a.name for a in node.names]
                          if isinstance(node,ast.ImportFrom) and node.level == 0 and node.module else [])
                for name in dotted:
                    target = _py_module(folder,name,available)
                    if target:
                        dependencies.add(target)
        for layer, names in names_by_layer.items():
            candidates = reference_store.python_member_files(root, names)
            dependencies.update(file for file in candidates if file in available and layer_of(file, rows).name == layer)
        files = sorted(dependencies)
    index = {d["key"]: i for i, d in enumerate(graph.decls)}
    parsed = {}
    cache = {} if cache is None else cache
    implementation = cachemod.POLICY.versions['python-refs']
    for rel in cache.keys() - set(files):
        del cache[rel]
    for rel in list(cache):
        if cache[rel][4].get('implementation') != implementation:
            del cache[rel]
    # A fresh process restores every Python shard. Fetch their typed SQL rows
    # together instead of opening the same domain once per file (and sometimes
    # once more while restoring its edges).
    cold = [PYTHON_RECORDS + "/" + rel + ".row" for rel in files
            if rel not in cache or cache[rel][0] != entries[rel] or "edges" not in cache[rel][4]]
    restored = ledger.read_tables(root, cold)
    for rel in files:
        saved = cache.get(rel)
        syntax_input = cachemod.POLICY.key('python-refs', [rel, entries[rel].get("sha256", "")])
        if saved is None or saved[0] != entries[rel]:
            stored = restored.get(PYTHON_RECORDS + "/" + rel + ".row", {})
            syntax = stored.get("syntax",{})
            if syntax.get("input") == syntax_input:
                saved = (entries[rel], "", None, syntax["imports"], {"syntax":syntax,"stored":stored}, tuple(syntax["attributes"]))
            else:
                try:
                    with open(os.path.join(root,rel),encoding="utf-8-sig",errors="replace") as stream:
                        text = stream.read()
                    tree = ast.parse(text)
                except (SyntaxError,ValueError):
                    continue
                nodes = list(ast.walk(tree))
                imports = [dict(kind="import" if isinstance(node,ast.Import) else "from", module=getattr(node,"module",None),
                                level=getattr(node,"level",0),name=alias.name,alias=alias.asname)
                           for node in nodes if isinstance(node,(ast.Import,ast.ImportFrom)) for alias in node.names]
                attrs = tuple(sorted({node.attr for node in nodes if isinstance(node,ast.Attribute)}))
                saved = (entries[rel],text,tree,imports,{},attrs)
            cache[rel] = saved
        _,text,tree,imports,retained,attrs = saved
        retained['implementation'] = implementation
        fno = _file_no(graph,rel)
        syntax = retained.get("syntax")
        module = _py_decl(graph,index,"py:%s:<module>" % rel,name=os.path.splitext(os.path.basename(rel))[0],
                          kind="module",file=fno,line=1,end=syntax["end"] if syntax else text.count("\n")+1,container=-1,access="public")
        pf = _PyFile(rel,tree,module)
        if tree is None:
            for decl in syntax["declarations"]:
                parent = index[decl["container"]]
                _py_decl(graph,index,decl["key"],**dict({k:v for k,v in decl.items() if k!="key"},container=parent,file=fno))
            pf.names.update((name,index[key]) for name,key in syntax["names"])
            pf.occurrences.update(((line,scope,name),index[key]) for line,scope,name,key in syntax["occurrences"])
        else:
            for node in tree.body:
                _py_declare(graph,index,pf,node,fno)
            retained["syntax"] = dict(input=syntax_input,end=text.count("\n")+1,imports=imports,attributes=attrs,
                names=tuple((name,graph.decls[i]["key"]) for name,i in pf.names.items()),
                occurrences=tuple((line,scope,name,graph.decls[i]["key"]) for (line,scope,name),i in pf.occurrences.items()),
                declarations=[dict((key,d[key]) for key in ("key","name","kind","line","end","access","bases")) |
                              {"container":graph.decls[d["container"]]["key"]}
                              for d in graph.decls if d.get("file")==fno and d.get("key","").startswith("py:") and d.get("container",-1)>=0])
        parsed[rel] = pf
    members = {}
    for rel,pf in parsed.items():
        layer = layer_of(rel,rows).name
        for decl in cache[rel][4]["syntax"]["declarations"]:
            parent = graph.decls[index[decl["container"]]]
            if parent["kind"]=="class":
                members.setdefault((layer,decl["name"]),[]).append(index[decl["key"]])
    for rel,pf in parsed.items():
        folder = os.path.dirname(rel)
        for item in cache[rel][3]:
            name,alias = item["name"],item["alias"]
            if item["kind"]=="import":
                target = _py_module(folder,name,parsed)
                if target and (alias or "." not in name): pf.modules[alias or name]=target
            elif item["level"]==0 and item["module"]:
                target = _py_module(folder,item["module"],parsed)
                sub = None if target else _py_module(folder,item["module"]+"."+name,parsed)
                if target: pf.imports[alias or name]=(target,name)
                elif sub: pf.modules[alias or name]=sub
    # 파일이 실제 조회한 이름과 import 문맥의 성공·실패 후보를 모두 보존한다.
    # 무관한 이름 추가는 그 이름을 조회하지 않은 파일의 본문 순회를 발생시키지 않는다.
    processed = set()
    for rel, pf in parsed.items():
        if only_files is not None and rel not in selected:
            continue
        retained = cache[rel][4]
        layer, fno = layer_of(rel, rows).name, _file_no(graph, rel)
        attrs, folder = cache[rel][5], os.path.dirname(rel)
        queries = {"member:" + layer + ":" + name: tuple(graph.decls[i]["key"] for i in members.get((layer, name), ())) for name in attrs}
        for alias, (target, name) in pf.imports.items():
            i = parsed[target].names.get(name)
            queries["import:" + target + ":" + name] = graph.decls[i]["key"] if i is not None else ""
        for alias, target in pf.modules.items():
            queries["module:" + alias + ":" + target] = tuple((name, graph.decls[parsed[target].names[name]]["key"] if name in parsed[target].names else "") for name in attrs)
        for item in cache[rel][3]:
            dotted = [item["name"]] if item["kind"]=="import" else [item["module"] or "",(item["module"] or "")+"."+item["name"]]
            for name in dotted:
                queries["resolve:" + folder + ":" + name] = _py_module(folder, name, parsed) or ""
        shape = (tuple((name, graph.decls[i]["key"]) for name, i in pf.names.items()),
                 tuple(sorted(pf.imports.items())), tuple(sorted(pf.modules.items())), tuple(sorted(queries.items())))
        for query in queries:
            graph.lookup_users.setdefault(query, set()).add(rel)
        previous = retained.get("lookup")
        if previous is not None:
            changed = {key for key in set(previous) | set(queries) if previous.get(key) != queries.get(key)}
            if changed:
                users = ledger.table_users(root, PYTHON_RECORDS, changed)
                for user in users - processed - {rel}:
                    if user in parsed:
                        cache[user][4].pop("shape", None)
        retained["lookup"] = queries
        processed.add(rel)
        shape_digest = hashlib.sha256(json.dumps(shape, ensure_ascii=False).encode()).hexdigest()
        dependency = cachemod.POLICY.key('python-refs', [rel, shape_digest, layer, entries[rel].get("sha256")])
        shard = PYTHON_RECORDS + "/" + rel + ".row"
        if "edges" not in retained:
            stored = retained.pop("stored",None)
            if stored is None: stored = restored.get(shard, {})
            if isinstance(stored, dict) and stored.get("input") == dependency and stored.get("file") == rel:
                edges = stored.get("edges", [])
                if all(isinstance(e, (list, tuple)) and len(e) == 5 and e[0] in index and e[1] in index for e in edges):
                    retained.update(shape=(shape, layer), edges=tuple(tuple(e) for e in edges))
        if retained.get("shape") == (shape, layer):
            for a, b, line, write, guess in retained["edges"]:
                frm, to = index[a], index[b]
                graph.edges.append([frm, to, fno, line, write])
                if guess:
                    graph.guessed.add((frm, to, fno, line))
            continue
        if pf.tree is None:
            # Candidate changes only need the affected consumer's body, not all declarations.
            with open(os.path.join(root,rel),encoding="utf-8-sig",errors="replace") as stream:
                pf.tree = ast.parse(stream.read())
        start = len(graph.edges)
        _PyEdges(pf, parsed, members, layer, fno, graph, index).run()
        retained["shape"] = (shape, layer)
        retained["edges"] = tuple((graph.decls[a]["key"], graph.decls[b]["key"], line, write,
                                    (a, b, f, line) in graph.guessed)
                                   for a, b, f, line, write in graph.edges[start:])
        ledger.write_table(root, shard, {"file": rel, "input": dependency, "lookup": queries, "edges": retained["edges"], "syntax":retained["syntax"]})
    if only_files is None:
        ledger.prune_tables(root, PYTHON_RECORDS, {PYTHON_RECORDS + "/" + rel + ".row" for rel in parsed})
    else:
        absent = set(only_files) - set(parsed)
        ledger.remove_sources(root, PYTHON_RECORDS, {f for f in absent if f.endswith(".py")})



def _file_no(graph, rel):
    """그래프의 파일 번호(없으면 더한다)."""
    if rel not in graph.files:
        graph.files.append(rel)
    return graph.files.index(rel)


def _py_decl(graph, index, key, **info):
    """선언 하나를 더하거나 고친다."""
    i = index.get(key)
    if i is None:
        i = len(graph.decls)
        graph.decls.append({"key": key, "mods": [], "attrs": [], "bases": []})
        index[key] = i
    # The combined graph shares immutable C# rows with its source graph.
    # Python declarations own a replacement row before adding their fields.
    graph.decls[i] = dict(graph.decls[i], **info)
    return i


def _py_targets(node):
    """문장 하나가 만드는 이름(함수·클래스·대입 대상)."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.Assign):
        return [t.id for t in node.targets if isinstance(t, ast.Name)]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id]
    return []


def _py_kind(node, name, top):
    """문장이 만드는 선언의 종류."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return "method"
    if isinstance(node, ast.ClassDef):
        return "class"
    return "const" if top and name.isupper() else "field"


def _py_access(name):
    """밑줄로 시작하면 private(`__이름__`은 public)."""
    return "private" if name.startswith("_") and not name.endswith("__") else "public"


def _py_declare(graph, index, pf, node, fno):
    """모듈 수준 문장 하나의 선언: 함수·클래스·변수, 클래스 안 메서드·변수."""
    for name in _py_targets(node):
        base = "py:%s:%s" % (pf.rel, name)
        ordinal = sum(1 for _, scope, ident in pf.occurrences if scope == "" and ident == name)
        key = base if not ordinal else base + ":occ" + str(ordinal)
        i = _py_decl(graph, index, key, name=name, kind=_py_kind(node, name, True), file=fno,
                     line=node.lineno, end=node.end_lineno, container=pf.module, access=_py_access(name))
        pf.occurrences[(node.lineno, "", name)] = i
        pf.names[name] = i
        if isinstance(node, ast.ClassDef):
            aliases = {}
            for statement in pf.tree.body:
                if isinstance(statement, ast.Import):
                    for imported in statement.names:
                        aliases[imported.asname or imported.name.split(".")[0]] = imported.name if imported.asname else imported.name.split(".")[0]
                elif isinstance(statement, ast.ImportFrom) and statement.level == 0 and statement.module:
                    for imported in statement.names:
                        aliases[imported.asname or imported.name] = statement.module + "." + imported.name
            bases = []
            for ancestor in node.bases:
                expression = ancestor.value if isinstance(ancestor, ast.Subscript) else ancestor
                if isinstance(expression, (ast.Name, ast.Attribute)):
                    name = ast.unparse(expression)
                    head, separator, tail = name.partition(".")
                    bases.append(aliases.get(head, head) + (separator + tail if separator else ""))
            graph.decls[i]["bases"] = bases
            for item in node.body:
                for inner in _py_targets(item):
                    base = key + "." + inner
                    ordinal = sum(1 for _, scope, ident in pf.occurrences if scope == key and ident == inner)
                    member = _py_decl(graph, index, base if not ordinal else base + ":occ" + str(ordinal), name=inner,
                             kind=_py_kind(item, inner, False), file=fno, line=item.lineno, end=item.end_lineno,
                             container=i, access=_py_access(inner))
                    pf.occurrences[(item.lineno, key, inner)] = member
                    pf.occurrences[(item.lineno, node.name, inner)] = member


def _py_module(folder, dotted, parsed):
    """가져오는 파일의 폴더부터 위 폴더로 올라가며 모듈 파일을 찾는다(패키지 폴더 안 모듈은 `폴더.모듈`)."""
    base = folder
    while True:
        rel = "/".join(filter(None, [base, dotted.replace(".", "/") + ".py"]))
        if rel in parsed:
            return rel
        if not base:
            return None
        base = os.path.dirname(base)


class _PyEdges:
    """파이썬 파일 하나의 참조: 모듈 수준 문장은 모듈에서, 함수 본문은 그 함수에서, 클래스 본문·기반은 그 클래스에서 출발한다."""

    def __init__(self, pf, parsed, members, layer, fno, graph, index):
        """파일·전체 파일 표·(계층, 이름) → 클래스 멤버 번호들·계층·파일 번호·그래프·열쇠 번호."""
        self.pf, self.parsed, self.members, self.layer = pf, parsed, members, layer
        self.fno, self.graph, self.index = fno, graph, index
        self.module_bindings = {}
        self.receiver_owners = {}
        self.arguments = {}
        for node in pf.tree.body:
            functions = node.body if isinstance(node, ast.ClassDef) else [node]
            for method in functions:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    scope = node.name if isinstance(node, ast.ClassDef) else ""
                    me = pf.occurrences[(method.lineno, scope, method.name)]
                    args = method.args.posonlyargs + method.args.args + method.args.kwonlyargs + [arg for arg in (method.args.vararg, method.args.kwarg) if arg is not None]
                    self.arguments[me] = {arg.arg for arg in args}
                    if isinstance(node, ast.ClassDef) and args and args[0].arg == "self":
                        self.receiver_owners[me] = pf.occurrences[(node.lineno, "", node.name)]
        for node in pf.tree.body:
            for name in _py_targets(node):
                self.module_bindings.setdefault(name, []).append((node.end_lineno, node.end_col_offset, pf.occurrences[(node.lineno, "", name)]))

    def run(self):
        """모듈 수준 문장을 돈다."""
        pf = self.pf
        for node in pf.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.refs(node.decorator_list + [node.args], pf.module)
                self.refs(node.body, pf.occurrences[(node.lineno, "", node.name)])
            elif isinstance(node, ast.ClassDef):
                cls = pf.occurrences[(node.lineno, "", node.name)]
                self.refs(node.decorator_list, pf.module)
                self.refs(node.bases, cls)
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        me = pf.occurrences[(item.lineno, self.graph.decls[cls]["key"], item.name)]
                        self.refs(item.decorator_list + [item.args], cls)
                        self.refs(item.body, me)
                    else:
                        self.refs([item], cls)
            else:
                self.refs([node], pf.module)

    def refs(self, nodes, frm):
        """마디들 안의 이름·속성·가져오기."""
        pf, parsed = self.pf, self.parsed
        folder = os.path.dirname(pf.rel)
        # Resolve only receivers whose local construction is unambiguous.
        # Unknown, rebound and inherited members retain the guessed-edge path.
        walked = [n for top in nodes for n in ast.walk(top)]
        stores = {}
        for n in walked:
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                stores[n.id] = stores.get(n.id, 0) + 1
        receivers = {}
        for n in walked:
            if not isinstance(n, ast.Assign) or len(n.targets) != 1 or not isinstance(n.targets[0], ast.Name):
                continue
            name = n.targets[0].id
            if stores.get(name) != 1 or not isinstance(n.value, ast.Call) or not isinstance(n.value.func, ast.Name):
                continue
            constructor = n.value.func.id
            if stores.get(constructor) or constructor in self.arguments.get(frm, ()):
                continue
            target = pf.names.get(constructor)
            if target is None and constructor in pf.imports:
                rel, imported = pf.imports[constructor]
                target = parsed[rel].names.get(imported)
            if target is not None and self.graph.decls[target].get("kind") == "class":
                receivers[name] = (target, n.end_lineno, n.end_col_offset)
        owner = self.receiver_owners.get(frm)
        if owner is not None and not stores.get("self"):
            receivers["self"] = (owner, 0, 0)
        if any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for n in walked):
            receivers.clear()
        for n in walked:
            if isinstance(n, ast.Lambda):
                for arg in n.args.posonlyargs + n.args.args + n.args.kwonlyargs + [arg for arg in (n.args.vararg,n.args.kwarg) if arg is not None]:
                    receivers.pop(arg.arg,None)
        for n in walked:
            if isinstance(n, ast.Import):
                for a in n.names:
                    target = _py_module(folder, a.name, parsed)
                    if target:
                        self.edge(frm, parsed[target].module, n.lineno, 0)
            elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                target = _py_module(folder, n.module, parsed)
                if target:
                    self.edge(frm, parsed[target].module, n.lineno, 0)
                    for a in n.names:
                        self.edge(frm, parsed[target].names.get(a.name), n.lineno, 0)
                else:
                    for a in n.names:
                        sub = _py_module(folder, n.module + "." + a.name, parsed)
                        if sub:
                            self.edge(frm, parsed[sub].module, n.lineno, 0)
            elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                if n.id in pf.names:
                    target = pf.names[n.id]
                    if frm == pf.module:
                        target = next((i for line, column, i in reversed(self.module_bindings.get(n.id, ())) if (line, column) <= (n.lineno, n.col_offset)), None)
                    self.edge(frm, target, n.lineno, 0)
                elif n.id in pf.imports:
                    target, name = pf.imports[n.id]
                    self.edge(frm, parsed[target].names.get(name), n.lineno, 0)
                elif n.id in pf.modules:
                    self.edge(frm, parsed[pf.modules[n.id]].module, n.lineno, 0)
            elif isinstance(n, ast.Attribute):
                if isinstance(n.value, ast.Name) and n.value.id in pf.modules:
                    t = parsed[pf.modules[n.value.id]].names.get(n.attr)
                    if t is not None:
                        self.edge(frm, t, n.lineno, 0)
                        continue
                receiver = receivers.get(n.value.id) if isinstance(n.value, ast.Name) else None
                if receiver is not None and (receiver[1], receiver[2]) <= (n.lineno, n.col_offset):
                    candidates = self.members.get((self.layer, n.attr), [])
                    owned = [t for t in candidates if self.graph.decls[t].get("container") == receiver[0]]
                    if owned:
                        for t in owned:
                            self.edge(frm, t, n.lineno, 1 if isinstance(n.ctx, ast.Store) else 0)
                        continue
                for t in self.members.get((self.layer, n.attr), []):
                    self.edge(frm, t, n.lineno, 1 if isinstance(n.ctx, ast.Store) else 0, guess=True)

    def edge(self, frm, to, line, write, guess=False):
        """참조 하나(자기 자신은 뺀다). guess면 이름으로 짐작한 참조라 `Graph.guessed`에도 적는다(2.8.5)."""
        if frm is not None and to is not None and frm != to:
            self.graph.edges.append([frm, to, self.fno, line, write])
            if guess:
                self.graph.guessed.add((frm, to, self.fno, line))


def _index_positions(graph):
    """파일이 소유한 위치 행 번호. 그래프 생성 때 한 번 만들고 줄 교체는 해당 행만 찾는다."""
    positions = {}
    for i,d in enumerate(graph.decls):
        files = {graph.files[d["file"]]} if "kind" in d and 0 <= d.get("file",-1) < len(graph.files) else set()
        files.update(p["file"] for p in d.get("occurrences",[]) if "file" in p)
        for rel in files:
            positions.setdefault(rel,{}).setdefault("decls",[]).append(i)
    for name,column in (("edges",2),("strings",1),("unresolved",1)):
        for i,row in enumerate(getattr(graph,name)):
            if 0 <= row[column] < len(graph.files):
                positions.setdefault(graph.files[row[column]],{}).setdefault(name,[]).append(i)
    for i,d in enumerate(graph.diagnostics):
        if "file" in d and "line" in d:
            positions.setdefault(d["file"],{}).setdefault("diagnostics",[]).append(i)
    graph.positions = positions


def build(root, ds, cur, unity, cache=None, only_files=None):
    """C# 그래프(캐시)에 파이썬 선언·참조를 더한다."""
    unity = unity_path(unity)
    cache = {} if cache is None else cache
    rows = layers(ds)
    if only_files is not None:
        # Follow persisted relationships in SQL. Source bodies and declaration
        # records outside this closure never enter the analysis process.
        selected = set(only_files)
        changed_sources = set(only_files)
        old_compiled = reference_store.compiled_facts(root, changed_sources)
        queries = set()
        for rel in selected:
            if rel.endswith(".py"):
                layer = layer_of(rel,rows)
                before = cache.get("previousFiles",{}).get(rel,{})
                after = cur.get(rel,{})
                shape = lambda s:(s.get("path"),s.get("kind"),s.get("name"),s.get("signature"))
                old,new = ({shape(s):s for s in entry.get("symbols",())} for entry in (before,after))
                changed = [old.get(k) or new[k] for k in old.keys() ^ new.keys()]
                classes = {(s.get("path") + "." if s.get("path") not in (None,"-") else "") + s["name"]
                           for entry in (before,after) for s in entry.get("symbols",()) if s.get("kind") == "class"}
                if layer:
                    queries.update("member:" + layer.name + ":" + s["name"] for s in changed if s.get("path") in classes)
                queries.update("import:" + rel + ":" + s["name"] for s in changed if s.get("path") in (None,"-"))
            if rel.endswith(".py") and (rel not in cur or not cache.get("previousFiles", {}).get(rel)):
                # Empty import lookups have no edge yet. Query their stored
                # import operands when a module is added, removed or renamed.
                components = rel[:-3].split("/")
                dotted = {".".join(components[n:]) for n in range(len(components))}
                dotted.update(name.rpartition(".")[0] for name in tuple(dotted) if "." in name)
                owners = set()
                for owner, kind, module, imported, level in reference_store.python_imports(root, dotted):
                    names = [imported] if kind == "import" else [module or "", (module or "") + "." + imported]
                    if not level and any(_py_module(os.path.dirname(owner), name, set(cur) | {rel}) == rel for name in names):
                        owners.add(owner)
                queries.update(reference_store.python_queries(root, owners))
        selected.update(ledger.table_users(root,PYTHON_RECORDS,queries))
        work = job(root,ds,cur,unity,selected)
        while True:
            before = set(selected)
            selected.update(reference_store.python_closure(root, selected))
            # A compiler unit owns semantic binding and variant reachability.
            # Only units containing an affected input are decoded/re-extracted.
            for unit in work["units"]:
                files = set(unit["walk"] + unit["context"])
                if files & selected:
                    selected.update(files)
            captured = cache.setdefault("beforeScope",set())
            cache.setdefault("beforeEdges",set()).update(reference_store.source_edges(root,selected-captured))
            captured.update(selected)
            cs = csharp(root,ds,cur,unity,cache.setdefault("csharp",{}),only_files=selected)
            graph = Graph(files=list(cs.files),decls=list(cs.decls),edges=list(cs.edges),
                overrides=list(cs.overrides),strings=list(cs.strings),unresolved=list(cs.unresolved),
                units=list(cs.units),diagnostics=list(cs.diagnostics),error=cs.error,
                compilations=cs.compilations,execution_edges=set(cs.execution_edges))
            python(root,cur,rows,graph,cache.setdefault("python",{}),only_files=selected)
            selected.update(graph.files)
            if any(f.endswith(".cs") for f in changed_sources):
                current = {d["key"]:(d.get("name"),d.get("kind"),d.get("hash"),d.get("stmts"))
                           for d in graph.decls if "kind" in d and graph.files[d["file"]] in changed_sources}
                different = {k for k in old_compiled.keys() | current.keys() if old_compiled.get(k) != current.get(k)}
                facts = [version[k] for version in (old_compiled,current) for k in different if k in version]
                digests = {h for _, _, h, n in facts if h and n and n >= 2}
                type_names = {n for n, k, _, _ in facts if k in ("class", "interface", "struct", "enum", "record", "delegate")}
                selected.update(reference_store.compiled_candidates(root, digests, type_names))
            if selected == before:
                break
        cache["scopeFiles"] = selected
        _index_positions(graph)
        return graph
    cs = csharp(root, ds, cur, unity, cache.setdefault("csharp", {}))
    inputs = (root, rows, tuple((rel, entry) for rel, entry in sorted(cur.items()) if rel.endswith(".py")))
    if not cs.error and cache.get("source") is cs and cache.get("inputs") == inputs:
        return cache["graph"]
    # Keep independent containers; C# rows are read-only in the Python merge.
    # Position updates already replace affected rows instead of mutating them.
    graph = Graph(files=list(cs.files), decls=list(cs.decls),
                  edges=list(cs.edges), overrides=list(cs.overrides),
                  strings=list(cs.strings), unresolved=list(cs.unresolved),
                  units=list(cs.units), diagnostics=list(cs.diagnostics), error=cs.error,
                  compilations=cs.compilations, execution_edges=set(cs.execution_edges),
                  guessed=set(cs.guessed), lookup_users={key:set(users) for key,users in cs.lookup_users.items()})
    if rows:
        python(root, cur, rows, graph, cache.setdefault("python", {}))
    _index_positions(graph)
    if not graph.error:
        cache.update(source=cs, inputs=inputs, graph=graph)
    return graph


def move_positions(graph, deltas):
    """토폴로지는 유지하고 변경 파일 소유의 선언·변수·참조·진단 줄만 독립 교체한다."""
    result = Graph(**{name: list(getattr(graph,name)) for name in
                    ("files","decls","edges","overrides","strings","unresolved","units","diagnostics")},
                   error=graph.error, guessed=set(), lookup_users=graph.lookup_users, positions=graph.positions,
                   compilations=graph.compilations, execution_edges=set(graph.execution_edges))
    if not graph.positions:
        _index_positions(graph)
        result.positions = graph.positions
    changed = {i for rel in deltas for i in graph.positions.get(rel,{}).get("decls",[])}
    for i in changed:
        d = graph.decls[i]
        rel = graph.files[d["file"]] if "kind" in d and 0 <= d.get("file",-1) < len(graph.files) else ""
        if rel not in deltas and not any(p.get("file") in deltas for p in d.get("occurrences", [])):
            continue
        row = dict(d)
        if rel in deltas:
            for key in ("line","end"):
                if key in row:
                    row[key] = diffmod.move_line(row[key],deltas[rel])
            if row.get("kind") == "module":
                row["line"] = 1
            if "variables" in row:
                row["variables"] = [dict(v, **{k:diffmod.move_line(v[k],deltas[rel]) for k in ("line","end") if k in v})
                                    for v in row["variables"]]
        if "occurrences" in row:
            row["occurrences"] = [dict(p, **{k:diffmod.move_line(p[k],deltas[p["file"]])
                                             for k in ("line","end") if k in p}) if p.get("file") in deltas else p
                                  for p in row["occurrences"]]
        result.decls[i] = row
    for name,file_column,line_column in (("edges",2,3),("strings",1,2),("unresolved",1,2)):
        for i in (i for rel in deltas for i in graph.positions.get(rel,{}).get(name,[])):
            row = getattr(graph,name)[i]
            rel = graph.files[row[file_column]] if 0 <= row[file_column] < len(graph.files) else ""
            if rel in deltas:
                replacement = list(row)
                replacement[line_column] = diffmod.move_line(row[line_column],deltas[rel])
                getattr(result,name)[i] = replacement
    result.execution_edges = {tuple(new) for old,new in zip(graph.edges,result.edges) if tuple(old) in graph.execution_edges}
    result.compilations = []
    for compilation in graph.compilations:
        if not set(compilation["files"]) & deltas.keys():
            result.compilations.append(compilation)
            continue
        raw = compilation_data(compilation)
        local = Graph()
        _Merger(local).add(raw)
        moved = move_positions(local, deltas)
        data = {name: getattr(moved,name) for name in ("files","decls","edges","overrides","strings","unresolved","units","diagnostics")}
        result.compilations.append({"owners": compilation["owners"], "files": list(data["files"]),
                                    "inputKey": compilation["inputKey"], "data": marshal.dumps(data)})
    for a,b,f,line in graph.guessed:
        rel = graph.files[f] if 0 <= f < len(graph.files) else ""
        result.guessed.add((a,b,f,diffmod.move_line(line,deltas[rel]) if rel in deltas else line))
    for rel in deltas:
        for i in graph.positions.get(rel,{}).get("diagnostics",[]):
            d = graph.diagnostics[i]
            result.diagnostics[i] = dict(d,line=diffmod.move_line(d["line"],deltas[rel]))
    return result
