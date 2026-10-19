# -*- coding: utf-8 -*-
"""판정(SPEC-36 2.6). 문서 표(scope·members·constants·rules·changes·allow)와 코드·변경을 대조해 파일·줄 단위 지적을 낸다.

엔진이 스스로 아는 규칙은 없다. 규칙은 모두 문서 표에서 온다."""
import ast
import hashlib
import json
from pathlib import Path
import io
import os
import re
import time
import tokenize as pytokenize
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import unquote

from documents import docs as docmod
from parsing import globs
from graph import layers
from judging import meta as metamod
from graph import refs
from graph.cache import AnalysisCache
from parsing import cache as cachemod
from documents import review
from storage import snapshot, ledger
from storage import diff as diffmod
from parsing.parse_cs import Symbol

FILE_KINDS = {"파일 추가", "파일 삭제", "파일 변경"}
TYPE_KINDS = {"class", "struct", "interface", "enum", "record"}
KIND_NAMES = sorted(docmod.SYMBOL_KINDS, key=len, reverse=True)


@dataclass
class Finding:
    """지적 하나."""
    code: str
    file: str
    line: int
    message: str
    rule: str = ""
    producer: str = ""


def symbols(entry):
    """색인 항목의 심볼들."""
    return [Symbol.from_dict(d) for d in (entry or {}).get("symbols", [])]


def _norm(text):
    """공백을 모두 뺀 글자(형식·값 비교용)."""
    return re.sub(r"\s+", "", text or "")


def parse_selector(text):
    """선택자 `종류[@접근/접근][+수식어][-수식어]` → (종류, 접근 집합 또는 None, 필요 수식어, 없어야 할 수식어)."""
    text = text.strip()
    kind = next((k for k in KIND_NAMES if text.startswith(k)), None)
    if kind is None:
        raise ValueError("모르는 선택자: " + text)
    rest = text[len(kind):]
    access = None
    m = re.match(r"^@([a-z/]+)", rest)
    if m:
        access = set(m.group(1).split("/"))
        rest = rest[m.end():]
    plus, minus = set(), set()
    for sign, word in re.findall(r"([+-])([a-z]+)", rest):
        (plus if sign == "+" else minus).add(word)
    return kind, access, plus, minus


def empty_body(text, ext, ctor=False):
    """멤버 선언 글자(주석·문자열 제거)의 본문이 비었거나 미구현 예외만 있는가. 본문 없는 선언(추상·인터페이스)은 거짓.
    생성자는 빈 본문을 허용하고 미구현 예외만 본다."""
    if ext == ".py":
        import textwrap
        try:
            node = ast.parse(textwrap.dedent(text)).body[0]
        except (SyntaxError, IndexError):
            return False
        body = [b for b in getattr(node, "body", []) if not (isinstance(b, ast.Expr) and isinstance(getattr(b, "value", None), ast.Constant))]
        if not body:
            return True
        if len(body) != 1:
            return False
        b = body[0]
        if isinstance(b, ast.Pass):
            return not ctor
        if isinstance(b, ast.Raise) and b.exc is not None:
            target = b.exc.func if isinstance(b.exc, ast.Call) else b.exc
            return getattr(target, "id", getattr(target, "attr", "")) == "NotImplementedError"
        return False
    open_paren = text.find("(")
    if open_paren < 0:
        return False
    depth, close = 0, -1
    for i in range(open_paren, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                close = i
                break
    if close < 0:
        return False
    rest = text[close + 1:]
    arrow, brace = rest.find("=>"), rest.find("{")
    if arrow >= 0 and (brace < 0 or arrow < brace):
        body = rest[arrow + 2:].rsplit(";", 1)[0]
    elif brace >= 0:
        end = rest.rfind("}")
        if end <= brace:
            return False
        body = rest[brace + 1:end]
    else:
        return False
    body = body.strip()
    if re.fullmatch(r"throw\s+new\s+(System\.)?NotImplementedException\s*\([^;]*\)\s*;?", body):
        return True
    return body == "" and not ctor


def finding_key(f):
    """지적 열쇠 — 줄 번호와 괄호 안 `파일:줄` 참조를 뺀 (코드, 파일, 규칙, 내용)."""
    message = re.sub(r"\s*\([^()]*:\d+\)", "", f.message) if "(" in f.message and ":" in f.message else f.message
    return "%s|%s|%s|%s" % (f.code, f.file, f.rule, message.strip())


def selector_match(sel, s):
    """심볼이 선택자에 맞는가."""
    kind, access, plus, minus = sel
    if s.kind != kind:
        return False
    if access is not None and s.access not in access:
        return False
    mods = set(s.modifiers)
    return plus <= mods and not (minus & mods)


def strip_code(text, ext, strings=False):
    """주석(선택하면 문자열 안쪽)을 공백으로 지운다. 접두사의 첫 글자가 맞을 때만 검사하며 줄 번호를 보존한다."""
    chars = list(text)
    if ext == ".py":
        try:
            lines = text.split("\n")
            offsets = [0]
            for ln in lines:
                offsets.append(offsets[-1] + len(ln) + 1)
            for tok in pytokenize.generate_tokens(io.StringIO(text).readline):
                if tok.type == pytokenize.COMMENT or (strings and tok.type == pytokenize.STRING):
                    a = offsets[tok.start[0] - 1] + tok.start[1]
                    b = offsets[tok.end[0] - 1] + tok.end[1]
                    for k in range(a, min(b, len(chars))):
                        if chars[k] != "\n":
                            chars[k] = " "
        except (pytokenize.TokenError, IndentationError, SyntaxError):
            pass
        return "".join(chars)
    i, n = 0, len(text)
    comment = "#" if ext == ".ps1" else "//"
    while i < n:
        c = text[i]
        if c == comment[0] and text.startswith(comment, i):
            while i < n and text[i] != "\n":
                chars[i] = " "
                i += 1
            continue
        if c == "/" and ext != ".ps1" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if chars[k] != "\n":
                    chars[k] = " "
            i = j
            continue
        if c == '"' or c == "'":
            verbatim = ext == ".cs" and i > 0 and text[i - 1] == "@"
            j = i + 1
            while j < n and text[j] != c:
                if text[j] == "\\" and not verbatim:
                    j += 2
                    continue
                if text[j] == "\n" and not verbatim:
                    break
                j += 1
            if strings:
                for k in range(i + 1, min(j, n)):
                    if chars[k] != "\n":
                        chars[k] = " "
            i = j + 1
            continue
        i += 1
    return "".join(chars)


def check_headings(text):
    """세 단계 번호(## 1. / ### 1.1. / #### 1.1.1.)와 순번."""
    out, fence, counters = [], False, [0, 0, 0]
    for no, line in enumerate(text.split("\n"), 1):
        if line.strip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        m = re.match(r"^(#{2,4})\s+(.*)$", line)
        if not m:
            continue
        level = len(m.group(1)) - 1
        num = re.match(r"^(\d+(?:\.\d+)*)\.\s", m.group(2) + " ")
        if not num:
            out.append((no, "번호 없는 제목: " + line.strip()))
            continue
        parts = [int(x) for x in num.group(1).split(".")]
        expected = counters[:level - 1] + [counters[level - 1] + 1]
        if parts != expected:
            out.append((no, "제목 번호 %s (기대 %s)" % (".".join(map(str, parts)), ".".join(map(str, expected)))))
        counters[level - 1] = parts[-1] if len(parts) == level else counters[level - 1] + 1
        for k in range(level, 3):
            counters[k] = 0
    return out


def check_links(root, rel, text, cache=None):
    """상대 링크가 실제 파일로 열리는가."""
    out = []
    folder = os.path.dirname(os.path.join(root, rel))
    saved = cache.get(rel) if cache is not None else None
    fingerprint = hashlib.sha256(text.encode("utf-8")).digest()
    if saved is None or saved[0] != fingerprint:
        tokens, fence = [], False
        for no, line in enumerate(text.split("\n"), 1):
            if line.strip().startswith("```"):
                fence = not fence
                continue
            if fence:
                continue
            plain = re.sub(r"(?<!`)(`+)(?!`).*?(?<!`)\1(?!`)", "", line)
            for target in re.findall(r"\]\(([^)\s]+)\)", plain):
                if re.match(r"^(https?:|mailto:|#)", target):
                    continue
                path = unquote(target.split("#")[0])
                if path:
                    tokens.append((no, target, path))
        saved = (fingerprint, tuple(tokens))
        if cache is not None:
            cache[rel] = saved
    for no, target, path in saved[1]:
        if not os.path.exists(os.path.normpath(os.path.join(folder, path))):
            out.append((no, "열리지 않는 링크: " + target))
    return out


def check_mermaid(text, allowed):
    """머메이드 블록의 종류."""
    out, lines = [], text.split("\n")
    for no, line in enumerate(lines, 1):
        if line.strip() == "```mermaid":
            for nxt in lines[no:]:
                if nxt.strip():
                    word = nxt.strip().split()[0]
                    if word not in allowed:
                        out.append((no, "허용하지 않는 머메이드 종류: " + word))
                    break
    return out


def rule_worker_init():
    """검사 작업자는 낮은 우선순위로 계산만 수행한다."""
    if os.name == "nt":
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.SetPriorityClass.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        if not kernel.SetPriorityClass(kernel.GetCurrentProcess(), 0x40):
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        os.nice(10)


def rule_file_batch(payload):
    """한 파일의 미갱신 규칙을 함께 검사한다. 디스크 결과나 장부는 쓰지 않는다."""
    root, file, entry, rows, scope, allowed, rules = payload
    ds = docmod.DocSet()
    ds.rows = rows + ([scope] if scope else [])
    judge = Judge(root, ds, None, {file: entry}, [])
    judge.allowed = set(allowed)
    result = {}
    for slot, rule in rules:
        judge.findings, judge.suppressed = [], 0
        try:
            judge._rule_code(rule, {file})
            result[slot] = (judge.findings, judge.suppressed, None)
        except (re.error, ValueError) as error:
            result[slot] = (judge.findings, judge.suppressed, str(error))
    return file, result


class Judge:
    """한 번의 판정."""

    RuleParallelFiles = 16
    _body_files: set[str] | None
    _assets_unchanged: bool

    def __init__(self, root, ds, base, cur, changes, unity=None, stage=None, member_cache=None, rule_cache=None,
                 analysis_cache=None, persistent=False, asset_changes=None):
        """표를 종류별로 모으고(scope는 파일별, members는 파일별 목록), 허용 목록을 세트로. unity는 Unity 에디터 폴더(참조 그래프),
        stage는 기준 스냅숏의 단계 이름(그 단계 changes 행의 완료 판정 W10)."""
        self.root, self.ds, self.base, self.cur, self.changes = root, ds, base, cur, changes
        self.unity = unity
        self.stage = stage
        self.analysis = None
        self.findings, self.notes = [], []
        self.analysis_cache = analysis_cache if analysis_cache is not None else AnalysisCache()
        if not isinstance(self.analysis_cache, AnalysisCache):
            raise TypeError("analysis_cache must be AnalysisCache")
        prepared = self.analysis_cache.get("contracts")
        if prepared is None or prepared[0] is not ds:
            allowed = {(r.cells["규칙"], r.cells["경로"]) for r in ds.of("allow")}
            scope,members,bodies = {},{},{}
            for r in ds.of("scope"):
                scope.setdefault(r.cells["파일"],r)
            for r in ds.of("members"):
                members.setdefault(r.cells["파일"],[]).append(r)
            for r in ds.of("body"):
                bodies.setdefault(r.cells["파일"],[]).append(r)
            prepared = (ds,allowed,scope,members,bodies)
            self.analysis_cache["contracts"] = prepared
        self.allowed,self.scope,self.members,self.bodies = prepared[1:]
        self.suppressed = 0
        self._texts = {}
        self._doc_paths = {}
        self.member_cache = member_cache if member_cache is not None else {}
        self.member_work = {"checked": 0, "reused": 0}
        self.rule_cache = rule_cache if rule_cache is not None else {}
        self.rule_work = {"checked": 0, "reused": 0}
        self.stage_work = {}
        self._reuse_meta = False
        self._analysis_candidate = None
        self._body_files = None
        self._assets_unchanged = asset_changes is not None and not asset_changes
        self.persistent = persistent
        self._disk_checks = {}
        self._dirty_checks = set()

    @staticmethod
    def _checker_paths(folder):
        """저장 판정에 영향을 주는 판정·문서·파서·그래프·저장 코드만 선택한다."""
        return sorted(path for package in ('judging', 'documents', 'parsing', 'graph', 'storage')
                      for path in (folder / package).rglob('*.py'))

    def _file_checks(self, kind, file):
        """공용 스키마의 파일별 판정 컨테이너. 유효성은 검사별 입력 지문으로 판정한다."""
        key = file
        if key not in self._disk_checks:
            rel = ".spec-conformance/Cache/checks/files/" + file + ".row"
            saved = ledger.read_checks(self.root, rel)
            valid = (isinstance(saved, dict) and saved.get("file") == file
                     and saved.get("checker") == 'cache-policy:' + str(cachemod.CachePolicy.SCHEMA))
            if not valid:
                saved = {}
            values = saved.get("kinds", {})
            self._disk_checks[key] = (rel, values if isinstance(values, dict) else {}, valid)
        rel, kinds, _ = self._disk_checks[key]
        values = kinds.get(kind)
        if not isinstance(values, dict):
            values = kinds[kind] = {}
        return rel, values

    def _prime_checks(self, kind, files):
        """폴더 DB의 재사용 연결로 파일 기본키 판정 행을 읽는다."""
        if not self.persistent:
            return
        pending = sorted(file for file in files if file not in self._disk_checks)
        if not pending:
            return
        for file in pending:
            self._file_checks(kind,file)

    def _saved_check(self, kind, file, slot, fingerprint, result=None):
        """파일별 입력 지문이 같은 지적과 허용 수를 읽거나 변경 조각만 원자적으로 쓴다."""
        if not self.persistent:
            return None
        rel, values = self._file_checks(kind, file)
        token = fingerprint
        if result is None:
            saved = values.get(slot)
            if isinstance(saved, dict) and saved.get("input") == token:
                try:
                    return [Finding(**f) for f in saved["findings"]], int(saved["suppressed"])
                except (KeyError, TypeError, ValueError):
                    return None
            return None
        findings, suppressed = result
        value = {"input": token, "findings": [dict(vars(f)) for f in findings], "suppressed": suppressed}
        if values.get(slot) != value:
            values[slot] = value
            self._dirty_checks.add((file, kind, slot))
        return None

    def _flush_checks(self, prune=True):
        """검사가 끝난 뒤 입력이 바뀐 파일별 조각만 기록한다."""
        dirty = sorted(self._dirty_checks)
        for file in sorted({file for file, _, _ in dirty}):
            rel, kinds, valid = self._disk_checks[file]
            if not valid:
                schema = 'cache-policy:' + str(cachemod.CachePolicy.SCHEMA)
                ledger.write_table(self.root, rel, {"file": file, "input": schema,
                    "checker": schema, "kinds": kinds})
                self._disk_checks[file] = (rel, kinds, True)
                continue
            for _, kind, slot in (item for item in dirty if item[0] == file):
                ledger.write_check(self.root, rel, kind, slot, kinds[kind][slot])
        self._dirty_checks.clear()
        if self.persistent and prune:
            folder = ".spec-conformance/Cache/checks/files"
            live = set(self.cur) | set(self.scope) | set(self.members)
            ledger.prune_tables(self.root,folder,{folder + "/" + file + ".row" for file in live})


    def add(self, code, file, line, message, rule=""):
        """지적을 더한다. 허용 목록(규칙 id 또는 경고 코드 + 경로)에 있으면 세기만 한다."""
        if (rule and (rule, file) in self.allowed) or (code, file) in self.allowed:
            self.suppressed += 1
            return
        self.findings.append(Finding(code, file, line, message, rule))

    def text(self, rel, strings=False):
        """파일 글자(주석 제거, 선택하면 문자열도)."""
        key = (rel, strings)
        if key not in self._texts:
            entry = self.cur.get(rel)
            retained = self.analysis_cache.setdefault("sourceTexts", {})
            fingerprint = (self.root, entry.get("sha256")) if entry else None
            saved = retained.get(rel)
            if fingerprint is not None and saved is not None and saved[0] == fingerprint:
                self._texts.update(((rel, mode), value) for mode, value in saved[1].items())
            if key in self._texts:
                return self._texts[key]
            raw_key = (rel, None)
            if raw_key not in self._texts:
                self._texts[raw_key] = snapshot.read_text(self.root, rel)
            self._texts[key] = strip_code(self._texts[raw_key], os.path.splitext(rel)[1].lower(), strings)
            if fingerprint is not None:
                retained[rel] = (fingerprint, {mode: self._texts[(rel, mode)] for mode in (None, False, True)
                                               if (rel, mode) in self._texts})
        return self._texts[key]

    def run(self, previous=None, only_files=None, graph=None, input_index=None):
        """모든 판정."""
        if only_files is not None:
            import copy
            original = self.ds
            selected = set(only_files)
            folders = {os.path.dirname(f) for f in selected}
            local = copy.copy(original)
            file_kinds = {"scope","members","body","constants","changes","overview"}
            local.rows = [r for r in original.selected_rows(selected) if
                (r.cells["파일"] in selected if r.kind in file_kinds else
                 any(f == r.cells["폴더"] or f.startswith(r.cells["폴더"] + "/") for f in selected)
                 if r.kind == "pipeline" else
                 bool({t.partition("#")[0] for col in ("구현 대상","검사 연결") for t in globs.split(r.cells[col])} & selected)
                 or r.cells["증거"] not in ("","-") if r.kind == "behaviors" else True)]
            positions = {(r.doc,r.line) for r in local.rows if r.kind in file_kinds | {"pipeline","behaviors"}}
            arch = {r.parsed.get("nodeKey"):r for r in original.of("architecture")}
            owned_nodes = {key for key,r in arch.items() if r.parsed.get("memberFile") in selected or
                           any(m[0].split("|")[0] in selected for m in r.parsed.get("entryMembers",()))}
            positions.update((doc,line) for r in arch.values() for a,kind,b,doc,line in r.parsed.get("edges",())
                             if a in owned_nodes or b in owned_nodes)
            self.ds = local
            self.scope = {f:r for f,r in self.scope.items() if f in selected}
            self.members = {f:r for f,r in self.members.items() if f in selected}
            self.bodies = {f:r for f,r in self.bodies.items() if f in selected}
            self._provided_graph,self._input_index = graph,input_index
            self._scoped = True
            self._scoped_files = selected
            fresh, notes = self.run()
            owned = lambda f:not f.code.startswith("D") and (f.file in selected or f.file in folders or (f.file,f.line) in positions)
            combined = [f for f in previous or () if not owned(f)] + [f for f in fresh if owned(f)]
            return sorted(combined,key=lambda f:(f.file,f.line,f.code,f.message,f.rule)),notes,self.analysis,False
        self.stage_work = {}
        def timed(name, action):
            started = time.perf_counter()
            result = action()
            self.stage_work[name] = round(time.perf_counter() - started, 4)
            return result
        if self.base is None:
            self.notes.append("기준 스냅숏이 없어 변경 판정(W1·W7·이름·주석)을 건너뜀")
        stages = (("parseErrors", self._parse_errors), ("scopeChanges", self._scope_changes),
                  ("documentedChanges", self._changes_documented), ("stageDone", self._stage_done),
                  ("members", self._members), ("regression", self._regression),
                  ("constants", self._constants), ("rules", lambda:self._rules(targets=("코드",)) if getattr(self,"_scoped",False) else self._rules()),
                  ("overview", self._overview), ("coverage", self._coverage),
                  ("layers", self._layers), ("shaders", self._shaders),
                  ("meta", self._meta), ("limits", self._limits),
                  ("interfaces", self._interfaces), ("pipeline", self._pipeline),
                  ("behaviors", self._behaviors),
                  ("review", self._review))
        for name, action in stages:
            timed(name, action)
        timed("checkStore", lambda:self._flush_checks(prune=not getattr(self,"_scoped",False)))
        if self.suppressed or self.ds.suppressed:
            self.notes.append("허용 목록으로 넘긴 지적 %d건" % (self.suppressed + self.ds.suppressed))
        return self.findings, self.notes

    @cachemod.produces('check.parse_errors')
    def _parse_errors(self):
        """Publish parser failures independently of the other judgment producers."""
        for file, entry in sorted(self.cur.items()):
            if entry.get("error"):
                self.add("P1", file, 1, "파싱 실패: " + entry["error"])

    def run_docs(self):
        """문서 대상 규칙(문서경로·문서내용)만."""
        self._rules(targets=("문서경로", "문서내용"))
        if self.suppressed:
            self.notes.append("허용 목록으로 넘긴 지적 %d건" % self.suppressed)
        return self.findings, self.notes

    def behavior_inputs(self, contract):
        """현재 계약·저장 참조·실행 환경으로 정적 검사의 보수적인 입력 경계를 산출한다."""
        import sys
        c = contract.cells if hasattr(contract,'cells') else contract
        evidence = {r.cells['증거'] for r in self.ds.of('behaviors') if r.cells['증거'] not in ('','-')}
        source = getattr(self,'_input_index',None) or self.cur
        headers = dict(source.summaries() if isinstance(source,ledger.SourceIndex) else source.items())
        all_inputs = {f:e.get('sha256') for f,e in headers.items() if f not in evidence}
        selected = {t.partition('#')[0] for col in ('구현 대상','검사 연결') for t in globs.split(c[col]) if t!='-'}
        layer_rows = self.ds.of('layers')
        owners = {r.cells['계층'] for r in layer_rows if any(globs.matches(f,globs.split(r.cells['경로'])) for f in selected)}
        entries = [r for r in self.ds.of('entries') if r.cells['계층'] in owners]
        selected.update(f for r in entries for f in all_inputs if globs.matches(f,globs.split(r.cells['대상'])))
        graph = self.analysis.graph if self.analysis is not None else None
        boundary, reason = 'dependency-closure', 'registered implementations, tests, entries and transitive source references'
        if c['검사 수준'] != '정적' or graph is None or graph.error:
            boundary, reason = 'all-watched', 'app boundary or reference analysis unavailable'
        else:
            cache_key = (id(graph),len(graph.decls),len(graph.edges),len(graph.strings),len(graph.unresolved))
            cached = self.analysis_cache.get('behaviorRelations')
            if cached is None or cached[0] != cache_key:
                dependencies = {}
                for edge in graph.edges:
                    a,b = edge[:2]
                    if 0 <= a < len(graph.decls) and 0 <= b < len(graph.decls):
                        af,bf = graph.decls[a].get('file',-1),graph.decls[b].get('file',-1)
                        if 0 <= af < len(graph.files) and 0 <= bf < len(graph.files):
                            dependencies.setdefault(graph.files[af],set()).add(graph.files[bf])
                uncertain = {graph.files[row[1]] for row in graph.strings+graph.unresolved if len(row)>1 and 0 <= row[1] < len(graph.files)}
                cached = (cache_key,dependencies,uncertain)
                self.analysis_cache['behaviorRelations'] = cached
            dependencies, uncertain = cached[1:]
            pending = list(selected)
            while pending:
                file = pending.pop()
                for dep in dependencies.get(file,()):
                    if dep not in selected: selected.add(dep); pending.append(dep)
            if not selected <= set(graph.files) or selected & uncertain:
                boundary,reason = 'all-watched','missing or unresolved dynamic dependency boundary'
            else:
                for file in selected:
                    # Existing text cache: no source parse or new graph per contract.
                    if re.search(r'\b(?:open|eval|exec|getattr|__import__|subprocess|importlib|environ|read_text|read_bytes|ReadAllText|ReadAllBytes|LoadLibrary|Assembly\.Load)\b',self.text(file)):
                        boundary,reason = 'all-watched','external or dynamic input cannot be bounded: '+file
                        break
        if boundary == 'all-watched': selected = set(all_inputs)
        else:
            # Declared non-code inputs belong to their compilation/owner layer.
            selected.update(f for r in layer_rows if r.cells['계층'] in owners for f in all_inputs
                            if not f.endswith(('.py','.cs')) and globs.matches(f,globs.split(r.cells['경로'])))
        digest = lambda value:hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        folder = Path(__file__).resolve().parent.parent
        paths = self._checker_paths(folder)+[folder/'engine.py',folder/'selftest/selftest.py']
        stamps = tuple((str(p),p.stat().st_mtime_ns,p.stat().st_size,p.stat().st_ctime_ns) for p in paths)
        runner = self.analysis_cache.get('behaviorRunner')
        if runner is None or runner[0] != stamps:
            runner = (stamps,digest({str(p.relative_to(folder)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}))
            self.analysis_cache['behaviorRunner'] = runner
        # Transport correlation IDs change on every tool/test invocation; they
        # are identities of the exchange, not semantic execution inputs.
        environment = {k:v for k,v in os.environ.items() if k not in ('CODEX_TOOL_CALL_ID','SPEC_SELFTEST_RUN_ID')}
        env = [sys.version,sys.platform,sys.executable,environment,
               [r.cells for r in self.ds.of('env')], [r.cells for r in entries],
               [r.cells for r in self.ds.of('rules') if r.cells.get('상태') in ('구현완료','수정완료')]]
        return {'inputBoundary':boundary,'boundaryReason':reason,'inputs':{f:all_inputs.get(f) for f in sorted(selected)},
                'runnerFingerprint':runner[1],'environmentFingerprint':digest(env)}

    @cachemod.produces('check.behaviors')
    def _behaviors(self):
        """W12: 동작의 구현·등록 검사·현재 입력 증거를 연결한다. 실행이나 문서 승인으로 대신하지 않는다."""
        rows = self.ds.of("behaviors")
        evidence_paths = {r.cells["증거"] for r in rows if r.cells["증거"] not in ("", "-")}
        inputs = getattr(self,"_input_index",None) or self.cur
        expected_inputs = {f: entry.get("sha256") for f, entry in (inputs.summaries() if isinstance(inputs,ledger.SourceIndex) else inputs.items()) if f not in evidence_paths}
        rules = {r.cells["규칙"]: r for r in self.ds.of("rules")}
        scopes = {r.cells["파일"] for r in self.ds.of("scope") if r.cells["상태"] != "삭제"}
        entry_layers = {r.cells["계층"] for r in self.ds.of("entries")}
        for row in rows:
            c = row.cells
            identity = c["동작 ID"]
            tag = "behavior:" + identity
            def fail(message):
                self.add("W12", row.doc, row.line, identity + ": " + message, tag)
            if c["상태"] not in {"구현완료", "수정완료"}:
                self.add("W8", row.doc, row.line, "동작 미완료: " + identity + " — " + c["상태"], tag)
            for col in ("구현 대상", "검사 연결"):
                targets = globs.split(c[col])
                if not targets or targets == ["-"]:
                    fail(col + " 없음 — " + ("동작 조건·보장을 검증하는 테스트 코드 작성·등록 필요" if col == "검사 연결" else "실제 구현과 동작 계약 연결 필요"))
                for target in targets:
                    if target == "-":
                        continue
                    file, _, member = target.partition("#")
                    if file not in self.cur or file not in scopes:
                        fail(col + "이 감시·소유 선언에 없음: " + target + " — 현재 파일의 감시·소유 등록 필요")
                        continue
                    def named(owner, name):
                        return (owner + "." if owner and owner != "-" else "") + name
                    declarations = [m for m in self.members.get(file, []) if m.parsed and
                                    named(m.parsed["path"], m.parsed["name"]) == member]
                    actual = [s for s in symbols(self.cur[file]) if named(s.path, s.name) == member]
                    if not declarations or not actual:
                        fail(col + "의 정확한 멤버 선언·코드가 없음: " + target + " — 실제 코드 작성·멤버 연결 필요")
                    elif any(m.cells["상태"] not in {"구현완료", "수정완료"} for m in declarations):
                        fail(col + "의 멤버가 미완료: " + target + " — 구현·검사 완료 근거 확인 필요")
                    if col == "검사 연결" and not any(
                            layer.cells["계층"] in entry_layers and globs.matches(file, globs.split(layer.cells["경로"]))
                            for layer in self.ds.of("layers")):
                        fail("검사 계층·실행 입구 등록 없음: " + target + " — 실행 가능한 검사 등록 필요")
            for rid in globs.split(c["규칙 연결"]):
                if rid == "-":
                    continue
                rule = rules.get(rid)
                if rule is None or rule.cells["상태"] not in {"구현완료", "수정완료"}:
                    fail("연결 규칙이 활성 상태가 아님: " + rid)
                elif any(f.rule == rid for f in self.findings):
                    fail("연결 규칙 위반이 남아 있음: " + rid)
            evidence = c["증거"]
            if evidence in ("", "-"):
                fail("현재 " + c["검사 수준"] + " 검사 증거 없음 — 등록 검사 실제 실행·결과 수집·하네스 재판정 필요")
                continue
            if evidence not in self.cur:
                fail("증거 파일이 감시 입력에 없음: " + evidence + " — 실행 결과 파일과 감시 연결 필요")
                continue
            try:
                with open(os.path.join(self.root, evidence), encoding="utf-8-sig") as stream:
                    proof = json.load(stream)
                contract = {k: v for k, v in c.items() if k not in ("상태", "증거")}
                fingerprint = hashlib.sha256(json.dumps(contract, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
                if not isinstance(proof, dict):
                    raise ValueError("JSON object required")
                if proof.get("behavior") != identity or proof.get("level") != c["검사 수준"] or proof.get("passed") is not True:
                    fail("동작 ID·검사 수준·통과 결과 불일치 — 실패한 검사·구현 수정 후 요구 수준에서 재실행 필요")
                if proof.get("contract") != fingerprint or proof.get("tests") != globs.split(c["검사 연결"]):
                    fail("조건·보장·연결 검사와 실행 증거 불일치 — 현재 계약의 검사 보완·재실행 필요")
                boundary = self.behavior_inputs(c) if proof.get('schemaVersion') == 2 and c['검사 수준']=='정적' else None
                if boundary and proof.get('inputBoundary')=='all-watched' and proof.get('boundaryReason'):
                    boundary = dict(boundary,inputBoundary='all-watched',boundaryReason=proof['boundaryReason'],inputs=expected_inputs)
                actual_inputs = boundary['inputs'] if boundary else expected_inputs
                if not actual_inputs or proof.get("inputs") != actual_inputs:
                    fail("실행 증거의 입력 목록·해시가 현재 감시 입력과 다름 — 현재 입력으로 재실행 필요")
                if boundary:
                    if any(proof.get(k) != v for k,v in boundary.items()):
                        fail('정적 검사 입력 경계·검사기·환경 불일치 — 재실행 필요')
                    try:
                        execution = proof['execution']
                        raw_path = execution['rawOutput']['path']
                        full = os.path.realpath(os.path.join(self.root,raw_path))
                        if os.path.commonpath([os.path.realpath(self.root),full]) != os.path.realpath(self.root): raise ValueError('external output')
                        raw = Path(full).read_bytes()
                        if hashlib.sha256(raw).hexdigest()!=execution['rawOutput']['sha256']: raise ValueError('raw output hash')
                        packets = [json.loads(line) for line in raw.decode('utf-8').splitlines() if line.startswith('{')]
                        result = next(p for p in reversed(packets) if p.get('event')=='summary')
                        names = {target.partition('#')[2] for target in globs.split(c['검사 연결'])}
                        results = result['results']
                        if (execution['transport']!='selftest-process' or execution['exitCode']!=0 or not execution['runId']
                                or result.get('runId')!=execution['runId'] or execution.get('aborted') or type(execution.get('processId')) is not int or execution['processId']<=0
                                or execution['inputsBefore']!=boundary or execution['inputsAfter']!=boundary
                                or result['failed'] or result['executed']!=len(results)
                                or not names <= {r['case'] for r in results if r['passed']}): raise ValueError('actual selected result mismatch')
                    except (OSError,KeyError,ValueError,TypeError,StopIteration) as error:
                        fail('정적 원 실행 결과 불일치 — 재실행 필요: '+str(error))
                if c["검사 수준"] == "앱":
                    try:
                        self._behavior_api(proof, c)
                    except (OSError, ValueError, TypeError, KeyError) as error:
                        fail("메인 앱 API 검사 근거 불일치 — 테스트 작성 후 API 실제 실행·재실행 필요: " + str(error))
            except (OSError, ValueError, TypeError) as error:
                fail("실행 증거 읽기 실패: " + str(error))

    def _behavior_api(self, proof, contract):
        """앱 검사는 현재 메인 빌드의 원 요청·응답과 등록 검사별 개별 단언을 요구한다."""
        execution = proof.get("execution")
        if not isinstance(execution, dict) or execution.get("transport") != "main-app-api":
            raise ValueError("메인 앱 API 요청·응답 없음; computer use·수동 통과 문구는 검사 증거가 아님")

        def local(path):
            if not isinstance(path, str) or not path or os.path.isabs(path):
                raise ValueError("프로젝트 상대 파일 경로 필요")
            resolved = os.path.realpath(os.path.join(self.root, path))
            if os.path.commonpath([os.path.realpath(self.root), resolved]) != os.path.realpath(self.root):
                raise ValueError("프로젝트 밖 실행 증거 경로")
            return resolved

        application = execution.get("application", "")
        if os.path.dirname(application).replace("\\", "/") != "Build" or not application.lower().endswith(".exe"):
            raise ValueError("기존 메인 Build 실행 파일 필요; 별도 복사 앱은 허용하지 않음")
        if not os.path.isfile(local(application)):
            raise ValueError("메인 실행 파일 없음")
        assembly = os.path.splitext(application)[0] + "_Data/Managed/Assembly-CSharp.dll"
        with open(local(assembly), "rb") as stream:
            assembly_hash = hashlib.sha256(stream.read()).hexdigest()

        def artifact(value):
            if not isinstance(value, dict) or value.get("path") not in self.cur:
                raise ValueError("원 요청·응답 파일의 감시 등록 없음")
            with open(local(value["path"]), "rb") as stream:
                raw = stream.read()
            if hashlib.sha256(raw).hexdigest() != value.get("sha256"):
                raise ValueError("원 요청·응답 파일 지문 불일치")
            result = json.loads(raw.decode("utf-8-sig"))
            if not isinstance(result, dict):
                raise ValueError("원 요청·응답 객체 필요")
            return result

        build = artifact(execution.get("build"))
        compiled = build.get("inputs")
        if build.get("assemblySha256") != assembly_hash or not isinstance(compiled, dict) or not compiled:
            raise ValueError("성공 빌드의 DLL·컴파일 입력 기록 없음")
        needed = {target.partition("#")[0] for column in ("구현 대상", "검사 연결") for target in globs.split(contract[column]) if target.partition("#")[0].endswith(".cs")}
        if not needed.issubset(compiled):
            raise ValueError("계약 구현·검사 소스가 빌드 입력에서 누락됨")
        # Derive the compilation boundary from the document, never from the supplied input list.
        declared = refs.layers(self.ds)
        owners = [refs.layer_of(path, declared) for path in needed]
        if not owners or any(owner is None or owner.unit != "하나" for owner in owners) or any(owner != owners[0] for owner in owners):
            raise ValueError("메인 앱 단일 컴파일 계층을 확인할 수 없음")
        owner = owners[0]
        expected = {path for path in globs.expand(self.root, owner.paths)
                    if path.lower().endswith(".cs") and refs.layer_of(path, declared) == owner}
        if set(compiled) != expected:
            missing, extra = sorted(expected-set(compiled)), sorted(set(compiled)-expected)
            raise ValueError("컴파일 입력 집합 불일치: 누락 %s · 삭제/외부 입력 %s; 다시 빌드·검사 필요" % (missing[:8], extra[:8]))
        if any(file not in self.cur or self.cur[file].get("sha256") != digest for file, digest in compiled.items()):
            raise ValueError("컴파일한 소스와 현재 감시 입력 불일치; 현재 코드로 다시 빌드·검사 필요")
        for file, digest in compiled.items():
            with open(local(file), "rb") as stream:
                if hashlib.sha256(stream.read()).hexdigest() != digest:
                    raise ValueError("컴파일한 소스와 현재 파일 불일치; 다시 빌드·검사 필요")

        exchanges = execution.get("exchanges")
        tests = globs.split(contract["검사 연결"])
        if not isinstance(exchanges, list) or len(exchanges) != len(tests):
            raise ValueError("등록된 모든 검사에 각각 API 실행 필요")
        seen = set()
        requests = set()
        for exchange in exchanges:
            if not isinstance(exchange, dict):
                raise ValueError("API 교환 객체 필요")
            test = exchange.get("test")
            if test not in tests or test in seen:
                raise ValueError("등록 검사 누락·중복·미등록 검사")
            seen.add(test)
            request, response = artifact(exchange.get("request")), artifact(exchange.get("response"))
            request_id = request.get("id")
            member = test.partition("#")[2]
            if not isinstance(request_id, str) or not request_id or request_id in requests:
                raise ValueError("API 요청 ID 없음·중복")
            requests.add(request_id)
            if request.get("command") != "frame" or request.get("option") != "contract-tests" or request.get("value") != member or request.get("channel") != contract["동작 ID"]:
                raise ValueError("동작 계약·검사와 원 요청 불일치")
            if response.get("id") != request_id or response.get("command") != "frame" or response.get("ok") is not True:
                raise ValueError("실패 응답 또는 원 요청 ID 불일치")
            if type(response.get("testProcessId")) is not int or response["testProcessId"] <= 0:
                raise ValueError("실제 앱 프로세스 ID 없음")
            if os.path.normcase(os.path.realpath(response.get("testApplication", ""))) != os.path.normcase(local(application)) or response.get("testAssemblySha256") != assembly_hash:
                raise ValueError("메인 앱 경로 또는 현재 로드 DLL 불일치")
            cases = response.get("contractTests")
            if not isinstance(cases, list) or not cases:
                raise ValueError("개별 기대값·실제값 검사 없음")
            ids = set()
            for case in cases:
                if not isinstance(case, dict) or case.get("test") != member or case.get("passed") is not True or not isinstance(case.get("id"), str) or not case["id"] or case["id"] in ids or not all(isinstance(case.get(key), str) and case[key] for key in ("expected", "actual")):
                    raise ValueError("실패·미실행·중복 검사 또는 기대값·실제값 누락")
                ids.add(case["id"])

    @cachemod.produces('check.scope_changes')
    def _scope_changes(self):
        """W7: 바뀐 파일이 어느 scope에도 없거나 상태가 '유지'. 문서 changes 표에 파일 삭제/추가로 적힌 파일은 뺀다(E18 — 문서화된 이동)."""
        moved = {r.cells["파일"] for r in self.ds.of("changes") if r.cells["변경"] in ("파일 삭제", "파일 추가")}
        first = {}
        for c in self.changes:
            first.setdefault(c.file, c.line)
            if c.base_file:
                first.setdefault(c.base_file, 1)
        for f in sorted(first):
            if f in moved:
                continue
            row = self.scope.get(f)
            if row is None:
                self.add("W7", f, first[f], "어느 문서의 scope에도 없는 파일이 바뀜(관계없는 변경)")
            elif row.cells["상태"] == "유지":
                self.add("W7", f, first[f], "scope 상태가 '유지'인 파일이 바뀜(%s:%d)" % (row.doc, row.line))

    @cachemod.produces('check.changes_documented')
    def _changes_documented(self):
        """W1: 변경마다 changes 행이 있는가. 새·지운 파일 안의 심볼 변경은 파일 단위 한 건으로 본다."""
        rows = self.ds.of("changes")
        by_file = {}
        for row in rows:
            by_file.setdefault((row.cells["파일"], row.cells["변경"]), []).append(row)
        whole = {(c.kind, c.file) for c in self.changes if c.kind in ("파일 추가", "파일 삭제")}
        gone = set()
        for c in self.changes:
            if c.kind == "삭제" and c.symkind in TYPE_KINDS and any(self._change_matches(r, c) for r in by_file.get((c.file, c.kind), ())):
                gone.add((c.file, c.name if c.path == "-" else c.path + "." + c.name))
        for c in self.changes:
            if (c.kind == "추가" and ("파일 추가", c.file) in whole) or (c.kind == "삭제" and ("파일 삭제", c.file) in whole):
                continue
            # 파일째 옮긴 심볼(새 파일은 파일 추가, 옛 파일은 파일 삭제)은 두 파일 행으로 본다
            if c.kind == "이동" and ("파일 추가", c.file) in whole and ("파일 삭제", c.base_file) in whole:
                continue
            if c.kind == "삭제" and any(f == c.file and (c.path == t or c.path.startswith(t + ".")) for f, t in gone):
                continue
            if not any(self._change_matches(r, c) for r in by_file.get((c.file, c.kind), ())):
                what = "파일" if c.kind in FILE_KINDS else "%s %s.%s" % (c.symkind, c.path, c.name)
                self.add("W1", c.file, c.line, "문서 changes에 없는 변경: %s %s%s" % (c.kind, what,
                                                                             (" | " + c.signature) if c.signature != "-" else ""))

    @cachemod.produces('check.stage_done')
    def _stage_done(self, only_files=None):
        """W10: 기준 스냅숏 단계의 changes 행 가운데, 대상 멤버가 완료 상태(구현완료·수정완료·삭제완료)인데 그 변경이 실제로 없는 것."""
        if not self.stage:
            return
        states = {}
        for f, rows in self.members.items():
            for m in rows:
                if m.parsed:
                    states[(f, m.parsed["path"], m.parsed["name"], m.parsed["signature"])] = m.cells["상태"]
        for r in self.ds.of("changes"):
            if only_files is not None and r.cells["파일"] not in only_files:
                continue
            if r.cells["단계"] != self.stage or r.cells["변경"] in FILE_KINDS or not r.parsed:
                continue
            p = r.parsed
            state = states.get((r.cells["파일"], p["path"], p["name"], p["signature"]))
            if state not in docmod.DONE:
                continue
            if not any(self._change_matches(r, c) for c in self.changes):
                self.add("W10", r.cells["파일"], 1, "문서에 '%s'인데 기준 스냅숏(%s) 대비 그 변경이 없음: %s %s (%s:%d)"
                         % (state, self.stage, r.cells["변경"], p["signature"], r.doc, r.line))

    @staticmethod
    def _change_matches(r, c):
        """changes 행 하나가 변경 하나와 맞는가(변경 종류·파일·소속 형·이름·정규화 시그니처)."""
        if r.cells["변경"] != c.kind or r.cells["파일"] != c.file:
            return False
        if c.kind in FILE_KINDS:
            return True
        p = r.parsed
        return bool(p) and p["path"] == c.path and p["name"] == c.name and p["signature"] == c.signature

    def _member_files(self, files, only_files=None):
        """내용·선언 계약·허용 목록이 같은 파일은 이전 결과를 합치고 바뀐 파일만 대조한다."""
        allowed = tuple(sorted(self.allowed))
        self._prime_checks("members", (files if only_files is None else files & only_files) - self.member_cache.keys())
        for stale in self.member_cache.keys() - files:
            del self.member_cache[stale]
        for file in sorted(files if only_files is None else files & only_files):
            entry = self.cur.get(file) or {}
            scope = self.scope.get(file)
            rows = ([scope] if scope is not None else []) + self.members.get(file, []) + self.bodies.get(file, [])
            fingerprint = cachemod.POLICY.key('members', (self.root, entry.get("sha256"),
                           entry.get("symbols"), entry.get("unit"), entry.get("error"),
                           os.path.exists(os.path.join(self.root, file)), allowed,
                           tuple((r.doc, r.line, r.cells, r.parsed) for r in rows)))
            cached = self.member_cache.get(file)
            if cached is None:
                saved = self._saved_check("members", file, "members", fingerprint)
                if saved is not None:
                    cached = (fingerprint, *saved)
                    self.member_cache[file] = cached
            if cached is not None and cached[0] == fingerprint:
                self.findings.extend(cached[1])
                self.suppressed += cached[2]
                self.member_work["reused"] += 1
                continue
            before, suppressed = len(self.findings), self.suppressed
            self.member_work["checked"] += 1
            yield file
            self.member_cache[file] = (fingerprint, self.findings[before:], self.suppressed - suppressed)
            self._saved_check("members", file, "members", fingerprint, self.member_cache[file][1:])

    @cachemod.produces('check.members')
    def _members(self, only_files=None):
        """W2·W3·W4: 모든 감시 심볼 파일과 선언 표를 양방향 대조한다.

        scope는 변경 소유권을 정하는 표다. 개요에만 등록된 파일이나
        scope가 누락된 파일도 멤버 누락 검사에서 제외하지 않는다.
        입력과 계약이 같은 파일은 이전 지적을 합산하고 변경 파일만 대조한다.
        """
        files = set(self.scope) | set(self.members) | {
            f for f, entry in (self.cur.summaries() if isinstance(self.cur,ledger.SourceIndex) else self.cur.items()) if entry.get("unit") == "심볼"
        }
        for f in self._member_files(files, only_files):
            row = self.scope.get(f)
            status = row.cells["상태"] if row else None
            exists = os.path.exists(os.path.join(self.root, f))
            entry = self.cur.get(f)
            if status == "삭제":
                if exists:
                    self.add("W4", f, 1, "scope 상태 '삭제'인 파일이 남음(%s:%d)" % (row.doc, row.line))
                if not exists:
                    continue
            if not exists:
                if row is None:
                    for r in self.members.get(f, []):
                        if r.parsed and r.cells["상태"] in ("구현완료", "수정완료", "수정중"):
                            self.add("W4", f, 1, "문서에 '%s'인데 코드 파일이 없음: %s (%s:%d)"
                                     % (r.cells["상태"], r.parsed["signature"], r.doc, r.line))
                elif status == "추가":
                    self.add("W8", f, 1, "미완성: 추가 파일이 아직 없음(%s:%d)" % (row.doc, row.line))
                else:
                    self.add("W4", f, 1, "scope 파일이 없음(%s:%d)" % (row.doc, row.line))
                continue
            if entry is None:
                self.add("W7", f, 1, "문서의 코드 파일이 감시 대상(watch)이 아님")
                continue
            if entry.get("error") or entry["unit"] != "심볼":
                continue
            code = {s.key: s for s in symbols(entry)}
            body_lines = None
            doc_rows = [r for r in self.members.get(f, []) if r.parsed]
            by_key = {r.parsed["key"]: r for r in doc_rows}
            bodies = {r.parsed["key"]: r for r in self.bodies.get(f, []) if r.parsed}
            identities = {(x.path, x.name, x.kind) for x in code.values()}
            for s in sorted(code.values(), key=lambda x: x.line):
                if s.key in by_key:
                    continue
                similar = [r for r in doc_rows if r.parsed["path"] == s.path and r.parsed["name"] == s.name
                           and r.cells["종류"] == s.kind]
                if similar:
                    self.add("W3", f, s.line, "문서와 시그니처(매개변수)가 다름 | 문서: %s | 코드: %s"
                             % (similar[0].parsed["signature"], s.signature))
                else:
                    self.add("W2", f, s.line, "문서에 없는 %s %s.%s | 코드: %s" % (s.kind, s.path, s.name, s.signature))
            for r in doc_rows:
                p, st = r.parsed, r.cells["상태"]
                s = code.get(p["key"])
                similar = (p["path"], p["name"], r.cells["종류"]) in identities
                where = "%s:%d" % (r.doc, r.line)
                if st in docmod.PLANNED:
                    # 조사·설계: 코드 작업 전. 코드에 이미 있으면 역행 — 승인본 기준으로 _regression(W11, E19)이 본다.
                    if s is None:
                        self.add("W8", f, 1, "미완성: %s — %s %s (%s)" % (st, p["path"], p["signature"], where))
                elif st in ("구현중", "수정중"):
                    if s is None and not similar and st == "수정중":
                        self.add("W4", f, 1, "문서에 '수정중'인데 고칠 멤버가 코드에 없음: %s (%s)" % (p["signature"], where))
                    elif s is not None and s.signature != p["signature"]:
                        self.add("W3", f, s.line, "문서와 시그니처가 다름 | 문서: %s | 코드: %s" % (p["signature"], s.signature))
                    else:
                        self.add("W8", f, s.line if s else 1, "진행 중: %s — %s %s (%s)" % (st, p["path"], p["signature"], where))
                elif st in ("구현완료", "수정완료"):
                    if s is None:
                        if similar:
                            candidate = next(x for x in code.values()
                                             if x.path == p["path"] and x.name == p["name"]
                                             and x.kind == r.cells["종류"])
                            self.add("W3", f, candidate.line,
                                     "문서와 시그니처가 다름 | 문서: %s | 코드: %s"
                                     % (p["signature"], candidate.signature))
                        else:
                            self.add("W4", f, 1, "문서에 '%s'인데 코드에 없음: %s (%s)" % (st, p["signature"], where))
                    elif s.signature != p["signature"]:
                        self.add("W3", f, s.line, "문서와 시그니처가 다름 | 문서: %s | 코드: %s" % (p["signature"], s.signature))
                    elif s.kind in ("method", "ctor", "operator"):
                        ext = os.path.splitext(f)[1].lower()
                        if body_lines is None:
                            body_lines = self.text(f, strings=ext != ".py").split("\n")
                        text = "\n".join(body_lines[s.line - 1:s.end])
                        body = bodies.get(s.key)
                        if body is not None:
                            if not re.fullmatch(r"[^{};=]*\)\s*\{\s*\}\s*", text.strip()):
                                self.add("W4", f, s.line, "문서의 무동작 본문 계약과 다름: %s (%s:%d)"
                                         % (s.signature, body.doc, body.line))
                        elif empty_body(text, ext, s.kind == "ctor"):
                            self.add("W4", f, s.line, "문서에 '%s'인데 본문이 비었거나 미구현 예외뿐: %s" % (st, s.signature))
                elif st == "삭제중" and s is not None:
                    self.add("W8", f, s.line, "진행 중: 삭제중 — 아직 남아 있음: %s (%s)" % (s.signature, where))
                elif st == "삭제완료" and s is not None:
                    self.add("W4", f, s.line, "문서에 '삭제완료'인데 남아 있음: %s (%s)" % (s.signature, where))

    @cachemod.produces('check.regression')
    def _regression(self):
        """W11(역행, SPEC-36 E19): 승인본(`review.approved_members`) 상태보다 앞선 코드. 승인본 상태가 착수 전(PLANNED)인데
        그 멤버가 코드에 실제로 있거나(구현·본문 있음), 승인본이 삭제 상태가 아닌데 코드에서 지워지고 작업 문서가 삭제 쪽으로
        물러난 것. 작업 문서가 아니라 승인본 상태로 판정하므로, 작업 문서만 코드에 맞춰 고쳐서는 풀리지 않고 승인돼야 풀린다."""
        if review.workflow_state(self.root)["authority"] == "code":
            return
        approved = review.approved_members(self.root)
        if not approved:
            return
        for key, (st_appr, f, p) in sorted(approved.items()):
            row = self.scope.get(f)
            if row is not None and row.cells["상태"] == "삭제":
                continue
            entry = self.cur.get(f)
            code = {}
            if entry is not None and not entry.get("error") and entry.get("unit") == "심볼":
                code = {s.key: s for s in symbols(entry)}
            s = code.get(key)
            st_work = next((r.cells["상태"] for r in self.members.get(f, []) if r.parsed and r.parsed.get("key") == key), None)
            if st_appr in docmod.PLANNED:
                if s is not None:
                    self.add("W11", f, s.line, "역행: 승인본 '%s'인데 코드에 이미 있음 — 문서 상태를 먼저 올려 승인받고 코드를 짠다: %s %s"
                             % (st_appr, p["path"], p["signature"]))
            elif st_appr not in ("삭제중", "삭제완료"):
                if s is None and (st_work is None or st_work in ("삭제중", "삭제완료")):
                    self.add("W11", f, 1, "역행: 승인본 '%s'인데 코드에서 지워짐 — 먼저 삭제를 문서에 올려 승인받는다: %s %s"
                             % (st_appr, p["path"], p["signature"]))

    @cachemod.produces('check.constants')
    def _constants(self, only_files=None):
        """W5: constants 행의 형식·값을 코드 초깃값과 대조."""
        for r in self.ds.of("constants"):
            if only_files is not None and r.cells["파일"] not in only_files:
                continue
            f, owner, name = r.cells["파일"], r.cells["형"] or "-", r.cells["이름"]
            entry = self.cur.get(f)
            if entry is None:
                continue
            found = [s for s in symbols(entry) if s.path == owner and s.name == name]
            if not found:
                designed = any(m.parsed and m.parsed["path"] == owner and m.parsed["name"] == name
                               and (m.cells["상태"] in docmod.PLANNED or m.cells["상태"] == "구현중")
                               for m in self.members.get(f, []))
                if not designed:
                    self.add("W5", f, 1, "상수·변수가 코드에 없음: %s.%s (%s:%d)" % (owner, name, r.doc, r.line))
                continue
            s = found[0]
            if r.cells["형식"] not in ("", "-") and _norm(r.cells["형식"]) != _norm(s.type):
                self.add("W5", f, s.line, "형식이 다름 %s.%s | 문서: %s | 코드: %s" % (owner, name, r.cells["형식"], s.type))
            if r.cells["값"] not in ("", "-") and _norm(r.cells["값"]) != _norm(s.value):
                self.add("W5", f, s.line, "값이 다름 %s.%s | 문서: %s | 코드: %s" % (owner, name, r.cells["값"], s.value))

    def _new_symbols(self):
        """새로 생기거나 시그니처가 바뀐 심볼(이름·주석 규칙 대상, SPEC-36 2.6). 내용 그대로 옮겨진 심볼('이동')은 뺀다(E18) —
        새 파일의 새 심볼은 심볼 단위 '추가'로 잡히므로 파일 추가 일괄 쓸기는 쓰지 않는다."""
        wanted = {(c.file, c.path, c.symkind, c.name) for c in self.changes if c.kind in ("추가", "시그니처 변경")}
        files = {item[0] for item in wanted}
        out = []
        for f, entry in self.cur.items():
            if f not in files:
                continue
            for s in symbols(entry):
                if (f, s.path, s.kind, s.name) in wanted:
                    out.append(s)
        return out

    def _code_files(self, patterns, exclude=(), candidates=None):
        """감시 파일 중 적용 패턴에 맞고 제외 패턴에 안 맞는 것."""
        return [f for f in sorted(self.cur if candidates is None else candidates) if globs.matches(f, patterns) and not globs.matches(f, exclude)]

    def _rule_input(self, row, file, allowed=None, shapes=None):
        """파일 규칙의 입력 계약. 전체 판정과 위치 교체가 같은 판정 캐시 열쇠를 만든다."""
        allowed = tuple(sorted(self.allowed)) if allowed is None else allowed
        prepared = self.analysis_cache.get("ruleContracts")
        if prepared is None or prepared[0] is not self.ds:
            prepared = (self.ds,{}, {})
            self.analysis_cache["ruleContracts"] = prepared
        shapes = prepared[1] if shapes is None else shapes
        if file not in shapes:
            rows = tuple((m.line,tuple(sorted(m.cells.items()))) for m in self.members.get(file,[]))
            scope = self.scope.get(file)
            shapes[file] = (rows,scope.cells.get("상태") if scope else None)
        rows,state = shapes[file]
        entry = self.cur[file]
        row_key = (row.doc,row.line)
        if row_key not in prepared[2]:
            prepared[2][row_key] = tuple(sorted(row.cells.items()))
        return cachemod.POLICY.key('rules', (self.root, prepared[2][row_key], entry.get("sha256"),
            entry.get("symbols"), entry.get("unit"), entry.get("error"), rows, state, allowed))

    def run_positions(self, previous, deltas, body=False):
        """문법·내용 토큰 불변: 변경 파일의 계약/텍스트 규칙만 교체하고 나머지 지적의 위치를 이동한다."""
        files = set(deltas)
        rules = [r for r in self.ds.of("rules") if r.cells["대상"] == "코드"
                 and r.cells["종류"] in ("금지","필수","의존")
                 and r.cells["상태"] not in docmod.PLANNED | {"삭제중","삭제완료"}]
        ids = {r.cells["규칙"] for r in rules}
        location_patterns = [(re.compile(re.escape(file)+r":(\d+)"),edits) for file,edits in deltas.items()]
        for f in previous:
            if f.rule.startswith("behavior:"):
                continue
            if f.file in files and ((not f.rule and f.code in ("W2","W3","W4","W8")) or f.rule in ids):
                continue
            if body and f.file in files and not f.rule and f.code in ("W1","W5","W7","W10","S2","S4"):
                continue
            line = diffmod.move_line(f.line,deltas[f.file]) if f.file in files else f.line
            if (f.code in ("W7","W9") or (f.code == "W1" and "없는 변경: 파일 " in f.message)
                    or (f.code == "L1" and f.message.startswith("어느 계층 경로에도"))):
                line = 1
            message = f.message
            if f.code == "L5":
                for pattern,edits in location_patterns:
                    message = pattern.sub(lambda match:match.group(0).rsplit(":",1)[0]+":"+
                                          str(diffmod.move_line(int(match.group(1)),edits)),message)
            self.findings.append(Finding(**dict(vars(f),line=line,message=message)))
        self._members(files)
        if body:
            self._scope_changes()
            self._changes_documented()
            self._stage_done(files)
            self._constants(files)
            if self.meta is not None:
                self._limits(files)
        for r in rules:
            if any(f.code == "D6" and f.rule == r.cells["규칙"] for f in previous):
                continue
            for file in files:
                patterns = [p.split("#",1)[0] for p in globs.split(r.cells["적용"])]
                if not globs.matches(file,patterns) or globs.matches(file,globs.split(r.cells["허용"])):
                    continue
                before, suppressed = len(self.findings),self.suppressed
                self._rule_code(r, {file})
                if r.cells["상태"] in docmod.DOING:
                    for f in self.findings[before:]:
                        if f.code == "W6":
                            f.code, f.message = "W8", "진행 중(%s 규칙): %s" % (r.cells["상태"], f.message)
                result = (self.findings[before:],self.suppressed-suppressed)
                fingerprint = self._rule_input(r,file)
                self.rule_cache[(r.cells["규칙"],file)] = (fingerprint,*result)
                self._saved_check("rules",file,r.cells["규칙"],fingerprint,result)
                self.rule_work["checked"] += 1
        self._behaviors()
        self._flush_checks(prune=False)
        return self.findings

    def _rule_batches(self, targets):
        """대상을 한 번 선택하고 파일별 미갱신 규칙만 최대 두 작업자에게 전달한다."""
        prepared, jobs = {}, {}
        if "코드" in targets and not self.rule_cache:
            self._prime_checks("rules", self.cur)
        allowed = tuple(sorted(self.allowed))
        contracts = self.analysis_cache.get("ruleContracts")
        if contracts is None or contracts[0] is not self.ds:
            contracts = (self.ds,{}, {})
            self.analysis_cache["ruleContracts"] = contracts
        file_shapes = contracts[1]
        membership = frozenset(self.cur)
        selection = self.analysis_cache.get("ruleSelections")
        if selection is None or selection[0] is not self.ds or selection[1] != membership:
            selection = (self.ds,membership,{})
            self.analysis_cache["ruleSelections"] = selection
        for slot, r in enumerate(self.ds.of("rules")):
            if (r.cells["대상"] != "코드" or "코드" not in targets
                    or r.cells["종류"] not in ("금지", "필수", "의존")
                    or r.cells["상태"] in docmod.PLANNED or r.cells["상태"] in ("삭제중", "삭제완료")):
                continue
            patterns = [p.split("#", 1)[0] for p in globs.split(r.cells["적용"])]
            exclude = globs.split(r.cells["허용"])
            if slot not in selection[2]:
                selection[2][slot] = [self._code_files([p], exclude) for p in patterns]
            selected = selection[2][slot]
            if not selected or not all(selected):
                continue
            files = sorted({f for group in selected for f in group})
            fingerprints = {}
            for file in files:
                fingerprint = self._rule_input(r,file,allowed,file_shapes)
                fingerprints[file] = fingerprint
                cached = self.rule_cache.get((r.cells["규칙"], file))
                if cached is None:
                    saved = self._saved_check("rules", file, r.cells["규칙"], fingerprint)
                    if saved is not None:
                        cached = (fingerprint, *saved)
                        self.rule_cache[(r.cells["규칙"], file)] = cached
                if not cached or cached[0] != fingerprint:
                    jobs.setdefault(file, []).append((slot, r))
            prepared[slot] = fingerprints
        payloads = [(self.root, file, self.cur[file], self.members.get(file, []), self.scope.get(file),
                     allowed, rules) for file, rules in sorted(jobs.items())]
        parallel = len(payloads) >= self.RuleParallelFiles and (os.cpu_count() or 1) > 1
        self.rule_work["workers"] = 2 if parallel else 0
        if parallel:
            with ProcessPoolExecutor(max_workers=2, mp_context=multiprocessing.get_context("spawn"),
                                     initializer=rule_worker_init) as pool:
                results = dict(pool.map(rule_file_batch, payloads, chunksize=4))
        else:
            results = dict(map(rule_file_batch, payloads))
        return prepared, results

    @cachemod.produces('check.rules')
    def _rules(self, targets=("코드", "문서경로", "문서내용")):
        """rules 행을 종류·대상별로 나눠 적용한다. 적용할 수 없는 행은 D6."""
        new_symbols = None
        links = self.analysis_cache.get("documentLinks", {})
        active_links = {r.cells["규칙"] for r in self.ds.of("rules")
                        if r.cells["대상"] == "문서내용" and r.cells["종류"] == "구조"
                        and r.cells["패턴"] == "링크" and r.cells["상태"] not in
                        (docmod.PLANNED | {"삭제중", "삭제완료"})}
        for stale in links.keys() - active_links:
            del links[stale]
        prepared, results = self._rule_batches(targets)
        for slot, r in enumerate(self.ds.of("rules")):
            rid, kind, target = r.cells["규칙"], r.cells["종류"], r.cells["대상"]
            if target not in targets:
                continue
            state = r.cells["상태"]
            if state in docmod.PLANNED or state in ("삭제중", "삭제완료"):
                if state != "삭제완료":
                    self.add("W8", r.doc, r.line, "미완성: %s 규칙 — 아직 적용하지 않음: %s" % (state, rid), rid)
                continue
            before = len(self.findings)
            try:
                if target == "코드":
                    if kind in ("이름", "주석"):
                        if new_symbols is None:
                            new_symbols = self._new_symbols()
                        self._rule_symbols(r, new_symbols)
                    else:
                        fingerprints = prepared.get(slot)
                        if fingerprints is None:
                            self._rule_code(r)
                        else:
                            rule_id = r.cells["규칙"]
                            active_keys = {(rule_id, file) for file in fingerprints}
                            for stale in [key for key in self.rule_cache if key[0] == rule_id and key not in active_keys]:
                                del self.rule_cache[stale]
                            for file, fingerprint in fingerprints.items():
                                key = (rule_id, file)
                                cached = self.rule_cache.get(key)
                                if cached and cached[0] == fingerprint:
                                    self.findings.extend(Finding(**vars(f)) for f in cached[1])
                                    self.suppressed += cached[2]
                                    self.rule_work["reused"] += 1
                                else:
                                    findings, suppressed, error = results[file][slot]
                                    self.findings.extend(Finding(**vars(f)) for f in findings)
                                    self.suppressed += suppressed
                                    if error is not None:
                                        raise ValueError(error)
                                    self.rule_cache[key] = (fingerprint, findings, suppressed)
                                    self._saved_check("rules", file, rule_id, fingerprint, (findings, suppressed))
                                    self.rule_work["checked"] += 1
                elif target == "문서경로":
                    self._rule_doc_paths(r)
                else:
                    self._rule_doc_text(r)
            except (re.error, ValueError) as e:
                self.add("D6", r.doc, r.line, "규칙 %s를 적용할 수 없음: %s" % (rid, e), rid)
            if state in docmod.DOING:
                # 구현중·수정중 규칙: 적용하되 막지 않는다(진행 중 알림)
                for f in self.findings[before:]:
                    if f.code == "W6":
                        f.code, f.message = "W8", "진행 중(%s 규칙): %s" % (state, f.message)

    @cachemod.produces('check.overview')
    def _overview(self):
        """Reuse overview judgments owned by an unchanged document and current source SHA."""
        saved = self.analysis_cache.get("overviewFiles")
        if saved is None or saved[0] is not self.ds:
            saved = (self.ds,{})
            self.analysis_cache["overviewFiles"] = saved
        groups = {}
        for row in self.ds.of("overview"):
            groups.setdefault(row.cells["파일"],[]).append(row)
        for file,rows in groups.items():
            entry = self.cur.get(file)
            fingerprint = entry.get("sha256") if entry and not entry.get("error") else None
            previous = saved[1].get(file)
            if fingerprint is not None and previous is not None and previous[0] == fingerprint:
                self.findings.extend(previous[1])
                self.suppressed += previous[2]
                continue
            before,count = len(self.findings),self.suppressed
            self._overview_rows(rows)
            if fingerprint is not None:
                saved[1][file] = (fingerprint,tuple(self.findings[before:]),self.suppressed-count)
            else:
                saved[1].pop(file,None)
        for file in saved[1].keys()-groups.keys():
            del saved[1][file]

    def _overview_rows(self, rows):
        """개요 표: 파일과 형 칸의 형(백틱 안 첫 이름)이 있는가. 조사·설계·구현중이면 없어도 W8, 수정중·완료인데 파일이 없으면 W4,
        진행 중(수정중)에 형이 없으면 W8, 완료인데 형이 없으면 W4, 삭제완료인데 있으면 W4, 삭제중이면 W8."""
        for r in rows:
            f, state = r.cells["파일"], r.cells["상태"]
            path = os.path.join(self.root, f)
            exists = os.path.isfile(path)
            if state in ("삭제중", "삭제완료"):
                if exists:
                    self.add("W4" if state == "삭제완료" else "W8", r.doc, r.line, "개요에 '%s'인데 파일이 남아 있음: %s" % (state, f))
                continue
            waiting = state in docmod.PLANNED or state == "구현중"
            if not exists:
                self.add("W8" if waiting else "W4", r.doc, r.line,
                         ("미완성: %s 파일이 아직 없음: %%s" % state if waiting else "개요의 파일이 없음: %s") % f)
                continue
            waiting = waiting or state in docmod.DOING
            if not f.endswith(".cs"):
                continue
            text = self.text(f, strings=True)
            cell = r.cells["형"]
            spans = re.findall(r"`([^`]+)`", cell) or ([cell] if cell not in ("", "-") else [])
            for span in spans:
                m = re.match(r"[A-Za-z_][\w.]*", span.strip())
                if not m:
                    continue
                name = m.group(0).split(".")[-1]
                if re.search(r"\b(?:class|struct|interface|enum|record|delegate)\s+(?:\w+\s+)*?%s\b" % re.escape(name), text):
                    continue
                self.add("W8" if waiting else "W4", r.doc, r.line,
                         ("미완성: %s 형이 아직 없음: %%s (%%s)" % state if waiting else "개요의 형이 파일에 없음: %s (%s)") % (name, f))

    @cachemod.produces('check.coverage')
    def _coverage(self):
        """W9: 감시 대상 코드 파일(심볼 단위)이 어느 scope·개요 표에도 없는가."""
        covered = set(self.scope) | {r.cells["파일"] for r in self.ds.of("overview")}
        for f, entry in sorted(self.cur.items()):
            if entry.get("unit") == "심볼" and f not in covered:
                self.add("W9", f, 1, "설계 문서(scope·개요 표)가 다루지 않는 코드 파일")

    @cachemod.produces('check.layers')
    def _layers(self):
        """L1~L5와 P2: 참조 그래프를 만들어 계층·진입점·인터페이스 표와 대조한다(2.8). 계층 표가 없으면 하지 않는다."""
        rows = self.ds.of("layers")
        if not rows:
            return
        graph = getattr(self,"_provided_graph",None) or refs.build(self.root, self.ds, self.cur, self.unity,
                           self.analysis_cache.setdefault("graphCache", {}))
        py_hashes = tuple((rel, entry.get("sha256")) for rel, entry in sorted(self.cur.items())
                          if rel.endswith(".py"))
        symbol_shape = tuple((rel, entry.get("unit"), entry.get("error"),
                              tuple((s.get("path"), s.get("kind"), s.get("name"), s.get("line"),
                                     s.get("end"), s.get("params")) for s in entry.get("symbols") or []))
                             for rel, entry in sorted(self.cur.items()) if rel.endswith((".cs", ".py")))
        cached = self.analysis_cache
        if (cached.get("ds") is self.ds and cached.get("symbolShape") == symbol_shape
                and graph == cached.get("graph")):
            self._body_files = {rel for rel,entry in self.cur.items()
                               if rel in cached.get("fileMeta",{}) and cached["fileMeta"][rel][0][0] != entry}
            self._reuse_meta = not self._body_files
            if self._reuse_meta:
                self.meta = cached["meta"]
            # 장면과 스크립트 GUID는 그래프 밖의 파일에서 읽는다. 이 진입점은
            # 현재 자산으로 다시 판정하되 선언/참조 메타데이터는 재사용한다.
            if self._assets_unchanged or not any(r.cells["종류"] == "장면" for r in self.ds.of("entries")):
                self.analysis = cached["analysis"]
                self.findings.extend(cached["layerFindings"])
                self.notes.extend(cached["layerNotes"])
                self.suppressed += cached["layerSuppressed"]
                if not self._reuse_meta:
                    self._analysis_candidate = {"ds": self.ds, "pyHashes": py_hashes, "symbolShape": symbol_shape,
                        "graph": graph, "analysis": self.analysis, "layerSuppressed": cached["layerSuppressed"],
                        "layerFindings": cached["layerFindings"], "layerNotes": cached["layerNotes"]}
                return
        if (cached.get("ds") is self.ds and cached.get("symbolShape") == symbol_shape
                and cached.get("analysis") is not None and not cached.get("layerSuppressed")
                and (self._assets_unchanged or not any(r.cells["종류"] == "장면" for r in self.ds.of("entries")))
                and layers.same_links(cached["graph"],graph)):
            before_findings, before_suppressed = len(self.findings),self.suppressed
            prior = cached["analysis"]
            self.analysis = layers.Analysis(graph,prior.rows,prior.file_layer,prior.bad_edges,prior.status)
            self.findings.extend(f for f in cached["layerFindings"] if f.code != "L5")
            self.notes.extend(cached["layerNotes"])
            layers.copies(graph,prior.rows,prior.file_layer,self.add)
            self._analysis_candidate = {"ds":self.ds,"pyHashes":py_hashes,"symbolShape":symbol_shape,
                "graph":graph,"analysis":self.analysis,"layerSuppressed":self.suppressed-before_suppressed,
                "layerFindings":tuple(self.findings[before_findings:]),"layerNotes":cached["layerNotes"]}
            self._body_files = {rel for rel,entry in self.cur.items()
                               if rel in cached.get("fileMeta",{}) and cached["fileMeta"][rel][0][0] != entry}
            return
        before_findings, before_notes = len(self.findings), len(self.notes)
        before_suppressed = self.suppressed
        if graph.error:
            self.add("P2", rows[0].doc, rows[0].line, "참조 그래프를 만들 수 없음: " + graph.error)
        broken = [u for u in graph.units if u.get("errors")]
        if broken:
            self.notes.append("참조 그래프: 컴파일 오류가 있는 단위 %d개(%s) — 해석한 참조만 판정"
                              % (len(broken), ", ".join("%s %d" % (u["name"], u["errors"]) for u in broken[:8])))
        seen = set()
        for diagnostic in graph.diagnostics:
            key = (diagnostic["file"], diagnostic["line"], diagnostic["code"], diagnostic["message"])
            if key in seen:
                continue
            seen.add(key)
            self.add("P3", diagnostic["file"], diagnostic["line"],
                     "참조 의미 해석 오류 %s: %s" % (diagnostic["code"], diagnostic["message"]))
        self.analysis = layers.judge(self.root, self.ds, graph, self.cur, self.add,
                                     self.analysis_cache.setdefault("layerInputs", {}),
                                     self.analysis_cache.setdefault("unitReach", {}))
        self._analysis_candidate = {"ds": self.ds, "pyHashes": py_hashes, "symbolShape": symbol_shape,
                                    "graph": graph, "analysis": self.analysis,
                                    "layerSuppressed": self.suppressed - before_suppressed,
                                    "layerFindings": tuple(self.findings[before_findings:]),
                                    "layerNotes": tuple(self.notes[before_notes:])}

    def _meta(self):
        """참조 메타데이터 한 벌을 만든다(2.14). 참조 그래프가 없으면 나무·문서 참조만."""
        if not self._reuse_meta:
            self.meta = (metamod.refresh_body(self.root,self.ds,self.analysis_cache["meta"],self.cur,
                         self._body_files,self.analysis_cache["fileMeta"]) if self._body_files is not None else None)
            if self.meta is not None:
                self.stage_work["bodyUpdate"] = len(self._body_files)
            else:
                self.meta = metamod.build(self.root, self.ds, self.cur, self.analysis,
                                     self.analysis_cache.setdefault("fileMeta", {}),
                                     self.analysis_cache.setdefault("relationMeta", {}),
                                     only_files=self._scoped_files if getattr(self,"_scoped",False) else None)
        if self._analysis_candidate is not None:
            self._analysis_candidate["meta"] = self.meta
            for rel in self.analysis_cache.get("sourceTexts", {}).keys() - self.cur.keys():
                del self.analysis_cache["sourceTexts"][rel]
            self.analysis_cache.publish(self._analysis_candidate)

    @cachemod.produces('check.limits')
    def _limits(self, only_files=None):
        """S1·S2·S4: 구조 한도 표의 활성 행마다 메타데이터 셈과 견준다. 범위 `문서 참조` 행은 어느 문서가 건드리는 자리만(2.6)."""
        nodes, places = self.meta.nodes, self.meta.places
        for r in self.ds.of("limits"):
            if r.cells["상태"] != "활성":
                continue
            unit, count, code, limit = r.cells["단위"], r.cells["셈"], r.cells["지적"], int(r.cells["한도"])
            for key in sorted(nodes):
                n = nodes[key]
                if only_files is not None and (n.kind == "폴더" or n.file not in only_files):
                    continue
                if n.kind != unit or n.counts.get(count, 0) <= limit:
                    continue
                place = key if unit in ("폴더", "파일") else n.file
                if r.cells["범위"] == "문서 참조" and not places.get(place):
                    continue
                if unit == "폴더" and count == "바로 든 형":
                    self.add(code, place, 1, "폴더 하나에 바로 든 형이 한도 %d개를 넘는다 — 하위 폴더로 나눈다" % limit)
                elif unit == "파일":
                    self.add(code, place, 1, "파일 하나의 %s가 구조 한도 %d개를 넘는다 — 폴더로 분기해 나눈다" % (count, limit))
                elif unit == "폴더":
                    self.add(code, place, 1, "폴더 하나의 %s가 구조 한도 %d개를 넘는다 — 하위 폴더로 나눈다" % (count, limit))
                else:
                    self.add(code, place, n.line, "%s %s의 %s가 구조 한도 %d개를 넘는다" % (unit, n.name, count, limit))

    @cachemod.produces('check.interfaces')
    def _interfaces(self):
        """I1·I2·I3: 메타데이터의 참조·인터페이스로(2.6). 참조 그래프가 없으면 하지 않는다."""
        if self.analysis is None:
            return
        nodes, m = self.meta.nodes, self.meta
        shared = {r.cells["공유 계층"] for r in self.ds.of("shared_layers")}
        shared_files = {rel for rel, layer in zip(self.analysis.graph.files, self.analysis.file_layer) if layer in shared}
        implemented = {}
        for ik, (names, impls) in m.interfaces.items():
            for c in impls:
                implemented.setdefault(c, []).append(ik)

        architecture = {r.parsed["nodeKey"]: r for r in self.ds.of("architecture")
                        if r.parsed.get("nodeKey") and r.cells["종류"] in {"class", "interface"}}
        if architecture:
            aliases, bound = {}, {}
            for key, node in nodes.items():
                if node.kind in {"클래스", "인터페이스"}:
                    aliases.setdefault(node.alias, []).append(key)
            for key, row in architecture.items():
                p = row.parsed
                if not p.get("memberFile"):
                    continue
                name = (p["memberOwner"] + "." if p["memberOwner"] != "-" else "") + p["memberName"]
                candidates = aliases.get(p["memberFile"] + "#" + name, [])
                if len(candidates) == 1:
                    bound[key] = candidates[0]
                elif candidates:
                    self.add("W12", row.doc, row.line, "구조: 형의 실제 소유 선언이 모호함 — " + name)
            reverse = {actual: key for key, actual in bound.items()}
            edges = {tuple(e) for row in architecture.values() for e in row.parsed.get("edges", []) if e[1] == "implements"}
            expected = {(bound[a], bound[b]) for a, _, b, _, _ in edges if a in bound and b in bound}
            actual = {(c, i) for c, interfaces in implemented.items() for i in interfaces}
            for c, i in actual - expected:
                if c in reverse and i in reverse:
                    self.add("I2", nodes[c].file, nodes[c].line, "구조: 실제 interface 구현의 implements 간선 없음 — " + reverse[c] + " -> " + reverse[i])
            for a, _, b, doc, line in edges:
                if a in bound and b in bound and (bound[a], bound[b]) not in actual:
                    self.add("I2", doc, line, "구조: 선언한 implements가 실제 코드와 다름 — " + a + " -> " + b)

        seen, bare = set(), {}
        for a, b, rel, line, write, crosses, via, guess in m.refs:
            t = nodes[b].owner_type
            if not crosses or not t or nodes[t].kind != "클래스":
                continue
            if t != b:
                for ik in implemented.get(t, []):
                    if nodes[b].name in m.interfaces[ik][0] and (rel, line, b) not in seen:
                        seen.add((rel, line, b))
                        self.add("I1", rel, line, "인터페이스 우회: %s → %s.%s — %s.%s로 쓴다"
                                 % (nodes[a].name, nodes[t].name, nodes[b].name, nodes[ik].name, nodes[b].name))
                        break
            if not guess and t not in implemented and rel not in shared_files and nodes[t].file not in shared_files and nodes[t].source_kind == "class" and "static" not in nodes[t].modifiers:
                bare.setdefault(nodes[t].folder, set()).add(nodes[t].name)
        for ik, (names, impls) in sorted(m.interfaces.items()):
            if not impls:
                self.add("I2", nodes[ik].file, nodes[ik].line, "구현 없는 인터페이스 %s" % nodes[ik].name)
        piped = [r.cells["폴더"] for r in self.ds.of("pipeline")]
        for folder in sorted(bare):
            # 파이프라인 표에 적힌 폴더는 I3 대신 I4(파이프라인 = 인터페이스, SPEC-00 6.8.8)
            if any(folder == p or folder.startswith(p + "/") for p in piped):
                continue
            self.add("I3", folder, 1, "인터페이스 없는 폴더 경계: 다른 폴더가 인터페이스 없이 바로 쓰는 클래스(%s) — 인터페이스를 두고 그것으로 쓰게 한다"
                     % ", ".join(sorted(bare[folder])))

    @cachemod.produces('check.pipeline')
    def _pipeline(self):
        """I4: 파이프라인 표마다 단계 폴더(하위 폴더 포함, 다른 단계로 적힌 하위 폴더는 뺌) 사이 확정 참조가 역방향이거나
        앞 단계의 입구·자료가 아니면 지적, 입구·자료가 코드에 없으면 그 표 행에 지적(2.6)."""
        architecture = {r.parsed["nodeKey"]: r for r in self.ds.of("architecture") if r.parsed.get("nodeKey")}
        if architecture:
            graph_edges = {tuple(e) for r in architecture.values() for e in r.parsed.get("edges", [])}
            relations = {(a, kind, b) for a, kind, b, _, _ in graph_edges}
            modules = {r.parsed["folder"]: key for key, r in architecture.items() if r.cells["종류"] == "module" and r.parsed.get("folder")}
            ordered = sorted(modules, key=lambda path: (-len(path), path))
            file_modules = {file: next((modules[p] for p in ordered if file.startswith(p + "/")), "") for file in self.cur}
            canonical = {}
            for file, entry in self.cur.items():
                if not file_modules.get(file):
                    continue
                for symbol, meta_key, _, _ in refs.source_records(file, entry):
                    identity = "%s|%s|%s|%s|%s" % (file, symbol.get("path") or "-", symbol.get("kind"), symbol.get("name"), symbol.get("params", ""))
                    canonical[(identity, symbol.get("signature", ""))] = meta_key
            bound, reverse, entry_targets = {}, {}, {}
            for key, row in architecture.items():
                p = row.parsed
                identity = p.get("declarationKey")
                if isinstance(identity, (list, tuple)):
                    meta_key = canonical.get(tuple(identity))
                    if meta_key in self.meta.nodes:
                        bound[key] = meta_key
                        reverse[meta_key] = key
                if "entryMembers" in p:
                    entry_targets[key] = {canonical[tuple(m)] for m in p["entryMembers"] if tuple(m) in canonical}
            chains = {}
            for key in architecture:
                chain, seen, cursor = [], set(), key
                while cursor and cursor not in seen:
                    seen.add(cursor); chain.append(cursor)
                    cursor = architecture[cursor].parsed.get("ownerKey", "") if cursor in architecture else ""
                chains[key] = set(chain)
            provides = {}
            uses = {(a, b) for a, kind, b in relations if kind == "uses"}
            for a, kind, b in relations:
                if kind == "provides":
                    provides.setdefault(b, set()).add(a)
            consumers_by_target = {}
            for consumer, entry in uses:
                if provides.get(entry):
                    for target in entry_targets.get(entry, ()):
                        consumers_by_target.setdefault(target, set()).add(consumer)
            seen_actual = set()
            confirmed_pairs = {(a, b) for a, b, _, _, _, _, _, guess in self.meta.refs if not guess}
            for a, b, rel, line, write, crosses, via, guess in self.meta.refs:
                if a not in self.meta.nodes or b not in self.meta.nodes:
                    continue
                source, target = self.meta.nodes[a], self.meta.nodes[b]
                ma, mb = file_modules.get(source.file), file_modules.get(target.file)
                if not ma or not mb or ma == mb or not crosses:
                    continue
                left = reverse.get(a) or reverse.get(source.owner_type) or ma
                right = reverse.get(b) or reverse.get(target.owner_type) or mb
                location = (rel, line, b)
                if location in seen_actual:
                    continue
                seen_actual.add(location)
                if guess:
                    # A guessed same-name target is not evidence of a call.
                    self.add("W12", rel, line, "구조: 경계 참조 대상 미확정 — " + source.name + " -> " + target.name + "; 실제 호출 검사 필요")
                    continue
                direct = (left, "calls", right) in relations or (left, "data", right) in relations
                left_members = architecture[left].cells["종류"] == "member"
                right_members = architecture[right].cells["종류"] == "member"
                consumers = consumers_by_target.get(b, set()) | consumers_by_target.get(target.owner_type, set())
                public = bool(chains.get(left, {left}) & consumers)
                if not direct and (not public or (left_members and right_members and target.kind == "메서드")):
                    self.add("I4" if rel.endswith(".py") else "I1", rel, line,
                             "구조: 선언하지 않은 실제 경계 참조 — " + left + " -> " + right)
            for a, kind, b, doc, line in graph_edges:
                if kind in {"calls", "data"} and a in bound and b in bound and (bound[a], bound[b]) not in confirmed_pairs:
                    self.add("W12", doc, line, "구조: 선언한 " + kind + "의 실제 참조 미확정 — " + a + " -> " + b + "; 실행 검사 필요")
                if kind in {"process", "request"}:
                    targets = []
                    for key in (a, b):
                        p = architecture[key].parsed
                        if p.get("memberFile"):
                            name = (p["memberOwner"] + "." if p["memberOwner"] != "-" else "") + p["memberName"]
                            targets.append(p["memberFile"] + "#" + name)
                        else:
                            targets.extend(m[0].split("|")[0] + "#" + ("." .join(m[0].split("|")[1:2]) + "." if m[0].split("|")[1] != "-" else "") + m[0].split("|")[3] for m in p.get("entryMembers", []))
                    covered = [r for r in self.ds.of("behaviors") if set(targets) and set(targets) <= set(globs.split(r.cells["구현 대상"]) + globs.split(r.cells["검사 연결"]))]
                    if not covered:
                        self.add("W12", doc, line, "구조: " + kind + "의 원 요청·응답/프로세스 검사 연결 없음 — " + a + " -> " + b)

        rows = self.ds.of("pipeline")
        if not rows:
            return
        nodes = self.meta.nodes
        stages = sorted(((r.cells["폴더"], r) for r in rows), key=lambda x: -len(x[0]))
        file_stages, node_aliases = {}, {}

        def stage_of(path):
            """그 파일이 든 단계 행(가장 긴 폴더). 없으면 None."""
            if path not in file_stages:
                file_stages[path] = next((r for folder, r in stages if path == folder or path.startswith(folder + "/")), None)
            return file_stages[path]

        def names(cell):
            """입구·자료 칸의 이름들."""
            return {x.strip() for x in cell.split(",") if x.strip() and x.strip() != "-"}

        def aliases(key, whole=False):
            """마디가 불리는 이름들: `모듈.이름`(파이썬)·`형`·`형.멤버`(C#). whole이 아니면 감싸는 형의 이름도(자료 형의 멤버)."""
            saved = node_aliases.get((key, whole))
            if saved is not None:
                return saved
            n = nodes[key]
            stem = os.path.splitext(os.path.basename(n.file))[0]
            parts = key.split("#", 1)[1].split("@")[0].split(".")
            out = set()
            for k in range(len(parts) if whole else 1, len(parts) + 1):
                q = ".".join(parts[:k])
                out |= {stem + "." + q, q}
            node_aliases[(key, whole)] = out
            return out

        allowed = {id(r): names(r.cells["입구"]) | names(r.cells["자료"]) for r in rows}
        present = {}
        for key, n in nodes.items():
            if n.kind in ("폴더", "파일"):
                continue
            r = stage_of(n.file)
            if r is not None:
                present.setdefault(id(r), set()).update(aliases(key, whole=True))
        for r in rows:
            for name in sorted(allowed[id(r)] - present.get(id(r), set())):
                self.add("I4", r.doc, r.line, "파이프라인 입구·자료가 코드에 없음: %s(단계 %s, 폴더 %s)" % (name, r.cells["단계"], r.cells["폴더"]))
        if self.analysis is None:
            return
        seen = set()
        for a, b, rel, line, write, crosses, via, guess in self.meta.refs:
            if guess or not crosses:
                continue
            ra, rb = stage_of(nodes[a].file), stage_of(nodes[b].file)
            if ra is None or rb is None or ra is rb or ra.doc != rb.doc or (rel, line, b) in seen:
                continue
            if int(rb.cells["순서"]) > int(ra.cells["순서"]):
                message = "파이프라인 역방향: %s 단계가 뒤 단계 %s의 %s를 쓴다" % (ra.cells["단계"], rb.cells["단계"], nodes[b].name)
            elif not (aliases(b) & allowed[id(rb)]):
                message = "파이프라인 입구·자료가 아님: %s 단계가 %s 단계의 %s를 쓴다 — 입구를 거치거나 표의 입구·자료에 적는다" % (
                    ra.cells["단계"], rb.cells["단계"], nodes[b].name)
            else:
                continue
            seen.add((rel, line, b))
            self.add("I4", rel, line, message)

    @cachemod.produces('check.review')
    def _review(self):
        """A1·A2: 체크 안 된·틀림 문서 변경 단위(2.12)."""
        for code, doc, line, message in review.findings(self.root):
            self.add(code, doc, line, message)

    @cachemod.produces('check.shaders')
    def _shaders(self):
        """L6: 셰이더 자리(2.8.4, SPEC-00 3.4.4). 셰이더 자리 표가 없으면 하지 않는다."""
        inputs = tuple((rel,entry.get("sha256"),entry.get("error")) for rel,entry in sorted(self.cur.items())
                       if rel.endswith((".cs", ".ps1")) or os.path.splitext(rel)[1].lower() in layers.SHADER_EXT)
        saved = self.analysis_cache.get("shaderJudgment")
        if saved is not None and saved[0] is self.ds and saved[1] == inputs:
            self.findings.extend(saved[2])
            self.suppressed += saved[3]
            return
        before,count = len(self.findings),self.suppressed
        layers.shaders(self.root, self.ds, self.cur, self.add)
        self.analysis_cache["shaderJudgment"] = (self.ds,inputs,tuple(self.findings[before:]),self.suppressed-count)

    @cachemod.produces('check.rules')
    def _rule_code(self, r, only_files=None):
        """코드 대상 금지·필수·의존 규칙."""
        rid, kind, pattern = r.cells["규칙"], r.cells["종류"], r.cells["패턴"]
        apply, allow = globs.split(r.cells["적용"]), globs.split(r.cells["허용"])
        if kind == "금지":
            rx = re.compile(pattern)
            for f in self._code_files([a for a in apply if "#" not in a], allow, only_files):
                if only_files is not None and f not in only_files:
                    continue
                for no, line in enumerate(self.text(f).split("\n"), 1):
                    if rx.search(line):
                        self.add("W6", f, no, "규칙 %s 금지 패턴: %s" % (rid, line.strip()[:160]), rid)
            # 파일#형.멤버 — 그 멤버 줄 범위만 본다. 파일·멤버가 없으면 아무것도 보지 않은 것이므로 W6.
            for item in [a for a in apply if "#" in a]:
                file, _, member = item.partition("#")
                targets = self._code_files([file], allow, only_files)
                if only_files is not None:
                    targets = [f for f in targets if f in only_files]
                if not targets:
                    if only_files is None:
                        self.add("W6", file, 1, "규칙 %s 금지: 적용 파일이 없음" % rid, rid)
                    continue
                owner, _, name = member.rpartition(".")
                for f in targets:
                    found = [s for s in symbols(self.cur.get(f)) if s.name == name and (not owner or s.path.endswith(owner))]
                    if not found:
                        self.add("W6", f, 1, "규칙 %s 금지: 멤버 %s 없음" % (rid, member), rid)
                        continue
                    lines = self.text(f).split("\n")
                    for s in found:
                        for no in range(s.line, min(s.end, len(lines)) + 1):
                            if rx.search(lines[no - 1]):
                                self.add("W6", f, no, "규칙 %s 금지 패턴: %s" % (rid, lines[no - 1].strip()[:160]), rid)
        elif kind == "필수":
            rx = re.compile(pattern, re.MULTILINE)
            for item in apply:
                file, _, member = item.partition("#")
                targets = self._code_files([file], candidates=only_files)
                if only_files is not None:
                    targets = [f for f in targets if f in only_files]
                if not targets:
                    if only_files is not None:
                        continue
                    row = self.scope.get(file)
                    if row is not None and row.cells["상태"] == "추가" and not os.path.exists(os.path.join(self.root, file)):
                        continue
                    self.add("W6", file, 1, "규칙 %s 필수: 적용 파일이 없음" % rid, rid)
                    continue
                for f in targets:
                    text = self.text(f)
                    line = 1
                    if member:
                        owner, _, name = member.rpartition(".")
                        found = [s for s in symbols(self.cur.get(f)) if s.name == name and (not owner or s.path.endswith(owner))]
                        if not found and any(m.parsed and m.parsed["name"] == name
                                             and (m.cells["상태"] in docmod.PLANNED or m.cells["상태"] == "구현중")
                                             for m in self.members.get(f, [])):
                            continue
                        if not found:
                            self.add("W6", f, 1, "규칙 %s 필수: 멤버 %s 없음" % (rid, member), rid)
                            continue
                        s = found[0]
                        line = s.line
                        text = "\n".join(text.split("\n")[s.line - 1:s.end])
                    if not rx.search(text):
                        self.add("W6", f, line, "규칙 %s 필수 패턴 없음: %s" % (rid, pattern), rid)
        elif kind == "의존":
            rx = re.compile(r"\b(?:%s)\b" % pattern)
            allowed = set(globs.split(r.cells["허용"]))
            for f in self._code_files(apply, candidates=only_files):
                if only_files is not None and f not in only_files:
                    continue
                seen = set()
                for no, line in enumerate(self.text(f, strings=True).split("\n"), 1):
                    for m in rx.finditer(line):
                        word = m.group(0)
                        if word not in allowed and word not in seen:
                            seen.add(word)
                            self.add("W6", f, no, "규칙 %s 의존: 허용 목록 밖 '%s'" % (r.cells["규칙"], word), r.cells["규칙"])

    def _rule_symbols(self, r, new_symbols):
        """코드 대상 이름·주석 규칙(새·바뀐 심볼 중 선택자에 맞는 것)."""
        rid, kind = r.cells["규칙"], r.cells["종류"]
        apply = globs.split(r.cells["적용"])
        selectors = [parse_selector(x) for x in r.cells["허용"].split(",") if x.strip() and x.strip() != "-"]
        rx = re.compile(r.cells["패턴"]) if kind == "이름" else None
        for s in new_symbols:
            if not globs.matches(s.file, apply) or not any(selector_match(sel, s) for sel in selectors):
                continue
            if kind == "이름" and not rx.fullmatch(s.name.split(".")[-1].lstrip("~")):
                self.add("W6", s.file, s.line, "규칙 %s 이름: %s %s" % (rid, s.kind, s.name), rid)
            if kind == "주석" and not s.documented:
                self.add("W6", s.file, s.line, "규칙 %s 주석 없음: %s %s.%s" % (rid, s.kind, s.path, s.name), rid)

    def _rule_doc_paths(self, r):
        """문서경로 금지 규칙."""
        rid = r.cells["규칙"]
        for rel in globs.expand(self.root, globs.split(r.cells["적용"])):
            if not globs.matches(rel, globs.split(r.cells["허용"])):
                self.add("W6", rel, 1, "규칙 %s 문서 위치 위반" % rid, rid)

    def _document_layout(self, r):
        """총괄의 상세 계약과 패키지별 소스·문서 폴더 소유 연결을 판정한다."""
        rid = r.cells["규칙"]
        selected = {path for path in self.ds.docs if globs.matches(path, globs.split(r.cells["적용"]))}
        def package(path):
            match = re.match(r"^(Docs/04_Specifications/[0-9]{2}-[^/]+?)(?:\.md$|/)", path)
            return match[1] if match else None
        def emit(row, message):
            self.add("W6", row.doc, row.line, "규칙 %s 문서 분리: %s" % (rid, message), rid)
        mappings, destinations = {}, set()
        for row in self.ds.of("document_folders"):
            if row.doc not in selected:
                continue
            owner = package(row.doc)
            source, target = row.cells["소스 폴더"], row.cells["문서 폴더"]
            invalid = lambda path: (not path or path == "-" or path.startswith("/") or
                                    any(c in path for c in "\\:*?[]") or
                                    any(part in ("", ".", "..") for part in path.split("/")))
            if (source != "." and invalid(source)) or invalid(target):
                emit(row, "폴더 연결은 정규 프로젝트 상대 경로여야 함: " + source + " → " + target)
                continue
            if not owner or not target.startswith(owner + "/"):
                emit(row, "문서 폴더가 같은 SPEC 패키지의 모듈 폴더가 아님: " + target)
                continue
            key = (owner, source)
            if key in mappings:
                previous = mappings[key]
                emit(previous, "중복 소스·문서 폴더 연결: " + source + " → " + target)
                emit(row, "중복 소스·문서 폴더 연결: " + source + " → " + target)
            else:
                mappings[key] = row
                destinations.add((owner, target))
        details, owners = {}, {}
        deleted = {(row.doc, row.cells["파일"]) for row in self.ds.of("scope") if row.cells["상태"] == "삭제"}
        for kind in ("scope", "members", "body", "constants"):
            for row in self.ds.of(kind):
                if row.doc not in selected:
                    continue
                file = row.cells["파일"]
                details.setdefault(row.doc, {}).setdefault(file, row)
                if kind in ("scope", "members"):
                    owners.setdefault(file, {}).setdefault(row.doc, row)
        for file, rows in owners.items():
            if len(rows) > 1:
                for row in rows.values():
                    emit(row, "scope·members 소유 문서 중복: " + file + " — " + ", ".join(sorted(rows)))
        for doc, files in details.items():
            owner = package(doc)
            first = min(files.values(), key=lambda row: row.line)
            if not owner:
                continue
            if doc == owner + ".md":
                emit(first, "총괄에 상세 scope·members·body·constants 계약이 있음; " + owner + "/의 모듈 문서로 이동")
                continue
            if owner + ".md" not in self.ds.docs:
                emit(first, "상세 문서의 총괄 패키지 문서 없음: " + owner + ".md")
            if "/" not in doc[len(owner) + 1:]:
                emit(first, "상세 계약은 동명 패키지 안의 모듈 폴더에 배치해야 함")
                continue
            actual = doc.rpartition("/")[0]
            while actual and (owner, actual) not in destinations:
                actual = actual.rpartition("/")[0]
            for file, row in files.items():
                if (doc, file) in deleted or row.cells.get("상태") in ("삭제중", "삭제완료"):
                    continue
                directory = file.rpartition("/")[0]
                mapping = None
                while directory:
                    mapping = mappings.get((owner, directory))
                    if mapping is not None:
                        break
                    directory = directory.rpartition("/")[0]
                if mapping is None:
                    mapping = mappings.get((owner, "."))
                if mapping is None:
                    emit(row, "소스 폴더의 문서 폴더 연결 없음: " + file)
                else:
                    expected = mapping.cells["문서 폴더"]
                    if actual != expected:
                        emit(row, "상세 계약의 소유 위치 불일치: " + file + " → " + expected + "/")

    def _rule_doc_text(self, r):
        """문서내용 필수·금지·구조·목록 규칙."""
        rid, kind, pattern = r.cells["규칙"], r.cells["종류"], r.cells["패턴"]
        if kind == "구조" and pattern == "문서분리":
            self._document_layout(r)
            return
        path_key = (r.cells["적용"], r.cells["허용"] if kind == "금지" else "")
        if path_key not in self._doc_paths:
            self._doc_paths[path_key] = globs.expand(self.root, globs.split(path_key[0]), globs.split(path_key[1]))
        retained = self.analysis_cache.setdefault("documentRules", {})
        for key in list(retained):
            if key[0] == rid and key[1] not in self._doc_paths[path_key]:
                del retained[key]
        for rel in self._doc_paths[path_key]:
            text_key = (rel, "document")
            if text_key not in self._texts:
                lines = self.ds.texts.get(rel)
                self._texts[text_key] = "\n".join(lines) if lines is not None else snapshot.read_text(self.root, rel)
            text = self._texts[text_key]
            local = kind in ("필수", "금지") or (kind == "구조" and pattern in ("제목번호", "머메이드"))
            fingerprint = (self.root, tuple(sorted(r.cells.items())), hashlib.sha256(text.encode("utf-8")).digest(), tuple(sorted(self.allowed)))
            saved = retained.get((rid, rel)) if local else None
            if saved is not None and saved[0] == fingerprint:
                self.findings.extend(Finding(**vars(f)) for f in saved[1])
                self.suppressed += saved[2]
                continue
            before, suppressed = len(self.findings), self.suppressed
            if kind == "필수":
                if not re.search(pattern, text, re.MULTILINE):
                    self.add("W6", rel, 1, "규칙 %s 필수 내용 없음: %s" % (rid, pattern), rid)
            elif kind == "금지":
                rx = re.compile(pattern)
                for no, line in enumerate(text.split("\n"), 1):
                    if rx.search(line):
                        self.add("W6", rel, no, "규칙 %s 금지 내용: %s" % (rid, line.strip()[:160]), rid)
            elif kind == "구조":
                if pattern == "제목번호":
                    problems = check_headings(text)
                elif pattern == "링크":
                    links = self.analysis_cache.setdefault("documentLinks", {}).setdefault(rid, {})
                    for stale in links.keys() - set(self._doc_paths[path_key]):
                        del links[stale]
                    problems = check_links(self.root, rel, text, links)
                elif pattern == "머메이드":
                    problems = check_mermaid(text, set(globs.split(r.cells["허용"])))
                else:
                    raise ValueError("모르는 구조 검사 '%s'" % pattern)
                for no, message in problems:
                    self.add("W6", rel, no, "규칙 %s %s" % (rid, message), rid)
            elif kind == "목록":
                for listed in globs.expand(self.root, globs.split(r.cells["허용"])):
                    if os.path.basename(listed) not in text:
                        self.add("W6", rel, 1, "규칙 %s 목록에 없음: %s" % (rid, os.path.basename(listed)), rid)
            if local:
                retained[(rid, rel)] = (fingerprint, tuple(Finding(**vars(f)) for f in self.findings[before:]),
                                        self.suppressed - suppressed)
