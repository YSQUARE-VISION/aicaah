# -*- coding: utf-8 -*-
"""문서의 기계 판독 표(SPEC-00 6.8)를 뽑고 형식을 검사한다(SPEC-36 2.4). 문서 이름이나 규칙을 스스로 갖지 않는다.

표는 머리줄로 종류를 정한다(표 종류 주석 줄은 쓰지 않는다). 문서의 모든 표와 글을 읽는다 — 표 형식을 닮았지만 어느 종류와도 맞지 않는 표(D7),
어느 규칙 표에도 없는 규칙 id(D8), 멤버 표에 없는 `형.멤버`(D9)를 잡는다."""
import os
import re
import hashlib
import json
import marshal
import zlib
from dataclasses import dataclass, field
from collections.abc import Mapping
from collections import Counter

from parsing import globs
from parsing import parse_cs
from parsing import parse_py
from parsing import languages
from storage import design, reference_store

PARSER_INPUT = hashlib.sha256(b"".join(open(path,"rb").read() for path in (__file__,parse_cs.__file__,parse_py.__file__,languages.__file__))).hexdigest()

COLUMNS = {
    "document_folders": ["소스 폴더", "문서 폴더", "이유"],
    "architecture": ["도식 ID", "구조 ID", "종류", "소유 ID", "선언 연결", "책임"],
    "scope": ["파일", "상태", "책임"],
    "members": ["파일", "형", "종류", "시그니처", "상태", "설명"],
    "body": ["파일", "형", "시그니처", "본문 계약", "이유"],
    "behaviors": ["동작 ID", "조건", "보장", "구현 대상", "상태", "규칙 연결", "검사 연결", "검사 수준", "증거"],
    "constants": ["파일", "형", "이름", "형식", "값", "단위"],
    "rules": ["규칙", "상태", "종류", "대상", "패턴", "적용", "허용", "이유"],
    "changes": ["단계", "변경", "파일", "형", "시그니처", "이유"],
    "watch": ["경로", "단위", "포함", "이유"],
    "allow": ["규칙", "경로", "이유"],
    "overview": ["파일", "형", "역할", "상태"],
    "layers": ["계층", "경로", "참조", "단위", "환경", "이유"],
    "shared_layers": ["공유 계층", "이유"],
    "env": ["환경", "참조", "정의", "이유"],
    "entries": ["계층", "종류", "대상", "이유"],
    "interface": ["계층", "형", "멤버", "이유"],
    "shaders": ["자리", "부르는 코드", "이유"],
    "phases": ["순위", "페이즈", "대상", "이유"],
    "limits": ["단위", "셈", "한도", "범위", "상태", "지적", "이유"],
    "pipeline": ["순서", "단계", "폴더", "입구", "자료", "이유"],
    "compilation": ["검사 파일", "컴파일 입력", "이유"],
    "compile_variant": ["검사 파일", "실행 입구", "정의", "변환기", "변환 입력", "이유"],
}
# 상태(멤버·개요·규칙 표, SPEC-00 6.8): 무엇을 하는가(조사·설계·구현=새로·수정=기존·삭제) × 어디까지 왔는가(중·완료)
STATES = ["조사중", "조사완료", "설계중", "설계완료", "구현중", "구현완료", "수정중", "수정완료", "삭제중", "삭제완료"]
PLANNED = {"조사중", "조사완료", "설계중", "설계완료"}
DOING = {"구현중", "수정중", "삭제중"}
DONE = {"구현완료", "수정완료", "삭제완료"}
SYMBOL_KINDS = ["enum-member", "interface", "delegate", "operator", "property", "indexer", "method", "struct", "record",
                "class", "const", "event", "field", "ctor", "enum"]
VALUES = {
    ("architecture", "종류"): {"module", "interface", "class", "member", "entry", "data"},
    ("scope", "상태"): {"유지", "변경", "추가", "삭제"},
    ("members", "종류"): set(SYMBOL_KINDS),
    ("members", "상태"): set(STATES),
    ("body", "본문 계약"): {"무동작"},
    ("behaviors", "상태"): set(STATES),
    ("behaviors", "검사 수준"): {"정적", "숫자", "앱"},
    ("rules", "상태"): set(STATES),
    ("rules", "종류"): {"필수", "금지", "의존", "이름", "주석", "구조", "목록"},
    ("rules", "대상"): {"코드", "문서경로", "문서내용"},
    ("changes", "변경"): {"추가", "삭제", "시그니처 변경", "본문 변경", "이동", "파일 추가", "파일 삭제", "파일 변경"},
    ("watch", "단위"): {"심볼", "파일"},
    ("watch", "포함"): {"포함", "제외"},
    ("overview", "상태"): set(STATES),
    ("layers", "단위"): {"하나", "폴더", "파일"},
    ("entries", "종류"): {"특성", "메시지", "상속", "장면", "이름", "직렬화", "문자열", "스크립트"},
    ("limits", "단위"): {"폴더", "파일", "인터페이스", "클래스", "메서드"},
    ("limits", "셈"): {"바로 든 파일", "바로 든 형", "바로 든 인터페이스", "바로 든 클래스", "인터페이스", "클래스", "메서드", "변수",
                     "멤버", "구현", "매개변수", "지역 변수"},
    ("limits", "범위"): {"전체", "문서 참조"},
    ("limits", "상태"): {"활성", "비활성"},
    ("limits", "지적"): {"S1", "S2", "S4"},
}
CODE_COLUMNS = {
    "document_folders": {"소스 폴더", "문서 폴더"},
    "architecture": {"선언 연결"},
    "scope": {"파일"},
    "members": {"파일", "형", "시그니처"},
    "body": {"파일", "형", "시그니처"},
    "behaviors": {"구현 대상", "규칙 연결", "검사 연결", "증거"},
    "constants": {"파일", "형", "형식", "값"},
    "rules": {"패턴", "적용", "허용"},
    "changes": {"파일", "형", "시그니처"},
    "watch": {"경로"},
    "allow": {"경로"},
    "overview": {"파일", "형"},
    "layers": {"경로"},
    "shared_layers": set(),
    "env": {"참조", "정의"},
    "entries": {"대상"},
    "interface": {"형", "멤버"},
    "shaders": {"자리", "부르는 코드"},
    "phases": {"대상"},
    "limits": set(),
    "pipeline": {"폴더", "입구", "자료"},
    "compilation": {"검사 파일", "컴파일 입력"},
    "compile_variant": {"검사 파일", "실행 입구", "변환기", "변환 입력"},
}
LEGACY = re.compile(r"^\s*<!--\s*codedoc:")
SEPARATOR = re.compile(r"^\s*\|[\s\-:|]+\|\s*$")
RULE_ID = re.compile(r"(?<![A-Za-z0-9_-])R-[A-Z]{1,3}[0-9]{0,3}(?![A-Za-z0-9_-])")
MEMBER_REF = re.compile(r"(?<![A-Za-z0-9_.])([A-Z][A-Za-z0-9_]*(?:\.[A-Z][A-Za-z0-9_]*)*)\.([A-Za-z_][A-Za-z0-9_]*)(?![A-Za-z0-9_])")
FILE_EXT = {"cs", "py", "js", "jsx", "ts", "tsx", "java", "go", "cjs", "mjs", "cts", "mts", "toml", "cjs", "md", "json", "jsonl", "bin", "ps1", "txt", "asset", "dll", "png", "glb", "pmx", "exe", "meta",
            "shader", "compute", "cginc", "hlsl", "xwear", "vrm", "vmd", "bvh", "vrma"}
TYPE_KINDS = {"class", "struct", "interface", "enum", "record", "delegate"}
FILE_KINDS = {"파일 추가", "파일 삭제", "파일 변경"}


@dataclass
class Row:
    """표의 한 행."""
    doc: str
    line: int
    kind: str
    cells: dict
    parsed: dict = field(default_factory=dict)


@dataclass
class Issue:
    """문서 형식 오류(D) 또는 파싱 오류(P)."""
    code: str
    file: str
    line: int
    message: str


class DocSet:
    """읽은 모든 표·글과 형식 오류."""

    def __init__(self):
        """빈 표 모음."""
        self._stored = None
        self._selected = None
        self.rows = []
        self.issues = []
        self.docs = []
        self.texts = {}
        self.suppressed = 0
        self._kind_rows = {}
        self._kind_rows_version = None

    def __getattr__(self, name):
        """Full materialization is explicit; incremental callers use of/selected_rows."""
        if name != 'rows':
            raise AttributeError(name)
        self.rows = load(self.root,self.docs,source_root=self.source_root).rows
        return self.rows

    def of(self, kind, files=None, cells=None):
        """종류별 행."""
        files = self._selected if files is None else files
        if self._stored is not None and 'rows' not in self.__dict__ and kind != 'architecture-graph':
            key = (kind, None if files is None else tuple(sorted(files)),tuple(sorted((cells or {}).items())))
            if key not in self._kind_rows:
                self._kind_rows[key] = [Row(**row) for row in design.contract_rows(self.root,self._stored,(kind,),files,cells)]
            return list(self._kind_rows[key])
        version = (id(self.rows), len(self.rows))
        if version != self._kind_rows_version:
            grouped = {}
            for row in self.rows:
                grouped.setdefault(row.kind, []).append(row)
            self._kind_rows = grouped
            self._kind_rows_version = version
        rows = list(self._kind_rows.get(kind, ()))
        if cells:
            rows = [r for r in rows if all(r.cells.get(k)==v for k,v in cells.items())]
        if files is not None and kind in {'scope','members','body','constants','changes','overview','behaviors'}:
            if kind == 'behaviors':
                return [r for r in rows if {t.partition('#')[0] for col in ('구현 대상','검사 연결') for t in globs.split(r.cells[col])} & set(files) or r.cells['증거'] not in ('','-')]
            return [r for r in rows if r.cells['파일'] in files or any(x in r.cells['파일'] for x in '*?[')]
        return rows

    def selected_rows(self, files=None, kinds=None):
        """Select contract rows by owner in SQL, leaving unrelated payloads unloaded."""
        files = self._selected if files is None else files
        kinds = tuple(kinds) if kinds is not None else tuple(COLUMNS)
        rows = [row for kind in kinds for row in self.of(kind,files)]
        if files is not None:
            rows = [r for r in rows if r.kind != 'pipeline' or any(f == r.cells['폴더'] or f.startswith(r.cells['폴더']+'/') for f in files)]
        order = {path:i for i,path in enumerate(self.docs)}
        return sorted(rows,key=lambda r:(order.get(r.doc,-1),r.line))

    def scoped(self, files):
        """A view of the same validated basis, restricted to affected source contracts."""
        import copy
        view=copy.copy(self)
        view._selected=set(files)
        return view

    def row_counts(self):
        return dict(self._stored['counts']) if self._stored is not None else dict(Counter(r.kind for r in self.rows))


class DocumentTexts(Mapping):
    """Document text is retrieved only when a caller needs that document's content."""
    def __init__(self, ds):
        self.ds, self.cache = ds, {}

    def __iter__(self):
        return iter(self.ds.docs)

    def __len__(self):
        return len(self.ds.docs)

    def __contains__(self, path):
        return path in self.ds.docs

    def __getitem__(self, path):
        if path not in self.cache:
            lines=design.contract_text(self.ds.root,self.ds._stored,path)
            self.cache[path]=zlib.compress(marshal.dumps(lines),1)
            return lines
        return marshal.loads(zlib.decompress(self.cache[path]))


def split_cells(line):
    """표 한 줄을 칸으로 나눈다. `\\|`는 칸 구분이 아니다."""
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|") and not s.endswith("\\|"):
        s = s[:-1]
    return [cell.strip() for cell in re.split(r"(?<!\\)\|", s)]



def clean(cell):
    """칸 이스케이프와 전체를 감싼 같은 길이의 백틱을 벗긴다."""
    value = cell.replace("\\|", "|").strip()
    if len(value) >= 2 and value.startswith("`") and value.endswith("`") and value.count("`") == 2:
        value = value[1:-1]
    else:
        span = re.fullmatch(r"(`+)(?!`)(.*?)(?<!`)\1", value, re.S)
        if span and not re.search(r"(?<!`)" + re.escape(span[1]) + r"(?!`)", span[2]):
            value = span[2]
    return value


def kind_of(header):
    """머리줄이 어느 종류와 정확히 같으면 그 종류, 아니면 None."""
    for kind, cols in COLUMNS.items():
        if header == cols:
            return kind
    return None


def resembles(header):
    """어느 종류와도 같지 않은데 그 종류의 첫 열(파일·규칙·단계·경로)을 가지고, 그 종류의 열을 셋 이상 갖거나
    열 전부가 그 종류의 열(둘 이상)이면 그 종류(D7). 아니면 None."""
    best, shared = None, 0
    names = set(header)
    for kind, cols in COLUMNS.items():
        key = cols[1] if kind in ("changes", "phases") else cols[0]
        n = len(names & set(cols))
        if key not in names or not (n >= 3 or (len(header) >= 2 and names < set(cols))):
            continue
        if n > shared:
            best, shared = kind, n
    return best


def infer(signature, container, file):
    """종류 칸 없이 시그니처만 있을 때(변경 표) 코드 파서로 종류를 알아낸다."""
    ext = os.path.splitext(file)[1].lower()
    if ext == ".py":
        kind = "class" if signature.strip().startswith("class ") else ("method" if "(" in signature else "field")
        return parse_py.parse_signature(signature, kind, container)
    if ext in languages.EXTENSIONS and ext != '.cs':
        kind = next((k for k in ('class', 'interface', 'enum', 'struct', 'record') if re.search(r'\b' + k + r'\b', signature)),
                    'method' if '(' in signature else 'field')
        return languages.signature(signature, kind, container, file)
    for kw in ("class", "struct", "interface", "enum", "record"):
        if re.search(r"(^|\s)%s\s" % kw, signature):
            return parse_cs.parse_signature(signature, kw, container)
    kind = "method" if "(" in signature.split("=")[0] else ("property" if "{" in signature else "field")
    return parse_cs.parse_signature(signature, kind, container)


def _parse_member(row, issues):
    """members 행의 시그니처를 코드 파서로 정규화하고 키를 만든다. 실패하면 D5."""
    file, sig, kind, owner = row.cells["파일"], row.cells["시그니처"], row.cells["종류"], row.cells["형"]
    ext = os.path.splitext(file)[1].lower()
    try:
        if ext in languages.EXTENSIONS:
            norm, name, params, parsed_kind = languages.signature(sig, kind, owner, file)
        else:
            norm, name, params, parsed_kind = parse_cs.parse_signature(sig, kind, owner)
    except parse_cs.ParseError as e:
        issues.append(Issue("D5", row.doc, row.line, "시그니처를 읽을 수 없음: %s (%s)" % (sig, e)))
        return
    if kind in ("field", "const") and parsed_kind in ("field", "const"):
        parsed_kind = kind
    if parsed_kind != kind:
        issues.append(Issue("D5", row.doc, row.line, "종류 '%s'와 시그니처가 맞지 않음(읽은 종류 '%s')" % (kind, parsed_kind)))
    path = owner if owner and owner != "-" else "-"
    row.parsed = {"signature": norm, "name": name, "params": params,
                  "key": "%s|%s|%s|%s|%s" % (file, path, kind, name, params), "path": path}


def _parse_body(row, issues):
    """무동작 계약은 정확한 C# void 메서드 선언과 이유를 요구한다."""
    member = Row(row.doc, row.line, "members", dict(row.cells, 종류="method"))
    _parse_member(member, issues)
    row.parsed = member.parsed
    if not row.cells["파일"].endswith(".cs") or not re.search(r"\bvoid\s+[\w.]+\s*\(", row.cells["시그니처"]):
        issues.append(Issue("D2", row.doc, row.line, "무동작 본문 계약은 C# void 메서드에만 지정한다"))
    if row.cells["이유"] in ("", "-"):
        issues.append(Issue("D2", row.doc, row.line, "본문 계약에는 부작용을 금지하는 이유를 적는다"))


def _parse_change(row, issues):
    """changes 행의 시그니처를 정규화한다(종류는 시그니처에서 추정)."""
    sig = row.cells["시그니처"]
    if row.cells["변경"] in FILE_KINDS:
        return
    if not sig or sig == "-":
        issues.append(Issue("D2", row.doc, row.line, "심볼 변경에 시그니처가 없음"))
        return
    owner = row.cells["형"]
    try:
        norm, name, params, kind = infer(sig, owner, row.cells["파일"])
    except parse_cs.ParseError as e:
        issues.append(Issue("D5", row.doc, row.line, "시그니처를 읽을 수 없음: %s (%s)" % (sig, e)))
        return
    path = owner if owner and owner != "-" else "-"
    row.parsed = {"signature": norm, "name": name, "params": params, "kind": kind,
                  "key": "%s|%s|%s|%s|%s" % (row.cells["파일"], path, kind, name, params), "path": path}


def orphan_contract(raw):
    """머리줄 없이 떨어진 정의·변경·소유 행이면 종류를 반환한다. 설명 표는 건드리지 않는다."""
    cells = [clean(c) for c in split_cells(raw)]
    if len(cells) == 9 and cells[4] in STATES and cells[7] in {"정적", "숫자", "앱"}:
        return "behaviors"
    if len(cells) == 6:
        if cells[2] in VALUES[("architecture", "종류")] and cells[4].startswith(("folder:", "member:", "pipeline:", "pipeline-data:", "interface:", "spec:")):
            return "architecture"
        if cells[2] in SYMBOL_KINDS and cells[4] in STATES:
            return "members"
        if cells[1] in VALUES[("changes", "변경")] and "/" in cells[2]:
            return "changes"
    if len(cells) == 3 and cells[1] in VALUES[("scope", "상태")] and "/" in cells[0]:
        return "scope"
    return None


def _behavior_rows(ds):
    """동작 설계의 감시·소유·형·정확한 변경·검사 연결을 검사한다. 실제 실행 증거는 W12가 판단한다."""
    seen = set()
    rules = {r.cells["규칙"] for r in ds.of("rules")}
    members, types = {}, set()
    for declaration in ds.of("members"):
        p = declaration.parsed
        if not p or declaration.cells["상태"] in {"삭제중", "삭제완료"}:
            continue
        name = (p["path"] + "." if p["path"] != "-" else "") + p["name"]
        key = (declaration.cells["파일"], name)
        members.setdefault(key, []).append(declaration)
        if declaration.cells["종류"] in TYPE_KINDS:
            types.add(key)
    scopes = {r.cells["파일"] for r in ds.of("scope") if r.cells["상태"] != "삭제"}
    included = [p for r in ds.of("watch") if r.cells["포함"] == "포함" and r.cells["단위"] == "심볼" for p in globs.split(r.cells["경로"])]
    excluded = [p for r in ds.of("watch") if r.cells["포함"] == "제외" for p in globs.split(r.cells["경로"])]
    changes = {(r.parsed["key"], r.parsed["signature"]) for r in ds.of("changes")
               if r.parsed and r.cells["변경"] not in {"삭제", "파일 삭제"}}
    for row in ds.of("behaviors"):
        c = row.cells
        identity = c["동작 ID"]
        executable = False
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", identity):
            ds.issues.append(Issue("D2", row.doc, row.line, "동작 ID는 영문 식별자: " + identity))
        if identity in seen:
            ds.issues.append(Issue("D4", row.doc, row.line, "같은 동작 ID가 두 번: " + identity))
        seen.add(identity)
        for col in ("조건", "보장"):
            if c[col] in ("", "-"):
                ds.issues.append(Issue("D2", row.doc, row.line, "동작 계약의 빈 " + col))
        for col in ("구현 대상", "검사 연결", "증거"):
            if col != "증거" and not globs.split(c[col]):
                ds.issues.append(Issue("D2", row.doc, row.line, identity + ": " + col + " 없음 — 정확한 멤버와 검사 함수를 등록한다"))
            for target in globs.split(c[col]):
                if target == "-":
                    continue
                path, marker, member = target.partition("#")
                invalid = (not path or path.startswith("/") or re.match(r"^[A-Za-z]:", path)
                           or "\\" in path or any(part in ("", ".", "..") for part in path.split("/")))
                if invalid or any(ch in path for ch in "*?[]"):
                    ds.issues.append(Issue("D3", row.doc, row.line, "동작 계약은 정확한 프로젝트 상대 경로: " + target))
                if col == "증거":
                    if marker or not path.endswith(".json"):
                        ds.issues.append(Issue("D2", row.doc, row.line, "동작 증거는 JSON 파일 하나: " + target))
                elif not marker or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", member):
                    ds.issues.append(Issue("D2", row.doc, row.line, "동작 대상은 파일#형.멤버 또는 파일#함수: " + target))
                else:
                    if path not in scopes or not globs.matches(path, included) or globs.matches(path, excluded):
                        ds.issues.append(Issue("D3", row.doc, row.line, identity + ": 감시·소유 선언 누락: " + target))
                    declarations = members.get((path, member), [])
                    if not declarations:
                        ds.issues.append(Issue("D5", row.doc, row.line, identity + ": 삭제되지 않은 정확한 멤버 선언 없음: " + target))
                    if col == "검사 연결" and (len(declarations) != 1 or declarations[0].cells["종류"] != "method"):
                        ds.issues.append(Issue("D5", row.doc, row.line, identity + ": 검사 연결은 단일 메서드·함수 선언이어야 함: " + target))
                    for declaration in declarations:
                        p = declaration.parsed
                        if col == "구현 대상" and declaration.cells["종류"] in {"method", "ctor", "operator", "indexer", "property"}:
                            executable = True
                        if path.endswith(".cs") and p["path"] != "-" and (path, p["path"]) not in types:
                            ds.issues.append(Issue("D5", row.doc, row.line, identity + ": 같은 파일의 소유 형 선언 없음: " + target))
                        if declaration.cells["상태"] in PLANNED | {"구현중", "수정중"} and (p["key"], p["signature"]) not in changes:
                            ds.issues.append(Issue("D5", row.doc, row.line, identity + ": 진행 멤버의 정확한 변경 선언 없음: " + target + " — " + p["signature"]))
            if col == "증거" and len(globs.split(c[col])) > 1:
                ds.issues.append(Issue("D2", row.doc, row.line, "동작 증거는 JSON 파일 하나만 지정한다"))
        if globs.split(c["구현 대상"]) and not executable:
            ds.issues.append(Issue("D5", row.doc, row.line, identity + ": 구현 대상에 실행 멤버가 없음 — 형·필드만으로 동작 구현을 대신할 수 없음"))
        for identity in globs.split(c["규칙 연결"]):
            if identity != "-" and identity not in rules:
                ds.issues.append(Issue("D8", row.doc, row.line, "동작 계약에 정의되지 않은 규칙: " + identity))



def _architecture_rows(ds):
    """구조 원본·선언·공개 경계·진행 변경을 같은 인덱스로 대조한다."""
    rows = ds.of("architecture")
    graphs = ds.of("architecture-graph")
    ident = r"[A-Za-z][A-Za-z0-9_-]*"
    relations = {"owns", "provides", "implements", "uses", "calls", "data", "process", "request"}
    graph_map, nodes, edges, aliases, declared = {}, {}, [], {}, {}
    issues = ds.issues
    def fail(code, row, message):
        issues.append(Issue(code, row.doc, row.line, "구조: " + message))
    for graph in graphs:
        gid = graph.cells["도식 ID"]
        address = (graph.doc, gid)
        if address in graph_map:
            fail("D4", graph, "같은 도식 ID — " + gid)
        graph_map[address] = graph
        syntax = graph.parsed["syntax"]
        if not syntax:
            raw = graph.parsed["raw"]
            parsed_nodes, parsed_edges, refs, errors, stack = {}, [], {}, [], []
            labels, groups, group_members = {}, {}, []
            if len(raw) < 2 or raw[0][1] not in {"flowchart LR", "flowchart TD"} or raw[1][1] != "%% architecture: " + gid or not re.fullmatch(ident, gid):
                errors.append(("D1", graph.line, "flowchart 방향·둘째 줄 architecture 표식·도식 ID가 규약과 다름"))
            for no, line in raw[2:]:
                node = re.fullmatch("(" + ident + r')\["([^"\n]*)"\]', line)
                edge = re.fullmatch("(" + ident + r") -->\|(" + "|".join(sorted(relations)) + r")\| (" + ident + ")", line)
                ref = re.fullmatch(r"%% ref (" + ident + ")=(" + ident + ")/(" + ident + ")", line)
                if node:
                    if node[1] in parsed_nodes:
                        errors.append(("D4", no, "중복 노드 ID: " + node[1]))
                    parsed_nodes[node[1]] = no
                    labels[node[1]] = node[2]
                    if stack: group_members.append((stack[-1][0],node[1]))
                elif edge:
                    parsed_edges.append((edge[1], edge[2], edge[3], no))
                elif ref:
                    if ref[1] in refs:
                        errors.append(("D4", no, "중복 별칭: " + ref[1]))
                    refs[ref[1]] = (ref[2], ref[3], no)
                elif re.fullmatch(r"subgraph " + ident + r'(?:\["[^"]*"\])?', line):
                    group = re.fullmatch(r'subgraph (' + ident + r')(?:\["([^"\n]*)"\])?',line)
                    if group[1] in groups: errors.append(("D4",no,"중복 그룹 ID: " + group[1]))
                    groups[group[1]] = (stack[-1][0] if stack else None,group[2] or group[1],no)
                    stack.append((group[1],no))
                elif line == "end" and stack:
                    stack.pop()
                elif line.startswith("%%") and not line.startswith("%% architecture:"):
                    continue
                elif re.fullmatch(r"(?:style|classDef) [A-Za-z0-9_, -]+ [A-Za-z0-9:#.,%() _-]+;?", line):
                    continue
                else:
                    errors.append(("D1", no, "지원하지 않는 구조 문법: " + line))
            if stack:
                errors.append(("D1", stack[-1][1], "닫히지 않은 subgraph"))
            syntax.update(nodes=parsed_nodes, edges=tuple(parsed_edges), refs=refs, errors=tuple(errors),
                          labels=labels,groups=groups,group_members=tuple(group_members))
        for code, line, message in syntax["errors"]:
            issues.append(Issue(code, graph.doc, line, "구조: " + message))
        for name, line in syntax["nodes"].items():
            nodes[graph.doc + "#" + gid + "/" + name] = (graph, line)
        for name, (target_graph, target_node, line) in syntax["refs"].items():
            candidates = [g for g in graphs if g.cells["도식 ID"] == target_graph]
            own = [g for g in candidates if g.doc == graph.doc]
            candidates = own or candidates
            key = graph.doc + "#" + gid + "/" + name
            if key not in nodes or len(candidates) != 1:
                issues.append(Issue("D5", graph.doc, line, "구조: 미정의·모호한 별칭 " + name))
            else:
                aliases[key] = candidates[0].doc + "#" + target_graph + "/" + target_node
        for a, kind, b, line in syntax["edges"]:
            edges.append((graph.doc + "#" + gid + "/" + a, kind, graph.doc + "#" + gid + "/" + b, graph.doc, line))
    for row in rows:
        c = row.cells
        key = row.doc + "#" + c["도식 ID"] + "/" + c["구조 ID"]
        row.parsed = {"nodeKey": key, "ownerKey": "", "declarationKey": "", "edges": [], "sourceLocations": [(row.doc, row.line)]}
        if not re.fullmatch(ident, c["도식 ID"]) or not re.fullmatch(ident, c["구조 ID"]) or c["책임"] in {"", "-"}:
            fail("D2", row, "식별자·책임을 명시해야 함")
        if key in declared:
            fail("D4", row, "중복 선언 노드: " + key)
            fail("D4", declared[key], "중복 선언 노드의 원 위치: " + key)
        declared[key] = row
        if c["선언 연결"].startswith("spec:"):
            value = c["선언 연결"][5:]
            path, marker, target = value.partition("#")
            if not marker or path not in ds.docs or path.startswith("/") or ".." in path.split("/") or "\\" in path:
                fail("D3", row, "외부 소유 SPEC가 없거나 정확한 상대 경로가 아님: " + value)
            else:
                aliases[key] = path + "#" + target
                row.parsed["external"] = True
        if key not in nodes:
            fail("D5", row, "그림에 없는 선언 노드: " + key)
        if c["소유 ID"] != "-":
            if not re.fullmatch(ident + "/" + ident, c["소유 ID"]):
                fail("D2", row, "소유 ID는 도식ID/구조ID: " + c["소유 ID"])
            row.parsed["ownerKey"] = row.doc + "#" + c["소유 ID"]
    resolved = {}
    def resolve(key):
        if key in resolved:
            return resolved[key]
        trail, seen, cursor = [], set(), key
        while cursor in aliases and cursor not in seen:
            seen.add(cursor); trail.append(cursor); cursor = aliases[cursor]
        if cursor in seen or cursor not in nodes or cursor not in declared:
            graph, line = nodes.get(key, (None, 1))
            if graph:
                issues.append(Issue("D4" if cursor in seen else "D5", graph.doc, line, "구조: 별칭 순환 또는 미정의 노드: " + key))
            cursor = ""
        for entry in trail + [key]:
            resolved[entry] = cursor
        return cursor
    for key, (graph, line) in nodes.items():
        if key not in declared and key not in aliases:
            issues.append(Issue("D5", graph.doc, line, "구조: 선언 표에 없는 노드: " + key))
        resolve(key)
    normalized_edges = []
    for a, kind, b, doc, line in edges:
        left, right = resolve(a), resolve(b)
        if not left or not right:
            issues.append(Issue("D5", doc, line, "구조: 간선의 노드·선언 누락: " + a + " -> " + b))
            continue
        if (a in aliases or b in aliases) and kind == "owns":
            issues.append(Issue("D4", doc, line, "구조: 참조 별칭에 새 소유 관계를 만들 수 없음"))
        normalized_edges.append((left, kind, right, doc, line))
    edge_set = {(a, kind, b) for a, kind, b, _, _ in normalized_edges}
    owners, children = {}, {}
    for key, row in declared.items():
        if key in aliases:
            continue
        owner = resolve(row.parsed["ownerKey"]) if row.parsed["ownerKey"] else ""
        owners[key] = owner
        if owner:
            children.setdefault(owner, set()).add(key)
        row.parsed["ownerKey"] = owner
        if not owner and row.cells["종류"] != "module":
            fail("D5", row, "루트 모듈 외 노드는 소유자가 필요함: " + key)
        if owner and (owner, "owns", key) not in edge_set:
            fail("D5", row, "소유 ID에 대응하는 owns 간선 없음: " + key)
        if owner and declared[owner].cells["종류"] not in {"module", "class", "interface"}:
            fail("D4", row, "소유자는 모듈 또는 형이어야 함: " + owner)
    module_keys, walked = {}, set()
    for key, row in declared.items():
        if key in aliases:
            continue
        trail, seen, cursor = [], set(), key
        while cursor and cursor not in module_keys and cursor not in seen:
            trail.append(cursor); seen.add(cursor)
            if declared[cursor].cells["종류"] == "module":
                module_keys[cursor] = cursor
                break
            cursor = owners.get(cursor, "")
        if cursor in seen and cursor not in module_keys:
            fail("D4", row, "소유 순환: " + key)
        module = module_keys.get(cursor, "")
        for entry in trail:
            module_keys[entry] = module
    # 모듈 자신의 부모 체인도 순환을 검사한다.
    for key, row in declared.items():
        cursor, seen = owners.get(key, ""), {key}
        while cursor and cursor not in seen:
            seen.add(cursor); cursor = owners.get(cursor, "")
        if cursor:
            fail("D4", row, "소유 순환: " + key)
    scopes = {r.cells["파일"]: r for r in ds.of("scope") if r.cells["상태"] != "삭제"}
    included = [p for r in ds.of("watch") if r.cells["포함"] == "포함" and r.cells["단위"] == "심볼" for p in globs.split(r.cells["경로"])]
    excluded = [p for r in ds.of("watch") if r.cells["포함"] == "제외" for p in globs.split(r.cells["경로"])]
    active = [r for r in ds.of("members") if r.parsed and r.cells["상태"] not in {"삭제중", "삭제완료"}]
    members, named = {}, {}
    for member in active:
        p = member.parsed
        members.setdefault((member.cells["파일"], p["path"], p["signature"]), []).append(member)
        name = (p["path"] + "." if p["path"] != "-" else "") + p["name"]
        named.setdefault((member.cells["파일"], name), []).append(member)
    names_by_full = {}
    for (file, name), declarations in named.items():
        names_by_full.setdefault(name, []).extend(declarations)
    pipelines = {r.cells["폴더"]: r for r in ds.of("pipeline")}
    folders, member_nodes, entries = {}, {}, {}
    selector_owners = {}
    for key, row in declared.items():
        if key in aliases:
            continue
        kind, selector = row.cells["종류"], row.cells["선언 연결"]
        tag, colon, value = selector.partition(":")
        matches = []
        if tag in {"folder", "member", "pipeline", "pipeline-data"}:
            path = value.partition("#")[0]
            if not path or path.startswith("/") or re.match(r"^[A-Za-z]:", path) or "\\" in path or any(p in {"", ".", ".."} for p in path.split("/")) or any(c in path for c in "*?[]"):
                fail("D3", row, "정확한 프로젝트 상대 경로가 아님: " + selector)
                continue
        if tag == "folder" and kind == "module":
            if value in folders:
                fail("D4", row, "두 모듈의 중복 소유 폴더: " + value)
                fail("D4", declared[folders[value]], "중복 소유 폴더의 원 위치: " + value)
            folders[value] = key
            if value not in pipelines and not any(f == value or f.startswith(value + "/") for f in scopes):
                fail("D3", row, "소유·파이프라인 선언 없는 모듈: " + value)
            row.parsed["folder"] = value
            row.parsed["declarationKey"] = selector
        elif tag == "member" and kind in {"class", "interface", "member", "data"}:
            parts = value.split("#", 2)
            if len(parts) != 3:
                fail("D2", row, "member 선택자는 파일#소유형#시그니처")
                continue
            file, owner, signature = parts
            try:
                norm, _, _, _ = infer(signature, owner, file)
            except (parse_cs.ParseError, ValueError) as error:
                fail("D5", row, "선언 시그니처를 읽을 수 없음: " + str(error))
                continue
            matches = members.get((file, owner, norm), [])
            if len(matches) != 1:
                fail("D5", row, "정확한 선언 하나에 연결되지 않음: " + selector)
                continue
            member = matches[0]
            actual_kind = member.cells["종류"]
            permitted = {"class": TYPE_KINDS - {"interface"}, "interface": {"interface"},
                         "member": set(SYMBOL_KINDS) - TYPE_KINDS, "data": TYPE_KINDS | {"field", "const", "enum-member"}}
            if actual_kind not in permitted[kind]:
                fail("D5", row, "구조 종류와 선언 종류 불일치: " + selector)
            if file not in scopes or not globs.matches(file, included) or globs.matches(file, excluded):
                fail("D3", row, "감시·소유 선언 누락: " + selector)
            canonical = (member.parsed["key"], member.parsed["signature"])
            if canonical in selector_owners:
                fail("D4", row, "같은 선언의 중복 소유: " + selector)
                fail("D4", selector_owners[canonical], "중복 선언의 원 위치: " + selector)
            selector_owners[canonical] = row
            member_nodes[canonical] = key
            row.parsed.update(declarationKey=canonical, memberFile=file, memberOwner=owner,
                              memberName=member.parsed["name"], memberKind=actual_kind, signature=norm,
                              sourceLocations=[(row.doc, row.line), (member.doc, member.line)])
        elif tag in {"pipeline", "pipeline-data"} and kind == "entry":
            folder, sep, name = value.partition("#")
            pipeline = pipelines.get(folder)
            column = "자료" if tag == "pipeline-data" else "입구"
            if not sep or pipeline is None or (name == "*" and tag == "pipeline-data"):
                fail("D5", row, "파이프라인 공개 입구 선택자 오류: " + selector)
                continue
            allowed = globs.split(pipeline.cells[column])
            selected = allowed if name == "*" else [name]
            if not selected or any(n not in allowed for n in selected):
                fail("D5", row, "파이프라인에 없는 공개 입구: " + selector)
            entry_members = []
            for n in selected:
                module, dot, symbol = n.partition(".")
                candidates = named.get((folder + "/" + module + ".py", symbol), []) if dot else []
                if not candidates:
                    # C# 파이프라인 입구는 폴더 안의 정확한 형.멤버 이름이다.
                    candidates = [m for m in names_by_full.get(n, []) if m.cells["파일"].startswith(folder + "/")]
                if len(candidates) != 1:
                    fail("D5", row, "공개 입구의 단일 제공 선언 없음: " + n)
                else:
                    entry_members.append((candidates[0].parsed["key"], candidates[0].parsed["signature"]))
            row.parsed.update(declarationKey=selector, entryMembers=entry_members, folder=folder)
            entries[key] = entry_members
        elif tag == "interface" and kind == "entry":
            parts = value.split("#")
            if len(parts) != 3:
                fail("D2", row, "interface 선택자는 계층#형#멤버")
                continue
            layer, typ, name = parts
            contracts = [r for r in ds.of("interface") if layer in globs.split(r.cells["계층"]) and typ == r.cells["형"] and name in globs.split(r.cells["멤버"])]
            layer_paths = [p for r in ds.of("layers") if r.cells["계층"] == layer for p in globs.split(r.cells["경로"])]
            matches = [m for m in active if globs.matches(m.cells["파일"], layer_paths) and m.parsed["path"] == typ and (m.parsed["name"] == name or name == "*")]
            if not contracts or not matches:
                fail("D5", row, "인터페이스 공개 계약·소유 계층·멤버 불일치: " + selector)
            entries[key] = [(m.parsed["key"], m.parsed["signature"]) for m in matches]
            row.parsed.update(declarationKey=selector, entryMembers=entries[key])
        else:
            fail("D2", row, "종류와 선언 연결 선택자가 맞지 않음: " + selector)
    ordered_folders = sorted(folders, key=lambda f: (-len(f), f))
    for folder in ordered_folders:
        parent = next((p for p in ordered_folders if folder.startswith(p + "/")), None)
        if parent and folder not in pipelines:
            fail("D4", declared[folders[folder]], "등록된 하위 단계가 아닌 부모·자식 모듈의 중복 소유: " + parent + " / " + folder)
    file_modules = {}
    for file, scope in scopes.items():
        if not file.endswith((".py", ".cs")):
            continue
        folder = next((f for f in ordered_folders if file.startswith(f + "/")), None)
        file_modules[file] = folders.get(folder, "")
        if not folder:
            fail("D5", scope, "코드 소유 파일의 모듈·흐름도 연결 없음: " + file)
    for key, row in declared.items():
        p = row.parsed
        if "memberFile" in p:
            if module_keys.get(key) != file_modules.get(p["memberFile"]):
                fail("D5", row, "선언 파일과 소유 모듈 불일치: " + p["memberFile"])
            owner = declared.get(owners.get(key))
            if owner and owner.cells["종류"] in {"class", "interface"}:
                op = owner.parsed
                full = (op.get("memberOwner", "") + "." if op.get("memberOwner") not in {"", "-"} else "") + op.get("memberName", "")
                if p["memberOwner"] != full or p["memberFile"] != op.get("memberFile"):
                    fail("D5", row, "소유 형과 선언 멤버의 형·파일 불일치")
        elif key in entries and row.parsed.get("folder") in folders and module_keys.get(key) != folders[row.parsed["folder"]]:
            fail("D5", row, "공개 입구와 소유 모듈 불일치")
    providers = {}
    used = {(a, b) for a, k, b in edge_set if k == "uses"}
    for a, kind, b, doc, line in normalized_edges:
        ra, rb = declared[a], declared[b]
        ka, kb = ra.cells["종류"], rb.cells["종류"]
        if kind == "owns" and owners.get(b) != a:
            issues.append(Issue("D4", doc, line, "구조: owns와 선언 소유 ID 불일치"))
        if kind == "provides":
            providers.setdefault(b, set()).add(a)
            if kb != "entry" or ka not in {"module", "class", "member", "interface", "data"} or module_keys.get(a) != module_keys.get(b):
                issues.append(Issue("D5", doc, line, "구조: 공개 입구의 제공자 종류·소유 불일치"))
            elif a in member_nodes.values() and ra.parsed.get("declarationKey") not in entries.get(b, []):
                issues.append(Issue("D5", doc, line, "구조: provides 제공 선언과 공개 입구가 다름"))
        if kind == "uses" and kb not in {"entry", "interface"}:
            issues.append(Issue("D5", doc, line, "구조: uses는 공개 entry·interface로 향해야 함"))
        if kind == "implements" and (ka != "class" or kb != "interface"):
            issues.append(Issue("D5", doc, line, "구조: implements는 class에서 interface로 향해야 함"))
        if kind == "calls" and (ka != "member" or kb != "member"):
            issues.append(Issue("D5", doc, line, "구조: calls는 실행 멤버 사이 관계"))
        if kind == "process" and kb != "entry":
            issues.append(Issue("D5", doc, line, "구조: process는 공개 entry로 향해야 함"))
        if kind == "request" and (ka != "member" or kb != "member"):
            issues.append(Issue("D5", doc, line, "구조: request는 전송·요청 처리 멤버 사이 관계"))
        ra.parsed["edges"].append((a, kind, b, doc, line))
    for key in entries:
        if not providers.get(key):
            fail("D5", declared[key], "공개 입구의 provides 제공자 없음: " + key)
    for a, kind, b, doc, line in normalized_edges:
        if kind == "calls" and module_keys.get(a) != module_keys.get(b):
            if not any((a, e) in used and (b in ps or module_keys.get(b) in ps) and declared[b].parsed.get("declarationKey") in entries.get(e, []) for e, ps in providers.items()):
                issues.append(Issue("D5", doc, line, "구조: 경계를 넘는 calls의 uses·provides 경로 없음"))
    required = {}
    for m in active:
        if m.cells["종류"] in TYPE_KINDS:
            required[(m.parsed["key"], m.parsed["signature"])] = m
    for r in ds.of("changes"):
        canonical = (r.parsed.get("key"), r.parsed.get("signature"))
        if r.parsed and r.cells["변경"] not in {"삭제", "파일 삭제"}:
            target = members.get((r.cells["파일"], r.parsed["path"], r.parsed["signature"]), [])
            for member in target:
                if member.cells["상태"] in PLANNED | DOING:
                    required[(member.parsed["key"], member.parsed["signature"])] = r
    for r in ds.of("behaviors"):
        for column in ("구현 대상", "검사 연결"):
            for target in globs.split(r.cells[column]):
                file, _, name = target.partition("#")
                for m in named.get((file, name), []):
                    required[(m.parsed["key"], m.parsed["signature"])] = r
    for canonical, origin in required.items():
        if canonical not in member_nodes:
            file = canonical[0].split("|", 1)[0]
            # 소유 모듈 자체 누락은 scope의 한 지적으로 모은다.
            if file_modules.get(file):
                fail("D5", origin, "형·진행 변경·동작·검사 선언의 구조 노드 누락: " + canonical[0])
    for folder, pipeline in pipelines.items():
        if folder not in folders:
            fail("D5", pipeline, "파이프라인 모듈의 구조 연결 없음: " + folder)
        for column, tag in (("입구", "pipeline:"), ("자료", "pipeline-data:")):
            for name in globs.split(pipeline.cells[column]):
                if not any(r.cells["선언 연결"] in {tag + folder + "#" + name, tag + folder + "#*"} for r in rows if r.cells["종류"] == "entry"):
                    fail("D5", pipeline, "파이프라인 공개 입구의 구조 노드 없음: " + name)
    groups, links = {}, {}
    for key, row in declared.items():
        groups.setdefault(key.rsplit("/", 1)[0], set()).add(key)
        row.parsed["moduleKey"] = module_keys.get(resolve(key), "")
    for a, _, b in edge_set:
        ga, gb = a.rsplit("/", 1)[0], b.rsplit("/", 1)[0]
        links.setdefault(ga, set()).add(gb)
        links.setdefault(gb, set()).add(ga)
    for a, b in aliases.items():
        ga, gb = a.rsplit("/", 1)[0], b.rsplit("/", 1)[0]
        links.setdefault(ga, set()).add(gb)
        links.setdefault(gb, set()).add(ga)
    fingerprints = {}
    for group in groups:
        if group in fingerprints:
            continue
        pending, component = [group], set()
        while pending:
            current = pending.pop()
            if current not in component:
                component.add(current); pending.extend(links.get(current, ()))
        keys = set().union(*(groups.get(g, set()) for g in component))
        semantics = sorted((key, declared[key].cells["종류"], declared[key].parsed.get("ownerKey"),
                            declared[key].parsed.get("declarationKey"), declared[key].parsed.get("entryMembers", [])) for key in keys)
        boundary = sorted(e for e in edge_set if e[0] in keys or e[2] in keys)
        digest = hashlib.sha256(json.dumps([semantics, boundary], ensure_ascii=False, sort_keys=True).encode()).hexdigest()
        affected = sorted(f for f, m in file_modules.items() if m in keys)
        for g in component:
            fingerprints[g] = (digest, affected)
        for key in keys:
            declared[key].parsed.update(inputHash=digest, affectedFiles=affected)
    ds.architecture = {"resolved":resolved,"edges":normalized_edges,"fileModules":file_modules}
    for graph in graphs:
        group = graph.doc + "#" + graph.cells["도식 ID"]
        digest, affected = fingerprints.get(group, ("", []))
        graph.parsed.update(inputHash=digest, affectedFiles=affected)


def _read(root, rel, ds, source_root=None):
    """문서 하나의 모든 표를 머리줄로 읽는다(코드 울타리 안은 표로 보지 않음). 열·칸 수·허용 값·백틱·경로 형식을 D1~D3로,
    닮았지만 맞지 않는 머리줄을 D7로. 표 종류 주석 줄이 남아 있으면 D1. 글 전체는 참조 판정(D8·D9)을 위해 남긴다."""
    with open(os.path.join(source_root or root, rel), encoding="utf-8-sig", errors="strict") as f:
        lines = f.read().split("\n")
    ds.texts[rel] = lines
    fence = False
    k = 0
    while k < len(lines):
        raw = lines[k]
        if not fence and raw.strip() == "```mermaid":
            end = next((i for i in range(k + 1, len(lines)) if lines[i].strip() == "```"), len(lines))
            body = tuple((i + 1, lines[i].strip()) for i in range(k + 1, end) if lines[i].strip())
            markers = [(no, line) for no, line in body if line.startswith("%% architecture:")]
            if markers:
                identity = markers[0][1].partition(":")[2].strip()
                ds.rows.append(Row(rel, k + 1, "architecture-graph", {"도식 ID": identity}, {"raw": body, "syntax": {}}))
                if end == len(lines):
                    ds.issues.append(Issue("D1", rel, k + 1, "구조 도식 코드 울타리가 닫히지 않음"))
            k = end + 1
            continue
        if raw.strip().startswith("```"):
            fence = not fence
            k += 1
            continue
        if fence:
            k += 1
            continue
        if LEGACY.match(raw):
            ds.issues.append(Issue("D1", rel, k + 1, "표 종류 주석 줄은 쓰지 않는다 — 표는 머리줄로 읽는다"))
            k += 1
            continue
        if not (raw.strip().startswith("|") and k + 1 < len(lines) and SEPARATOR.match(lines[k + 1])):
            if raw.strip().startswith("|") and not SEPARATOR.match(raw):
                orphan = orphan_contract(raw)
                if orphan:
                    ds.issues.append(Issue("D7", rel, k + 1, "머리줄 없는 계약 행(%s) — 표 머리줄과 구분줄이 필요함" % orphan))
            k += 1
            continue
        header = [clean(c) for c in split_cells(raw)]
        kind = kind_of(header)
        header_line = k + 1
        k += 2
        body = []
        while k < len(lines) and lines[k].strip().startswith("|"):
            body.append((k + 1, lines[k]))
            k += 1
        if kind is None:
            near = resembles(header)
            if near:
                ds.issues.append(Issue("D7", rel, header_line, "표 형식(%s)을 닮았지만 열이 다름: %s (기대 %s)"
                                       % (near, " · ".join(header), " · ".join(COLUMNS[near]))))
            continue
        for line_no, text in body:
            raw_cells = split_cells(text)
            if len(raw_cells) != len(COLUMNS[kind]):
                ds.issues.append(Issue("D1", rel, line_no, "칸 수 %d (기대 %d)" % (len(raw_cells), len(COLUMNS[kind]))))
                continue
            cells = {}
            for col, rc in zip(COLUMNS[kind], raw_cells):
                value = clean(rc)
                if col in CODE_COLUMNS[kind] and value not in ("-", "") and "`" not in rc:
                    ds.issues.append(Issue("D3", rel, line_no, "'%s' 칸은 백틱으로 감싼다: %s" % (col, rc)))
                cells[col] = value
            for (tk, col), allowed in VALUES.items():
                if tk == kind and cells.get(col) not in allowed:
                    ds.issues.append(Issue("D2", rel, line_no, "'%s' 칸 값 '%s'은 허용 값이 아님(%s)" % (col, cells.get(col), ", ".join(sorted(allowed)))))
            for col in ("파일", "경로"):
                v = cells.get(col, "")
                if v and v != "-" and (re.match(r"^[A-Za-z]:", v) or v.startswith("/") or "\\" in v):
                    ds.issues.append(Issue("D3", rel, line_no, "경로는 프로젝트 루트 기준 '/' 경로: %s" % v))
            if kind == "overview" and ("," in cells["파일"] or "`" in cells["파일"] or "(" in cells["파일"]):
                ds.issues.append(Issue("D3", rel, line_no, "개요 표의 파일 칸은 파일 하나(프로젝트 루트 기준 경로): %s" % raw_cells[0]))
            ds.rows.append(Row(rel, line_no, kind, cells))


def _references(ds, root, cache=None):
    """글 전체(코드 울타리 포함)에서 규칙 id가 규칙·허용 표에 없으면 D8, 백틱 안의 `형.멤버`가 멤버 표에 없으면 D9."""
    defined = {r.cells["규칙"] for r in ds.of("rules")} | {r.cells["규칙"] for r in ds.of("allow")}
    members, types = {}, set()
    qualified_types, namespaces = set(), {}
    namespace_inputs = {}
    for row in ds.of("members"):
        file = row.cells["파일"]
        if row.cells["종류"] in TYPE_KINDS and file.endswith(".cs") and file not in namespace_inputs:
            try:
                stat = os.stat(os.path.join(root, file))
                namespace_inputs[file] = (stat.st_mtime_ns,stat.st_ctime_ns,stat.st_size,PARSER_INPUT)
            except OSError:
                namespaces[file] = ()
    namespaces.update(reference_store.source_namespaces(root, namespace_inputs))
    namespace_updates = {}
    historical_rows = {(r.doc, r.line) for r in ds.of("changes")}
    for r in ds.of("members"):
        if not r.parsed:
            continue
        if r.cells["상태"] != "삭제완료":
            members.setdefault(r.parsed["path"], set()).add(r.parsed["name"])
        else:
            historical_rows.add((r.doc, r.line))
        types.add(r.parsed["path"])
        if r.cells["종류"] in TYPE_KINDS:
            typename = r.parsed["name"] if r.parsed["path"] == "-" else r.parsed["path"] + "." + r.parsed["name"]
            types.add(typename)
            file = r.cells["파일"]
            if file.endswith(".cs"):
                if file not in namespaces:
                    try:
                        path = os.path.join(root, file)
                        with open(path, encoding="utf-8-sig") as stream:
                            namespaces[file] = tuple(re.findall(r"^\s*namespace\s+([A-Za-z_][A-Za-z0-9_.]*)", stream.read(), re.M))
                        namespace_updates[file] = namespaces[file]
                    except OSError:
                        namespaces[file] = []
                qualified_types.update(namespace + "." + typename for namespace in namespaces[file])
    if namespace_updates:
        reference_store.source_namespaces(root, namespace_inputs, namespace_updates)
    types.discard("-")
    type_suffixes = {}
    for typ in types:
        parts = typ.split(".")
        for start in range(len(parts)):
            type_suffixes.setdefault(".".join(parts[start:]), []).append(typ)
    qualified_suffixes = set()
    for qualified in qualified_types:
        parts = qualified.split(".")
        qualified_suffixes.update(".".join(parts[start:]) for start in range(len(parts)))
    token_cache = design.reference_tokens(root, ds.source_root, ds.docs)
    token_updates = {}
    for rel, lines in ds.texts.items():
        retained = cache[rel][2] if cache is not None else {}
        tokens = retained.get("referenceTokens",token_cache.get(rel))
        if tokens is None:
            tokens = []
            for no, line in enumerate(lines, 1):
                rules = tuple(m.group(0) for m in RULE_ID.finditer(line))
                references = tuple((m.group(1), m.group(2))
                                   for span in re.findall(r"`([^`]+)`", line) if "/" not in span
                                   for m in MEMBER_REF.finditer(span))
                if rules or references:
                    tokens.append((no, rules, references))
            token_updates[rel] = tokens
        retained["referenceTokens"] = tokens
        for no, rules, references in tokens:
            for rule in rules:
                if rule not in defined:
                    ds.issues.append(Issue("D8", rel, no, "규칙 표에 없는 규칙 id: %s" % rule))
            if (rel, no) in historical_rows:
                continue
            for typ, name in references:
                if name in FILE_EXT:
                    continue
                reference = typ + "." + name
                if reference in qualified_suffixes:
                    continue
                cands = type_suffixes.get(typ, ())
                if not cands:
                    continue
                if any(name in members.get(p, ()) or (p + "." + name) in types for p in cands):
                    continue
                ds.issues.append(Issue("D9", rel, no, "멤버 표에 없는 멤버 참조: %s" % (typ + "." + name)))
    if token_updates:
        design.reference_tokens(root, ds.source_root, ds.docs, token_updates)


def _allow(ds):
    """허용 표의 (코드, 문서 경로)에 있는 형식 오류는 빼고 수만 센다."""
    allowed = {(r.cells["규칙"], r.cells["경로"]) for r in ds.of("allow")}
    kept = [i for i in ds.issues if (i.code, i.file) not in allowed]
    ds.suppressed += len(ds.issues) - len(kept)
    ds.issues = kept


def doc_paths(root):
    """읽는 문서: `Docs/**/*.md`(단 `Docs/98_History/**`·`Docs/99_Legacy/**` 제외)."""
    return globs.expand(root, ["Docs/**/*.md"], ["Docs/98_History/**", "Docs/99_Legacy/**"])


def load(root, paths=None, cache=None, source_root=None, reuse=False):
    """문서의 모든 표와 글을 읽는다. 기본은 doc_paths(root)."""
    ds = DocSet()
    ds.root = root
    ds.source_root = os.path.abspath(source_root or root)
    if paths is None:
        paths = doc_paths(ds.source_root)
    ds.docs = list(paths)
    cache = {} if cache is None else cache
    changed_documents = []
    fingerprints = {}
    pending = {}
    for rel in ds.docs:
        st = os.stat(os.path.join(ds.source_root, rel))
        fingerprint = (root, ds.source_root, st.st_mtime_ns, st.st_size, st.st_ctime_ns)
        fingerprints[rel] = fingerprint
        saved = cache.get(rel)
        if saved is None or saved[0] != fingerprint:
            pending[rel] = (fingerprint[2:], PARSER_INPUT)
    contract_input = hashlib.sha256(repr((PARSER_INPUT,ds.source_root,sorted(fingerprints.items()))).encode('utf-8')).hexdigest()
    if reuse:
        state = design.contract_state(root,ds.source_root,contract_input)
        if state is not None:
            ds._stored=state
            ds._validated=state
            del ds.rows
            ds.issues=[Issue(*issue) for issue in state['issues']]
            ds.suppressed=state['suppressed']
            ds.texts=DocumentTexts(ds)
            return ds
    restored_documents = design.read_documents(root, ds.source_root, pending)
    for rel in ds.docs:
        fingerprint = fingerprints[rel]
        saved = cache.get(rel)
        if saved is None or saved[0] != fingerprint:
            restored = restored_documents.get(rel)
            if restored is None:
                part = DocSet()
                _read(root,rel,part,source_root=ds.source_root)
                normalized = {}
                changed_documents.append((rel,fingerprint[2:]))
            else:
                stored,normalized = restored
                part = DocSet()
                part.texts[rel] = stored['text']
                part.rows = [Row(rel,**row) for row in stored['rows']]
                part.issues = [Issue(*issue) for issue in stored['issues']]
                normalized = {key:(value,[Issue(*issue) for issue in issues])
                              for key,(value,issues) in normalized.items()}
            if saved is not None:
                old_rows = {(r.line, r.kind): r.cells for r in saved[1].rows}
                source_files = {r.cells.get("파일") for r in part.rows if r.kind == "members"}
                for row in part.rows:
                    slot = (row.line, row.kind)
                    if old_rows.get(slot) == row.cells and slot in saved[2]:
                        normalized[slot] = saved[2][slot]
                for slot, value in saved[2].items():
                    if isinstance(slot, tuple) and slot[0] == "namespace" and slot[1] in source_files:
                        normalized[slot] = value
            saved = (fingerprint, part, normalized)
            cache[rel] = saved
        part = saved[1]
        ds.rows.extend(Row(r.doc, r.line, r.kind, dict(r.cells), dict(r.parsed)) for r in part.rows)
        ds.issues.extend(part.issues)
        ds.texts.update((rel, list(lines)) for rel, lines in part.texts.items())
    for rel in cache.keys() - set(ds.docs):
        del cache[rel]
    def normalize(row, action):
        normalized = cache[row.doc][2]
        key = (row.line, row.kind)
        if key not in normalized:
            issues = []
            action(row, issues)
            normalized[key] = (dict(row.parsed), issues)
        parsed, issues = normalized[key]
        row.parsed = dict(parsed)
        ds.issues.extend(issues)
    seen_members, seen_scope, seen_rules, seen_const, seen_body = {}, {}, {}, {}, {}
    for row in ds.rows:
        if row.kind == "members" and not any(i.line == row.line and i.file == row.doc for i in ds.issues):
            normalize(row, _parse_member)
            key = row.parsed.get("key")
            if key:
                if key in seen_members:
                    ds.issues.append(Issue("D4", row.doc, row.line, "같은 멤버가 두 번 정의됨(먼저: %s:%d)" % seen_members[key]))
                seen_members.setdefault(key, (row.doc, row.line))
        elif row.kind == "body":
            normalize(row, _parse_body)
            key = row.parsed.get("key")
            if key in seen_body:
                ds.issues.append(Issue("D4", row.doc, row.line, "같은 본문 계약이 두 번 정의됨"))
            seen_body[key] = (row.doc, row.line)
        elif row.kind == "changes":
            normalize(row, _parse_change)
        elif row.kind == "scope":
            f = row.cells["파일"]
            if f in seen_scope:
                ds.issues.append(Issue("D4", row.doc, row.line, "한 파일을 두 곳이 소유함(먼저: %s:%d)" % seen_scope[f]))
            seen_scope.setdefault(f, (row.doc, row.line))
        elif row.kind == "rules":
            rid = row.cells["규칙"]
            if rid in seen_rules:
                ds.issues.append(Issue("D4", row.doc, row.line, "같은 규칙 id(먼저: %s:%d)" % seen_rules[rid]))
            seen_rules.setdefault(rid, (row.doc, row.line))
            if row.cells["종류"] in ("금지", "필수", "의존", "이름") and row.cells["패턴"] not in ("", "-"):
                try:
                    re.compile(row.cells["패턴"])
                except re.error as e:
                    ds.issues.append(Issue("D6", row.doc, row.line, "정규식 오류: %s" % e))
        elif row.kind == "constants":
            key = (row.cells["파일"], row.cells["형"], row.cells["이름"])
            if key in seen_const:
                ds.issues.append(Issue("D4", row.doc, row.line, "같은 상수가 두 번(먼저: %s:%d)" % seen_const[key]))
            seen_const.setdefault(key, (row.doc, row.line))
            if row.cells["형식"] in ("float", "double") and row.cells["단위"] in ("", "-"):
                ds.issues.append(Issue("D2", row.doc, row.line, "실수 상수에는 단위를 적는다"))
    # 페이즈 표(SPEC-00 6.8.6): 순위는 1부터 빈틈·중복 없는 정수, 이름은 겹치지 않고, 대상은 `단계 이름` 또는 `지적코드 경로패턴`
    body_members = {row.parsed.get("key"): row for row in ds.of("members") if row.parsed}
    for row in ds.of("body"):
        member = body_members.get(row.parsed.get("key"))
        if member is None or member.doc != row.doc or member.parsed["signature"] != row.parsed.get("signature"):
            ds.issues.append(Issue("D5", row.doc, row.line, "본문 계약은 같은 소유 문서의 정확한 멤버 선언을 요구한다"))
    ranks, names = [], set()
    for row in ds.of("phases"):
        if not re.fullmatch(r"PH[A-Za-z0-9_-]+", row.cells["페이즈"]):
            ds.issues.append(Issue("D2", row.doc, row.line, "페이즈 이름은 PH 접두를 사용: " + row.cells["페이즈"]))
        try:
            ranks.append(int(row.cells["순위"]))
        except ValueError:
            ds.issues.append(Issue("D2", row.doc, row.line, "순위는 정수: %s" % row.cells["순위"]))
        if row.cells["페이즈"] in names:
            ds.issues.append(Issue("D2", row.doc, row.line, "같은 이름의 페이즈: %s" % row.cells["페이즈"]))
        names.add(row.cells["페이즈"])
        items = [x.strip() for x in row.cells["대상"].split(",") if x.strip()]
        bad = [x for x in items if not re.match(r"^(단계 \S+|[A-Z*][A-Za-z0-9*]* \S+)$", x)]
        if bad or not items:
            ds.issues.append(Issue("D2", row.doc, row.line, "대상은 `단계 이름` 또는 `지적코드 경로패턴`: %s" % (", ".join(bad) or "빈 칸")))
    if ranks and sorted(ranks) != list(range(1, len(ranks) + 1)):
        first = ds.of("phases")[0]
        ds.issues.append(Issue("D2", first.doc, first.line, "페이즈 순위는 1부터 빈틈·중복 없이: %s" % ", ".join(map(str, ranks))))
    # 구조 한도 표(SPEC-00 6.8.7): 활성 행의 한도는 양의 정수, 같은 (단위, 셈, 범위)는 한 번
    seen_limits = {}
    for row in ds.of("limits"):
        if row.cells["상태"] == "활성" and not re.match(r"^[1-9][0-9]*$", row.cells["한도"]):
            ds.issues.append(Issue("D2", row.doc, row.line, "활성 한도 행의 한도는 양의 정수: %s" % row.cells["한도"]))
        key = (row.cells["단위"], row.cells["셈"], row.cells["범위"])
        if key in seen_limits:
            ds.issues.append(Issue("D2", row.doc, row.line, "같은 한도 행이 두 번(먼저: %s:%d)" % seen_limits[key]))
        seen_limits.setdefault(key, (row.doc, row.line))
    # 파이프라인 표(SPEC-00 6.8.8): 한 문서 안 순서는 1부터 빈틈·중복 없이, 폴더는 모든 파이프라인 표에서 한 번
    orders, seen_folders = {}, {}
    for row in ds.of("pipeline"):
        try:
            orders.setdefault(row.doc, []).append(int(row.cells["순서"]))
        except ValueError:
            ds.issues.append(Issue("D2", row.doc, row.line, "파이프라인 순서는 정수: %s" % row.cells["순서"]))
        folder = row.cells["폴더"]
        if folder in seen_folders:
            ds.issues.append(Issue("D2", row.doc, row.line, "같은 폴더가 두 단계에(먼저: %s:%d)" % seen_folders[folder]))
        seen_folders.setdefault(folder, (row.doc, row.line))
    for doc, got in orders.items():
        if sorted(got) != list(range(1, len(got) + 1)):
            first = next(r for r in ds.of("pipeline") if r.doc == doc)
            ds.issues.append(Issue("D2", doc, first.line, "파이프라인 순서는 1부터 빈틈·중복 없이: %s" % ", ".join(map(str, got))))
    for rel,stamp in changed_documents:
        design.write_document(root,ds.source_root,rel,stamp,PARSER_INPUT,cache[rel][1],cache[rel][2])
    _behavior_rows(ds)
    _architecture_rows(ds)
    _references(ds, root, cache)
    _allow(ds)
    ds._validated=design.contract_state(root,ds.source_root,contract_input,ds)
    return ds
