# -*- coding: utf-8 -*-
"""파이썬 심볼 파서(SPEC-36 2.2). 표준 `ast`로 모듈 함수·클래스·메서드·모듈/클래스 변수를 뽑는다."""
import ast
import hashlib

from parsing.parse_cs import Symbol, ParseError


def _hash(node):
    """노드의 AST 덤프 해시(본문 비교용)."""
    dump = ast.dump(node, annotate_fields=True, include_attributes=False)
    return hashlib.sha1(dump.encode("utf-8")).hexdigest()[:16]


def _signature(node):
    """함수·클래스의 정규화 시그니처(`def 이름(인자)`, `class 이름(부모)`)."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        prefix = "async def " if isinstance(node, ast.AsyncFunctionDef) else "def "
        return prefix + node.name + "(" + ast.unparse(node.args) + ")"
    if isinstance(node, ast.ClassDef):
        bases = [ast.unparse(b) for b in node.bases]
        return "class " + node.name + ("(" + ", ".join(bases) + ")" if bases else "")
    return ""


def _access(name):
    """밑줄로 시작하면 private, 아니면 public."""
    return "private" if name.startswith("_") else "public"


def _variables(node, path, file, owner_kind):
    """대입문 하나의 변수 심볼들. 모듈 수준 대문자 이름은 const."""
    out = []
    targets, value = [], None
    if isinstance(node, ast.Assign):
        targets, value = node.targets, node.value
    elif isinstance(node, ast.AnnAssign):
        targets, value = [node.target], node.value
    for target in targets:
        names = []
        if isinstance(target, ast.Name):
            names = [target.id]
        elif isinstance(target, ast.Tuple):
            names = [e.id for e in target.elts if isinstance(e, ast.Name)]
        for name in names:
            kind = "const" if name.isupper() and owner_kind == "module" else "field"
            text = ast.unparse(value) if value is not None else ""
            out.append(Symbol(file, path, kind, name, name, "", _access(name), (), node.lineno,
                              getattr(node, "end_lineno", node.lineno), _hash(value) if value is not None else "",
                              False, text, ""))
    return out


def parse(text, path):
    """파이썬 원문 하나에서 심볼 목록을 뽑는다."""
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        raise ParseError("파이썬 구문 오류: %s" % e.msg, e.lineno or 0)
    symbols = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.append(Symbol(path, "-", "method", node.name, _signature(node), "", _access(node.name), (),
                                  node.lineno, node.end_lineno, _hash(node), bool(ast.get_docstring(node))))
        elif isinstance(node, ast.ClassDef):
            symbols.append(Symbol(path, "-", "class", node.name, _signature(node), "", _access(node.name), (),
                                  node.lineno, node.end_lineno, "", bool(ast.get_docstring(node))))
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    symbols.append(Symbol(path, node.name, "method", item.name, _signature(item), "", _access(item.name), (),
                                          item.lineno, item.end_lineno, _hash(item), bool(ast.get_docstring(item))))
                elif isinstance(item, (ast.Assign, ast.AnnAssign)):
                    symbols.extend(_variables(item, node.name, path, "class"))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            symbols.extend(_variables(node, "-", path, "module"))
    return symbols


def parse_signature(signature, kind, container):
    """문서의 시그니처 한 칸을 코드와 같은 규칙으로. (정규화 시그니처, 이름, 매개변수, 종류)."""
    text = signature.strip()
    if kind in ("const", "field"):
        return text, text, "", kind
    try:
        tree = ast.parse(text + ":\n    pass\n")
    except SyntaxError as e:
        raise ParseError("파이썬 시그니처 구문 오류: %s" % e.msg, 0)
    node = tree.body[0]
    return _signature(node), node.name, "", "class" if isinstance(node, ast.ClassDef) else "method"
