"""공통 선언 계약을 구현하는 언어 어댑터 등록부. 런타임 다운로드는 하지 않는다."""
import hashlib
import importlib
import importlib.metadata
import os
import re
from functools import lru_cache
from parsing import parse_cs, parse_py, settings

EXTENSIONS = {ext:language for language,extensions in dict(settings.EXTENSIONS).items() for ext in extensions}
TYPE_NODES = {"class_declaration":"class", "class":"class", "abstract_class_declaration":"class",
              "interface_declaration":"interface", "enum_declaration":"enum", "record_declaration":"record",
              "annotation_type_declaration":"interface"}
FUNCTION_NODES = {"function_declaration", "generator_function_declaration", "function_signature", "method_definition",
                  "method_signature", "abstract_method_signature", "method_declaration", "constructor_declaration", "method_elem"}
PACKAGES = {"javascript":"tree-sitter-javascript", "typescript":"tree-sitter-typescript", "java":"tree-sitter-java", "go":"tree-sitter-go"}


def available():
    """표준 선언 어댑터 목록. 의미 참조 지원과 구별한다."""
    return {language:{"extensions":extensions, "structure":True,
                      "semanticReferences":language in ("python", "csharp")}
            for language,extensions in dict(settings.EXTENSIONS).items()}


def language(path):
    """파일 확장자로 어댑터를 선택하고 미지원 입력을 명시적으로 거절한다."""
    selected = EXTENSIONS.get(os.path.splitext(path)[1].lower())
    if selected is None: raise ValueError("Unsupported source language: " + path)
    return selected


@lru_cache(maxsize=8)
def _parser(selected, tsx=False):
    """설치된 문법으로 파서를 만든다. 누락은 설치 진단이며 빈 성공이 아니다."""
    try:
        from tree_sitter import Language, Parser
        module = importlib.import_module(PACKAGES[selected].replace("-", "_"))
        factory = (module.language_tsx if tsx else module.language_typescript) if selected == "typescript" else module.language
        return Parser(Language(factory()))
    except ImportError as error:
        raise parse_cs.ParseError("Missing grammar dependency; install the package language dependencies: " + str(error), 1) from error


def _tree(text, path):
    """정상 구문 트리만 반환한다. 오류와 누락 노드는 판정 오류로 남긴다."""
    selected = language(path)
    tree = _parser(selected, path.endswith(".tsx")).parse(text.encode("utf-8"))
    if tree.root_node.has_error:
        pending = [tree.root_node]
        while pending:
            node = pending.pop()
            if node.is_error or node.is_missing:
                raise parse_cs.ParseError("Syntax error (" + selected + ")", node.start_point.row + 1)
            pending.extend(reversed(node.children))
        raise parse_cs.ParseError("Syntax error (" + selected + ")", 1)
    return tree


def _text(node):
    """UTF-8 노드 원문."""
    return node.text.decode("utf-8") if node is not None else ""


def _normalized(node):
    """주석을 뺀 문법 토큰 정규화. 문자열 내부의 공백은 보존한다."""
    if node is None: return ""
    tokens, pending = [], [node]
    while pending:
        item = pending.pop()
        if "comment" in item.type: continue
        if not item.children or item.type in ("string", "string_literal", "template_string", "raw_string_literal", "interpreted_string_literal"):
            tokens.append(_text(item))
        else: pending.extend(reversed(item.children))
    return " ".join(tokens)


def _bindings(node):
    """구조 분해에서 속성 이름과 실제 선언 이름을 구분한다."""
    if node is None: return []
    if node.type in ('identifier', 'field_identifier', 'property_identifier', 'private_property_identifier', 'shorthand_property_identifier_pattern'):
        return [node]
    if node.type in ('pair_pattern', 'object_assignment_pattern'):
        return _bindings(node.child_by_field_name('value') or node.child_by_field_name('left'))
    if node.type == 'assignment_pattern': return _bindings(node.child_by_field_name('left'))
    if node.type in ('object_pattern', 'array_pattern', 'rest_pattern', 'expression_list'):
        return [bound for child in node.named_children for bound in _bindings(child)]
    return []


def _extract(text, path):
    """네 추가 언어의 선언을 기존 Symbol 계약으로 정규화한다."""
    tree = _tree(text, path)
    selected = language(path)
    output = []
    def emit(node, owner, kind, name, signature=None, parameters=None, value=None):
        body = node.child_by_field_name("body")
        header = signature or " ".join(_normalized(c) for c in node.children if c != body and "comment" not in c.type).strip().rstrip(";")
        modifiers = tuple(c.type for c in node.children if c.type in ("static", "async", "abstract", "readonly"))
        raw = _text(node)
        access = "private" if re.search(r"\bprivate\b", header) or name.startswith("#") else "protected" if re.search(r"\bprotected\b", header) else "public"
        documented = node.prev_named_sibling is not None and "comment" in node.prev_named_sibling.type
        output.append(parse_cs.Symbol(path, owner or "-", kind, name, header,
            _normalized(parameters).strip()[1:-1].strip() if parameters is not None else "", access, modifiers,
            node.start_point.row+1, node.end_point.row+1, hashlib.sha256(_normalized(node).encode()).hexdigest()[:16],
            documented, _text(value), ""))
    def visit(node, owner="-"):
        kind = TYPE_NODES.get(node.type)
        if node.type == "type_spec" and selected == "go":
            target = node.child_by_field_name("type")
            kind = {"struct_type":"struct", "interface_type":"interface"}.get(target.type if target else "")
        if kind:
            name = _text(node.child_by_field_name("name"))
            if not name: return
            body = node.child_by_field_name("body") or (node.child_by_field_name("type") if selected == "go" else None)
            signature = ("type " + name + " " + ("interface" if kind == "interface" else "struct")) if selected == "go" else None
            emit(node, owner, kind, name, signature=signature)
            nested = name if owner == "-" else owner + "." + name
            if body:
                for child in body.named_children: visit(child, nested)
            return
        if node.type in FUNCTION_NODES:
            name = _text(node.child_by_field_name("name")) or ("constructor" if node.type == "constructor_declaration" else "")
            if not name: return
            receiver = node.child_by_field_name("receiver")
            target_owner = owner
            if receiver is not None:
                declaration = receiver.named_children[0] if receiver.named_children else None
                target_owner = re.sub(r"[^\w.]", "", _text(declaration.child_by_field_name("type"))) if declaration else owner
            kind = "ctor" if name == "constructor" or node.type == "constructor_declaration" else "method"
            emit(node, target_owner, kind, name, parameters=node.child_by_field_name("parameters"))
            return
        if node.type in ("variable_declarator", "var_spec", "const_spec", "field_declaration", "public_field_definition", "property_signature"):
            names = [bound for named in node.children_by_field_name("name") for bound in _bindings(named)]
            # Java field_declaration contains variable_declarator children.
            if node.type == "field_declaration" and selected == "java":
                for child in node.named_children:
                    if child.type == "variable_declarator": visit(child, owner)
                return
            value = node.child_by_field_name("value")
            for name_node in names:
                name = _text(name_node)
                method = value is not None and value.type in ("arrow_function", "function_expression", "generator_function")
                if method:
                    parameters = value.child_by_field_name("parameters")
                    single = value.child_by_field_name("parameter")
                    signature = "function " + name + (_normalized(parameters) if parameters else "("+_text(single)+")")
                    emit(node, owner, "method", name, signature=signature, parameters=parameters)
                    if single is not None: output[-1].params = _text(single)
                else:
                    kind = "const" if node.type == "const_spec" or (node.parent and _text(node.parent).lstrip().startswith("const ")) else "field"
                    emit(node, owner, kind, name, signature=name, value=value)
            return
        # Descend declaration containers, never function bodies or object literals.
        if node.type in ("program", "source_file", "export_statement", "lexical_declaration", "variable_declaration",
                         "type_declaration", "var_declaration", "const_declaration", "field_declaration_list", "enum_body"):
            for child in node.named_children: visit(child, owner)
    visit(tree.root_node)
    return output


def parse(text, path):
    """모든 언어가 같은 선언 자료형과 오류 경계로 반환한다."""
    selected = language(path)
    if selected == "python": return parse_py.parse(text, path)
    if selected == "csharp": return parse_cs.parse(text, path)
    return _extract(text, path)


def signature(text, kind, owner, path):
    """문서 선언을 코드와 같은 어댑터로 정규화한다."""
    selected = language(path)
    if selected == "python": return parse_py.parse_signature(text, kind, owner)
    if selected == "csharp": return parse_cs.parse_signature(text, kind, owner)
    if kind in ("field", "const", "property", "event", "enum-member"):
        return text.strip(), text.strip(), "", kind
    source = text.strip()
    is_type = kind in ("class", "struct", "interface", "enum", "record")
    if selected == "go":
        source = "package fixture\n" + (source + " {}" if is_type or source.startswith("func ")
                                        else "type Fixture interface { " + source + " }") + "\n"
    elif selected == "java" and not is_type:
        source = "class " + (owner if owner != "-" else "Fixture") + " { " + source + " {} }"
    elif selected in ("javascript", "typescript") and owner != "-" and not is_type and not source.startswith("function "):
        source = "class Fixture { " + source + " {} }"
    else:
        source += " {}"
    members = _extract(source, path)
    member = next((s for s in members if s.kind == kind and (is_type or s.kind not in TYPE_NODES.values())), None)
    if member is None: raise parse_cs.ParseError("Cannot parse declaration signature: " + text, 0)
    return member.signature, member.name, member.params, member.kind


def locals_by_line(text, path):
    """추가 언어의 함수별 지역 선언 수. 중첩 함수의 지역 선언은 분리한다."""
    tree = _tree(text, path)
    output = {}
    def visit(node, scope=None):
        if node.type in FUNCTION_NODES or node.type in ("arrow_function", "function_expression"):
            line = node.start_point.row+1
            name = _text(node.child_by_field_name('name')) or ('constructor' if node.type == 'constructor_declaration' else '')
            parameters = node.child_by_field_name('parameters')
            params = _normalized(parameters).strip()[1:-1].strip() if parameters is not None else _text(node.child_by_field_name('parameter'))
            # Variable declarator is the owning declaration for arrow functions.
            if node.parent and node.parent.type == "variable_declarator":
                line = node.parent.start_point.row+1
                name = _text(node.parent.child_by_field_name('name'))
            scope = (line, name, params)
            output.setdefault(scope, set())
        if scope is not None and node.type in ("variable_declarator", "var_spec", "const_spec", "short_var_declaration"):
            names = [bound for named in node.children_by_field_name("name") for bound in _bindings(named)]
            left = node.child_by_field_name("left")
            if left is not None: names += _bindings(left)
            output[scope].update(_text(n) for n in names if _text(n) != "_")
        for child in node.named_children: visit(child, scope)
    visit(tree.root_node)
    return {line:len(names) for line,names in output.items()}


@lru_cache(maxsize=8)
def runtime_version(selected):
    """문법 런타임 버전도 파서 입력에 포함한다."""
    names = ("tree-sitter", PACKAGES[selected]) if selected in PACKAGES else ()
    try: return tuple((name, importlib.metadata.version(name)) for name in names)
    except importlib.metadata.PackageNotFoundError: return (("missing", selected),)
