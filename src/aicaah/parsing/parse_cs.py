# -*- coding: utf-8 -*-
"""C# 심볼 파서(SPEC-36 2.2). 형 선언과 형 수준 멤버를 뽑고, 문서와 같은 규칙으로 시그니처를 정규화한다.

메서드 본문 안(지역 함수·람다)은 멤버로 뽑지 않고 본문 해시에만 들어간다."""
import hashlib
import re
from dataclasses import dataclass, asdict
from functools import lru_cache

OPS2 = {"=>", "==", "!=", "<=", "&&", "||", "??", "?.", "::", "->", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="}
MODIFIERS = {"public", "internal", "protected", "private", "static", "readonly", "const", "abstract", "virtual",
             "override", "sealed", "partial", "async", "extern", "unsafe", "new", "volatile", "fixed", "required"}
ACCESS = ("public", "internal", "protected", "private")
TYPE_KEYWORDS = {"class", "struct", "interface", "enum", "record"}
PARAM_MODIFIERS = {"this", "ref", "out", "in", "params", "scoped"}


class ParseError(Exception):
    """파싱할 수 없는 구조(짝이 안 맞는 괄호 등). 줄 번호를 함께 든다."""

    def __init__(self, message, line):
        """메시지와 줄 번호."""
        super().__init__(message)
        self.line = line


@dataclass
class Token:
    """토큰 하나: 종류(id·num·str·chr·op), 글자, 줄."""
    kind: str
    text: str
    line: int


@dataclass
class Symbol:
    """형 또는 형 수준 멤버 하나."""
    file: str
    path: str
    kind: str
    name: str
    signature: str
    params: str
    access: str
    modifiers: tuple
    line: int
    end: int
    body: str
    documented: bool
    value: str = ""
    type: str = ""

    @property
    def key(self):
        """심볼 키: 파일 + 소속 형 경로 + 종류 + 이름 + 매개변수 형."""
        return "%s|%s|%s|%s|%s" % (self.file, self.path, self.kind, self.name, self.params)

    def to_dict(self):
        """스냅숏 매니페스트용 사전."""
        d = asdict(self)
        d["modifiers"] = list(self.modifiers)
        return d

    @staticmethod
    def from_dict(d):
        """스냅숏 매니페스트에서 되살린다."""
        d = dict(d)
        d["modifiers"] = tuple(d.get("modifiers", ()))
        return Symbol(**d)


def _line_start(text, i):
    """위치 i가 줄의 첫 글자(공백 뒤)인가."""
    j = i - 1
    while j >= 0 and text[j] in " \t":
        j -= 1
    return j < 0 or text[j] == "\n"


def _skip_string(text, i, line, verbatim, interp):
    """문자열 끝 다음 위치와 줄 수(일반·축자·보간 문자열)."""
    n = len(text)
    while i < n:
        c = text[i]
        if verbatim:
            if c == '"':
                if i + 1 < n and text[i + 1] == '"':
                    i += 2
                    continue
                return i + 1, line
        else:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                return i + 1, line
        if c == "\n":
            line += 1
        if interp and c == "{":
            if i + 1 < n and text[i + 1] == "{":
                i += 2
                continue
            i, line = _skip_hole(text, i + 1, line)
            continue
        i += 1
    return i, line


def _skip_hole(text, i, line):
    """보간 문자열의 `{...}` 구멍을 건너뛴다(중첩 문자열 포함)."""
    n = len(text)
    depth = 1
    while i < n and depth > 0:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c == "{":
            depth += 1
            i += 1
            continue
        if c == "}":
            depth -= 1
            i += 1
            continue
        m = re.match(r'(\$@|@\$|\$|@)?"', text[i:i + 3])
        if m:
            prefix = m.group(1) or ""
            i, line = _skip_string(text, i + len(prefix) + 1, line, "@" in prefix, "$" in prefix)
            continue
        if c == "'":
            j = i + 1
            while j < n and text[j] != "'":
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        i += 1
    return i, line


def tokenize(text):
    """C# 원문을 토큰으로. 주석·전처리 줄은 버리고, `///` 주석이 있는 줄 번호를 따로 모은다."""
    tokens, doclines = [], set()
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in " \t\r\f\v﻿":
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            if text.startswith("///", i):
                doclines.add(line)
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += text.count("\n", i, j)
            i = j
            continue
        if c == "#" and _line_start(text, i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        m = re.match(r'(\$@|@\$|\$|@)?"', text[i:i + 3])
        if m:
            prefix = m.group(1) or ""
            start, first = i, line
            i, line = _skip_string(text, i + len(prefix) + 1, line, "@" in prefix, "$" in prefix)
            tokens.append(Token("str", text[start:i], first))
            continue
        if c == "@" and i + 1 < n and (text[i + 1].isalpha() or text[i + 1] == "_"):
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            tokens.append(Token("id", text[i + 1:j], line))
            i = j
            continue
        if c == "'":
            j = i + 1
            while j < n and text[j] != "'":
                j += 2 if text[j] == "\\" else 1
            j += 1
            tokens.append(Token("chr", text[i:j], line))
            i = j
            continue
        if c.isalpha() or c == "_" or ord(c) > 127:
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_" or ord(text[j]) > 127):
                j += 1
            tokens.append(Token("id", text[i:j], line))
            i = j
            continue
        if c.isdigit() or (c == "." and i + 1 < n and text[i + 1].isdigit()):
            j = i + 1
            while j < n:
                if text[j] in "eE" and j + 1 < n and text[j + 1] in "+-" and not text[i:j].lower().startswith("0x"):
                    j += 2
                    continue
                if text[j].isalnum() or text[j] in "._":
                    j += 1
                    continue
                break
            tokens.append(Token("num", text[i:j], line))
            i = j
            continue
        two = text[i:i + 2]
        if two in OPS2:
            tokens.append(Token("op", two, line))
            i += 2
            continue
        tokens.append(Token("op", c, line))
        i += 1
    return tokens, doclines


def render(tokens):
    """토큰 목록을 정규화한 글자로(SPEC-36 2.3)."""
    out = []
    prev = None
    for k, t in enumerate(tokens):
        s = t.text if isinstance(t, Token) else t
        if prev is None:
            out.append(s)
        else:
            space = True
            if s in (",", ")", "]", ";", ".", ">", "?", "("):
                space = False
            if s == "[" and prev not in ("=", ",", "("):
                space = False
            if prev in ("(", "[", ".", "<", "!", "~"):
                space = False
            if s == "<" and prev not in ("=", ","):
                space = False
            if prev == "-" and k >= 2:
                before = tokens[k - 2].text if isinstance(tokens[k - 2], Token) else tokens[k - 2]
                if before in ("=", "(", ",", "return", "["):
                    space = False
            if s == "*" and prev not in ("=", ","):
                space = False
            out.append((" " if space else "") + s)
        prev = s
    text = "".join(out)
    text = re.sub(r",(?=\S)", ", ", text)
    return text


def body_hash(tokens):
    """본문 토큰의 해시(공백·주석과 무관)."""
    if not tokens:
        return ""
    h = hashlib.sha1()
    for t in tokens:
        h.update(t.text.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()[:16]


class Parser:
    """토큰 목록에서 심볼을 뽑는다."""

    def __init__(self, text, path):
        """토큰과 `///` 줄, 괄호 짝을 준비한다."""
        self.path = path
        self.t, self.doclines = tokenize(text)
        self.match = self._pairs()
        self.symbols = []
        self.context = []

    def _pairs(self):
        """여는 괄호 → 닫는 괄호 위치. 짝이 안 맞으면 ParseError."""
        pairs, stack = {}, []
        opens = {"(": ")", "[": "]", "{": "}"}
        for k, tok in enumerate(self.t):
            if tok.kind != "op":
                continue
            if tok.text in opens:
                stack.append(k)
            elif tok.text in (")", "]", "}"):
                if not stack:
                    raise ParseError("닫는 괄호가 남음 '%s'" % tok.text, tok.line)
                o = stack.pop()
                if opens[self.t[o].text] != tok.text:
                    raise ParseError("괄호 짝이 다름 '%s'…'%s'" % (self.t[o].text, tok.text), tok.line)
                pairs[o] = k
        if stack:
            raise ParseError("닫히지 않은 괄호 '%s'" % self.t[stack[-1]].text, self.t[stack[-1]].line)
        return pairs

    def parse(self):
        """파일 전체를 읽어 심볼 목록을 돌려준다."""
        self._block(0, len(self.t), "-", None, None)
        return self.symbols

    def _documented(self, start, first_line):
        """선언 바로 위(특성 줄 건너뛰고)에 `///` 줄이 있는가."""
        prev_line = self.t[start - 1].line if start > 0 else 0
        return any(prev_line < d < first_line for d in self.doclines)

    def _block(self, i, end, tpath, tkind, tname):
        """형 본문 또는 이름공간 한 블록의 선언들을 읽는다."""
        t = self.t
        while i < end:
            if t[i].text in (";", "}"):
                i += 1
                continue
            if tkind == "enum":
                self._enum(i, end, tpath)
                return
            start = i
            while i < end and t[i].text == "[":
                i = self.match[i] + 1
            if i >= end:
                return
            if tkind is None and t[i].text in ("using", "extern") and t[i].kind == "id":
                while i < end and t[i].text != ";":
                    i = self.match.get(i, i) + 1 if t[i].text in ("(", "[", "{") else i + 1
                self.context.append(" ".join(token.text for token in t[start:i + 1]))
                i += 1
                continue
            if t[i].text == "namespace":
                j = i + 1
                while j < end and t[j].text not in ("{", ";"):
                    j += 1
                self.context.append(" ".join(token.text for token in t[i:j + 1]))
                if j < end and t[j].text == "{":
                    close = self.match[j]
                    self._block(j + 1, close, "-", None, None)
                    self.context.append("}")
                    i = close + 1
                else:
                    i = j + 1
                continue
            head_start = i
            j, eq = i, None
            while j < end:
                x = t[j]
                if x.kind == "op" and x.text in ("(", "["):
                    j = self.match[j] + 1
                    continue
                if x.kind == "op" and x.text == "{":
                    if eq is not None:
                        j = self.match[j] + 1
                        continue
                    break
                if x.kind == "op" and x.text == ";":
                    break
                if x.kind == "op" and x.text == "=>" and eq is None:
                    break
                if x.kind == "op" and x.text == "=" and eq is None:
                    eq = j
                j += 1
            if j >= end:
                raise ParseError("선언이 끝나지 않음", t[head_start].line)
            head = t[head_start:j]
            term = t[j].text
            i = self._declaration(start, head_start, head, j, term, eq, tpath, tkind, tname)

    def _modifiers(self, head):
        """선언 머리의 수식어들."""
        m = 0
        while m < len(head) and head[m].text in MODIFIERS and head[m].kind == "id":
            m += 1
        return [x.text for x in head[:m]], m

    def _access(self, mods, tkind, tpath, is_type):
        """적힌 접근자, 없으면 C# 기본값(멤버 private, 최상위 형 internal, 인터페이스 멤버 public)."""
        for a in ACCESS:
            if a in mods:
                if a == "protected" and "internal" in mods:
                    return "protected"
                return a
        if tkind in ("interface", "enum"):
            return "public"
        if is_type and tpath == "-":
            return "internal"
        return "private"

    def _declaration(self, start, hs, head, j, term, eq, tpath, tkind, tname):
        """선언 하나를 종류별(형·대리자·이벤트·메서드·인덱서·속성·필드·상수)로 심볼로."""
        t = self.t
        mods, m = self._modifiers(head)
        rest = head[m:]
        first_line = head[0].line
        documented = self._documented(start, first_line)
        # 형 선언
        if rest and rest[0].text in TYPE_KEYWORDS and rest[0].kind == "id" and len(rest) > 1:
            kw = rest[0].text
            k = 1
            if kw == "record" and rest[1].text in ("class", "struct"):
                k = 2
            name = rest[k].text
            cut = len(head)
            for q, x in enumerate(head):
                if x.text == "where" and x.kind == "id" and q > m + k:
                    cut = q
                    break
            signature = render(head[:cut])
            kind = "record" if kw == "record" else kw
            path = name if tpath == "-" else tpath + "." + name
            if term == "{":
                close = self.match[j]
                self.symbols.append(Symbol(self.path, tpath, kind, name, signature, "", self._access(mods, tkind, tpath, True),
                                           tuple(mods), first_line, t[close].line, "", documented))
                self._block(j + 1, close, path, kind, name)
                nxt = close + 1
                if nxt < len(t) and t[nxt].text == ";":
                    nxt += 1
                return nxt
            self.symbols.append(Symbol(self.path, tpath, kind, name, signature, "", self._access(mods, tkind, tpath, True),
                                       tuple(mods), first_line, t[j].line, "", documented))
            return j + 1
        # 대리자
        if rest and rest[0].text == "delegate" and rest[0].kind == "id":
            paren = next((q for q in range(len(head)) if head[q].text == "("), None)
            if paren is None:
                raise ParseError("대리자 매개변수 없음", first_line)
            name_idx = self._name_before(head, paren)
            name = head[name_idx].text
            close = self.match[hs + paren] - hs
            signature = render(head[:close + 1])
            params = self._param_types(head[paren + 1:close])
            self.symbols.append(Symbol(self.path, tpath, "delegate", name, signature, params, self._access(mods, tkind, tpath, True),
                                       tuple(mods), first_line, t[j].line, "", documented))
            return j + 1
        # 이벤트
        if rest and rest[0].text == "event" and rest[0].kind == "id":
            if term == "{":
                close = self.match[j]
                body = t[j + 1:close]
                names = [head[-1].text]
                end_line = t[close].line
                nxt = close + 1
            else:
                body, end_line, nxt = [], t[j].line, j + 1
                names = self._declarator_names(head, m + 1)
            type_tokens = self._type_tokens(head, m + 1)
            for name in names:
                signature = render(list(head[:m + 1]) + type_tokens + [Token("id", name, 0)])
                self.symbols.append(Symbol(self.path, tpath, "event", name, signature, "", self._access(mods, tkind, tpath, False),
                                           tuple(mods), first_line, end_line, body_hash(body), documented, "", render(type_tokens)))
            return nxt
        # 괄호가 있는 멤버(메서드·생성자·연산자·소멸자)
        limit = (eq - hs) if eq is not None else len(head)
        paren = self._param_paren(head, m, limit)
        if paren is not None:
            close = self.match[hs + paren] - hs
            name_idx = self._name_before(head, paren)
            name_tok = head[name_idx]
            kind = "method"
            name = name_tok.text
            op_start = next((q for q in range(paren) if head[q].text == "operator"), None)
            if op_start is not None:
                kind = "operator"
                name = "operator" + "".join(x.text for x in head[op_start + 1:paren])
            elif name_idx > 0 and head[name_idx - 1].text == "~":
                name = "~" + name
            elif tname is not None and name == tname and name_idx == m:
                kind = "ctor"
            signature = render(head[:close + 1])
            params = self._param_types(head[paren + 1:close])
            if term == "{":
                cl = self.match[j]
                body = t[j + 1:cl]
                end_line, nxt = t[cl].line, cl + 1
            elif term == "=>":
                q = j + 1
                while q < len(t) and t[q].text != ";":
                    q = self.match[q] + 1 if t[q].text in ("(", "[", "{") else q + 1
                body = t[j + 1:q]
                end_line, nxt = t[q].line, q + 1
            else:
                body, end_line, nxt = [], t[j].line, j + 1
            self.symbols.append(Symbol(self.path, tpath, kind, name, signature, params, self._access(mods, tkind, tpath, False),
                                       tuple(mods), first_line, end_line, body_hash(body), documented, "",
                                       render(head[m:name_idx]) if kind == "method" else ""))
            return nxt
        # 인덱서
        this_idx = next((q for q in range(m, len(head)) if head[q].text == "this" and q + 1 < len(head) and head[q + 1].text == "["), None)
        if this_idx is not None and term in ("{", "=>"):
            br = this_idx + 1
            close = self.match[hs + br] - hs
            signature, body, end_line, nxt = self._accessors(head[:close + 1], j, term)
            params = self._param_types(head[br + 1:close])
            self.symbols.append(Symbol(self.path, tpath, "indexer", "this", signature, params, self._access(mods, tkind, tpath, False),
                                       tuple(mods), first_line, end_line, body, documented, "", render(head[m:this_idx])))
            return nxt
        # 속성
        if term in ("{", "=>"):
            name = head[-1].text
            signature, body, end_line, nxt = self._accessors(list(head), j, term)
            self.symbols.append(Symbol(self.path, tpath, "property", name, signature, "", self._access(mods, tkind, tpath, False),
                                       tuple(mods), first_line, end_line, body, documented, "", render(head[m:-1])))
            return nxt
        # 필드·상수(한 줄 여러 선언은 나눈다)
        kind = "const" if "const" in mods else "field"
        type_tokens = self._type_tokens(head, m)
        for name, value, line in self._declarators(head, m):
            signature = render(list(head[:m]) + type_tokens + [Token("id", name, 0)])
            self.symbols.append(Symbol(self.path, tpath, kind, name, signature, "", self._access(mods, tkind, tpath, False),
                                       tuple(mods), line, t[j].line, body_hash(value), documented, render(value), render(type_tokens)))
        return j + 1

    def _param_paren(self, head, m, limit):
        """머리에서 매개변수 괄호의 위치."""
        operator = next((q for q in range(m, limit) if head[q].text == "operator"), None)
        if operator is not None:
            # 연산 기호는 식별자가 아니며 <·>도 제네릭 괄호가 아니다.
            return next((q for q in range(operator + 1, limit) if head[q].text == "("), None)
        q = m
        if q < limit and head[q].text == "(":  # 튜플 반환형
            q = self._close_in_head(head, q) + 1
        angle = 0
        while q < limit:
            x = head[q].text
            if x == "<":
                angle += 1
            elif x == ">":
                angle = max(0, angle - 1)
            elif x == "(" and angle == 0:
                if q > 0 and (head[q - 1].kind == "id" or head[q - 1].text == ">"):
                    return q
                q = self._close_in_head(head, q) + 1
                continue
            elif x == "[":
                q = self._close_in_head(head, q) + 1
                continue
            q += 1
        return None

    def _close_in_head(self, head, q):
        """머리 안에서 괄호 q의 짝 위치."""
        depth = 0
        for k in range(q, len(head)):
            if head[k].text in ("(", "["):
                depth += 1
            elif head[k].text in (")", "]"):
                depth -= 1
                if depth == 0:
                    return k
        raise ParseError("머리 안 괄호가 닫히지 않음", head[q].line)

    def _name_before(self, head, paren):
        """괄호 앞의 이름(제네릭 인자·명시적 인터페이스 포함)."""
        k = paren - 1
        if head[k].text == ">":
            depth = 0
            while k >= 0:
                if head[k].text == ">":
                    depth += 1
                elif head[k].text == "<":
                    depth -= 1
                    if depth == 0:
                        break
                k -= 1
            k -= 1
        return k

    def _split_top(self, tokens):
        """최상위 쉼표로 토큰을 나눈다."""
        parts, cur, depth = [], [], 0
        for x in tokens:
            if x.text in ("(", "[", "{", "<"):
                depth += 1
            elif x.text in (")", "]", "}", ">"):
                depth -= 1
            if x.text == "," and depth == 0:
                parts.append(cur)
                cur = []
                continue
            cur.append(x)
        if cur:
            parts.append(cur)
        return parts

    def _param_types(self, tokens):
        """매개변수 목록의 형만(수식어 ref·out·in·params·this 포함) `,`로 이어 붙인다."""
        types = []
        for p in self._split_top(tokens):
            q = 0
            while q < len(p) and p[q].text == "[":
                depth = 0
                while q < len(p):
                    if p[q].text == "[":
                        depth += 1
                    elif p[q].text == "]":
                        depth -= 1
                        if depth == 0:
                            q += 1
                            break
                    q += 1
            p = p[q:]
            eqs = [k for k, x in enumerate(p) if x.text == "="]
            if eqs:
                p = p[:eqs[0]]
            while p and p[0].text in PARAM_MODIFIERS:
                p = p[1:]
            if len(p) > 1:
                p = p[:-1]
            types.append(render(p))
        return ",".join(types)

    def _type_tokens(self, head, m):
        """필드·속성 선언의 형 토큰."""
        k = m
        angle = 0
        while k < len(head):
            x = head[k]
            if x.text == "<":
                angle += 1
            elif x.text == ">":
                angle -= 1
            elif x.text in ("(", "["):
                k = self._close_in_head(head, k) + 1
                continue
            elif angle == 0 and x.kind == "id" and k > m and (k + 1 >= len(head) or head[k + 1].text in ("=", ",", ";")):
                return list(head[m:k])
            k += 1
        return list(head[m:-1])

    def _declarator_names(self, head, m):
        """필드 선언 하나의 이름들."""
        return [n for n, _, _ in self._declarators(head, m)]

    def _declarators(self, head, m):
        """필드 선언의 (이름, 초깃값) 목록."""
        type_len = len(self._type_tokens(head, m))
        k = m + type_len
        out = []
        while k < len(head):
            name = head[k]
            line = name.line
            k += 1
            value = []
            if k < len(head) and head[k].text == "=":
                k += 1
                depth = 0
                while k < len(head):
                    x = head[k]
                    if x.text in ("(", "[", "{"):
                        depth += 1
                    elif x.text in (")", "]", "}"):
                        depth -= 1
                    elif x.text == "," and depth == 0 and k + 1 < len(head) and head[k + 1].kind == "id" and \
                            (k + 2 >= len(head) or head[k + 2].text in ("=", ",")):
                        break
                    value.append(x)
                    k += 1
            out.append((name.text, value, line))
            if k < len(head) and head[k].text == ",":
                k += 1
        return out

    def _accessors(self, sig_head, j, term):
        """속성·인덱서·이벤트의 접근자 요약(`{ get; private set; }`)."""
        t = self.t
        if term == "=>":
            q = j + 1
            while q < len(t) and t[q].text != ";":
                q = self.match[q] + 1 if t[q].text in ("(", "[", "{") else q + 1
            return render(sig_head) + " { get; }", body_hash(t[j + 1:q]), t[q].line, q + 1
        close = self.match[j]
        inner = t[j + 1:close]
        accessors, body_tokens, k = [], [], 0
        while k < len(inner):
            mods = []
            while k < len(inner) and inner[k].text in ACCESS:
                mods.append(inner[k].text)
                k += 1
            while k < len(inner) and inner[k].text == "[":
                depth = 0
                while k < len(inner):
                    if inner[k].text == "[":
                        depth += 1
                    elif inner[k].text == "]":
                        depth -= 1
                        if depth == 0:
                            k += 1
                            break
                    k += 1
            if k >= len(inner):
                break
            word = inner[k].text
            k += 1
            accessors.append(" ".join(mods + [word]) + ";")
            if k < len(inner) and inner[k].text == "{":
                depth = 0
                while k < len(inner):
                    if inner[k].text == "{":
                        depth += 1
                    elif inner[k].text == "}":
                        depth -= 1
                        if depth == 0:
                            k += 1
                            break
                    body_tokens.append(inner[k])
                    k += 1
            elif k < len(inner) and inner[k].text == "=>":
                while k < len(inner) and inner[k].text != ";":
                    body_tokens.append(inner[k])
                    k += 1
                k += 1
            elif k < len(inner) and inner[k].text == ";":
                k += 1
        nxt = close + 1
        end_line = t[close].line
        if nxt < len(t) and t[nxt].text == "=":
            q = nxt
            while q < len(t) and t[q].text != ";":
                q = self.match[q] + 1 if t[q].text in ("(", "[", "{") else q + 1
            body_tokens.extend(t[nxt:q])
            end_line, nxt = t[q].line, q + 1
        return render(sig_head) + " { " + " ".join(accessors) + " }", body_hash(body_tokens), end_line, nxt

    def _enum(self, i, end, tpath):
        """열거형 멤버들."""
        t = self.t
        part = []
        for k in range(i, end + 1):
            if k == end or (t[k].text == "," and t[k].kind == "op"):
                toks = part
                while toks and toks[0].text == "[":
                    depth, q = 0, 0
                    while q < len(toks):
                        if toks[q].text == "[":
                            depth += 1
                        elif toks[q].text == "]":
                            depth -= 1
                            if depth == 0:
                                break
                        q += 1
                    toks = toks[q + 1:]
                if toks and toks[0].kind == "id":
                    name = toks[0].text
                    value = toks[2:] if len(toks) > 2 and toks[1].text == "=" else []
                    self.symbols.append(Symbol(self.path, tpath, "enum-member", name, name, "", "public", (), toks[0].line,
                                               toks[-1].line, body_hash(value), False, render(value), ""))
                part = []
            else:
                part.append(t[k])


def parse(text, path):
    """C# 원문 하나에서 심볼 목록을 뽑는다."""
    return Parser(text, path).parse()


@lru_cache(maxsize=8192)
def parse_signature(signature, kind, container):
    """문서의 시그니처 한 칸을 코드와 같은 규칙으로 파싱한다. (정규화 시그니처, 이름, 매개변수 형, 종류) 또는 오류."""
    owner = (container or "-").split(".")[-1]
    if kind in ("class", "struct", "interface", "enum", "record"):
        text = signature + " {}"
        syms = Parser(text, "doc").parse()
        if not syms:
            raise ParseError("형 시그니처를 읽을 수 없음", 0)
        s = syms[0]
        return s.signature, s.name, s.params, s.kind
    if kind == "enum-member":
        return signature.strip(), signature.strip(), "", "enum-member"
    if owner == "-":
        owner = "__Top"
    body = signature.strip()
    if kind in ("method", "ctor", "operator", "delegate"):
        body += ";"
    elif kind in ("property", "indexer"):
        if "{" not in body:
            body += " { get; }"
    elif kind == "event":
        body += ";"
    else:
        body += ";"
    text = "class %s { %s }" % (owner, body)
    syms = [s for s in Parser(text, "doc").parse() if s.kind != "class" or s.name != owner]
    if not syms:
        raise ParseError("멤버 시그니처를 읽을 수 없음", 0)
    s = syms[0]
    return s.signature, s.name, s.params, s.kind


def parse_with_context(text, path=""):
    """한 토큰화에서 선언과 namespace/using/extern 해석 문맥 해시를 반환한다."""
    parser = Parser(text, path)
    symbols = parser.parse()
    return symbols, hashlib.sha256("\n".join(parser.context).encode("utf-8")).hexdigest()
