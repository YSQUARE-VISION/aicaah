# -*- coding: utf-8 -*-
"""Claude/Codex 훅 입력을 실행하지 않고 공통 편집 정책의 대상으로 바꾼다."""
import os
import re
import shlex


def _relative(root, cwd, path):
    """실재 작업 폴더 기준 경로를 해석하고 링크·드라이브·루트 탈출을 거절한다."""
    if not isinstance(cwd, str) or not os.path.isabs(cwd) or not os.path.isdir(cwd):
        raise ValueError("유효한 절대 cwd 필요")
    if not isinstance(path, str) or not path.strip() or any(c in path for c in "\x00\r\n"):
        raise ValueError("편집 대상 경로 없음 또는 잘못된 경로")
    drive, tail = os.path.splitdrive(path)
    if ":" in tail or (drive and not os.path.isabs(path)):
        raise ValueError("드라이브 상대 경로·대체 데이터 스트림 금지")
    base = os.path.realpath(root)
    absolute = os.path.realpath(os.path.join(cwd, path))
    if os.path.normcase(os.path.commonpath([base, absolute])) != os.path.normcase(base):
        raise ValueError("프로젝트 밖 편집 대상")
    rel = os.path.relpath(absolute, base).replace("\\", "/")
    if rel == ".":
        raise ValueError("파일 경로 필요")
    return rel


def patch_targets(root, cwd, patch):
    """apply_patch 전체를 읽고 추가·삭제·수정·이동 양쪽 경로를 반환한다."""
    if not isinstance(patch, str):
        raise ValueError("패치 문자열 필요")
    lines = patch.strip().splitlines()
    if len(lines) < 3 or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        raise ValueError("패치 시작·끝 형식 오류")
    targets, seen = [], set()
    i = 1
    while i < len(lines)-1:
        match = re.fullmatch(r"\*\*\* (Add|Delete|Update) File: (.+)", lines[i])
        if not match:
            raise ValueError("알 수 없는 패치 파일 지시")
        operation, path = match.groups()
        paths = [path]
        i += 1
        if i < len(lines)-1 and lines[i].startswith("*** Move to: "):
            if operation != "Update":
                raise ValueError("이동은 Update File에서만 허용")
            paths.append(lines[i][13:])
            i += 1
        body = []
        while i < len(lines)-1 and not re.match(r"\*\*\* (Add|Delete|Update) File: ", lines[i]):
            body.append(lines[i])
            i += 1
        if operation == "Delete" and body:
            raise ValueError("삭제 패치에 예상하지 않은 본문")
        if operation == "Add" and (not body or any(not line.startswith("+") for line in body)):
            raise ValueError("추가 패치 본문 오류")
        if operation == "Update":
            hunk = False
            for line in body:
                if line == "@@" or line.startswith("@@ "):
                    hunk = True
                elif line == "*** End of File" and hunk and line == body[-1]:
                    continue
                elif not hunk or not line or line[0] not in " +-":
                    raise ValueError("수정 패치 본문 오류")
            if not hunk and len(paths) != 2:
                raise ValueError("수정 패치의 변경 내용 없음")
        for path in paths:
            rel = _relative(root, cwd, path)
            if os.path.normcase(rel) in seen:
                raise ValueError("중복 패치 대상")
            seen.add(os.path.normcase(rel))
            targets.append(rel)
    if not targets:
        raise ValueError("패치 대상 없음")
    return targets


def shell_action(root, cwd, command):
    """고정된 단일 읽기 명령·검증 입구만 허용 후보로 분류한다."""
    if not isinstance(command, str) or not command.strip():
        raise ValueError("셸 명령 문자열 필요")
    # Treat shell metacharacters conservatively even inside quotes. Never evaluate commands.
    if re.search(r"[\r\n;&|<>`$(){}\x00]", command):
        return "edit"
    try:
        words = [word[1:-1] if len(word)>1 and word[0]==word[-1] and word[0] in "\"'" else word
                 for word in shlex.split(command, posix=False)]
    except ValueError:
        return "edit"
    if not words:
        return "edit"
    name = words[0].lower()
    if name in ('aicaah', 'aicaah.exe'):
        words = ['python', 'SpecConformance/engine.py', *words[1:]]
        name = 'python'
    if name in ("rg", "rg.exe"):
        allowed = {"--files", "--hidden", "--no-ignore", "--no-ignore-vcs", "--no-ignore-parent", "--no-heading", "--line-number", "--fixed-strings", "--ignore-case", "--smart-case", "--count", "--files-with-matches", "--files-without-match", "--only-matching", "--word-regexp", "--invert-match", "--", "-n", "-i", "-l", "-F", "-S", "-c", "-o", "-v", "-w"}
        values = {"-g", "--glob", "-t", "--type", "-T", "--type-not", "-e", "--regexp", "-m", "--max-count", "-A", "-B", "-C"}
        i = 1
        while i < len(words):
            word = words[i]
            if word in values:
                i += 1
                if i == len(words): return "edit"
            elif word.startswith("-") and word not in allowed:
                return "edit"
            i += 1
        return "read"
    if name in ("get-content", "get-childitem", "get-item", "get-filehash", "test-path", "resolve-path"):
        allowed = {"-literalpath", "-path", "-filter", "-recurse", "-force", "-name", "-file", "-directory", "-totalcount", "-tail", "-raw", "-encoding", "-algorithm"}
        return "read" if all(not w.startswith("-") or w.lower() in allowed for w in words[1:]) else "edit"
    if name in ("python", "python.exe", "python3", "python3.exe"):
        args = words[1:]
        if args[:2] == ["-X", "utf8"]: args = args[2:]
        if args[:2] == ['-m', 'aicaah']: args = ['SpecConformance/engine.py', *args[2:]]
        if len(args) >= 2:
            try: script = _relative(root, cwd, args[0])
            except ValueError: return "edit"
            if script == "SpecConformance/engine.py":
                tail = args[1:]
                if tail == ['stop']:
                    return 'control'
                if tail == ['selftest', '--list']:
                    return 'read'
                if tail == ['selftest', '--portable']:
                    return 'verification'
                if tail[0] == 'selftest' and len(tail) > 1:
                    pairs = list(zip(tail[1::2], tail[2::2]))
                    if (len(tail) % 2 == 1 and all(flag == '--case' and re.fullmatch(r'[A-Za-z_]\w*', value) for flag, value in pairs)
                            and len({value for _, value in pairs}) == len(pairs)):
                        return 'verification'
                if tail[0] == 'priority':
                    flags = {}; i = 1
                    while i < len(tail):
                        flag = tail[i]
                        if flag in flags or flag not in ('--groups','--group','--id','--limit','--offset','--order'):
                            return 'edit'
                        if flag == '--groups':
                            flags[flag] = True; i += 1; continue
                        if i + 1 >= len(tail): return 'edit'
                        value = tail[i + 1]
                        if flag in ('--limit','--offset') and not re.fullmatch(r'[0-9]+', value): return 'edit'
                        if flag == '--order' and value not in ('asc','desc'): return 'edit'
                        if flag in ('--id','--group') and (not value or value.startswith('-') or any(c.isspace() for c in value)): return 'edit'
                        flags[flag] = value; i += 2
                    if sum(flag in flags for flag in ('--groups','--group','--id')) > 1: return 'edit'
                    return 'read'
                if args[1:] == ["selftest"] or args[1:] in (["check", "--gate", "--purpose", "verification"], ["check", "--gate", "--purpose", "verification", "--quiet"]):
                    return "verification"
                if args[1:] in (["docs"], ["mode"], ["ask", "status"], ["ask", "review"]):
                    return "read"
    if name in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
        args = words[1:]
        if args and args[0].lower() == "-noprofile": args = args[1:]
        if len(args) == 4 and args[0].lower() == "-file" and args[2].lower() == "-outputdirectory":
            try:
                script = _relative(root, cwd, args[1])
                output = _relative(root, cwd, args[3])
            except ValueError: return "edit"
            if script == "Tests/AddonSystem/run-main-api-contracts.ps1" and output.startswith("Reports/"):
                return "verification"
    return "edit"


def parse_event(root, client, data):
    """실행 환경·이벤트·도구 입력을 명시적으로 읽고 분류/대상 목록을 반환한다."""
    if client not in ("claude", "codex") or not isinstance(data, dict):
        raise ValueError("실행 환경과 JSON 객체 필요")
    event = data.get("hook_event_name", "PreToolUse")
    if event not in ("PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit", "Stop"):
        raise ValueError("지원하지 않는 훅 이벤트")
    if event == "Stop":
        return {"event":event, "action":"finish", "targets":[]}
    if event in ("SessionStart", "UserPromptSubmit"):
        return {"event":event, "action":"context", "targets":[]}
    cwd = data.get("cwd", root)
    if not isinstance(cwd,str) or not os.path.isabs(cwd) or not os.path.isdir(cwd):
        raise ValueError("유효한 절대 cwd 필요")
    tool, values = data.get("tool_name"), data.get("tool_input")
    if not isinstance(values, dict):
        raise ValueError("도구 입력 객체 필요")
    if tool == "apply_patch" and client == "codex":
        action, targets = "edit", patch_targets(root, cwd, values.get("command"))
    elif tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        action = "edit"
        key = "notebook_path" if tool == "NotebookEdit" else "file_path"
        targets = [_relative(root, cwd, values.get(key))]
    elif tool in ("Bash", "PowerShell", "exec_command"):
        command = values.get("command") if tool != "exec_command" else values.get("cmd")
        action = shell_action(root, cwd, command)
        targets = ["."] if action == "edit" else []
    else:
        raise ValueError("지원하지 않는 도구 입력: " + str(tool))
    return {"event":event, "action":action, "targets":targets}

def changed_members(root, event, data):
    """도구를 실행하지 않고 전후 텍스트의 정확한 선언·파일 변경을 구한다."""
    import difflib
    import hashlib
    from dataclasses import asdict
    from parsing import parse_cs, parse_py
    cwd = data.get("cwd", root)
    tool, values = data["tool_name"], data["tool_input"]
    files = []
    def read(rel):
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            raise ValueError("원본 파일 없음: " + rel)
        with open(path, "rb") as stream:
            raw = stream.read()
        return raw.decode("utf-8-sig").replace("\r\n", "\n"), hashlib.sha256(raw).hexdigest()
    def replace(text, old, new, all_matches=False):
        if not isinstance(old, str) or not old or not isinstance(new, str):
            raise ValueError("원문·변경 문자열 필요")
        count = text.count(old)
        if count == 0 or (count != 1 and not all_matches):
            raise ValueError("원문 치환 불명 또는 모호함")
        return text.replace(old, new) if all_matches else text.replace(old, new, 1)
    if tool == "apply_patch":
        patch_targets(root, cwd, values.get("command"))
        lines = values["command"].strip().splitlines()
        i = 1
        while i < len(lines)-1:
            match = re.fullmatch(r"\*\*\* (Add|Delete|Update) File: (.+)", lines[i])
            op, path = match.groups()
            rel = _relative(root, cwd, path)
            i += 1
            destination = rel
            if lines[i].startswith("*** Move to: "):
                destination = _relative(root, cwd, lines[i][13:])
                i += 1
            body = []
            while i < len(lines)-1 and not re.match(r"\*\*\* (Add|Delete|Update) File: ", lines[i]):
                body.append(lines[i])
                i += 1
            before, fingerprint = ("", "") if op == "Add" else read(rel)
            if op == "Add":
                if os.path.exists(os.path.join(root, rel)):
                    raise ValueError("추가 대상 이미 존재")
                after = "\n".join(line[1:] for line in body) + "\n"
            elif op == "Delete":
                after = ""
            else:
                source = before.splitlines()
                cursor, result, j = 0, [], 0
                while j < len(body):
                    if not body[j].startswith("@@"):
                        raise ValueError("패치 청크 오류")
                    j += 1
                    old, new = [], []
                    at_end = False
                    while j < len(body) and not body[j].startswith("@@"):
                        line = body[j]
                        if line == "*** End of File":
                            at_end = True
                        else:
                            if line[0] in " -": old.append(line[1:])
                            if line[0] in " +": new.append(line[1:])
                        j += 1
                    if not old:
                        raise ValueError("문맥 없는 삽입은 위치 판정 불가")
                    hits = [k for k in range(cursor, len(source)-len(old)+1)
                            if source[k:k+len(old)] == old and (not at_end or k+len(old) == len(source))]
                    if len(hits) != 1:
                        raise ValueError("패치 원문 없음 또는 모호함")
                    start = hits[0]
                    result.extend(source[cursor:start])
                    result.extend(new)
                    cursor = start + len(old)
                result.extend(source[cursor:])
                after = "\n".join(result) + ("\n" if before.endswith("\n") else "")
            if destination != rel:
                if os.path.exists(os.path.join(root, destination)):
                    raise ValueError("이동 목적지 이미 존재")
                files.extend([(rel, before, "", fingerprint, "move"), (destination, "", after, "", "move")])
            else:
                files.append((rel, before, after, fingerprint, {"Add": "add", "Delete": "delete", "Update": "modify"}[op]))
    elif tool in ("Edit", "MultiEdit", "Write"):
        rel = _relative(root, cwd, values.get("file_path"))
        exists = os.path.isfile(os.path.join(root, rel))
        before, fingerprint = read(rel) if exists else ("", "")
        after = before
        if tool == "Write":
            after = values.get("content")
            if not isinstance(after, str):
                raise ValueError("Write 본문 필요")
        else:
            edits = values.get("edits") if tool == "MultiEdit" else [values]
            if not exists or not isinstance(edits, list) or not edits:
                raise ValueError("편집 원본·변경 목록 필요")
            for edit in edits:
                after = replace(after, edit.get("old_string"), edit.get("new_string"), edit.get("replace_all", False))
        files.append((rel, before, after, fingerprint, "modify" if exists else "add"))
    else:
        raise ValueError("실제 변경을 증명할 수 없는 도구·셸 쓰기")
    out = []
    for rel, before, after, fingerprint, file_op in files:
        if rel.casefold().startswith("docs/"):
            continue
        parser = parse_py if rel.endswith(".py") else parse_cs if rel.endswith(".cs") else None
        if parser is None:
            if before != after:
                out.append(dict(file=rel, kind="file", operation=file_op, beforeHash=fingerprint,
                                afterHash=hashlib.sha256(after.encode("utf-8")).hexdigest()))
            continue
        try:
            old_symbols = [asdict(s) for s in parser.parse(before, rel)]
            new_symbols = [asdict(s) for s in parser.parse(after, rel)]
        except (parse_cs.ParseError, SyntaxError) as error:
            raise ValueError("편집 전후 파싱 실패: " + str(error))
        def identity(s):
            return (s["path"], s["kind"], s["name"], s["params"])
        def content(s, symbols, text):
            lines = text.splitlines()
            # Child edits belong to their own declaration, not the whole class.
            children = [c for c in symbols if s["line"] < c["line"] and c["end"] <= s["end"]]
            covered = set()
            for child in children:
                covered.update(range(child["line"], child["end"]+1))
            return "\n".join(lines[n-1] for n in range(s["line"], s["end"]+1) if n not in covered and lines[n-1].strip())
        old = {identity(s): s for s in old_symbols}
        new = {identity(s): s for s in new_symbols}
        removed, added = set(old)-set(new), set(new)-set(old)
        pairs = [(old[k], new[k]) for k in old.keys() & new.keys()]
        for key in list(removed):
            matches = [k for k in added if k[:3] == key[:3]]
            if len(matches) == 1:
                target = matches[0]
                pairs.append((old[key], new[target]))
                removed.remove(key)
                added.remove(target)
        pairs += [(old[k], None) for k in removed] + [(None, new[k]) for k in added]
        for first, last in pairs:
            changed = first is None or last is None or content(first, old_symbols, before) != content(last, new_symbols, after)
            if not changed:
                continue
            op = file_op if file_op == "move" else "add" if first is None else "delete" if last is None else (
                "signature" if first["signature"] != last["signature"] else "modify")
            out.append(dict(file=rel, kind=(last or first)["kind"], operation=op, before=first, after=last,
                            beforeHash=fingerprint, afterHash=hashlib.sha256(after.encode("utf-8")).hexdigest()))
        def outside(text, symbols):
            lines = text.splitlines()
            covered = set()
            for symbol in symbols:
                covered.update(range(symbol["line"], symbol["end"]+1))
            return "\n".join(line for n, line in enumerate(lines, 1) if n not in covered and line.strip())
        if file_op in ("add", "delete", "move") or outside(before, old_symbols) != outside(after, new_symbols):
            out.append(dict(file=rel, kind="file", operation=file_op, beforeHash=fingerprint,
                            afterHash=hashlib.sha256(after.encode("utf-8")).hexdigest()))
    return out

