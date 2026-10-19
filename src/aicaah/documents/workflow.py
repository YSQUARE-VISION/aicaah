# -*- coding: utf-8 -*-
"""작업 방향만 저장한다. 코드와 작업 문서는 수정하지 않는다."""
import json
import os
import uuid
import hashlib
import datetime
import threading

from documents import docs as docmod
from storage import snapshot
from storage import ledger

STATE_FILE = ".spec-conformance/History/workflow.json"
LEGACY_FILE = ".spec-conformance/History/apply.json"
MODES = ("document-to-code", "code-to-document")
CODE_POLICIES = ("deny", "allow", "request")
BASELINE_FILE = ".spec-conformance/History/workflow-code-baseline.bin"
REQUEST_FILE = ".spec-conformance/History/workflow-code-requests.bin"
SOURCE_EXTENSIONS = {".cs", ".py", ".shader", ".hlsl", ".cginc", ".compute", ".ps1", ".asmdef", ".asmref"}
REQUEST_LOCK = threading.RLock()


def state(root):
    saved = {}
    for rel in (STATE_FILE, LEGACY_FILE):
        try:
            with open(os.path.join(root, rel), encoding="utf-8") as stream:
                saved = json.load(stream)
            mode = saved.get("mode")
            if mode not in MODES:
                mode = "code-to-document" if saved.get("on") is True else "document-to-code"
            break
        except (OSError, ValueError, AttributeError):
            mode = "document-to-code"
    code_first = mode == "code-to-document"
    policy = saved.get("codePolicy", "deny")
    if policy not in CODE_POLICIES:
        policy = "deny"
    return {"mode": mode, "authority": "code" if code_first else "document", "codePolicy": policy,
            "instructions": (
                "코드→문서 검증 모드. 현재 코드 본문을 기준으로 관련 문서의 설명 문장·예시·제약·구조 표를 직접 수정한다. "
                "자동 생성/apply 명령을 사용하지 않는다. 서버는 문서를 쓰지 않고 불일치를 검사한다. "
                 "코드→문서에서는 문서 변경 승인 대기(A1·A2)와 승인본 기준 역행(W11)을 적용하지 않는다. 문서 반영은 사용자 승인 없이 진행한다. "
                 "미해결에는 선언·값·변경 기록 불일치, 코드 품질·구조·규칙 지적과 문서·파싱 오류를 집계한다. 실제 지적을 제외해 완료로 표시하지 않는다. "
                "지적 목록과 보고서의 미해결 항목을 확인하며 문장마다 실제 코드 근거를 대조하고, "
                "표만 맞추거나 코드로 확인되지 않는 단위·의도·검증 결과를 지어내지 않는다. "
                "현재 코드 수정 정책: " + {"deny": "문서만 수정(코드 편집 금지)", "allow": "코드 수정 허용",
                                      "request": "코드 수정 필요 시 사용자의 수락을 먼저 요청(편집 요청 한 번에만 적용)"}[policy] +
                ". 승인본은 수정하지 않는다. 문서 반영 지적은 현재 코드에 맞춰 문서에서 바로잡는다. 별도 코드 품질 지적을 줄이려고 코드를 삭제하거나 구조 표·진입점을 허위로 추가하지 않는다."
                if code_first else
                "문서→코드 작업 모드. 문서를 기준으로 구현 코드를 수정한다. 기존 문서 검토와 역행 금지 규칙을 따른다."
            ) + " 두 모드 모두 P 계열 파싱·참조 오류와 D 계열 문서 계약 오류는 필수 선행 수정 대상이다. priority의 P/D 필수 선행 오류를 먼저 처리한다. W12는 운영 코드 수정 전 테스트 코드 작성·보완과 기준 실행, 감시·소유·멤버·검사 계층·실행 입구 등록, 요구 수준의 실제 실행(앱 수준은 기존 메인 앱 API 요청·응답 단위 테스트, computer use·별도 복사 앱 금지), 실패 수정·재실행, 현재 계약·입력의 결과 수집과 하네스 재판정까지 끝낼 필수 작업이다. 검사 연결 없음이나 증거 없음으로 남겨놓고 완료를 선언하지 않는다. 검증을 사용자에게 맡겼다고 W12가 해소되지는 않으며, 상태·검사 수준 변경이나 통과 증거 임의 작성으로 대체하지 않는다. P 오류를 문서 반영·제외·상태 변경으로 대체하지 않는다. D 오류를 이유로 운영 코드를 오래된 문서에 맞추지 않는다. 코드 편집 정책이 금지·요청이면 차단 원인과 필요한 편집을 명시하며 수정 없이 완료로 보고하지 않는다."}


def reflection_finding(finding):
    """코드→문서의 실제 대조 지적. 문서→코드 전용 승인 판정은 비적용이다."""
    code = finding.get("code", "") if isinstance(finding, dict) else finding.code
    return bool(code) and code not in ("A1", "A2", "W11")


def task_findings(root, findings):
    """작업 방향에 관계없이 모든 판정 지적을 전달한다."""
    return list(findings)


def set_mode(root, mode, code_policy=None):
    if mode not in MODES:
        raise ValueError("mode는 document-to-code 또는 code-to-document여야 합니다")
    previous = state(root)
    if code_policy is not None and code_policy not in CODE_POLICIES:
        raise ValueError("codePolicy는 deny, allow, request여야 합니다")
    policy = code_policy or previous["codePolicy"]
    if mode == "code-to-document" and (previous["mode"] != mode or not os.path.exists(os.path.join(root, BASELINE_FILE))):
        capture_baseline(root)
    ledger.write_json(root, STATE_FILE, {"mode": mode, "codePolicy": policy})
    return state(root)


def source_hashes(current):
    return {path:entry["sha256"] for path,entry in (current.summaries() if isinstance(current,ledger.SourceIndex) else current.items())
            if not path.startswith("Docs/") and os.path.splitext(path)[1].lower() in SOURCE_EXTENSIONS}


def capture_baseline(root, current=None):
    if current is None:
        current = snapshot.current(root, docmod.load(root))
    baseline = {"epoch": uuid.uuid4().hex, "started": datetime.datetime.now().isoformat(timespec="seconds"),
                "files": source_hashes(current)}
    ledger.write_binary(root, BASELINE_FILE, baseline)
    ledger.write_binary(root, REQUEST_FILE, {"epoch": baseline["epoch"], "requests": []})
    return baseline


def inspect_code(root, current):
    baseline = ledger.read_binary(root, BASELINE_FILE, None)
    if baseline is None:
        baseline = capture_baseline(root, current)
    actual, previous = source_hashes(current), baseline["files"]
    requests = code_requests(root)
    policy = state(root)["codePolicy"]
    changed = []
    for path in sorted(set(actual) | set(previous)):
        if actual.get(path) == previous.get(path):
            continue
        permitted = policy == "allow" or any(r["file"] == path and r["status"] == "used" and
                                             r.get("resultSha") == actual.get(path) for r in requests)
        changed.append({"file": path, "change": "추가" if path not in previous else "삭제" if path not in actual else "수정",
                        "permitted": permitted})
    return {"started": baseline["started"], "tracked": len(previous), "unchanged": not changed,
            "changes": changed, "violations": sum(not c["permitted"] for c in changed),
            "policy": policy, "requests": requests}


def code_requests(root):
    return ledger.read_binary(root, REQUEST_FILE, {"requests": []})["requests"]


def request_code_edit(root, file, reason, edit):
    """정확히 같은 도구 편집 요청에만 한 번 수락을 사용할 수 있다."""
    absolute = os.path.realpath(os.path.join(root, file))
    if os.path.commonpath([os.path.realpath(root), absolute]) != os.path.realpath(root):
        raise ValueError("프로젝트 밖 코드 편집 요청")
    file = os.path.relpath(absolute, root).replace("\\", "/")
    digest = hashlib.sha256(json.dumps(edit, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    with REQUEST_LOCK:
        saved = ledger.read_binary(root, REQUEST_FILE, {"requests": []})
        for entry in saved["requests"]:
            if entry["file"] == file and entry["edit"] == digest and entry["status"] in ("pending", "approved", "rejected"):
                return entry
        entry = {"id": uuid.uuid4().hex, "file": file, "reason": reason, "edit": digest,
                 "status": "pending", "time": datetime.datetime.now().isoformat(timespec="seconds")}
        entry["sourceSha"] = _file_hash(absolute)
        saved["requests"].append(entry)
        ledger.write_binary(root, REQUEST_FILE, saved)
        return entry


def decide_code_edit(root, request_id, accept):
    with REQUEST_LOCK:
        saved = ledger.read_binary(root, REQUEST_FILE, {"requests": []})
        for entry in saved["requests"]:
            if entry["id"] == request_id and entry["status"] == "pending":
                entry["status"] = "approved" if accept else "rejected"
                ledger.write_binary(root, REQUEST_FILE, saved)
                return entry
        raise ValueError("대기 중인 코드 수정 요청을 찾을 수 없습니다")


def consume_code_edit(root, request_id):
    with REQUEST_LOCK:
        mode = state(root)
        if mode["authority"] != "code" or mode["codePolicy"] != "request":
            return False
        saved = ledger.read_binary(root, REQUEST_FILE, {"requests": []})
        for entry in saved["requests"]:
            if entry["id"] == request_id and entry["status"] == "approved":
                if _file_hash(os.path.join(root, entry["file"])) != entry["sourceSha"]:
                    entry["status"] = "stale"
                    ledger.write_binary(root, REQUEST_FILE, saved)
                    return False
                entry["status"] = "used"
                ledger.write_binary(root, REQUEST_FILE, saved)
                return True
        return False


def _file_hash(path):
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as stream:
        return hashlib.sha256(stream.read()).hexdigest()


def record_code_edit(root, file, edit):
    digest = hashlib.sha256(json.dumps(edit, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    with REQUEST_LOCK:
        saved = ledger.read_binary(root, REQUEST_FILE, {"requests": []})
        for entry in reversed(saved["requests"]):
            if entry["file"] == file and entry["edit"] == digest and entry["status"] == "used" and "resultSha" not in entry:
                entry["resultSha"] = _file_hash(os.path.join(root, file))
                ledger.write_binary(root, REQUEST_FILE, saved)
                return True
        return False
