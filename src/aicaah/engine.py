# -*- coding: utf-8 -*-
"""문서·코드 대조 엔진 명령줄(SPEC-36 4.1).

명령: snapshot · recent · diff · check · docs · scaffold · selftest · serve · stop · ask
일반 검사 종료 코드: 0 = 지적 없음, 1 = 경고(W·L), 2 = 문서 형식(D)·파싱(P) 오류.
제품용 agent-hook은 종료 0과 이벤트별 JSON으로 허용·차단을 구분한다."""
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from judging import check as checkmod  # noqa: E402
from output import codemap  # noqa: E402
from storage import diff as diffmod  # noqa: E402
from documents import docs as docmod  # noqa: E402
from parsing import globs, tool_inputs
from parsing import settings
from installation import setup as setupmod, api as libraryapi, release  # noqa: E402
from output import priority
from output import report  # noqa: E402
from documents import review  # noqa: E402
from documents import workflow as workflowmod  # noqa: E402
from serving import server  # noqa: E402
from serving import service  # noqa: E402
from storage import snapshot  # noqa: E402

DEFAULT_ROOT = os.getcwd()


def _load(args):
    """문서 표를 읽고, 단계(--stage)가 있으면 그 단계의 changes 행만 남긴다."""
    if getattr(args, "command", None) != "docs" and review.workflow_state(args.root)["authority"] == "document":
        ds, basis = review.execution_basis(args.root)
    else:
        ds = docmod.load(args.root)
    if getattr(args, "stage", None):
        stages = {x.strip() for x in args.stage.split(",") if x.strip()}
        ds.rows = [r for r in ds.rows if r.kind != "changes" or r.cells["단계"] in stages]
    return ds


def _base(args):
    """기준 스냅숏 매니페스트(--base, 없으면 가장 최근)."""
    return snapshot.load(args.root, getattr(args, "base", None))


def _judge(args, ds):
    """판정. 문서 형식 오류(D)가 있으면 코드 판정을 보류하고 D와 독립 문서 규칙을 돌려준다.
    돌려주는 값: (기준 매니페스트, 지적, 참고, 계층 판정 결과 또는 None)."""
    manifest = _base(args)
    if ds.issues:
        issues = [checkmod.Finding(i.code, i.file, i.line, i.message) for i in ds.issues]
        findings, notes = checkmod.Judge(args.root, ds, None, {}, []).run_docs()
        return manifest, issues + findings, ["문서 형식 오류가 있어 코드 판정은 보류; 문서 규칙은 계속 대조"] + notes, None
    cur = snapshot.current(args.root, ds)
    base_files = manifest["files"] if manifest else None
    changes = diffmod.compare(base_files, cur) if base_files is not None else []
    judge = checkmod.Judge(args.root, ds, base_files, cur, changes, getattr(args, "unity", None), (manifest or {}).get("label"))
    findings, notes = judge.run()
    return manifest, findings, notes, judge.analysis


def cmd_snapshot(args):
    """snapshot: 감시 대상을 백업하고 색인과 그때의 지적 열쇠를 매니페스트에 적는다."""
    ds = _load(args)
    name = snapshot.take(args.root, ds, args.label)
    args.base = name
    manifest, findings, notes, analysis = _judge(args, ds)
    snapshot.record(args.root, name, [checkmod.finding_key(f) for f in findings])
    map_data = codemap.data(analysis, findings, notes, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"))
    map_data["documentLinks"] = codemap.document_links(ds, findings)
    codemap.write(args.root, map_data)
    print("스냅숏 %s — 파일 %d개, 그때 지적 %d건" % (name, len(manifest["files"]), len(findings)))
    return 0


def cmd_recent(args):
    """recent: 감시 파일을 수정 시각 순으로, 기준 스냅숏 대비 상태(새 파일·바뀜·같음·삭제)와 함께."""
    ds = _load(args)
    manifest = _base(args)
    cur = snapshot.current(args.root, ds)
    base_files = manifest["files"] if manifest else {}
    rows = []
    for rel, entry in cur.items():
        b = base_files.get(rel)
        state = "새 파일" if b is None else ("같음" if b["sha256"] == entry["sha256"] else "바뀜")
        if args.changed and state == "같음":
            continue
        rows.append((entry["mtime"], rel, state))
    deleted = sorted(set(base_files) - set(cur))
    rows.sort(reverse=True)
    print("기준 스냅숏: %s · 감시 파일 %d개" % (manifest["name"] if manifest else "없음", len(cur)))
    for mtime, rel, state in rows[:args.limit]:
        print("%s  %-6s %s" % (datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S"), state, rel))
    for rel in deleted:
        print("%-19s  %-6s %s" % ("-", "삭제", rel))
    return 0


def cmd_diff(args):
    """diff: 기준 스냅숏 대비 파일·심볼 변경을 파일별로."""
    ds = _load(args)
    manifest = _base(args)
    if manifest is None:
        print("기준 스냅숏이 없음 — 먼저 snapshot")
        return 2
    changes = diffmod.compare(manifest["files"], snapshot.current(args.root, ds))
    print("기준 스냅숏: %s · 변경 %d건" % (manifest["name"], len(changes)))
    current = None
    for c in sorted(changes, key=lambda x: (x.file, x.line)):
        if c.file != current:
            current = c.file
            print("\n== " + current)
        if c.kind in checkmod.FILE_KINDS:
            print("  %s" % c.kind)
        else:
            print("  L%-5d %-7s %-8s %s.%s | %s%s" % (c.line, c.kind, c.symkind, c.path, c.name, c.signature,
                                                    ("  (" + c.detail + ")") if c.detail else ""))
    return 0


def _hook_input(args):
    """훅 입력(stdin JSON)의 tool_input.file_path를 루트 기준 경로로. 루트 밖이면 None."""
    try:
        data = json.load(sys.stdin)
    except ValueError:
        return None, {}
    path = (data.get("tool_input") or {}).get("file_path") or ""
    if not path:
        return None, data
    try:
        rel = globs.relative(args.root, os.path.abspath(path))
    except ValueError:
        return None, data
    return (None if rel.startswith("..") else rel), data


def _hook_target(args):
    return _hook_input(args)[0]


def _edit_fingerprint(data):
    raw = json.dumps(data.get("tool_input") or {}, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return {"tool": data.get("tool_name", ""), "sha256": hashlib.sha256(raw).hexdigest()}


def _server(args, start=False):
    """감시 서버(server.json). --local이면 쓰지 않는다. start면 없을 때 띄운다."""
    if args.local:
        return None
    return server.ensure(args.root, args.unity) if start else server.alive(args.root)


def _print_pass(p, all_findings=False):
    """패스 결과(판·변경·새 지적·해소) 출력."""
    state = p.get("completion") or report.completion([], rev=p.get("rev"))
    print("판 %d · 전체 %s · 화면 기준 미해결 %s건 · 현재 검사 지적 %d건 · 대조 차단 %s — %s/latest.txt"
          % (p["rev"], "완료" if state["complete"] else "미완료", state["remaining"] if state["remaining"] is not None else "미확정",
             sum(p["counts"].values()), "있음" if state["blocked"] else "없음", snapshot.REPORT_ROOT))
    if state["blocked"]:
        print("해소 확정 불가. 이전 미해결은 재검사 대기이며 현재 지적 수·파일별 0건을 전체 완료 근거로 사용할 수 없습니다.")
    for f in p["new"]:
        print("  새  %s:%d %s %s" % (f["file"], f["line"], f["code"], f["message"]))
    for k in p["resolved"]:
        print(("  해소 후보(미확정)  " if state["blocked"] else "  해소  ") + k)


def _local_pass(args, trigger):
    """제 프로세스에서 패스 한 번. 돌려주는 값: (Service, 패스 JSON)."""
    svc = service.Service(args.root, args.unity)
    r = svc.run(trigger)
    relevant = workflowmod.task_findings(args.root, r.findings)
    resolved = r.resolved if workflowmod.state(args.root)["authority"] != "code" else [k for k in r.resolved if workflowmod.reflection_finding({"code": k.split("|", 1)[0]})]
    assessment = report.completion(relevant, (svc.map_data or {}).get("comparison"), workflowmod.state(args.root)["authority"], r.rev)
    return svc, {"rev": r.rev, "judged": r.judged, "changes": len(r.changes), "docs": r.docs,
                 "new": [service.as_dict(f) for f in workflowmod.task_findings(args.root, r.new)], "resolved": resolved,
                 "counts": {c: sum(1 for f in relevant if f.code == c) for c in {f.code for f in relevant}},
                 "completion": assessment,
                 "exit": service.exit_code(relevant) or (2 if assessment["blocked"] else 1 if not assessment["complete"] else 0)}



def cmd_agent_hook(args):
    """Claude/Codex 도구 입력을 공통 문서 검토·코드 편집 정책에 연결한다."""
    event_name = "PreToolUse"
    try:
        data = json.load(sys.stdin)
        if isinstance(data, dict):
            event_name = data.get("hook_event_name", "PreToolUse")
        client = getattr(args, "client", None) or ("codex" if isinstance(data, dict) and data.get("tool_name") == "apply_patch" else "claude")
        event = tool_inputs.parse_event(args.root, client, data)
        if event["action"] == "finish":
            result = _finish_result(args, data)
            if result["decision"] == "pause":
                output = {"continue":False, "stopReason":result["reason"]}
            else:
                output = {"decision":"block", "reason":result["reason"]} if result["decision"] == "block" else {}
            print(json.dumps(output, ensure_ascii=False))
            return 0
        state = review.workflow_state(args.root)
        def announce(context):
            from storage import ledger
            session = data.get('session_id')
            cache = None
            if isinstance(session, str) and session:
                identity = hashlib.sha256((client+':'+session).encode()).hexdigest()
                cache = ledger.HISTORY_ROOT+'/hook-announcements/'+identity+'.json'
                digest = hashlib.sha256(json.dumps([client,session,state['mode'],state['codePolicy'],state['instructions']],ensure_ascii=False).encode()).hexdigest()
                try:
                    with open(os.path.join(args.root,cache),encoding='utf-8') as stream:
                        if json.load(stream).get('digest') == digest: return
                except (OSError,ValueError,AttributeError):
                    pass
            print(json.dumps({'hookSpecificOutput':{'hookEventName':event['event'],'additionalContext':context}},ensure_ascii=False))
            if cache:
                ledger.write_json(args.root,cache,{'digest':digest})
        if event["action"] == "context":
            waiting, wrong = review.counts(args.root)
            context = state["instructions"] + " 문서 체크 대기 %d건 · 틀림 %d건. 검증 실행 허용은 코드 편집 승인이 아닙니다." % (waiting, wrong)
            announce(context)
            return 0
        if event["action"] in ("read", "verification", "control"):
            return 0
        targets = event["targets"]
        code = [path for path in targets if not path.casefold().startswith("docs/")]
        if event["event"] == "PostToolUse":
            if code and state["authority"] == "document":
                key = hashlib.sha256((str(data.get("session_id", "")) + json.dumps(data["tool_input"], sort_keys=True, ensure_ascii=False)).encode("utf-8")).hexdigest()
                from storage import ledger
                path = os.path.join(args.root, ledger.HISTORY_ROOT, "edit-decisions", key + ".json")
                if not os.path.isfile(path):
                    raise ValueError("사전 편집 판정 기록 없음 — 사전 차단 활성화를 확인하지 못함")
                with open(path, encoding="utf-8") as stream:
                    prior = json.load(stream)
                _, current_basis = review.execution_basis(args.root)
                if current_basis["status"] != "ready" or prior["basisId"] != current_basis["id"]:
                    raise ValueError("편집 중 승인 기준 변경(stale) — 재판정 필요")
                for target in prior["targets"]:
                    full = os.path.join(args.root, target["file"])
                    if os.path.isfile(full):
                        with open(full, encoding="utf-8-sig") as stream:
                            actual = hashlib.sha256(stream.read().encode("utf-8")).hexdigest()
                    else:
                        actual = hashlib.sha256(b"").hexdigest()
                    if target["afterHash"] != actual:
                        raise ValueError("편집 결과가 사전 판정과 다름(stale): " + target["file"])
            regressions = []
            if state["authority"] == "document":
                for path in targets:
                    if path.casefold().startswith("docs/"):
                        regressions.extend(review.guard(args.root,path)["regressions"])
            if not _server(args, start=True):
                raise ValueError("편집 후 하네스 서버 검사 불가. 완료로 처리하지 않습니다.")
            if len(code) == 1 and code[0] != "." and state["authority"] == "code" and state["codePolicy"] == "request":
                done = server.ask(args.root,"POST","/workflow/completed",body={"file":code[0],"edit":_edit_fingerprint(data)})
                if not done or done.get("error"):
                    raise ValueError("편집 결과의 수락 기록 연결 실패")
            result = server.ask(args.root,"POST","/hook?"+urllib.parse.urlencode({'file':targets},doseq=True),timeout=110.0)
            if not result or result.get("error"):
                raise ValueError("편집 후 판정 실패 또는 문서·파싱 오류")
            blocked = result.get("blocked", False)
            if blocked and code and len(code) == len(targets) and state["authority"] == "document":
                # Keep global errors visible. Only a complete, matching set of
                # already scoped contract errors may leave this edit unblocked.
                summary = server.ask(args.root, "POST", "/sync", body={"paths": code}, timeout=110.0)
                errors = result.get("blocking", [])
                known = {(x["code"], x["file"], x["line"], x["message"])
                         for x in current_basis.get("contractErrors", [])}
                affected = set(current_basis.get("blockedFiles", []))
                if (summary and not summary.get("error") and summary.get("rev") == result.get("rev")
                        and (summary.get("executionBasis") or {}).get("id") == prior["basisId"]
                        and affected and "*" not in affected and not affected.intersection(code)
                        and errors and len(errors) == sum(n for c, n in summary.get("counts", {}).items()
                                                         if c.startswith(("D", "P")))
                        and all((x.get("code"), x.get("file"), x.get("line"), x.get("message")) in known
                                for x in errors)):
                    blocked = False
            if blocked:
                raise ValueError("편집 후 판정 실패 또는 문서·파싱 오류")
            if regressions or result.get("newCount",0):
                raise ValueError("편집 후 하네스 지적: 역행 %d건 · 새 지적 %d건. 문서나 코드를 자동 복구하지 않습니다." % (len(regressions),result.get("newCount",0)))
            return 0
        if not code:
            return 0
        if state["authority"] == "document":
            decision = review.edit_decision(args.root, event, data)
            if not decision["allowed"]:
                raise ValueError(decision["reason"])
            key = hashlib.sha256((str(data.get("session_id", "")) + json.dumps(data["tool_input"], sort_keys=True, ensure_ascii=False)).encode("utf-8")).hexdigest()
            from storage import ledger
            ledger.write_json(args.root, ledger.HISTORY_ROOT + "/edit-decisions/" + key + ".json", decision)
            return 0
        if state["codePolicy"] == "deny":
            raise ValueError("코드→문서 작업 모드: 코드 편집 금지.")
        if state["codePolicy"] == "request":
            if len(code) != 1 or code[0] == ".":
                raise ValueError("수락 요청 모드에서는 정확한 단일 코드 파일 편집이 필요합니다. 다중 승인 일부 소비와 대상 불명 셸은 차단합니다.")
            if not _server(args, start=True):
                raise ValueError("코드 수정 수락 요청을 기록할 서버 없음")
            values = data["tool_input"]
            reason = values.get("description") or ("%s 요청: %s" % (data["tool_name"],code[0]))
            request = server.ask(args.root,"POST","/workflow/request",body={"file":code[0],"reason":reason,"edit":_edit_fingerprint(data)})
            if not request or request.get("error"):
                raise ValueError("코드 수정 수락 요청 실패")
            if request.get("status") != "approved":
                raise ValueError("코드 수정 사용자 수락 필요: %s — 요청 %s" % (code[0],request.get("id","")))
            decision = server.ask(args.root,"POST","/workflow/consume?id="+request["id"])
            if not decision or not decision.get("allowed"):
                raise ValueError("코드 수정 수락 만료 또는 이미 사용됨")
        announce(state['instructions'])
        return 0
    except Exception as error:
        reason = "하네스 차단: %s — 실행 허용으로 처리하지 않습니다." % error
        if getattr(args, "review", False):
            sys.stderr.write(reason + "\n")
            return 2
        # PowerShell converts a child exit 2 to shell exit 1. Deliver the
        # blocking decision as successful protocol JSON instead of an exit code.
        if event_name in ("PostToolUse", "Stop", "UserPromptSubmit"):
            output = {"decision":"block", "reason":reason}
        elif event_name == "SessionStart":
            output = {"continue":False, "stopReason":reason}
        else:
            output = {"hookSpecificOutput":{"hookEventName":"PreToolUse",
                      "permissionDecision":"deny", "permissionDecisionReason":reason}}
        print(json.dumps(output, ensure_ascii=False))
        return 0


def cmd_check(args):
    """check: 패스를 돌고 장부 대비 새 지적·해소를 낸다(2.10). 감시 서버가 떠 있으면 서버에 묻는다(2.11).
    --stage·--base는 장부를 거치지 않는 단계 판정이다. --hook은 받는 쪽 hook이 아직 받지 않은 새 지적만, --gate는 관문.
    --review는 편집 전 훅(2.12): 편집 대상이 문서가 아니고 체크 대기·틀림 문서 변경이 있으면 막는다."""
    if args.guard_doc:
        if workflowmod.state(args.root)["authority"] == "code":
            return 0
        target = _hook_target(args)
        if target is None or not target.startswith("Docs/"):
            return 0
        result = review.guard(args.root, target)
        if not result["regressions"]:
            return 0
        meta = server.alive(args.root)
        where = ("http://127.0.0.1:%d/" % meta["port"]) if meta else "engine.py ask status"
        items = "; ".join("%s %s(%s→%s)" % (kind, p["signature"], sa, sw) for kind, f, p, sa, sw in result["regressions"][:8])
        sys.stderr.write("역행 문서 지적(SPEC-36 2.12 E19): %s — 코드가 문서 승인보다 앞선 수정 %d건: %s. %s 의 지적과 검토 상태를 확인해 바로잡으세요. 하네스는 문서를 자동 복구하지 않습니다.\n"
                         % (target, len(result["regressions"]), items, where))
        return 2
    if args.review:
        return cmd_agent_hook(args)
    if args.stage or args.base:
        ds = _load(args)
        manifest, findings, notes, analysis = _judge(args, ds)
        data = report.build(args.root, "check", manifest["name"] if manifest else None, ds, findings, notes)
        data["priority"] = priority.build(findings, workflowmod.state(args.root)["authority"])
        body = report.write(args.root, data)
        if not args.quiet:
            sys.stdout.write(body)
        else:
            print("한정 대조 지적 %d건 — 전체 완료 판정 아님 — %s/latest.txt" % (len(findings), snapshot.REPORT_ROOT))
        return service.exit_code(findings)
    if args.hook:
        target, hook_data = _hook_input(args)
        if target is None and hook_data.get("tool_name") in ("Bash", "PowerShell"):
            target = "."
        if target is None:
            return 0
        meta = _server(args, start=True)
        if meta is not None and not target.startswith("Docs/") and review.workflow_state(args.root)["codePolicy"] == "request":
            server.ask(args.root, "POST", "/workflow/completed", body={"file": target, "edit": _edit_fingerprint(hook_data)})
        if meta is not None:
            got = server.ask(args.root, "POST", "/hook?file=" + urllib.parse.quote(target), timeout=110.0)
            if got is None or got.get("error"):
                sys.stderr.write("하네스 훅 입구 실패: %s. 서버 버전과 상태를 확인하세요.\n" % ((got or {}).get("error") or "응답 없음"))
                return 2
            rev, new = got["rev"], got["new"]
            new_count, resolved_count = got["newCount"], got["resolvedCount"]
            if got.get("blocked"):
                lines = ["하네스 판정 차단(판 %d): 미해결 수는 확정되지 않았습니다. 먼저 문서·파싱 오류를 수정하세요." % rev]
                lines.extend("  %s:%d %s %s" % (f["file"], f["line"], f["code"], f["message"]) for f in got.get("blocking", []))
                sys.stderr.write("\n".join(lines) + "\n")
                return 2
        elif args.local:
            svc, _ = _local_pass(args, "훅")
            rev, new_f, resolved = svc.since("hook")
            new = [service.as_dict(f) for f in new_f]
            new_count, resolved_count = len(new), len(resolved)
        else:
            sys.stderr.write("하네스 서버가 없어 편집 후 검사를 완료하지 못했습니다.\n")
            return 2
        if not new:
            return 0
        lines = ["문서·코드 대조(판 %d): 새 지적 %d건 · 해소 %d건 (편집: %s, 전체 %s/latest.txt)"
                 % (rev, new_count, resolved_count, target, snapshot.REPORT_ROOT)]
        for f in new[:40]:
            lines.append("  %s:%d %s %s" % (f["file"], f["line"], f["code"], f["message"]))
        sys.stderr.write("\n".join(lines) + "\n")
        return 2
    if args.gate:
        purpose = getattr(args, "purpose", "completion")
        meta = _server(args)
        got = server.ask(args.root, "POST", "/gate?purpose=" + purpose) if meta is not None else None
        if got is None:
            svc, _ = _local_pass(args, "관문")
            relevant = workflowmod.task_findings(args.root, svc.last.findings)
            fresh_f, pending, told = service.gate(relevant, snapshot.load(args.root), svc.ds,
                                                  svc.meta.places if svc.meta is not None else None, purpose=purpose)
            if purpose == "completion" and workflowmod.state(args.root)["authority"] == "code":
                fresh_f, pending, told = relevant, 0, 0
            got = {"rev": svc.last.rev, "purpose": purpose, "fresh": [service.as_dict(f) for f in fresh_f],
                   "reported": [service.as_dict(f) for f in relevant] if purpose == "verification" else [],
                   "pending": pending, "told": told, "total": len(relevant),
                   "exit": service.exit_code(fresh_f), "base": svc.last.base}
            got["completion"] = report.completion(relevant, (svc.map_data or {}).get("comparison"), workflowmod.state(args.root)["authority"], svc.last.rev)
            if purpose == "completion" and not got["completion"]["complete"]:
                got["exit"] = got["exit"] or (2 if got["completion"]["blocked"] else 1)
        if got.get("error") or got.get("purpose") != purpose:
            sys.stderr.write("관문 목적 응답 오류: 서버를 갱신하고 요청 목적을 확인하세요. %s\n" % got.get("error", "purpose 불일치"))
            return 2
        if purpose == "verification":
            print("검증 실행 허용(판 %d): 지적 %d건은 보고 유지, 완료·성공 판정 아님 — %s/latest.txt"
                  % (got["rev"], got["total"], snapshot.REPORT_ROOT))
            shown = [] if args.quiet else got.get("reported", [])
        else:
            assessment = got.get("completion") or report.completion([], rev=got["rev"])
            print("전체 완료 판정: %s · 미해결 %s건 · 대조 차단 %s"
                  % ("완료" if assessment["complete"] else "미완료", assessment["remaining"], assessment["blocked"]))
            print("완료 관문(판 %d): 기준 스냅숏 %s 대비 막을 지적 %d건(전체 %d건, 그 단계 미완성 W8 %d건 — 막음, 다른 문서 미완성 W8 %d건 — 알리기만) — %s/latest.txt"
                  % (got["rev"], got["base"] or "없음", len(got["fresh"]), got["total"], got["pending"], got.get("told", 0), snapshot.REPORT_ROOT))
            shown = got["fresh"]
        for f in shown[:40]:
            print("  %s:%d %s %s" % (f["file"], f["line"], f["code"], f["message"]))
        if purpose == "completion":
            assessment = got.get("completion") or report.completion([], rev=got.get("rev"))
            return got["exit"] or (2 if assessment["blocked"] else 1 if not assessment["complete"] else 0)
        return got["exit"]
    meta = _server(args)
    got = server.ask(args.root, "POST", "/sync") if meta is not None else None
    if got is None:
        _, got = _local_pass(args, "check")
    _print_pass(got)
    if args.all:
        with open(os.path.join(args.root, snapshot.REPORT_ROOT, "latest.txt"), encoding="utf-8") as f:
            sys.stdout.write(f.read())
    print("통합 지도: %s" % (("http://127.0.0.1:%d/" % meta["port"]) if meta else snapshot.REPORT_ROOT + "/map.html"))
    assessment = got.get("completion") or report.completion([], rev=got.get("rev"))
    return got["exit"] or (2 if assessment["blocked"] else 1 if not assessment["complete"] else 0)


def cmd_serve(args):
    """serve: 감시 서버를 이 프로세스에서 띄운다(2.11). 이미 떠 있으면 알리고 끝낸다."""
    meta = server.alive(args.root)
    if meta is not None:
        print("감시 서버가 이미 떠 있음: pid %d · http://127.0.0.1:%d/" % (meta["pid"], meta["port"]))
        return 0
    # 실시간 편집 앱의 입력을 검사 작업이 선점하지 않게 한다. Windows는 자식
    # 프로세스가 우선순위 클래스를 상속하므로 참조 추출기도 유휴 급에서 돈다.
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GetCurrentProcess.restype = ctypes.c_void_p
            kernel32.SetPriorityClass.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
            kernel32.SetPriorityClass.restype = ctypes.c_int
            if not kernel32.SetPriorityClass(kernel32.GetCurrentProcess(), 0x00000040):
                raise ctypes.WinError(ctypes.get_last_error())
        except (AttributeError, OSError) as error:
            sys.stderr.write("검사 서버 우선순위를 낮추지 못함: %s\n" % error)
    server.Server(args.root, args.unity).serve()
    return 0


def cmd_stop(args):
    """stop: 떠 있는 감시 서버를 멈춘다."""
    got = server.ask(args.root, "POST", "/stop", timeout=5.0) if server.alive(args.root) else None
    print("감시 서버를 멈춤" if got else "떠 있는 감시 서버 없음")
    return 0


def cmd_ask(args):
    """ask: 감시 서버에 묻는다(없으면 띄운다). status · new(받는 쪽 worker) · file 경로 · review(틀림 체크와 이유)."""
    meta = server.ensure(args.root, args.unity)
    if meta is None:
        print("감시 서버에 닿지 못함 — %s" % server.LOG_FILE)
        return 2
    if args.what == "status":
        got = server.ask(args.root, "GET", "/status")
        print(json.dumps(got, ensure_ascii=False, indent=1))
        print("지도: http://127.0.0.1:%d/" % meta["port"])
    elif args.what == "new":
        server.ask(args.root, "POST", "/sync")
        got = server.ask(args.root, "GET", "/since?client=worker")
        assessment = got.get("completion") or report.completion([], rev=got["rev"])
        _print_pass(dict(got, changes=0, counts={"observed": assessment["observedFindings"]}, completion=assessment))
    elif args.what == "review":
        got = server.ask(args.root, "GET", "/review")
        items = got["units"]
        wrong = [u for u in items if u["verdict"] == "틀림"]
        print("체크 대기 %d건 · 틀림 %d건 — 지도: http://127.0.0.1:%d/#c:" % (len(items) - len(wrong), len(wrong), meta["port"]))
        for u in wrong:
            print("  틀림 %s:%d [%s · %s] %s" % (u["doc"], u["new_line"], u["kind"], u["plan"].get("action", "글"), u["heading"]))
            if u["old"]:
                print("      - " + u["old"])
            if u["new"]:
                print("      + " + u["new"])
            print("      이유: " + (u["memo"] or "-"))
    else:
        rel = (args.path or "").replace("\\", "/")
        got = server.ask(args.root, "GET", "/findings?file=" + urllib.parse.quote(rel))
        print("%s 선택 파일 지적 %d건 — 전체 완료 판정 아님" % (rel, len(got["findings"])))
        assessment = got.get("completion") or report.completion([], rev=got.get("rev"))
        print("전체 미해결 %s건 · 대조 차단 %s" % (assessment["remaining"], assessment["blocked"]))
        for f in got["findings"]:
            print("  L%d %s %s" % (f["line"], f["code"], f["message"]))
    return 0


def cmd_docs(args):
    """docs: 문서 표 형식(D)과 문서 대상 규칙(문서경로·문서내용)만."""
    ds = _load(args)
    judge = checkmod.Judge(args.root, ds, None, {}, [])
    findings, notes = judge.run_docs()
    findings = findings + [checkmod.Finding(i.code, i.file, i.line, i.message) for i in ds.issues]
    data = report.build(args.root, "docs", None, ds, findings, notes)
    sys.stdout.write(report.text(data))
    return service.exit_code(findings)


def _cell(text):
    """표 칸 값: 백틱으로 감싸고 칸 구분 글자(세로 막대)를 역슬래시로 막는다."""
    return "`%s`" % text.replace("|", "\\|")


def cmd_scaffold(args):
    """scaffold: 파일의 현재 심볼을 members·constants 표 행으로 출력한다(사람이 상태·설명을 검토해 문서에 넣는다)."""
    for rel in args.files:
        rel = rel.replace("\\", "/")
        entry = snapshot.index_file(args.root, rel, "심볼")
        if entry["error"]:
            print("파싱 실패 %s: %s" % (rel, entry["error"]))
            return 2
        syms = checkmod.symbols(entry)
        print("| 파일 | 형 | 종류 | 시그니처 | 상태 | 설명 |")
        print("|---|---|---|---|---|---|")
        for s in syms:
            owner = "-" if s.path == "-" else _cell(s.path)
            print("| %s | %s | %s | %s | %s | - |" % (_cell(rel), owner, s.kind, _cell(s.signature), args.status))
        consts = [s for s in syms if s.kind == "const" or (s.kind == "field" and "static" in s.modifiers
                                                             and "readonly" in s.modifiers)]
        if consts:
            print()
            print("| 파일 | 형 | 이름 | 형식 | 값 | 단위 |")
            print("|---|---|---|---|---|---|")
            for s in consts:
                owner = "-" if s.path == "-" else _cell(s.path)
                value = _cell(s.value) if s.value else "-"
                print("| %s | %s | %s | %s | %s | - |" % (_cell(rel), owner, s.name, _cell(s.type), value))
        print()
    return 0


def cmd_selftest(args):
    """selftest: 엔진 자체 시험. 시험 단계를 가져오지 않고 따로 띄운다(역방향 참조 없음, SPEC-36 3.3)."""
    if getattr(args, 'portable', False) or not os.path.isfile(os.path.join(HERE, 'selftest', 'selftest.py')):
        if getattr(args, 'case', []):
            print('Project-specific --case selection is available only in the development checkout', file=sys.stderr)
            return 2
        command = [sys.executable, '-X', 'utf8', os.path.join(HERE, 'selftest', 'test_public.py')]
        if getattr(args, 'list', False): command.append('--list')
        return subprocess.run(command, cwd=args.root, timeout=120).returncode
    command = [sys.executable, '-u', os.path.join(HERE, 'selftest', 'selftest.py')]
    if getattr(args, 'list', False): command.append('--list')
    for case in getattr(args, 'case', []): command.extend(['--case', case])
    limit = 120 if getattr(args, 'case', []) or getattr(args, 'list', False) else 600
    if getattr(args,'list',False):
        return subprocess.run(command,cwd=args.root,env=dict(os.environ,SPEC_CONFORMANCE_PROJECT_ROOT=args.root),timeout=limit).returncode
    import threading
    import uuid
    from storage import ledger
    run_id = uuid.uuid4().hex
    run_root = ledger.HISTORY_ROOT+'/selftest-runs/'+run_id
    raw_rel = run_root+'/output.jsonl'
    os.makedirs(os.path.join(args.root,run_root),exist_ok=True)
    rows = []; before = {}; preparation_error = None
    try:
        ds = docmod.load(args.root)
        chosen = set(getattr(args,'case',[]))
        rows = [r for r in ds.of('behaviors') if r.cells['검사 수준']=='정적' and r.cells['증거'] not in ('','-')
                and all(t.startswith('SpecConformance/selftest/selftest.py#') for t in globs.split(r.cells['검사 연결']))
                and (not chosen or {t.partition('#')[2] for t in globs.split(r.cells['검사 연결'])} <= chosen)]
        if rows:
            judge = checkmod.Judge(args.root,ds,None,snapshot.current(args.root,ds),[])
            before = {r.cells['동작 ID']:judge.behavior_inputs(r) for r in rows}
    except Exception as error:
        preparation_error = str(error)
    process = subprocess.Popen(command, cwd=args.root,
        env=dict(os.environ, SPEC_CONFORMANCE_PROJECT_ROOT=args.root,SPEC_SELFTEST_RUN_ID=run_id),
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
        start_new_session=os.name != 'nt',
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
    def forward():
        with open(os.path.join(args.root,raw_rel),'wb') as output:
            for line in iter(process.stdout.readline,b''):
                output.write(line); output.flush()
                sys.stdout.write(line.decode('utf-8',errors='replace'));sys.stdout.flush()
    pump = threading.Thread(target=forward,daemon=True);pump.start()
    aborted = None
    try:
        code = process.wait(timeout=limit)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        if os.name == 'nt':
            subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        else:
            import signal
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        print(json.dumps({'event':'selftest-aborted','reason':type(error).__name__,'limitSeconds':limit,'complete':False}),flush=True)
        code = 124 if isinstance(error,subprocess.TimeoutExpired) else 130
        aborted = type(error).__name__
    pump.join(timeout=5)
    with open(os.path.join(args.root,raw_rel),'rb') as output: raw=output.read()
    execution = {'transport':'selftest-process','runId':run_id,'processId':process.pid,'exitCode':code,
                 'rawOutput':{'path':raw_rel,'sha256':hashlib.sha256(raw).hexdigest()},'aborted':aborted}
    published = []; evidence_error = preparation_error
    try:
        packets = [json.loads(line) for line in raw.decode('utf-8').splitlines() if line.startswith('{')]
        summary = next((p for p in reversed(packets) if p.get('event')=='summary'),None)
        if code==0 and summary and summary.get('runId')==run_id and not summary['failed'] and not pump.is_alive() and rows and not preparation_error:
            after_ds = docmod.load(args.root)
            judge = checkmod.Judge(args.root,after_ds,None,snapshot.current(args.root,after_ds),[])
            actual = {r['case'] for r in summary['results'] if r['passed']}
            current = {r.cells['동작 ID']:r for r in after_ds.of('behaviors')}
            for row in rows:
                c = row.cells; identity = c['동작 ID']
                if identity not in current or c != current[identity].cells: continue
                boundary = judge.behavior_inputs(row)
                tests = globs.split(c['검사 연결'])
                if boundary != before[identity] or not {t.partition('#')[2] for t in tests} <= actual: continue
                contract = {k:v for k,v in c.items() if k not in ('상태','증거')}
                target = c['증거']
                if os.path.isabs(target) or not target.replace('\\','/').startswith('Docs/98_History/') or '..' in target.replace('\\','/').split('/'):
                    raise ValueError('static evidence must be an owned Docs/98_History path')
                proof = dict(boundary,schemaVersion=2,behavior=identity,level='정적',passed=True,tests=tests,
                    contract=hashlib.sha256(json.dumps(contract,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                    execution=dict(execution,inputsBefore=before[identity],inputsAfter=boundary))
                ledger.write_json(args.root,target,proof);published.append(identity)
    except Exception as error:
        evidence_error = str(error)
    ledger.write_json(args.root,run_root+'/execution.json',dict(execution,evidencePublished=published,evidenceError=evidence_error))
    print(json.dumps({'event':'selftest-evidence','runId':run_id,'published':published,'error':evidence_error,'rawOutput':raw_rel},ensure_ascii=False),flush=True)
    return code


def cmd_mode(args):
    """검증 방향만 전환한다. 문서를 생성하거나 갱신하지 않는다."""
    try:
        if args.local:
            got = review.set_workflow(args.root, args.mode or review.workflow_state(args.root)["mode"], args.code_policy) if args.mode or args.code_policy else review.workflow_state(args.root)
        else:
            if not _server(args, start=True):
                raise ValueError("감시 서버를 시작할 수 없습니다")
            params = {"mode": args.mode or review.workflow_state(args.root)["mode"]}
            if args.code_policy:
                params["codePolicy"] = args.code_policy
            path = "/workflow?" + urllib.parse.urlencode(params) if args.mode or args.code_policy else "/workflow"
            got = server.ask(args.root, "POST" if args.mode or args.code_policy else "GET", path)
            if got is None:
                raise ValueError("감시 서버 모드 요청 실패")
            if got.get("error"):
                raise ValueError(got["error"])
        print(json.dumps(got, ensure_ascii=False, indent=2))
        return 0
    except ValueError as error:
        sys.stderr.write(str(error) + "\n")
        return 2


def _stop_pause_reason(args, payload):
    """실제 중지 입력과 문서 검토 대기를 완료 판정 전에 확인한다."""
    transcript = payload.get("transcript_path")
    client = getattr(args, "client", None)
    if client in ("codex", "claude") and transcript:
        try:
            with open(transcript, "rb") as stream:
                header = json.loads(stream.readline())
                if (not payload.get("session_id") or (client == "codex" and
                        (header.get("type") != "session_meta" or header.get("payload", {}).get("id") != payload["session_id"]))):
                    raise ValueError("세션과 중지 기록이 일치하지 않음")
                stream.seek(0, os.SEEK_END)
                offset = max(0, stream.tell() - 8 * 1024 * 1024)
                stream.seek(offset)
                if offset:
                    stream.readline()
                lines = stream.read().splitlines()
            found = False
            for line in reversed(lines):
                if not line.strip():
                    continue
                row = json.loads(line)
                if client == "claude":
                    if row.get("type") != "user" or row.get("isMeta") or row.get("isSidechain"):
                        continue
                    if row.get("sessionId") != payload["session_id"]:
                        raise ValueError("세션과 중지 기록이 일치하지 않음")
                    native = row.get("message", {})
                    if native.get("role") != "user":
                        continue
                    content = native.get("content", [])
                    if isinstance(content, str): content = [{"type":"text", "text":content}]
                    content = [{"type":"input_text", "text":p["text"]} for p in content if p.get("type") == "text"]
                    row = {"type":"response_item", "payload":{"type":"message", "role":"user", "content":content,
                        "internal_chat_message_metadata_passthrough":{"content_item_kinds":["user.text"]}}}
                data = row.get("payload", {})
                if row.get("type") == "event_msg" and data.get("type") == "turn_aborted" and data.get("reason") == "interrupted":
                    return "사용자 중지 — 자동 훅과 화면 문맥으로 작업을 재개하지 않습니다. 새 사용자 입력을 기다립니다."
                if row.get("type") != "response_item" or data.get("type") != "message" or data.get("role") != "user":
                    continue
                kinds = data.get("internal_chat_message_metadata_passthrough", {}).get("content_item_kinds", [])
                if "user.text" not in kinds:
                    continue
                message = "\n".join(part.get("text", "") for part in data.get("content", []) if part.get("type") == "input_text").strip()
                if not message or message.startswith(("<hook_prompt", "<external_codex_apps_open_page", "<in-app-browser-context")):
                    continue
                if message.startswith("<send_user_message_question_reply>"):
                    answers = json.loads(message.split(">", 1)[1].rsplit("</", 1)[0])
                    controls = [answer["answer"].strip().casefold() for answer in answers]
                else:
                    controls = [message.casefold().rstrip(".! ")]
                if any(control in ('중지','작업 중지','중지 유지') or
                       (re.match(r'^(?:(?:지금|일단|제발)\s+)*(?:멈춰|그만해|중지해)(?:[\s.!?,]|$)',control)
                        and not re.search(r'(?:말고|말아|하지\s*마|라는|이라고|예문)',control)) or
                       re.fullmatch(r'(?:please\s+)?(?:stop|cancel)(?:\s+(?:please|now|the\s+task|working))*[.! ]*',control)
                       for control in controls):
                    return "사용자 중지 — 새 사용자 입력 전까지 자동 작업을 재개하지 않습니다."
                found = True
                break
            if not found:
                raise ValueError("최근 기록에서 실제 사용자 입력을 확인할 수 없음")
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
            return "중지 기록 확인 필요 — 자동 재개를 보류합니다: " + str(error)
    if review.workflow_state(args.root)["authority"] == "document":
        waiting, wrong = review.counts(args.root)
        ds, basis = review.execution_basis(args.root)
        if basis["status"] != "ready":
            return "승인 입력 진행 불가 — " + basis["reason"]
        plans = review.implementation_plans(ds, snapshot.current(args.root, ds), args.root, basis)
        if "*" in basis.get("blockedFiles", []):
            return "승인 계약 영향 범위 판정 불가 — " + basis["reason"]
        plans = [p for p in plans if p["plan"]["file"] not in basis.get("blockedFiles", [])]
        if (waiting or wrong) and not plans:
            return "문서 검토 대기 %d건 · 틀림 %d건 — 실행할 승인 작업 없음. 사용자 검토를 기다립니다." % (waiting, wrong)
    return None


def _finish_result(args, payload):
    """직접 조회와 실제 Stop이 같은 최신 전체 판정으로 종료 여부를 결정한다."""
    try:
        if not isinstance(payload, dict):
            raise ValueError("final report JSON object required")
        pause_reason = _stop_pause_reason(args, payload)
        if pause_reason:
            # A paused response is not project completion. Do not run a full
            # sync or rewrite findings/approvals while the user is stopping.
            remaining, revision = None, None
            try:
                with open(os.path.join(args.root, snapshot.REPORT_ROOT, "latest.json"), encoding="utf-8") as stream:
                    last = json.load(stream)
                remaining = last.get("completion", {}).get("remaining")
                revision = last.get("rev")
                if type(remaining) is not int or remaining < 0:
                    remaining = None
            except (OSError, ValueError, TypeError, AttributeError):
                pass
            return {"decision":"pause", "remaining":remaining,
                    "completion":{"rev":revision, "scope":"whole-project", "remaining":remaining,
                                  "complete":False, "resolvedConfirmed":False, "stateCurrent":False, "decision":"block"},
                    "reason":pause_reason + " 마지막 판 %s · 미해결 %s. 전체 완료가 아닙니다." %
                             (revision if revision is not None else "확인 불가", str(remaining) + "건" if remaining is not None else "확인 불가")}
        message = payload.get("last_assistant_message", "")
        if message is None:
            message = ""
        if not isinstance(message, str):
            raise ValueError("last_assistant_message must be text")
        meta = _server(args)
        from storage import ledger
        policy = workflowmod.state(args.root)
        session = payload.get('session_id')
        repeat_record = None; previous = None; observation = None
        if isinstance(session,str) and session:
            identity = hashlib.sha256((str(getattr(args,'client',''))+':'+session).encode()).hexdigest()
            repeat_record = ledger.HISTORY_ROOT+'/stop-decisions/'+identity+'.json'
            try:
                with open(os.path.join(args.root,repeat_record),encoding='utf-8') as stream: previous=json.load(stream)
            except (OSError,ValueError): pass
            if meta is not None and payload.get('stop_hook_active'):
                observation = server.ask(args.root,'GET','/status?inputs=1',timeout=15.0)
                if (isinstance(previous,dict) and isinstance(observation,dict) and observation.get('inputsCurrent')
                        and previous.get('inputFingerprint') == observation.get('inputFingerprint')
                        and previous.get('mode') == policy['mode'] and previous.get('codePolicy') == policy['codePolicy']
                        and previous.get('rev') == observation.get('rev')):
                    assessment = dict(observation.get('completion') or {},complete=False,stateCurrent=True)
                    return {'decision':'pause','remaining':assessment.get('remaining'),'completion':assessment,
                            'reason':'같은 입력·판·작업에서 진전 없음 — 자동 반복을 멈춥니다. 미해결 %s건. 전체 완료가 아닙니다.' % assessment.get('remaining')}
        if meta is not None:
            result = server.ask(args.root, "POST", "/sync", timeout=110.0)
            if not isinstance(result, dict) or result.get("error"):
                raise ValueError("최신 대조 실패")
        else:
            _, result = _local_pass(args, "최종 보고 검사")
        with open(os.path.join(args.root, snapshot.REPORT_ROOT, "latest.json"), encoding="utf-8") as stream:
            latest = json.load(stream)
        if not isinstance(latest, dict) or not isinstance(latest.get("findings"), list):
            raise ValueError("전체 보고서 객체와 지적 목록 필요")
        if not isinstance(result, dict) or type(result.get("rev")) is not int or result["rev"] != latest.get("rev"):
            raise ValueError("최신 대조와 보고서의 판이 다름; 오래된 0건으로 종료할 수 없음")
        findings = latest["findings"]
        unfinished = any(word in message for word in (
            "않았습니다", "못했습니다", "미완료", "남아 있습니다", "남았습니다",
            "아직", "다음에", "추후", "not completed", "not finished"))
        assessment = latest.get("completion")
        if (not isinstance(assessment, dict) or assessment.get("rev") != latest.get("rev")
                or assessment.get("scope") != "whole-project" or assessment.get("remaining") is None):
            assessment = report.completion(findings, rev=latest.get("rev"))
        else:
            saved = assessment
            pending = saved.get("pendingFindings", [])
            authority = workflowmod.state(args.root)["authority"]
            assessment = report.completion(findings, {"remaining": len(pending), "items": pending, "blocked": saved["blocked"]},
                                           authority, latest.get("rev"))
            if saved.get("authority") != authority or saved["remaining"] != assessment["remaining"]:
                assessment.update(remaining=None, blocked=True, resolvedConfirmed=False, complete=False, decision="block")
        blocked = not assessment["complete"] or unfinished
        ranking = latest.get('priority') or priority.build([checkmod.Finding(f['code'],f['file'],f['line'],f['message'],rule=f.get('rule','')) for f in findings],policy['authority'])
        work = priority.listing(ranking, 5, groups=True)
        basis_id = None
        if workflowmod.state(args.root)["authority"] == "document":
            ds, basis = review.execution_basis(args.root)
            if basis["status"] != "ready":
                return {"decision": "pause", "completion": assessment, "remaining": assessment["remaining"],
                        "reason": "승인 입력 진행 불가 — " + basis["reason"]}
            plans = review.implementation_plans(ds, snapshot.current(args.root, ds), args.root, basis)
            plans = [p for p in plans if "*" not in basis.get("blockedFiles", [])
                     and p["plan"]["file"] not in basis.get("blockedFiles", [])]
            files = {p["plan"]["file"] for p in plans}
            sources = {(s["doc"], s["line"]) for p in plans for s in p["sources"]}
            eligible = [f for f in latest.get("approvedFindings", findings)
                        if f["file"] in files or (f["file"], f["line"]) in sources]
            if blocked and not eligible:
                return {"decision": "pause", "remaining": assessment["remaining"], "completion": assessment,
                        "reason": "실행 가능한 승인 작업 없음 — 검토·진행 불가 사유 확인 필요. 전체 완료가 아닙니다."}
            approved_priority = priority.build([checkmod.Finding(f["code"], f["file"], f["line"], f["message"], rule=f.get("rule", "")) for f in eligible], "document")
            work = priority.listing(approved_priority, 5, groups=True)
            basis_id = basis['id']
        if blocked and repeat_record:
            state = {'basisId':basis_id,'rev':latest['rev'],'next':[g['id'] for g in work['groups']],
                     'mode':policy['mode'],'codePolicy':policy['codePolicy']}
            if payload.get('stop_hook_active') and isinstance(previous,dict) and all(previous.get(k)==v for k,v in state.items()):
                return {'decision':'pause','remaining':assessment['remaining'],'completion':dict(assessment,complete=False),
                        'reason':'같은 입력·판·작업에서 진전 없음 — 자동 반복을 멈춥니다. 미해결 %s건. 전체 완료가 아닙니다.' % assessment['remaining']}
            if meta is not None:
                observation = server.ask(args.root,'GET','/status?inputs=1',timeout=15.0)
                if isinstance(observation,dict) and observation.get('inputsCurrent') and observation.get('rev')==latest['rev']:
                    state['inputFingerprint'] = observation.get('inputFingerprint')
            ledger.write_json(args.root,repeat_record,state)
        output = {"remaining": assessment["remaining"], "completion": assessment,
                  "decision": "block" if blocked else "allow", "incompleteReport": unfinished,
                  "next": work["groups"], "priorityTotal": work['uniqueFindings'], 'groupTotal':work['groupCount'],
                  "detailRequest": work["detailRequest"], "instruction": work["instruction"]}
        if blocked:
            concise = [{key: item[key] for key in ("id", "code", "file", "line", "behaviorId", "uniqueFindings", "occurrences", "mustFix", "blocksResolution") if key in item}
                       for item in output["next"]]
            prefix = ('하네스 판 %s · 전체 미해결 %s건 · 원 발생 %s건 · 고유 지적 %s건 · 작업 묶음 %s개. '
                      '사용자 중지 우선. 지적 숨김 없이 실제 수정 후 재판정한다. ' %
                      (assessment['rev'],assessment['remaining'],work['occurrences'],work['uniqueFindings'],work['groupCount'])
                      + work['instruction']+' ')
            while True:
                reason = prefix+json.dumps(concise,ensure_ascii=False,separators=(',',':'))+' 다음: priority --groups --offset '+str(len(concise))+' --limit 5'
                if len(reason.encode('utf-8')) <= 6144 or not concise: break
                concise.pop()
            output.update(decision='block',reason=reason)
        return output
    except Exception as error:
        # This is the external Stop boundary: checker faults must become a
        # blocking hook response, never an exit-1 warning that permits stopping.
        return {"decision": "block", "reason":
                "최종 보고 검사를 완료하지 못했다. 검사 오류를 해결하고 작업을 계속한다: " + str(error)}


def cmd_finish(args):
    """공통 종료 판정을 조회한다. 자동 강제 연결은 agent-hook의 Stop이 담당한다."""
    try:
        payload = json.load(sys.stdin)
    except (ValueError, TypeError) as error:
        print(json.dumps({"decision":"block", "reason":"최종 보고 입력 오류: " + str(error)},ensure_ascii=False))
        return 0
    print(json.dumps(_finish_result(args, payload), ensure_ascii=False))
    return 0


def cmd_priority(args):
    """저장된 최신 판정의 공통 원인 순위만 조회한다. 재검사하지 않는다."""
    with open(os.path.join(args.root, snapshot.REPORT_ROOT, "latest.json"), encoding="utf-8") as stream:
        latest = json.load(stream)
    ranking = latest.get("priority")
    if ranking is None:
        print(json.dumps({"error": "최신 판정에 순위 자료가 없습니다. 변경 반영 패스가 필요합니다."}, ensure_ascii=False))
        return 2
    if args.id:
        if server.alive(args.root) is None:
            print(json.dumps({"error":"SQL 상세 조회는 완료된 메타데이터를 가진 서버에 요청해야 합니다."}, ensure_ascii=False))
            return 2
        output = server.ask(args.root, "GET", "/priority?id=" + urllib.parse.quote(args.id) + "&limit=" + str(args.limit or 100))
    else:
        output = dict(priority.listing(ranking, args.limit, args.order, args.offset,
                      groups=getattr(args,'groups',False),group_id=getattr(args,'group',None)), rev=latest.get("rev"))
    output["completion"] = latest.get("completion") or report.completion(latest["findings"], rev=latest.get("rev"))
    output["listingIsCompletion"] = False
    print(json.dumps(output, ensure_ascii=False))
    return 0


def main(argv=None):
    """명령줄 진입점. 출력은 UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(
        prog="engine.py", formatter_class=argparse.RawDescriptionHelpFormatter,
        description="AICAAH — AI Coding Agent Architecture Harness (0.1 beta). 문서·코드 대조 명령 입구.",
        epilog="""사용 순서 (모든 명령은 이 engine.py에서 실행):
  priority --limit 20          이미 판정된 미해결을 처리순으로 조회. 재검사 없음.
  priority --id <지적ID>       그 지적의 선언·소비부·소유 문서를 SQL로 조회. 재검사 없음.
  docs                        문서 형식·문서 경로/본문 규칙만 검사. 전체 지적 해소 판정 아님.
  check                       변경을 반영해 전체 하네스 대조. 새 지적·해소·현재 지적을 출력.
  check --all                 같은 대조 결과의 전체 지적도 출력.
  ask status                  마지막 결과·검사 중·오류 조회. 대조 요청 없음; 서버 부재 시 시작 검사 가능.
  mode                        코드→문서 / 문서→코드 작업 방향 조회.
  serve / stop                감시 서버 시작 / 종료.

서버 HTTP API는 위 명령이 내부에서 사용한다. 작업자는 별도 Python import나 HTTP 호출 대신 이 명령을 사용한다.
priority·ask의 종료코드 0은 조회 성공이고 docs의 0은 문서 규칙 검사 통과다. 전체 미해결 0건을 뜻하지 않는다.
check의 일반 대조 결과로 전체 지적을 확인한다. --stage/--base는 한정 대조, --hook/--review는 편집 처리다.
--gate --purpose verification은 검증 실행 허용이며 전체 완료 판정이 아니다.
전체 완료는 같은 판의 completion.complete=true에서만 인정한다. remaining은 화면 미해결이며 observedFindings와 다를 수 있다.
blocked=true, 비교 자료 부재, 한정 검사 또는 파일별0건은 완료 근거가 아니다. 최종 보고 전 finish를 사용한다.
명령별 세부 용도와 부작용: engine.py <명령> --help""")
    ap.add_argument("--version", action="version", version=settings.VERSION)
    ap.add_argument("--root", default=DEFAULT_ROOT, help="프로젝트 루트")
    ap.add_argument("--local", action="store_true", help="감시 서버를 쓰지 않고 제 프로세스에서 돈다")
    ap.add_argument("--unity", default=None, help="Unity 에디터 설치 폴더(참조 그래프). 기본: 환경 변수 AIKA_UNITY_EDITOR, 없으면 refs.UNITY_DEFAULT")
    sub = ap.add_subparsers(dest="command")
    p = sub.add_parser("init", help="Step-by-step project setup / 프로젝트 설치")
    p.add_argument('--language', choices=settings.LOCALES)
    p.add_argument('--languages')
    p.add_argument('--source', action='append')
    p.add_argument('--module', action='append')
    p.add_argument('--limit', action='append', help='unit.metric=maximum; repeatable')
    p.add_argument('--config', help='Prepared project configuration')
    p.add_argument('--yes', action='store_true')
    p.add_argument('--dry-run', action='store_true')
    p.set_defaults(func=setupmod.initialize)
    p = sub.add_parser('settings', help='Project structure settings / 구조 설정')
    p.add_argument('--file')
    p.add_argument('--schema', action='store_true')
    p.add_argument('--dry-run', action='store_true')
    p.set_defaults(func=setupmod.configure)
    p = sub.add_parser('api', help='Versioned JSON library protocol')
    p.set_defaults(func=libraryapi.command)
    p = sub.add_parser('export', help='Export a clean, Git-ready AICAAH source distribution')
    p.add_argument('--destination', required=True, help='New output directory; existing paths are never overwritten')
    p.set_defaults(func=release.export)
    p = sub.add_parser("priority", help="미해결 처리순·지적별 SQL 근거 조회; 재검사 없음",
        description="저장된 최신 전체 지적을 처리순으로 반환한다. --id는 해당 지적의 실제 선언·소비부·소유 문서를 실행 중 서버의 SQL 자료에서 조회한다. 소스를 수정하거나 새 판정을 실행하지 않는다. 종료코드 0은 조회 성공이다.")
    p.add_argument("--limit", type=int, default=20, help="0이면 전체 지적")
    p.add_argument("--order", choices=("asc", "desc"), default="asc")
    p.add_argument("--offset", type=int, default=0)
    selection = p.add_mutually_exclusive_group()
    selection.add_argument("--id", default=None, help="지적 ID의 상세 근거만 요청")
    selection.add_argument('--groups', action='store_true', help='작업 묶음과 원 지적 수 조회')
    selection.add_argument('--group', default=None, help='묶음에 속한 원 지적 조회')
    p.set_defaults(func=cmd_priority)
    p = sub.add_parser("mode", help="검증 방향 조회·전환(문서 수정 없음)",
        description="작업 기준을 조회하거나 code-to-document/document-to-code로 전환한다. 실제 코드·문서는 자동 수정하지 않는다. --code-policy는 코드 수정 권한 정책이다.")
    p.add_argument("mode", nargs="?", choices=["document-to-code", "code-to-document"])
    p.add_argument("--code-policy", choices=["deny", "allow", "request"], help="문서만 수정 / 코드 수정 허용 / 필요 시 수락 요청")
    p.set_defaults(func=cmd_mode)
    p = sub.add_parser("snapshot", help="감시 대상 현 상태 백업",
        description="현재 감시 파일을 스냅숏으로 보관하고 당시 지적을 기록한다. 파일을 쓰는 백업 작업이며 지적 해소나 복구 실행이 아니다.")
    p.add_argument("--label", default="")
    p.set_defaults(func=cmd_snapshot)
    p = sub.add_parser("recent", help="최근 수정 파일(기준 스냅숏 대비 상태)",
        description="감시 대상 파일을 수정 시각 순으로 조회한다. --changed는 기준 대비 바뀐 파일만 표시한다. 지적 판정이나 코드 수정은 하지 않는다.")
    p.add_argument("--base")
    p.add_argument("--limit", type=int, default=40)
    p.add_argument("--changed", action="store_true", help="바뀐 파일만")
    p.set_defaults(func=cmd_recent)
    p = sub.add_parser("diff", help="기준 스냅숏 대비 심볼 변경",
        description="기준과 현재의 파일·선언 변경을 출력한다. 변경 목록은 지적 목록과 다르며 해소 판정이 아니다. 기준 스냅숏이 없으면 오류다.")
    p.add_argument("--base")
    p.set_defaults(func=cmd_diff)
    p = sub.add_parser("agent-hook", help="Claude/Codex 실행 환경별 도구 입력을 공통 편집 관문에 연결")
    p.add_argument("--client", choices=["claude", "codex"], required=True)
    p.set_defaults(func=cmd_agent_hook)
    p = sub.add_parser("check", help="변경 반영 후 전체 하네스 대조; 실제 새 지적·해소 확인",
        description="일반 실행은 감시 서버의 변경 반영 패스를 요청하고, 서버가 없으면 로컬에서 전체 대조한다. 전체 지적에는 문서·선언·미구현·코드 품질·계층·폴더 경계가 포함된다. --stage/--base는 한정 대조이며 전체 완료 근거가 아니다. --gate verification은 실행 허용일 뿐 완료가 아니다.")
    p.add_argument("--base")
    p.add_argument("--stage", help="이 id의 changes 표만 허용 변경으로 본다")
    p.add_argument("--hook", action="store_true", help="Claude Code 훅: stdin JSON의 파일에 대한 지적만, 있으면 종료 코드 2")
    p.add_argument("--gate", action="store_true", help="관문: 기준 스냅숏 때 없던 새 지적만 판정")
    p.add_argument("--purpose", choices=["completion", "verification"], default="completion", help="관문 목적: 완료 판정 또는 검증 실행 허용")
    p.add_argument("--review", action="store_true", help="편집 전 훅: 문서 밖 편집을 체크 대기·틀림 문서 변경이 있으면 막는다")
    p.add_argument("--guard-doc", dest="guard_doc", action="store_true", help="편집 뒤 훅: 기존 역행 규칙으로 지적하며 문서는 자동 복구하지 않음")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--all", action="store_true", help="전체 지적도 출력")
    p.set_defaults(func=cmd_check)
    p = sub.add_parser("finish", help="기존 최종 보고 검사; stdin JSON·전체 대조·미완료 시 차단",
        description="기존 보고 처리 기능. stdin의 last_assistant_message와 전체 대조 결과를 확인하고 미해결 또는 미완료 문구가 있으면 decision=block을 반환한다. 종료코드 0은 응답 전달 성공이므로 완료 여부는 decision과 remaining을 읽는다. 이 명령을 실행한다고 종료 훅이 설치되지 않는다.")
    p.set_defaults(func=cmd_finish)
    p = sub.add_parser("docs", help="문서 형식·경로·본문 규칙만 검사; 전체 완료 판정 아님",
        description="문서를 읽어 표 형식과 문서경로·문서내용 대상 규칙만 검사한다. 실제 코드 선언·계층·폴더 경계·미구현 계약은 대조하지 않는다. 서버 대조와 최신 전체 보고서는 갱신하지 않는다. 종료코드 0은 이 문서 규칙 검사만 통과했다는 뜻이다. 실제 남은 지적 조회는 priority, 변경 반영과 해소 확인은 check를 사용한다.")
    p.set_defaults(func=cmd_docs)
    p = sub.add_parser("scaffold", help="파일의 현재 심볼을 members·constants 표로",
        description="현재 선언을 문서 표 초안으로 stdout에 출력한다. 문서를 저장하거나 지적 상태를 바꾸지 않는다. 설명과 상태는 실제 코드를 검토해 작성한다.")
    p.add_argument("files", nargs="+")
    p.add_argument("--status", default="구현완료")
    p.set_defaults(func=cmd_scaffold)
    p = sub.add_parser("selftest", help="엔진 자체 시험",
        description="검증 엔진의 회귀 시험을 실행한다. 애플리케이션 전체 지적 해소나 캐릭터 런타임 정상 판정과는 별개다.")
    p.set_defaults(func=cmd_selftest)
    selection = p.add_mutually_exclusive_group()
    selection.add_argument('--list', action='store_true', help='등록 검사 ID만 조회; 검사 실행 없음')
    selection.add_argument('--portable', action='store_true', help='Independent installed-package tests; no project fixtures')
    selection.add_argument('--case', action='append', default=[], help='정확한 검사 함수 ID; 반복 지정 가능')
    p = sub.add_parser("serve", help="감시 서버를 띄운다",
        description="감시 서버를 이 프로세스에서 실행한다. 시작 대조 후 파일 변경을 감시한다. 이미 실행 중이면 중복 서버를 만들지 않는다.")
    p.set_defaults(func=cmd_serve)
    p = sub.add_parser("stop", help="감시 서버를 멈춘다",
        description="이 프로젝트의 하네스 서버에 정상 종료를 요청한다. 다른 앱·등록·빌드 프로세스를 종료하지 않는다.")
    p.set_defaults(func=cmd_stop)
    p = sub.add_parser("ask", help="status/new/file/review별 서버 조회·대조 요청",
        description="status: 마지막 판정·검사 중·오류를 조회하며 대조 요청 없음(서버가 없으면 시작하므로 시작 검사가 발생할 수 있음). new: 변경 반영 대조 후 worker가 아직 받지 않은 새 지적·해소를 조회. file <경로>: 마지막 결과에서 그 파일 지적만 조회. review: 문서 검토 상태 조회. 조회 성공은 전체 완료를 뜻하지 않는다.")
    p.add_argument("what", choices=["status", "new", "file", "review"])
    p.add_argument("path", nargs="?")
    p.set_defaults(func=cmd_ask)
    args = ap.parse_args(argv)
    if args.command is None:
        from installation import wizard
        args.root = os.path.abspath(args.root)
        return wizard.run(args)
    if args.command == "check" and args.purpose == "verification":
        if not args.gate or any((args.stage, args.base, args.hook, args.review, args.guard_doc)):
            ap.error("verification requires --gate and cannot be combined with --stage/--base/--hook/--review/--guard-doc")
    args.root = os.path.abspath(args.root)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
