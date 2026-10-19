# -*- coding: utf-8 -*-
"""감시 서버와 API(SPEC-36 2.11). 뒤에서 늘 떠서 감시 대상·문서의 수정 시각·크기를 POLL_SECONDS마다 보고, 바뀌면 패스(2.10)를 돈다.
훅·관문·지도·작업자는 127.0.0.1의 HTTP(JSON)로 묻는다. 받는 쪽 도우미(서버 찾기·띄우기·묻기)도 여기 있다."""
import datetime
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import traceback
import uuid
from types import SimpleNamespace
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from output import codemap, startup, priority
from documents import docs as docmod
from storage import ledger, change_store
from documents import review
from documents import workflow
from serving import service
from output import phase, report
from storage import snapshot
from parsing import cache as cachemod
from parsing import settings
from storage import settings_store
from output import settings_page

POLL_SECONDS = 1.0
RECONCILE_SECONDS = 60.0
QUIET_SECONDS = 2.0
START_SECONDS = 30.0
PORT = 5700
SERVER_FILE = ledger.HISTORY_ROOT + "/server.json"
LOG_FILE = ledger.HISTORY_ROOT + "/server.log"
HERE = os.path.dirname(os.path.abspath(__file__))


class Server:
    """감시 서버 하나: 패스를 도는 Service, 패스 자물쇠, 감시 고리, HTTP 서버."""

    def __init__(self, root, unity=None, port=PORT):
        """루트와 Unity 에디터 폴더, 묶을 포트(자체 시험만 다른 포트를 준다)."""
        self.root, self.unity, self.port = root, unity, port
        self.service = service.Service(root, unity)
        self.lock = threading.Lock()
        self.busy = False
        self.stopping = threading.Event()
        self.seen = None
        self._failed_seen = None
        self.httpd = None
        self.error = ""
        self.review_batch_guard = threading.Lock()
        self.review_batch = None
        self.performance = {"syncs": 0, "reused": 0, "seconds": 0.0}
        self._resume_checked = False
        self._saved_inputs = None
        self._notice_api = None
        self._notice_handles = []
        self._notice_seen = object()
        self._notice_deadline = 0.0
        self._idle_since = time.monotonic()
        self._idle_trimmed = False
        # Environment/schema compatibility is separate from producer invalidation.
        self._runtime_input = (os.path.normcase(os.path.abspath(root)), service.refs.unity_path(unity),
                               sys.version, sys.executable, 'producer-cache:1')
        self.service.input_runtime = (self._runtime_input, sorted(cachemod.POLICY.versions.items()))

    def sync(self, trigger, force=False, observed=None, paths=None):
        """바뀐 것이 있으면 패스를 돈다(자물쇠 안). 패스 앞의 감시 서명을 남겨, 패스 중 바뀐 것은 다음 고리가 잡게 한다."""
        with self.lock:
            self.busy = True
            started = time.perf_counter()
            self.performance["syncs"] += 1
            seen = None
            try:
                if not self._resume_checked:
                    self._resume_checked = True
                    restore_started = time.perf_counter()
                    prior = {} if force else ledger.read_table(self.root, ledger.STATE_ROOT + "/server-inputs.row", {})
                    self._saved_inputs = prior
                    self.performance["restored"] = False
                    if prior.get("runtime") == self._runtime_input and isinstance(prior.get("producers"), dict):
                        led = ledger.load(self.root, lazy=True)
                        unfinished = change_store.pending(self.root,None)
                        if led is not None and (led["rev"] == prior.get("rev") or unfinished):
                            self.service.runtime_changes = cachemod.POLICY.changed(prior["producers"])
                            self.service._ledger = led
                            self.service._ledger_stamp = ledger.stamp(self.root)
                            self.service._index = led["files"].copy()
                            self.service._workflow_marker = prior["workflow"]
                            self.service._settings_marker = prior.get('settings')
                            self.service._watch_rows = prior["watch"]
                            self.seen = prior["seen"]
                            self.service._restored_dependency_paths = tuple(
                                row[0] for row in self.seen if os.path.isabs(row[0]))
                            self.performance["restored"] = True
                    self.performance["restoreSeconds"] = round(time.perf_counter() - restore_started, 4)
                if observed is not None:
                    seen = observed
                elif paths is not None and self.seen is not None and not force:
                    captured = {row[0]:row for row in self.seen}
                    # Unknown paths need discovery: a new file may enter a watch glob.
                    if any(path not in captured for path in paths):
                        seen = self.service.signature()
                    else:
                        for path in paths:
                            try:
                                stat = os.stat(os.path.join(self.root,path))
                                captured[path] = (path,stat.st_mtime_ns,stat.st_size,stat.st_ctime_ns)
                            except FileNotFoundError:
                                captured.pop(path,None)
                                self.service._watched = None
                        seen = tuple(sorted(captured.values()))
                else:
                    seen = self.service.signature()
                pending_input = change_store.pending(self.root,None)
                if (not force and not self.error and self.service.last is None
                        and self.performance.get("restored")):
                    map_rev = (self.service._ledger["rev"] if pending_input and pending_input["diagnosed"]
                               else self._saved_inputs["rev"])
                    loaded = codemap.load_sql(self.root, map_rev, self.service._index,structure=False)
                    if loaded is None and map_rev != self._saved_inputs["rev"]:
                        loaded = codemap.load_sql(self.root,self._saved_inputs["rev"],self.service._index,structure=False)
                    if loaded is not None:
                        try:
                            with open(os.path.join(self.root, snapshot.REPORT_ROOT, "map-annotations.json"), encoding="utf-8") as stream:
                                published = json.load(stream)
                        except (OSError, ValueError):
                            published = {}
                        current_map, findings = loaded
                        if (published.get("rev") == current_map["rev"]
                                and published.get("mapStamp") == current_map["stamp"]
                                and len(published.get("findingProducers", ())) == len(findings)):
                            current_map.update(notes=published["notes"], units=published["units"],
                                phases=published["phases"], workflow=published["workflow"],
                                implementationPlans=published["implementationPlans"],
                                standardFindings=published.get("standardFindings", []),
                                documentLinks=published.get("documentLinks", []),
                                executionBasis=published["executionBasis"],
                                documentReview=published["documentReview"])
                            if published.get("comparison") is not None:
                                current_map["comparison"] = published["comparison"]
                            for finding, producer in zip(findings, published['findingProducers']):
                                finding.producer = producer
                            self.service._analysis_cache['producerNotes'] = published.get('producerNotes', {})
                            self.service._analysis_cache['producerSuppressed'] = published.get('producerSuppressed', {})
                            self.service.standard_findings = published.get('standardFindings', [])
                            try:
                                with open(os.path.join(self.root, snapshot.REPORT_ROOT, 'latest.json'), encoding='utf-8') as stream:
                                    saved_report = json.load(stream)
                            except (OSError, ValueError):
                                saved_report = {}
                            current_map['priority'] = (saved_report['priority'] if
                                saved_report.get('rev') == current_map['rev'] and 'priority' in saved_report
                                else priority.build(findings, published['workflow']['authority']))
                            current_map["priority"]["elapsedSeconds"] = published["priorityElapsed"]
                            current_map["completion"] = report.completion(findings,
                                current_map.get("comparison"), published["workflow"]["authority"], current_map["rev"])
                            self.service._analysis_cache["reportTexts"] = current_map.pop("sourceSnippets",{})
                            self.service.presentation.revision = current_map.pop('projectionRev',None)
                            self.service.map_data = service.Projection(self.root,current_map,self.service._index,self.service.presentation)
                            self.service.presentation.notify()
                            self.service.meta = SimpleNamespace(places=service.metamod.load_places(self.root))
                            self.service.last = service.PassResult(current_map["rev"], False,
                                findings=findings, notes=published["notes"], base=published.get("base") or "")
                            self.performance["sqlPublication"] = True
                            self.performance["reused"] += 1
                            if seen == self.seen and pending_input is None and not self.service.runtime_changes:
                                return self.service.last
                if not force and not self.error and seen == self.seen and self.service.last is not None and pending_input is None and not self.service.runtime_changes:
                    self.performance["reused"] += 1
                    self.service.stage_work = {}
                    self.service.pipeline_work = {}
                    self.service.member_work = {"checked": 0, "reused": 0}
                    self.service.rule_work = {"checked": 0, "reused": 0}
                    self.error = ""
                    last = self.service.last
                    return service.PassResult(last.rev, False, findings=last.findings,
                                              notes=last.notes, base=last.base)
                before = {row[0]:row[1:] for row in (self.seen or ())}
                after = {row[0]:row[1:] for row in seen}
                changed_paths = {path for path in before.keys() | after.keys() if before.get(path) != after.get(path)}
                if pending_input is not None:
                    changed_paths.update(pending_input["changed"])
                previous_watch = self.service._watch_rows
                result = self.service.run(trigger,force,changed_paths=changed_paths if self.seen is not None else None)
                restored_dependencies = self.service._restored_dependency_paths
                self.service._restored_dependency_paths = ()
                source_only_restore = (not force and self.seen is not None
                    and previous_watch == self.service._watch_rows and restored_dependencies
                    and self.service._watch_units is not None
                    and changed_paths and all(not os.path.isabs(path) and path.endswith((".cs", ".py"))
                                          and path in before for path in changed_paths))
                if source_only_restore:
                    # The source edit did not change watch declarations. Refresh
                    # just external dependencies, dropping stale restored paths;
                    # rebuilding every source glob here duplicates the first scan.
                    self.service._dependency_paths = self.service.dependency_paths()
                    captured = {row[0]:row for row in seen if not os.path.isabs(row[0])}
                    dependencies = set(self.service._dependency_paths) | set(self.service._analysis_cache.get("layerInputs", {}))
                    for path in dependencies:
                        try:
                            stat = os.stat(path)
                            captured[path] = (path,stat.st_mtime_ns,stat.st_size,stat.st_ctime_ns)
                        except OSError:
                            captured[path] = (path,None,None,None)
                    seen = tuple(sorted(captured.values()))
                elif self.seen is None or previous_watch != self.service._watch_rows or restored_dependencies:
                    # Discover new inputs without replacing the stamps actually
                    # consumed by this pass. Mid-pass edits/deletes remain pending.
                    self.service._watched = None
                    captured_inputs = {row[0]: row for row in seen}
                    for row in self.service.signature():
                        captured_inputs.setdefault(row[0], row)
                    seen = tuple(sorted(captured_inputs.values()))
                captured = {row[0]:row for row in seen}
                for path,(fingerprint,_) in self.service._analysis_cache.get("layerInputs",{}).items():
                    captured.setdefault(path,(path,fingerprint[0],fingerprint[2],fingerprint[1]))
                # phase.advance writes its own input; use the stamp captured by
                # the same pass, not a new source stamp taken after completion.
                captured.pop(phase.STATE_FILE, None)
                if self.service._phase_input is not None:
                    captured[phase.STATE_FILE] = self.service._phase_input
                self.seen, self.error = tuple(sorted(captured.values())), ""
                # Store input ownership only. Analysis lives in its existing SQL
                # declarations, references and checks, not an object checkpoint.
                if self.service.ds is not None:
                    current_inputs = {"file": "server-inputs", "runtime": self._runtime_input, "rev": result.rev,
                         "seen": self.seen, "workflow": self.service._workflow_marker, "watch": self.service._watch_rows,
                         "producers": dict(cachemod.POLICY.versions)}
                    if self.service._settings_marker is not None:
                        current_inputs['settings'] = self.service._settings_marker
                    if current_inputs != self._saved_inputs:
                        ledger.write_table(self.root,ledger.STATE_ROOT+"/server-inputs.row",current_inputs)
                        self._saved_inputs = current_inputs
                if self.service.input_commit is not None:
                    change_store.acknowledge(self.root,self.service.input_commit)
                    self.service.input_commit = None
                self.service.runtime_changes.clear()
                self._failed_seen = None
                return result
            except Exception:
                self._failed_seen = seen
                self.error = traceback.format_exc()
                self.log(self.error)
                raise
            finally:
                self.performance["seconds"] = round(time.perf_counter() - started, 4)
                self._idle_since = time.monotonic()
                self._idle_trimmed = False
                self.busy = False

    def close_notifications(self):
        """Release OS notification handles on reconfiguration or shutdown."""
        if self._notice_api is not None:
            for handle in self._notice_handles:
                self._notice_api.FindCloseChangeNotification(handle)
        self._notice_handles = []

    def wait_for_changes(self):
        """Cheap notification probe; a bounded reconciliation and polling fallback preserve discovery."""
        if os.name != 'nt':
            self.performance['watchMode'] = 'polling-fallback'
            return True
        import ctypes
        from ctypes import wintypes
        try:
            if self._notice_api is None:
                api = ctypes.WinDLL('kernel32',use_last_error=True)
                api.FindFirstChangeNotificationW.argtypes = [wintypes.LPCWSTR,wintypes.BOOL,wintypes.DWORD]
                api.FindFirstChangeNotificationW.restype = wintypes.HANDLE
                for name in ('FindNextChangeNotification','FindCloseChangeNotification'):
                    getattr(api,name).argtypes = [wintypes.HANDLE]
                    getattr(api,name).restype = wintypes.BOOL
                api.WaitForMultipleObjects.argtypes = [wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE),wintypes.BOOL,wintypes.DWORD]
                api.WaitForMultipleObjects.restype = wintypes.DWORD
                self._notice_api = api
            now = time.monotonic()
            refresh = self._notice_seen is not self.seen or not self._notice_handles
            if refresh:
                root = os.path.normcase(os.path.abspath(self.root))
                paths = {root}
                for row in self.seen or ():
                    if not os.path.isabs(row[0]):
                        continue
                    path = os.path.normcase(os.path.dirname(os.path.abspath(row[0])))
                    while not os.path.isdir(path) and os.path.dirname(path) != path:
                        path = os.path.dirname(path)
                    paths.add(path)
                roots = []
                for path in sorted(paths,key=len):
                    if not any(path == parent or path.startswith(parent+os.sep) for parent in roots):
                        roots.append(path)
                if len(roots)>64:
                    raise OSError('more than 64 notification roots')
                self.close_notifications()
                for path in roots:
                    handle=self._notice_api.FindFirstChangeNotificationW(path,True,0x1f)
                    if handle in (None,ctypes.c_void_p(-1).value):
                        raise ctypes.WinError(ctypes.get_last_error())
                    self._notice_handles.append(handle)
                self._notice_seen = self.seen
                self._notice_deadline = now + RECONCILE_SECONDS
            changed = refresh or now >= self._notice_deadline
            handles = (wintypes.HANDLE * len(self._notice_handles))(*self._notice_handles)
            for _ in self._notice_handles:
                result = self._notice_api.WaitForMultipleObjects(len(handles),handles,False,0)
                if result == 258:
                    break
                if result >= len(handles) or not self._notice_api.FindNextChangeNotification(handles[result]):
                    raise ctypes.WinError(ctypes.get_last_error())
                changed = True
                self.performance['watchNotifications'] = self.performance.get('watchNotifications',0)+1
            self.performance['watchMode'] = 'windows-notification'
            self.performance.pop('watchError',None)
            if changed:
                self._notice_deadline = now + RECONCILE_SECONDS
            return changed
        except (OSError, AttributeError) as error:
            self.close_notifications()
            self.performance.update(watchMode='polling-fallback',watchError=str(error))
            return True

    def watch(self):
        """감시 고리: 처음 한 번 패스를 돌고, 바뀐 서명이 QUIET_SECONDS 동안 유지되면 한 번 판정한다."""
        try:
            self.wait_for_changes()
            self.sync("시작")
        except Exception:
            pass
        pending = None
        changed_at = 0.0
        while not self.stopping.wait(POLL_SECONDS):
            try:
                if self.busy:
                    continue
                changed = self.wait_for_changes()
                if not changed and pending is None:
                    if not self._idle_trimmed and time.monotonic()-self._idle_since>=self.service.RebuildSeconds and self.lock.acquire(blocking=False):
                        try:
                            self.service.trim_idle()
                            self._idle_trimmed = True
                            self.performance['idleTrims'] = self.performance.get('idleTrims',0)+1
                        finally:
                            self.lock.release()
                    continue
                if changed:
                    self.service._watched = None
                self.performance['watchScans'] = self.performance.get('watchScans',0)+1
                signature = self.service.signature()
                if signature == self.seen or signature == self._failed_seen:
                    pending = None
                    continue
                if signature != pending:
                    pending = signature
                    changed_at = time.monotonic()
                    continue
                if time.monotonic() - changed_at >= QUIET_SECONDS:
                    self.sync("감시",observed=signature)
                    pending = None
            except Exception:
                self.log(traceback.format_exc())

    def log(self, text):
        """서버 기록에 한 줄."""
        path = os.path.join(self.root, LOG_FILE)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write("%s %s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), text))

    def status(self):
        """GET /status 응답."""
        last = self.service.last
        counts = Counter(f.code for f in last.findings) if last else Counter()
        task_counts = Counter(f.code for f in workflow.task_findings(self.root, last.findings)) if last else Counter()
        comparison = (self.service.map_data or {}).get("comparison", {})
        assessment = report.completion(last.findings if last else [], comparison or None,
                                       review.workflow_state(self.root)["authority"], last.rev if last else None)
        if self.busy or self.error:
            assessment.update(blocked=True, resolvedConfirmed=False, complete=False, decision="block")
        assessment["stateCurrent"] = not self.busy and not self.error
        return {"pid": os.getpid(), "rev": last.rev if last else None, "busy": self.busy, "error": self.error,
                "uiVersion": hashlib.sha256(codemap.PAGE.encode("utf-8")).hexdigest(),
                "time": ledger.now(), "counts": dict(task_counts), "findings": sum(task_counts.values()),
                "allCounts": dict(counts), "reflectionRemaining": comparison.get("remaining"),
                "reflectionBlocked": comparison.get("blocked"),
                "completion": assessment,
                "storage": ledger.table_status(),
                "presentation": {"diagnosisRev":last.rev if last else None,
                                 "readyRev":self.service.presentation.revision,
                                 "error":self.service.presentation.error,
                                 "seconds":self.service.presentation.seconds},
                "workflow": review.workflow_state(self.root),
                "cachePolicy": {"schema": cachemod.CachePolicy.SCHEMA,
                                "versions": dict(cachemod.POLICY.versions),
                                "dependencies": {key: len(value) for key, value in cachemod.POLICY.dependencies.items()}},
                "performance": dict(self.performance, memberChecks=dict(self.service.member_work),
                                     codeRuleFiles=dict(self.service.rule_work),
                                     stages=dict(self.service.stage_work),
                                     pipeline=dict(self.service.pipeline_work))}

    def memory_usage(self):
        """Explicit diagnostic only: count owned Python objects without materializing lazy SQL views."""
        seen, owners = set(), {}
        roots = list(vars(self.service).items())
        # Count canonical inputs before display aliases to avoid charging a
        # Projection's reference to the source index to browser-only geometry.
        roots.sort(key=lambda pair: pair[0] == 'map_data')
        roots.extend(('module.' + module.__name__ + '.' + key, value)
                     for module in (service.refs, service.metamod, ledger, snapshot)
                     for key, value in vars(module).items()
                     if key.startswith('_') and key.isupper() and isinstance(value, (dict, set)))
        roots.append(('server.savedInputs', self._saved_inputs))
        for name, value in roots:
            owners.setdefault(name, 0)
            stack = [(value, name)]
            while stack and len(seen) < 10000000:
                item, owner = stack.pop()
                if id(item) in seen:
                    continue
                seen.add(id(item))
                owners[owner] = owners.get(owner, 0) + sys.getsizeof(item)
                if isinstance(item, dict):
                    for key, child in dict.items(item):
                        label = name + '.' + str(key) if item is self.service._analysis_cache else owner
                        stack.extend(((key, label), (child, label)))
                elif isinstance(item, (list, tuple, set, frozenset)):
                    stack.extend((child, owner) for child in item)
                if type(item).__module__.startswith(('documents.', 'graph.', 'judging.', 'output.', 'storage.', 'serving.')) and hasattr(item, '__dict__'):
                    stack.append((vars(item), owner))
        return {'bytes':sum(owners.values()), 'owners':owners, 'objects':len(seen),
                'viewStructureResident':'decls' in (self.service.map_data or {}),
                'compressedViewBytes':len(getattr(self.service.map_data, 'packed', b'') or b''),
                'truncated':len(seen)>=10000000, 'scope':'owned Python objects, shared references counted once in root order; excludes allocator and native SQLite memory'}

    def pass_summary(self, result):
        """패스 결과 → JSON."""
        findings = workflow.task_findings(self.root, result.findings)
        resolved = result.resolved
        assessment = report.completion(findings, (self.service.map_data or {}).get("comparison"), workflow.state(self.root)["authority"], result.rev)
        return {"rev": result.rev, "judged": result.judged, "changes": len(result.changes), "docs": result.docs,
                "new": [service.as_dict(f) for f in workflow.task_findings(self.root, result.new)], "resolved": resolved,
                "counts": dict(Counter(f.code for f in findings)),
                "executionBasis": (self.service.map_data or {}).get("executionBasis"),
                "documentReview": (self.service.map_data or {}).get("documentReview", {}),
                "approvedWorkCount": len((self.service.map_data or {}).get("implementationPlans", [])),
                "completion": assessment,
                "prioritySummary": {key:(self.service.map_data or {}).get('priority',{}).get(key,0)
                                    for key in ('occurrences','uniqueFindings','groupCount')},
                "performance": {"pipeline":dict(getattr(self.service,'pipeline_work',{})),
                                "stages":dict(getattr(self.service,'stage_work',{})),
                                "members":dict(getattr(self.service,'member_work',{}))},
                "exit": service.exit_code(findings) or (2 if assessment["blocked"] else 1 if not assessment["complete"] else 0)}

    def review_batch_status(self, batch_id):
        with self.review_batch_guard:
            batch = self.review_batch
            if batch is None or batch["id"] != batch_id:
                return 404, "application/json", {"error": "체크 작업을 찾을 수 없습니다"}
            return 200, "application/json", {key: value for key, value in batch.items() if key not in ("chunks", "items", "memo")}

    def review_batch_progress(self, batch_id, stage, done=0, total=0, step=None):
        with self.review_batch_guard:
            if self.review_batch and self.review_batch["id"] == batch_id:
                if stage == "대조 중":
                    percent = 25 + 30 * done // total if total else 25
                elif stage == "기준본 적용 중":
                    percent = 55 + 25 * done // total if total else 55
                elif stage == "체크 기록 중":
                    percent = 82
                elif stage == "완료":
                    percent = 100
                else:
                    percent = self.review_batch["percent"]
                self.review_batch.update(stage=stage, done=done, stageTotal=total,
                                         percent=max(self.review_batch["percent"], percent))

    def complete_review_batch(self, batch_id):
        with self.review_batch_guard:
            batch = self.review_batch
            if batch is None or batch["id"] != batch_id:
                return
            items, verdict, memo = batch["items"], batch["verdict"], batch["memo"]
        with self.lock:
            self.busy = True
            try:
                got = review.check(self.root, [tuple(item.rsplit("|", 1)) for item in items], verdict, memo,
                                   progress=lambda stage, done, total: self.review_batch_progress(batch_id, stage, done, total))
                if not got.get("ok"):
                    raise ValueError(got.get("error", "체크 실패"))
                with self.review_batch_guard:
                    self.review_batch["result"] = got
                self.review_batch_progress(batch_id, "완료")
            except Exception as error:
                self.review_batch_progress(batch_id, "실패")
                with self.review_batch_guard:
                    self.review_batch["error"] = str(error)
                self.log(traceback.format_exc())
            finally:
                self.busy = False

    def route(self, method, path, query):
        """요청 하나 → (상태 코드, 내용 형식, 본문)."""
        if method == 'GET' and path == '/locales':
            return 200, 'application/json', {'locales':list(settings.LOCALES)}
        if path in ('/settings', '/settings/config'):
            if method == 'GET':
                config = settings.load(self.root) or settings.defaults()
                if path == '/settings/config':
                    return 200, 'application/json', {'config':config, 'fingerprint':settings_store.fingerprint(self.root), 'schema':settings.schema()}
                locale = query.get('lang', [config['locale']])[0]
                if locale not in settings.LOCALES: return 400, 'application/json', {'error':'Unsupported display language'}
                return 200, 'text/html; charset=utf-8', settings_page.page(config,settings.schema(),settings_store.fingerprint(self.root),locale)
            if method == 'POST' and path == '/settings/config':
                try:
                    incoming = json.loads(query['settings'][0])
                    with self.lock:
                        settings_store.save(self.root, incoming['config'], incoming['expected'])
                        self.service._watched = None
                    threading.Thread(target=self.sync, args=('structure settings',), daemon=True).start()
                    return 200, 'application/json', {'fingerprint':settings_store.fingerprint(self.root)}
                except (ValueError, KeyError, OSError) as error:
                    return 409 if str(error) == 'settings.conflict' else 400, 'application/json', {'error':str(error)}
        if method == "GET" and path == "/status":
            result = self.status()
            if (query.get('memory') or ['0'])[0] == '1':
                if not self.lock.acquire(blocking=False):
                    return 409, "application/json", {'error':'진단 중에는 메모리를 계측하지 않습니다.'}
                try:
                    result['memory'] = self.memory_usage()
                finally:
                    self.lock.release()
            if (query.get('inputs') or ['0'])[0] == '1':
                result['inputsCurrent'] = False
                if self.lock.acquire(blocking=False):
                    try:
                        self.service._watched = None
                        observed = self.service.signature()
                        result['inputFingerprint'] = hashlib.sha256(repr(observed).encode()).hexdigest()
                        result['inputsCurrent'] = not self.error and observed == self.seen
                    finally:
                        self.lock.release()
            return 200, "application/json", result
        if method == "POST" and path == "/review/batch/start":
            try:
                total = int((query.get("total") or ["0"])[0])
            except ValueError:
                total = 0
            verdict = (query.get("verdict") or [""])[0]
            if not 0 < total <= 50000 or verdict not in ("맞음", "틀림"):
                return 400, "application/json", {"error": "체크 건수 또는 판정이 올바르지 않습니다"}
            with self.review_batch_guard:
                old = self.review_batch
                if old and old["stage"] not in ("전송 중", "완료", "실패"):
                    return 409, "application/json", {"error": "다른 묶음 체크가 진행 중입니다"}
                batch_id = uuid.uuid4().hex
                self.review_batch = {"id": batch_id, "stage": "전송 중", "total": total, "uploaded": 0, "percent": 0,
                                     "done": 0, "stageTotal": 0, "verdict": verdict,
                                     "memo": (query.get("memo") or [""])[0], "chunks": {}, "items": [],
                                     "created": time.monotonic(), "result": None, "error": ""}
            return self.review_batch_status(batch_id)
        if method == "POST" and path == "/review/batch/chunk":
            batch_id = (query.get("batch") or [""])[0]
            try:
                index = int((query.get("index") or ["-1"])[0])
            except ValueError:
                index = -1
            items = query.get("item") or []
            if index < 0 or not items or len(items) > 500:
                return 400, "application/json", {"error": "묶음 번호 또는 크기가 올바르지 않습니다"}
            with self.review_batch_guard:
                batch = self.review_batch
                if batch is None or batch["id"] != batch_id or batch["stage"] != "전송 중":
                    return 409, "application/json", {"error": "전송 중인 체크 작업이 없습니다"}
                prior = batch["chunks"].get(index)
                if prior is not None and prior != items:
                    return 409, "application/json", {"error": "같은 번호의 묶음 내용이 다릅니다"}
                if prior is None:
                    if batch["uploaded"] + len(items) > batch["total"]:
                        return 400, "application/json", {"error": "예정 건수를 넘었습니다"}
                    batch["chunks"][index] = items
                    batch["uploaded"] += len(items)
                    batch["percent"] = max(batch["percent"], 25 * batch["uploaded"] // batch["total"])
                return 200, "application/json", {"ok": True, "uploaded": batch["uploaded"], "total": batch["total"]}
        if method == "POST" and path == "/review/batch/finish":
            batch_id = (query.get("batch") or [""])[0]
            with self.review_batch_guard:
                batch = self.review_batch
                if batch is None or batch["id"] != batch_id:
                    return 404, "application/json", {"error": "체크 작업을 찾을 수 없습니다"}
                if batch["stage"] != "전송 중":
                    return 200, "application/json", {key: value for key, value in batch.items() if key not in ("chunks", "items", "memo")}
                chunks = batch["chunks"]
                if batch["uploaded"] != batch["total"] or sorted(chunks) != list(range(len(chunks))):
                    return 400, "application/json", {"error": "아직 전달되지 않은 묶음이 있습니다"}
                items = [item for index in range(len(chunks)) for item in chunks[index]]
                if len(set(items)) != len(items):
                    return 400, "application/json", {"error": "중복된 변경키가 있습니다"}
                batch["items"] = items
                batch["chunks"] = {}
                batch.update(stage="대기 중", done=0, stageTotal=0, percent=25)
                self.busy = True
            threading.Thread(target=self.complete_review_batch, args=(batch_id,), daemon=True).start()
            return self.review_batch_status(batch_id)
        if method == "GET" and path == "/review/batch/status":
            return self.review_batch_status((query.get("batch") or [""])[0])
        if method == "GET" and path == "/priority":
            data = self.service.map_data or {}
            try:
                limit = int((query.get("limit") or ["20"])[0])
                offset = int((query.get("offset") or ["0"])[0])
                order = (query.get("order") or ["asc"])[0]
                finding_id = (query.get("id") or [None])[0]
                groups = (query.get('groups') or ['0'])[0] in ('1','true')
                group_id = (query.get('group') or [None])[0]
                if sum((bool(finding_id),groups,group_id is not None)) > 1:
                    raise ValueError('select id, groups or group')
                if finding_id:
                    if not self.lock.acquire(blocking=False):
                        return 409, "application/json", {"error":"판정 자료 갱신 중입니다. 완료 뒤 같은 ID로 요청하세요."}
                    try:
                        data = self.service.map_data or {}
                        evidence = priority.detail(self.root, data.get("priority", {}), finding_id,
                            self.service.meta, self.service._analysis_cache.get("relationMeta", {}),
                            self.service._analysis, limit or 100)
                        return 200, "application/json", dict(evidence, rev=data.get("rev"))
                    finally:
                        self.lock.release()
                return 200, "application/json", dict(priority.listing(data.get("priority", {}), limit, order, offset, groups=groups,group_id=group_id), rev=data.get("rev"))
            except KeyError:
                return 404, "application/json", {"error": "해당 지적 ID가 현재 판에 없습니다."}
            except ValueError as error:
                return 400, "application/json", {"error": str(error)}
        if path == "/apply":
            return 410, "application/json", {"error": "표 자동 생성 apply는 제거됐습니다. /workflow로 검증 방향만 전환하고 문서를 직접 수정하세요. 서버는 불일치를 검사합니다."}
        if method == "GET" and path == "/workflow":
            return 200, "application/json", review.workflow_state(self.root)
        if method == "GET" and path == "/comparison":
            data = self.service.map_data or {}
            return 200, "application/json", dict(data.get("comparison", {}), rev=data.get("rev"))
        if method == "GET" and path == "/workflow/requests":
            return 200, "application/json", {"requests": workflow.code_requests(self.root)}
        if method == "POST" and path.startswith("/workflow/"):
            try:
                with self.lock:
                    file = (query.get("file") or [""])[0]
                    request_id = (query.get("id") or [""])[0]
                    edit = json.loads((query.get("edit") or ["{}"]) [0])
                    if path == "/workflow/request":
                        mode = workflow.state(self.root)
                        if mode["authority"] != "code" or mode["codePolicy"] != "request":
                            raise ValueError("코드 수정 수락 요청 정책이 아닙니다")
                        result = workflow.request_code_edit(self.root, file, (query.get("reason") or ["코드 편집 요청"])[0], edit)
                    elif path == "/workflow/decision":
                        decision = (query.get("accept") or [""])[0]
                        if decision not in ("true", "false"):
                            raise ValueError("accept=true 또는 false가 필요합니다")
                        result = workflow.decide_code_edit(self.root, request_id, decision == "true")
                    elif path == "/workflow/consume":
                        result = {"allowed": workflow.consume_code_edit(self.root, request_id)}
                    elif path == "/workflow/completed":
                        result = {"recorded": workflow.record_code_edit(self.root, file, edit)}
                    else:
                        return 404, "application/json", {"error": "모르는 작업 모드 요청"}
                    self.seen = None
                return 200, "application/json", result
            except ValueError as error:
                return 400, "application/json", {"error": str(error)}
        if method == "POST" and path == "/workflow":
            try:
                with self.lock:
                    value = (query.get("mode") or [""])[0]
                    result = review.set_workflow(self.root, value, (query.get("codePolicy") or [None])[0])
                    self.seen = None
                return 200, "application/json", result
            except ValueError as error:
                return 400, "application/json", {"error": str(error)}
        if method == "POST" and path == "/sync":
            files = {file.replace("\\", "/") for file in query.get("file", [])}
            if any(not file or os.path.isabs(file) or ".." in file.split("/") or ":" in file for file in files):
                return 400, "application/json", {"error": "검사 파일은 루트 안의 상대 경로여야 합니다"}
            return 200, "application/json", self.pass_summary(self.sync("요청",paths=files or None))
        if method == "POST" and path == "/hook":
            files = {file.replace('\\','/') for file in query.get('file',[])}
            if not files or any(not file or os.path.isabs(file) or '..' in file.split('/') or ':' in file for file in files):
                return 400, "application/json", {"error": "훅 파일은 루트 안의 상대 경로여야 합니다"}
            self.sync("훅",paths=files)
            with self.lock:
                rev, new, resolved = self.service.since("hook")
                comparison = (self.service.map_data or {}).get("comparison", {})
                blocking = [service.as_dict(f) for f in self.service.last.findings if f.code.startswith(("D", "P"))]
            return 200, "application/json", {"rev": rev, "new": [service.as_dict(f) for f in new[:40]],
                                             "newCount": len(new), "resolvedCount": len(resolved),
                                             "blocked": bool(blocking) or comparison.get("blocked", False),
                                             "blocking": blocking[:40], "remaining": comparison.get("remaining")}
        if method == "GET" and path == "/since":
            client = (query.get("client") or ["worker"])[0]
            with self.lock:
                rev, new, resolved = self.service.since(client)
            return 200, "application/json", {"rev": rev, "new": [service.as_dict(f) for f in new], "resolved": resolved,
                                             "completion": self.status()["completion"],
                                             "workflow": review.workflow_state(self.root)}
        if method == "GET" and path == "/findings":
            rel = (query.get("file") or [""])[0].replace("\\", "/")
            last = self.service.last
            findings = last.findings if last else []
            items = [f for f in workflow.task_findings(self.root, findings) if f.file == rel]
            ranking = (self.service.map_data or {}).get("priority", {})
            priorities = {r["findingId"]: r for r in ranking.get("findingPriority", []) if r["file"] == rel}
            annotated = []
            for f in items:
                item = service.as_dict(f)
                work = priorities.get(service.checkmod.finding_key(f))
                if work:
                    item["priority"] = {k: work[k] for k in ("id", "priorityRank", "priorityBand", "actionKind", "evidenceStatus", "mustFix", "modeIndependent", "blocksResolution", "requiredAction", "repairInstruction") if k in work}
                annotated.append(item)
            return 200, "application/json", {"file": rel, "findings": annotated,
                                             "rev": last.rev if last else None,
                                             "scope": "selected-file", "completion": self.status()["completion"],
                                             "workflow": review.workflow_state(self.root)}
        if method == "POST" and path == "/gate":
            purpose = (query.get("purpose") or ["completion"])[0]
            if purpose not in ("completion", "verification"):
                return 400, "application/json", {"error": "Unknown gate purpose: " + str(purpose)}
            result = self.sync("관문")
            if self.service.ds is None and purpose == "completion" and workflow.state(self.root)["authority"] == "document":
                with self.lock:
                    self.service._docs()
            relevant = workflow.task_findings(self.root, result.findings)
            fresh, pending, told = service.gate(relevant, snapshot.load(self.root),
                                                self.service.ds,
                                                self.service.meta.places if self.service.meta is not None else None,
                                                purpose=purpose)
            if purpose == "completion" and workflow.state(self.root)["authority"] == "code":
                fresh, pending, told = relevant, 0, 0
            assessment = self.pass_summary(result)["completion"]
            return 200, "application/json", {"rev": result.rev, "purpose": purpose,
                                             "fresh": [service.as_dict(f) for f in fresh],
                                             "reported": [service.as_dict(f) for f in relevant] if purpose == "verification" else [],
                                             "pending": pending, "told": told, "total": len(relevant),
                                             "completion": assessment,
                                             "exit": (service.exit_code(fresh) or (2 if assessment["blocked"] else 1 if not assessment["complete"] else 0))
                                                     if purpose == "completion" else service.exit_code(fresh), "base": result.base}
        if method == "GET" and path == "/review":
            current_mode = workflow.state(self.root)
            return 200, "application/json", {"workflow": current_mode,
                "units": [] if current_mode["authority"] == "code"
                else [review.as_dict(u) for u in review.units(self.root)]}
        if method == "POST" and path == "/review/check":
            items = [tuple(x.rsplit("|", 1)) for x in query.get("item") or [] if "|" in x]
            if len(items) > 500:
                return 413, "application/json", {"error": "한 번에 500건을 넘길 수 없습니다. 지도를 새로고침해 묶음 체크를 사용하세요."}
            with self.lock:
                got = review.check(self.root, items, (query.get("verdict") or [""])[0], (query.get("memo") or [""])[0])
            return 200, "application/json", got
        if method == "GET" and path == "/phases":
            last = self.service.last
            return 200, "application/json", phase.as_dict(docmod.load(self.root), last.findings if last else [],
                                                  self.service.meta.places if self.service.meta is not None else None)
        if method == "POST" and path.startswith("/phases/"):
            name = (query.get("name") or [""])[0]
            with self.lock:
                try:
                    if path == "/phases/move":
                        body = phase.move(self.root, name, int((query.get("rank") or ["0"])[0]))
                    elif path == "/phases/add":
                        body = phase.insert(self.root, name, (query.get("targets") or [""])[0], (query.get("reason") or [""])[0])
                    elif path == "/phases/defer":
                        body = phase.defer(self.root, name)
                    elif path == "/phases/drop":
                        body = phase.drop(self.root, name)
                    else:
                        return 404, "application/json", {"error": "모르는 페이즈 조작: " + path}
                except ValueError as e:
                    return 200, "application/json", {"ok": False, "error": str(e)}
                last = self.service.last
                return 200, "application/json", {"ok": True, "rows": body,
                                                 "phases": phase.as_dict(docmod.load(self.root), last.findings if last else [],
                                                      self.service.meta.places if self.service.meta is not None else None)}
        if method == "GET" and path == "/data":
            self._idle_since = time.monotonic()
            self._idle_trimmed = False
            if self.service.map_data is None:
                empty = codemap.data(None, [], [], '', rev=None)
                empty.update(workflow=workflow.state(self.root), implementationPlans=[],
                    completion={'remaining':None,'complete':False,'stateCurrent':False})
                return 200, "application/json", {'full':empty} if 'since' in query else empty
            if "since" in query:
                with self.lock:
                    current = self.service.map_data or {}
                    delta = self.service.previous_delta(query["since"][0])
                    return 200, "application/json", delta if delta is not None else codemap.delta(None, current)
            return 200, "application/json", codemap.live_data(self.service.map_data or {})
        if method == "GET" and path in ("/", "/map"):
            data = self.service.map_data
            config = settings.load(self.root)
            locale = query.get('lang', [(config or {}).get('locale','ko')])[0]
            if locale not in settings.LOCALES: return 400, 'application/json', {'error':'Unsupported display language'}
            return 200, "text/html; charset=utf-8", codemap.page(data, live=True, locale=locale)
        if method == "POST" and path == "/stop":
            threading.Thread(target=self.shutdown, daemon=True).start()
            return 200, "application/json", {"stopping": True}
        return 404, "application/json", {"error": "모르는 요청: %s %s" % (method, path)}

    def shutdown(self):
        """감시 고리와 HTTP 서버를 멈춘다."""
        self.stopping.set()
        self.service.presentation.close()
        if self.httpd is not None:
            self.httpd.shutdown()

    def serve(self):
        """HTTP 서버를 띄우고 server.json을 쓴다. 포트는 self.port 고정(2.11). 그 포트를 다른 프로그램이 쓰고 있으면
        기록에 남기고 OSError를 그대로 던진다(빈 포트로 넘어가지 않음). 멈출 때까지 돌고, 멈춰도 server.json은 남긴다."""
        owner = self

        class Handler(BaseHTTPRequestHandler):
            """요청을 Server.route로 넘긴다."""

            def handle_one(self, method):
                """요청 하나를 처리해 답한다."""
                url = urllib.parse.urlparse(self.path)
                try:
                    query = urllib.parse.parse_qs(url.query)
                    length = int(self.headers.get("Content-Length", "0"))
                    limit = 8 * 1024 * 1024 if url.path == "/review/check" else 512 * 1024 if url.path == "/review/batch/chunk" else 65536
                    if length > limit or length < 0:
                        raise ValueError("요청 본문이 너무 큽니다")
                    if method == "POST" and length:
                        incoming = json.loads(self.rfile.read(length).decode("utf-8"))
                        if not isinstance(incoming, dict):
                            raise ValueError("JSON 객체가 필요합니다")
                        if url.path == '/settings/config':
                            query['settings'] = [json.dumps(incoming,ensure_ascii=False)]
                        if "mode" in incoming:
                            if not isinstance(incoming["mode"], str):
                                raise ValueError("mode는 문자열이어야 합니다")
                            query["mode"] = [incoming["mode"]]
                        for key in ("codePolicy", "file", "id", "reason", "verdict", "memo", "batch"):
                            if key in incoming:
                                if not isinstance(incoming[key], str):
                                    raise ValueError(key + "는 문자열이어야 합니다")
                                query[key] = [incoming[key]]
                        for key in ("index", "total"):
                            if key in incoming:
                                if type(incoming[key]) is not int:
                                    raise ValueError(key + "는 정수여야 합니다")
                                query[key] = [str(incoming[key])]
                        if "items" in incoming:
                            items = incoming["items"]
                            allowed = url.path in ("/review/check", "/review/batch/chunk")
                            maximum = 500 if url.path == "/review/batch/chunk" else 50000
                            if not allowed or not isinstance(items, list) or len(items) > maximum or not all(isinstance(item, str) and "|" in item for item in items):
                                raise ValueError("items는 최대 50000개의 문서|변경키 문자열 배열이어야 합니다")
                            query["item"] = items
                        if "edit" in incoming:
                            query["edit"] = [json.dumps(incoming["edit"], ensure_ascii=False)]
                        if "accept" in incoming:
                            if not isinstance(incoming["accept"], bool):
                                raise ValueError("accept는 boolean이어야 합니다")
                            query["accept"] = ["true" if incoming["accept"] else "false"]
                        if "on" in incoming:
                            if not isinstance(incoming["on"], bool):
                                raise ValueError("on은 boolean이어야 합니다")
                            query["on"] = ["true" if incoming["on"] else "false"]
                        if "paths" in incoming:
                            if not isinstance(incoming["paths"], list) or not all(isinstance(f, str) for f in incoming["paths"]):
                                raise ValueError("paths는 파일 경로 배열이어야 합니다")
                            query["file"] = incoming["paths"]
                    code, kind, body = owner.route(method, url.path, query)
                except (ValueError, UnicodeError) as error:
                    code, kind, body = 400, "application/json", {"error": str(error)}
                except Exception:
                    code, kind, body = 500, "application/json", {"error": traceback.format_exc()}
                raw = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
                data = raw.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", kind if kind.startswith("text/") else kind + "; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                """GET."""
                self.handle_one("GET")

            def do_POST(self):
                """POST."""
                self.handle_one("POST")

            def log_message(self, fmt, *args):
                """요청마다 찍지 않는다."""

        class Http(ThreadingHTTPServer):
            """주소 재사용을 끈다 — 윈도우에서는 켜 두면 다른 프로그램이 쓰는 포트에도 묶여 버린다."""
            allow_reuse_address = False

        try:
            self.httpd = Http(("127.0.0.1", self.port), Handler)
        except OSError as e:
            self.log("포트 %d에 묶지 못함(다른 프로그램이 쓰는 중?): %s" % (self.port, e))
            raise
        port = self.httpd.server_address[1]
        self.service.live_url = "http://127.0.0.1:%d/" % port
        started = {"pid": os.getpid(), "port": port, "root": self.root, "started": ledger.now()}
        path = os.path.join(self.root, SERVER_FILE)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(started, f, ensure_ascii=False)
        self.log("서버 시작 pid %d 포트 %d" % (os.getpid(), port))
        self.service.presentation.start()
        watch_thread = threading.Thread(target=self.watch, daemon=True)
        watch_thread.start()
        try:
            self.httpd.serve_forever(poll_interval=0.2)
        finally:
            self.stopping.set()
            self.httpd.server_close()
            watch_thread.join()
            self.close_notifications()
            if self.service.map_data is not None:
                codemap.write(self.root, self.service.map_data)
            ledger.close_tables(self.root)
            snapshot.release(self.root)
            self.log("서버 멈춤")


def info(root):
    """server.json(dict). 없으면 None."""
    path = os.path.join(root, SERVER_FILE)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def ask(root, method, path, timeout=600.0, body=None):
    """서버에 묻는다. 닿지 못하면 None."""
    meta = info(root)
    if meta is None:
        return None
    path = urllib.parse.quote(path, safe="/?=&%")
    payload = json.dumps(body,ensure_ascii=False).encode("utf-8") if body is not None else (b"" if method == "POST" else None)
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (meta["port"], path), method=method,
                                 data=payload, headers={"Content-Type":"application/json"} if body is not None else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            return json.loads(error.read().decode("utf-8"))
        except ValueError:
            return {"error": str(error)}
    except (urllib.error.URLError, OSError, ValueError):
        return None


def alive(root):
    """떠 있는 서버의 server.json(응답이 있을 때만). 없으면 None."""
    meta = info(root)
    if meta is None:
        return None
    return meta if ask(root, "GET", "/status", timeout=3.0) is not None else None


def start(root, unity=None):
    """서버를 뒤에서 띄우고 응답할 때까지 START_SECONDS 기다린다. 돌려주는 값: server.json 또는 None."""
    log = os.path.join(root, LOG_FILE)
    os.makedirs(os.path.dirname(log), exist_ok=True)
    cmd = [sys.executable, os.path.join(os.path.dirname(HERE), "engine.py"), "--root", root]
    if unity:
        cmd += ["--unity", unity]
    cmd.append("serve")
    flags = 0
    if os.name == "nt":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | 0x08000000
    with open(log, "a", encoding="utf-8") as out:
        subprocess.Popen(cmd, stdout=out, stderr=out, stdin=subprocess.DEVNULL, creationflags=flags, close_fds=True)
    until = time.time() + START_SECONDS
    while time.time() < until:
        meta = alive(root)
        if meta is not None:
            return meta
        time.sleep(0.3)
    return None


def ensure(root, unity=None):
    """떠 있는 서버, 없으면 띄운 서버. 띄우지 못하면 None."""
    return alive(root) or start(root, unity)
