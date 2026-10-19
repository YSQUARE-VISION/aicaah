# -*- coding: utf-8 -*-
"""패스(SPEC-36 2.10): 문서 → 색인 → 판정(2.6·2.8) → 장부·이력 → 보고서·지도. 감시 서버(server.py)와 명령줄(engine.py)이
같은 것을 쓴다. 문서 표는 문서 해시가 같으면 다시 읽지 않는다."""
import datetime
import glob
import hashlib
import os
import time
import gc
import marshal
import zlib
from dataclasses import dataclass, field

from judging import check as checkmod
from output import codemap
from storage import diff as diffmod
from documents import docs as docmod
from storage import ledger, design, change_store, map_store
from serving.presentation import Presentation, Projection
from judging import meta as metamod
from output import report
from documents import review
from storage import snapshot
from output import phase
from output import reconciliation, priority
from documents import workflow
from graph import refs, layers
from graph.cache import AnalysisCache
from parsing import globs
from parsing import cache as cachemod
from parsing import settings
from judging import standards
from output import localization


@dataclass
class PassResult:
    """패스 한 번의 결과. judged가 거짓이면 바뀐 것이 없어 판정하지 않았다(지적은 마지막 판정의 것)."""
    rev: int
    judged: bool
    changes: list = field(default_factory=list)
    docs: list = field(default_factory=list)
    new: list = field(default_factory=list)
    resolved: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    base: str = ""


def always(f):
    """관문이 스냅숏과 상관없이 막는 지적인가(문서 파일의 지적·D·W9·W11·W12·A1·A2)."""
    return f.code in ("W9", "W11", "W12", "A1", "A2") or f.code[0] == "D" or f.file.startswith("Docs/")


def stage_scope(ds, manifest):
    """관문 단계 범위(E8): 기준 스냅숏 이름표의 changes 행 파일과, 그 파일을 scope에 둔 문서·그 changes 행이 있는 문서.
    이름표가 없거나 그 행이 없으면 None(W8을 모두 막음)."""
    label = (manifest or {}).get("label")
    if not label or ds is None:
        return None
    rows = ds.of("changes",cells={"단계":label})
    if not rows:
        return None
    files = {r.cells["파일"] for r in rows}
    docs = {r.doc for r in rows} | {r.doc for r in ds.of("scope",files=files) if r.cells["파일"] in files}
    return files | docs


def gate(findings, manifest, ds=None, places=None, purpose='completion'):
    """관문(2.6): 기준 스냅숏 때 없던 지적, 늘 막는 지적, 그 단계의 W8(미완성, stage_scope). 돌려주는 값: (막을 지적, 그 가운데 W8 수, 알리기만 한 W8 수)."""
    if purpose not in ("completion", "verification"):
        raise ValueError("Unknown gate purpose: " + str(purpose))
    if purpose == "verification":
        return [], 0, sum(1 for f in findings if f.code == "W8")
    known = set((manifest or {}).get("findings") or [])
    scope = stage_scope(ds, manifest)
    # 우선순위·페이즈(2.13): 지금 페이즈에 맞는 지적은 기준 스냅숏에 있었어도 막는다. 페이즈 표가 없으면 단계 범위(E8)로
    now = set()
    has_phases = ds is not None and bool(ds.of("phases"))
    if has_phases and not ds.issues:
        _, remaining, current, _ = phase.assign(ds, findings, places)
        now = {id(f) for f in remaining.get(current.name, [])} if current is not None else set()
    # 미완성(W8)은 지금 페이즈(표가 없으면 그 단계) 것이면 기준 스냅숏에 있었어도 막고, 새로 생겼어도 그 밖의 것은 알리기만 한다(E7·E8)
    def pending(f):
        if has_phases:
            return f.code == "W8" and id(f) in now
        return f.code == "W8" and (scope is None or f.file in scope)
    fresh = [f for f in findings if pending(f) or (f.code != "W8" and (always(f) or id(f) in now or checkmod.finding_key(f) not in known))]
    blocked = sum(1 for f in fresh if f.code == "W8")
    return fresh, blocked, sum(1 for f in findings if f.code == "W8") - blocked


def exit_code(findings):
    """종료 코드: D·P가 있으면 2, W·L만 있으면 1, 없으면 0."""
    if any(f.code[0] in "DP" for f in findings):
        return 2
    return 1 if findings else 0


def as_dict(f):
    """지적 → dict(API·이력용)."""
    return {"code": f.code, "file": f.file, "line": f.line, "message": f.message, "rule": f.rule}


class Service:
    """패스를 도는 쪽. 문서 표·마지막 결과·지도 자료를 쥔다."""

    RebuildSeconds = 15.0

    def __init__(self, root, unity=None):
        """루트와 Unity 에디터 폴더."""
        self.root, self.unity = root, unity
        self.ds, self.doc_hashes = None, {}
        self._doc_stats = {}
        self._doc_cache = {}
        self.execution_basis = None
        self.review_ds, self.review_hashes = None, {}
        self._review_cache = {}
        self.last = None
        self.map_data = None
        self.presentation = Presentation(root)
        self.previous_map = None
        self.live_url = None
        self.meta = None
        self._watched = None
        self._watch_units = None
        self._watch_rows = None
        self._dependency_rows = ()
        self._dependency_paths = ()
        self._restored_dependency_paths = ()
        self._watched_at = 0.0
        self._workflow_marker = None
        self._last_doc_structure = None
        self._last_code_hashes = None
        self._analysis = None
        self._member_cache = {}
        self.member_work = {"checked": 0, "reused": 0}
        self._rule_cache = {}
        self.rule_work = {"checked": 0, "reused": 0}
        self.stage_work = {}
        self.pipeline_work = {}
        self._analysis_cache = AnalysisCache()
        self._index = {}
        self._ledger = None
        self._ledger_stamp = None
        self._manifest = None
        self._manifest_stamp = None
        self._map_positions = None
        self._phase_input = None
        self.input_runtime = None
        self.runtime_changes = set()
        self.input_commit = None
        self._settings_marker = None
        self.standard_findings = []

    def refresh_runtime(self, ds, manifest, cur, findings, notes, analysis):
        """Replace only changed judgment producers; retain unrelated findings and SQL geometry."""
        changed = self.runtime_changes
        selected = {name for name in cachemod.CachePolicy.CHECKS if 'check.' + name[1:] in changed}
        if 'members' in changed:
            selected.add('_members')
        if 'rules' in changed:
            selected.add('_rules')
        if ds.of('behaviors'):
            selected.add('_behaviors')
        if ds.issues:
            selected &= {'_members', '_coverage', '_rules', '_behaviors', '_parse_errors'}
        geometry = bool(changed & {'analysis.graph', 'analysis.metadata', 'publication-structure',
                                  'check.layers', 'source-records', 'publication-map'})
        needs_meta = geometry or bool(selected & {'_limits', '_interfaces', '_pipeline'}) or 'check.standards' in changed
        judge = checkmod.Judge(self.root, ds, manifest['files'] if manifest else None, cur,
            diffmod.compare(manifest['files'], cur) if manifest else [], self.unity,
            (manifest or {}).get('label'), member_cache=self._member_cache, rule_cache=self._rule_cache,
            analysis_cache=self._analysis_cache, persistent=True)
        prior_notes = dict(self._analysis_cache.get('producerNotes', {}))
        if needs_meta:
            if ds.issues:
                graph = refs.build(self.root, ds, cur, self.unity, self._analysis_cache.setdefault('graphCache', {}))
                rows = refs.layers(ds)
                owners = [refs.layer_of(file, rows) for file in graph.files]
                analysis = layers.Analysis(graph, rows, [row.name if row else None for row in owners])
            else:
                judge._layers()
                analysis = judge.analysis
                selected.add('_layers')
            self.meta = metamod.build(self.root, ds, cur, analysis,
                self._analysis_cache.setdefault('fileMeta', {}), self._analysis_cache.setdefault('relationMeta', {}))
            judge.meta = self.meta
        domains = {'check.' + name[1:] for name in selected}
        removed_notes = {text for domain in domains for text in prior_notes.get(domain, ())}
        notes = [text for text in notes if text not in removed_notes and not text.startswith('허용 목록으로 넘긴 지적 ')]
        judge.findings = [f for f in findings if f.producer not in domains] + judge.findings
        for name in cachemod.CachePolicy.CHECKS:
            if name not in selected or name == '_layers' and needs_meta:
                continue
            if ds.issues and name == '_rules':
                judge.run_docs()
            elif ds.issues and name == '_behaviors':
                import copy
                valid = copy.copy(ds)
                blocked_docs = {issue.file for issue in ds.issues}
                valid.rows = [row for row in ds.rows if row.kind != 'behaviors' or row.doc not in blocked_docs]
                judge.ds = valid
                judge._behaviors()
                judge.ds = ds
                for row in ds.of('behaviors'):
                    if row.doc in blocked_docs:
                        identity = row.cells.get('동작 ID', 'unparsed')
                        judge.findings.append(checkmod.Finding('W12', row.doc, row.line,
                            identity + ': 문서 계약 오류로 동작 검증 보류 — 문서 수정 후 현재 검사 증거 재판정 필요',
                            'behavior:' + identity, 'check.behaviors'))
            else:
                getattr(judge, name)()
        judge._flush_checks(prune=False)
        self.member_work = {key:self.member_work.get(key, 0) + judge.member_work.get(key, 0) for key in ('checked','reused')}
        self.rule_work = {key:self.rule_work.get(key, 0) + judge.rule_work.get(key, 0) for key in ('checked','reused')}
        notes = list(dict.fromkeys(notes + judge.notes))
        suppressed = sum(self._analysis_cache.get('producerSuppressed', {}).values()) + ds.suppressed
        if suppressed:
            notes.append('허용 목록으로 넘긴 지적 %d건' % suppressed)
        self.stage_work.update(runtimeChecks=sorted(domains), runtimeProducers=sorted(changed),
                               runtimeGeometry=geometry, runtimeMetadata=needs_meta)
        return judge.findings, notes, analysis

    def signature(self):
        """감시 대상·문서의 (경로, 수정 시각, 크기). 감시 고리가 바뀜을 알아채는 데 쓴다.
        목록은 변경 알림·주기 보완 때 갱신하고, 안정화 확인 중에는 아는 파일의 stat을 재사용한다."""
        now = time.monotonic()
        if self._watched is None or now - self._watched_at >= self.RebuildSeconds:
            if self.ds is None and self._watch_rows is not None:
                ds = docmod.DocSet()
                ds.rows = [docmod.Row("", 0, "watch", dict(cells)) for cells in self._watch_rows]
                ds.rows.extend(docmod.Row("", 0, kind, dict(cells)) for kind, cells in self._dependency_rows)
            else:
                # Another CLI request may have published changed documents to SQL.
                # Refresh the document basis before using a lazy watch contract.
                self._docs()
                ds = self.review_ds
            self._watch_units = snapshot.watch_set(self.root, ds)
            self._watch_rows = tuple(tuple(sorted(row.cells.items())) for row in ds.of("watch"))
            self._watched = sorted(set(self._watch_units) | set(docmod.doc_paths(self.root)))
            self._dependency_rows = tuple((r.kind, tuple(sorted(r.cells.items()))) for r in ds.of('env') + ds.of('entries')
                                          if r.kind == "env" or r.kind == "entries" and r.cells["종류"] == "장면")
            self._dependency_paths = self.dependency_paths(ds, include_restored=True)
            self._watched_at = now
        out, missing, stats = [], False, {}
        for rel in self._watched:
            path = os.path.join(self.root, rel)
            identity = os.path.normcase(os.path.abspath(path))
            try:
                st = os.stat(path)
            except OSError:
                stats[identity] = None
                missing = True
                continue
            stats[identity] = st
            out.append((rel, st.st_mtime_ns, st.st_size, st.st_ctime_ns))
        # 파일이 사라졌으면(삭제·이동) 다음 호출에서 목록을 다시 만든다 — 새 자리를 곧 잡는다.
        if missing:
            self._watched = None
        for path in set(self._analysis_cache.get("layerInputs", {})) | set(self._dependency_paths):
            identity = os.path.normcase(os.path.abspath(path))
            try:
                st = stats[identity] if identity in stats else os.stat(path)
                if st is None:
                    out.append((path,None,None,None))
                    continue
                stats[identity] = st
                out.append((path,st.st_mtime_ns,st.st_size,st.st_ctime_ns))
            except OSError:
                out.append((path,None,None,None))
        approved_paths = [review.APPROVED_ROOT + "/" + rel for rel in docmod.doc_paths(os.path.join(self.root, review.APPROVED_ROOT))]
        base_names = snapshot.names(self.root)
        base_paths = [snapshot.SNAPSHOT_ROOT + "/" + base_names[-1] + "/manifest.bin"] if base_names else []
        for rel in (settings.FILE, settings.LEGACY_FILE, workflow.STATE_FILE, workflow.LEGACY_FILE, workflow.REQUEST_FILE, workflow.BASELINE_FILE,
                    review.EXECUTION_FILE, review.STATE_FILE, phase.STATE_FILE, *base_paths, *approved_paths):
            try:
                st = os.stat(os.path.join(self.root, rel))
                out.append((rel,st.st_mtime_ns,st.st_size,st.st_ctime_ns))
            except OSError:
                pass
        return tuple(sorted(out))

    def dependency_paths(self, ds=None, include_restored=False):
        """Discover external inputs without rebuilding the ordinary watch set."""
        ds = self.ds if ds is None else ds
        scene_patterns = [p for r in ds.of("entries") if r.cells["종류"] == "장면" for p in globs.split(r.cells["대상"])]
        dependencies = {os.path.abspath(os.path.join(self.root, rel)) for rel in globs.expand(self.root, scene_patterns)} if scene_patterns else set()
        if scene_patterns:
            dependencies.update(os.path.abspath(os.path.join(self.root, rel + ".meta"))
                                for rel in self._watch_units if rel.endswith(".cs"))
        for patterns, _ in refs.environments(ds).values():
            for pattern in patterns:
                pattern = pattern.lstrip("!").replace("{unity}", refs.unity_path(self.unity))
                dependencies.update(os.path.abspath(p) for p in glob.glob(os.path.join(self.root, pattern)) if os.path.isfile(p))
        if include_restored:
            # Before the first graph pass, keep the published dependency paths
            # long enough for the initial signature comparison.
            dependencies.update(self._restored_dependency_paths)
        return tuple(sorted(dependencies))

    def trim_idle(self):
        """Release validated, SQL-backed document copies after a quiet interval; keep analysis and findings."""
        seen = set()
        for ds in (self.ds, self.review_ds):
            if ds is None or id(ds) in seen or not getattr(ds, '_validated', None):
                continue
            try:
                with docmod.design.contract_snapshot(ds.root, ds._validated):
                    seen.add(id(ds))
                    ds._stored = ds._validated
                    ds.__dict__.pop('rows', None)
                    ds._kind_rows.clear()
                    ds._kind_rows_version = None
                    ds.texts = docmod.DocumentTexts(ds)
            except ValueError:
                # A full view may outlive a later SQL contract publication.
                # Keep that view rather than replacing it with another basis.
                continue
        if seen:
            self._review_cache.clear()
            self._doc_cache.clear()
            for key in ('contracts', 'ruleContracts'):
                self._analysis_cache.pop(key, None)
        current = self.map_data
        if current is not None and 'decls' in current and self.presentation.revision == current.get('rev'):
            # Browsers own their rendered arrays. Keep one compressed wire basis
            # for the next delta; a new reader restores geometry from owned SQL.
            packed = getattr(current, 'packed', None)
            if packed is None:
                packed = zlib.compress(marshal.dumps(codemap.live_data(current)), 1)
            geometry = {'layers','mods','files','decls','edges','finds','sig','bases',
                        'variables','modifiers','folders','sourceFiles'}
            header = {key:value for key,value in current.items() if key not in geometry}
            self.map_data = Projection(self.root, header, self._index, self.presentation)
            self.map_data.packed = packed
            del current
        # Historical acknowledgements, resolved findings and old source text
        # already have durable owners. Restore them only for their next use.
        self._ledger = self._ledger_stamp = None
        self._manifest = self._manifest_stamp = None
        snapshot.release(self.root)
        gc.collect()

    def _docs(self, unchanged_hashes=None):
        """검토 대기본과 승인 실행 입력의 원본·해시·캐시를 분리한다."""
        stats = {}
        draft_paths = docmod.doc_paths(self.root)
        authority = ("document" if self.execution_basis is not None else "code") if self.ds is not None else workflow.state(self.root)["authority"]
        sources = [(self.root, draft_paths)]
        if authority == "document":
            approved_root = os.path.join(self.root, review.APPROVED_ROOT)
            sources.append((approved_root, docmod.doc_paths(approved_root)))
        for base, paths in sources:
            for rel in paths:
                full = os.path.join(base, rel)
                st = os.stat(full)
                stats[full] = (st.st_mtime_ns, st.st_ctime_ns, st.st_size)
        for rel in (review.EXECUTION_FILE, workflow.STATE_FILE, workflow.LEGACY_FILE):
            metadata = os.path.join(self.root, rel)
            if os.path.isfile(metadata):
                st = os.stat(metadata)
                stats[metadata] = (st.st_mtime_ns, st.st_ctime_ns, st.st_size)
        if self.ds is not None and self._doc_stats == stats:
            validated = getattr(self.ds,'_validated',None)
            if (unchanged_hashes is None or validated is None or
                    design.contract_state(self.root,self.ds.source_root,validated['input']) is not None):
                return self.ds, self.doc_hashes
            # Namespace-dependent D9 must be refreshed even when document bytes
            # are unchanged. This follows the same persisted dependency check as
            # a cold process; an in-memory DocSet is not an authority bypass.
            self.review_ds = None
        current_authority = workflow.state(self.root)["authority"]
        if current_authority != authority:
            authority = current_authority
            stats = {}
            sources = [(self.root, draft_paths)]
            if authority == "document":
                approved_root = os.path.join(self.root, review.APPROVED_ROOT)
                sources.append((approved_root, docmod.doc_paths(approved_root)))
            for base, paths in sources:
                for rel in paths:
                    full = os.path.join(base, rel)
                    st = os.stat(full)
                    stats[full] = (st.st_mtime_ns, st.st_ctime_ns, st.st_size)
            for rel in (review.EXECUTION_FILE, workflow.STATE_FILE, workflow.LEGACY_FILE):
                metadata = os.path.join(self.root, rel)
                if os.path.isfile(metadata):
                    st = os.stat(metadata)
                    stats[metadata] = (st.st_mtime_ns, st.st_ctime_ns, st.st_size)
        hashes = {}
        try:
            if unchanged_hashes is not None and set(unchanged_hashes) == set(draft_paths):
                # Server.sync compared the persisted input inventory first. A
                # source-only change cannot alter these published document hashes.
                hashes.update(unchanged_hashes)
            else:
                for rel in draft_paths:
                    with open(os.path.join(self.root, rel), "rb") as stream:
                        hashes[rel] = hashlib.sha256(stream.read()).hexdigest()
            if self.review_ds is None or hashes != self.review_hashes:
                self.review_ds = docmod.load(self.root, paths=draft_paths, cache=self._review_cache,
                                             reuse=unchanged_hashes is not None)
        except (OSError, UnicodeError) as error:
            self.review_ds = docmod.DocSet()
            self.review_ds.issues.append(docmod.Issue("D1", "Docs", 1, "대기본 읽기 실패: " + str(error)))
        self.review_hashes = hashes
        if authority == "document":
            published = ledger.read_binary(self.root, review.EXECUTION_FILE, None)
            if ("_approved_ds" not in self._doc_cache and self.review_ds is not None
                    and published is not None and published.get("status") == "ready"
                    and published.get("documents") == hashes):
                # Reuse parsing only after execution_basis verifies the actual
                # approved bytes have this exact fingerprint. Never use it on
                # a missing, changed, or failed approved input.
                import copy
                import json
                identity = hashlib.sha256(json.dumps(sorted(hashes.items()), ensure_ascii=False).encode("utf-8")).hexdigest()
                same_bytes = copy.deepcopy(self.review_ds)
                same_bytes.source_root = os.path.abspath(os.path.join(self.root, review.APPROVED_ROOT))
                self._doc_cache["_approved_ds"] = (identity, same_bytes)
            self.ds, self.execution_basis = review.execution_basis(self.root, self._doc_cache)
            self.doc_hashes = dict(self.execution_basis["documents"])
        else:
            self.ds, self.doc_hashes = self.review_ds, dict(hashes)
            self.execution_basis = None
        self._doc_stats = stats
        return self.ds, self.doc_hashes

    def _judge(self, ds, manifest, cur, asset_changes=None):
        """판정. 문서 오류가 있어도 가능한 선언·파일 누락 대조를 계속한다.

        잘못된 문서로 전체 규칙의 완료를 판정하지 않으며 막힘은 유지한다.
        돌려주는 값: (지적, 참고, 계층 판정, 막힘).
        """
        if ds.issues:
            stage_started=time.perf_counter()
            issues = [checkmod.Finding(i.code, i.file, i.line, i.message, producer="check.documents") for i in ds.issues]
            base_files = manifest["files"] if manifest else None
            judge = checkmod.Judge(self.root, ds, base_files, cur, [], self.unity,
                                   member_cache=self._member_cache, rule_cache=self._rule_cache,
                                   analysis_cache=self._analysis_cache, persistent=True)
            judge._members()
            self.member_work = dict(judge.member_work)
            self.rule_work = dict(judge.rule_work)
            self.stage_work = dict(judge.stage_work)
            judge._coverage()
            judge.run_docs()
            judge._flush_checks()
            self.stage_work["membersAndCoverage"]=round(time.perf_counter()-stage_started,4)
            issues.extend(judge.findings)
            issues.extend(checkmod.Finding("P1", file, 1, "파싱 실패: " + entry["error"], producer="check.parse_errors")
                          for file, entry in cur.items() if entry.get("error"))
            # 코드 구조는 문서 판정과 별개다. 오류가 있는 문서로 코드의 옳고
            # 그름을 판단하지 않되, 현재 코드의 탐색 지도는 계속 제공한다.
            stage_started=time.perf_counter()
            graph = refs.build(self.root, ds, cur, self.unity,
                               self._analysis_cache.setdefault("graphCache", {}))
            self.stage_work["referenceGraph"]=round(time.perf_counter()-stage_started,4)
            rows = refs.layers(ds)
            symbol_files = {rel for rel, entry in cur.items() if entry.get("unit") == "심볼"}
            file_layers = []
            for rel in graph.files:
                layer = refs.layer_of(rel, rows)
                file_layers.append(layer.name if layer and rel in symbol_files else None)
            analysis = layers.Analysis(graph, rows, file_layers)
            stage_started=time.perf_counter()
            self.meta = metamod.build(self.root, ds, cur, analysis,
                                     self._analysis_cache.setdefault("fileMeta", {}),
                                     self._analysis_cache.setdefault("relationMeta", {}))
            self.stage_work["metadata"]=round(time.perf_counter()-stage_started,4)
            # A malformed document blocks completion, not independent behavior
            # evidence. Keep blocked contracts visible instead of dropping W12.
            import copy
            blocked_docs = {issue.file for issue in ds.issues}
            contracts = ds.of("behaviors")
            valid = copy.copy(ds)
            valid.rows = [r for r in ds.rows if r.kind != "behaviors" or r.doc not in blocked_docs]
            judge.ds, judge.analysis = valid, analysis
            judge.findings = []
            judge._behaviors()
            issues.extend(judge.findings)
            for row in contracts:
                if row.doc in blocked_docs:
                    identity = row.cells.get("동작 ID", "unparsed")
                    issues.append(checkmod.Finding("W12",row.doc,row.line,
                        identity + ": 문서 계약 오류로 동작 검증 보류 — 문서 수정 후 현재 검사 증거 재판정 필요",
                        "behavior:" + identity, "check.behaviors"))
            notes = ["문서 오류: 전체 규칙 완료 판정은 차단; 읽을 수 있는 선언·파일 누락·문서 규칙 대조와 현재 코드 구조 표시는 계속 수행"]
            if graph.error:
                owner = next((row for row in ds.of("compile_variant")
                              if row.cells.get("검사 파일") and row.cells["검사 파일"] in graph.error), None)
                location = (owner.doc, owner.line) if owner else (ds.issues[0].file, ds.issues[0].line)
                issues.append(checkmod.Finding("P2", *location, "참조 그래프를 만들 수 없음: " + graph.error, producer="check.layers"))
                notes.append("코드 구조 참조 해석 오류: " + graph.error)
            return issues, notes, analysis, True
        base_files = manifest["files"] if manifest else None
        changes = diffmod.compare(base_files, cur) if base_files is not None else []
        judge = checkmod.Judge(self.root, ds, base_files, cur, changes, self.unity, (manifest or {}).get("label"),
                               member_cache=self._member_cache, rule_cache=self._rule_cache,
                               analysis_cache=self._analysis_cache, persistent=True,asset_changes=asset_changes)
        findings, notes = judge.run()
        self.member_work = dict(judge.member_work)
        self.rule_work = dict(judge.rule_work)
        self.stage_work = dict(judge.stage_work)
        self.meta = judge.meta
        return findings, notes, judge.analysis, False

    def run(self, trigger, force=False, review_only=False, changed_paths=None, progress=None):
        """완료한 패스만 게시한다. 실패한 중간 캐시는 폐기해 다음 패스가 위치를 중복 이동하지 않게 한다."""
        published = (self.map_data,self.previous_map,self._workflow_marker)
        try:
            return self._run(trigger,force,review_only,changed_paths,progress)
        except Exception:
            self._analysis = None
            self._ledger = None
            self._ledger_stamp = None
            self._map_positions = None
            self.meta = None
            self._index = {}
            self._analysis_cache.clear()
            self._member_cache.clear()
            self._rule_cache.clear()
            self.map_data,self.previous_map,self._workflow_marker = published
            raise

    def _run(self, trigger, force=False, review_only=False, changed_paths=None, progress=None):
        """패스 한 번(2.10). 같은 입력의 검토 갱신은 승인 의존 지적만 재판정하고, 결과 게시는 공통 경로를 쓴다."""
        self.pipeline_work = {}
        previous_time = time.perf_counter()
        def mark(name):
            nonlocal previous_time
            current_time = time.perf_counter()
            self.pipeline_work[name] = round(current_time - previous_time, 4)
            previous_time = current_time
            if progress:
                progress(name)
        old_review = dict(self.review_hashes)
        if self.review_ds is None:
            import json
            try:
                with open(os.path.join(self.root, snapshot.REPORT_ROOT, "latest.json"), encoding="utf-8") as stream:
                    previous_report = json.load(stream)
                old_review = previous_report.get("documentReview", {}).get("hashes", old_review)
                with open(os.path.join(self.root,snapshot.REPORT_ROOT,'map-annotations.json'),encoding='utf-8') as stream:
                    annotations = json.load(stream)
                if (previous_report.get('rev') is not None and previous_report.get('rev') == annotations.get('rev')
                        and previous_report.get('completion',{}).get('rev') == annotations['rev']):
                    manifests = {domain:entries for domain,entries in annotations.get('publicationCache',{}).items()
                                 if annotations.get('publicationVersions',{}).get(domain) == cachemod.POLICY.versions.get(domain)}
                    retained = self._analysis_cache.setdefault('publication',{})
                    if 'publication-priority' in manifests and 'priority' in previous_report:
                        retained['publication-priority'] = {'ranking':(manifests['publication-priority']['ranking'],previous_report['priority'])}
                    for domain, value in (('publication-report', previous_report),
                            ('publication-comparison', annotations.get('comparison')),
                            ('publication-phases', annotations.get('phases')),
                            ('publication-document-links', annotations.get('documentLinks'))):
                        if domain in manifests and 'current' in manifests[domain]:
                            retained[domain] = {'current': (manifests[domain]['current'], value)}
                    if 'publication-plans' in manifests:
                        grouped = {file:[] for file in manifests['publication-plans']}
                        for item in annotations.get('implementationPlans',[]):
                            grouped[item['plan']['file']].append(item)
                        retained['publication-plans'] = {file:(key,grouped[file]) for file,key in manifests['publication-plans'].items()}
            except (OSError, ValueError, KeyError, TypeError):
                self._analysis_cache.pop('publication',None)
        unchanged_hashes = (self.map_data.get("documentReview",{}).get("hashes")
            if not force and self.last is not None and self.map_data is not None and changed_paths
            and all(not os.path.isabs(path) and path.endswith((".cs",".py")) for path in changed_paths) else None)
        ds, hashes = self._docs(unchanged_hashes)
        review_changed = old_review != self.review_hashes
        with ledger.locked(self.root):
            mark("lock")
            published = ledger.read_binary(self.root, review.EXECUTION_FILE, None)
            if self.execution_basis and published is not None and (published.get("id") != self.execution_basis["id"]
                    or published.get("status") != self.execution_basis["status"]):
                raise ValueError("승인 입력이 판정 시작 전에 바뀜 — 재시도 필요")
            self.stage_work = {}
            self.member_work = {"checked": 0, "reused": 0}
            self.rule_work = {"checked": 0, "reused": 0}
            mode = workflow.state(self.root)
            request_path = os.path.join(self.root, workflow.REQUEST_FILE)
            marker = (mode["mode"], mode["codePolicy"], os.stat(request_path).st_mtime_ns if os.path.exists(request_path) else 0)
            force = force or (marker != self._workflow_marker and
                              (self._workflow_marker is not None or mode["authority"] == "code"))
            force = force or bool(self.runtime_changes & {'restart-orchestration', 'check.documents'})
            if self.runtime_changes and self.last is not None and any(not f.producer for f in self.last.findings):
                force = True
            mark("docs")
            config = settings.load(self.root)
            config_marker = repr({k:v for k,v in config.items() if k != 'locale'}) if config else None
            config_changed = config_marker != self._settings_marker
            if config_changed:
                self._watched, self._watch_units = None, None
                changed_paths = None
            source_ds = self.review_ds or ds
            watch_rows = tuple(tuple(sorted(row.cells.items())) for row in source_ds.of("watch"))
            if watch_rows != self._watch_rows:
                self._watched, self._watch_units = None, None
                self._watch_rows = watch_rows
                changed_paths = None
            watched = self._watch_units if not force and watch_rows == self._watch_rows else None
            old_index = self._index
            if any(name.startswith('parse.') for name in self.runtime_changes):
                parser_files = {file for file, entry in old_index.summaries() if entry.get('parser') != snapshot.parser_input(file)} if isinstance(old_index, ledger.SourceIndex) else {
                    file for file, entry in old_index.items() if entry.get('parser') != snapshot.parser_input(file)}
                changed_paths = set(changed_paths or ()) | parser_files
            input_basis = hashlib.sha256(repr((self.input_runtime,sorted(hashes.items()),marker)).encode()).hexdigest()
            pending_input = change_store.pending(self.root,input_basis)
            committed_input = None
            input_commit = None
            if (pending_input and pending_input["compatible"] and not force and old_index
                    and changed_paths is not None and set(changed_paths) <= pending_input["changed"]):
                saved = change_store.read(self.root,pending_input["id"])
                same = True
                for file in pending_input["scope"]:
                    expected = saved["after"].get(file)
                    try:
                        with open(os.path.join(self.root,file),"rb") as stream:
                            actual = hashlib.sha256(stream.read()).hexdigest()
                    except FileNotFoundError:
                        actual = None
                    if actual != (expected or {}).get("sha256"):
                        same = False
                        break
                if same:
                    committed_input,input_commit = saved,pending_input["id"]
            old_texts = {}
            if (committed_input is None and not force and changed_paths and old_index
                    and self.last is not None and self.map_data is not None):
                for rel in changed_paths:
                    if rel in old_index and rel.endswith(".py"):
                        saved = ledger.read_table(self.root,snapshot.CACHE_ROOT + "/" + rel + ".row",{})
                        if saved.get("entry",{}).get("sha256") == old_index[rel].get("sha256"):
                            old_texts[rel] = saved.get("source","")
            if committed_input is not None:
                cur = old_index.copy()
                for file in pending_input["scope"]:
                    if file in committed_input["after"]: cur[file] = committed_input["after"][file]
                    elif file in cur: del cur[file]
            else:
                cur = snapshot.current(self.root, source_ds, previous=old_index, watched=watched,
                                       changed_paths=changed_paths if not force else None)
            self._index = cur
            mark("index")
            base_folder = os.path.join(self.root,snapshot.SNAPSHOT_ROOT)
            base_stat = os.stat(base_folder) if os.path.isdir(base_folder) else None
            base_path = os.path.join(base_folder,self._manifest["name"],"manifest.bin") if self._manifest else None
            item_stat = os.stat(base_path) if base_path and os.path.isfile(base_path) else None
            base_stamp = (base_stat.st_mtime_ns if base_stat else None,
                          (item_stat.st_mtime_ns,item_stat.st_ctime_ns,item_stat.st_size) if item_stat else None)
            if force or self._manifest_stamp != base_stamp:
                self._manifest = snapshot.load(self.root)
                if self._manifest:
                    item_stat = os.stat(os.path.join(base_folder,self._manifest["name"],"manifest.bin"))
                    base_stamp = (base_stat.st_mtime_ns,(item_stat.st_mtime_ns,item_stat.st_ctime_ns,item_stat.st_size))
                self._manifest_stamp = base_stamp
            manifest = self._manifest
            mark("baseline")
            ledger_stamp = ledger.stamp(self.root)
            if self._ledger is None or ledger_stamp != self._ledger_stamp:
                self._ledger = ledger.load(self.root,lazy=True)
                self._ledger_stamp = ledger_stamp
            led = self._ledger
            rebuilding = bool(led and led.get("rebuildPending"))
            if rebuilding:
                force = True
                # Old current-analysis rows were explicitly discarded; retain the
                # warning/revision history and start the new source baseline here.
                led["files"] = cur
            mark("ledgerRead")
            fresh_start = led is None
            if fresh_start and manifest is not None:
                led = ledger.start(manifest, cur, hashes, [])
            changes = ledger.diff_since(led, cur,changed_paths if not force and old_index else None) if led is not None else []
            docs = ledger.changed_docs(led, hashes) if led is not None else []
            previous_files = old_index or (led or {}).get("files",{})
            scene_patterns = [pattern for row in ds.of("entries") if row.cells["종류"] == "장면"
                              for pattern in globs.split(row.cells["대상"])]
            asset_changes = {os.path.abspath(os.path.join(self.root,path)) for path in changed_paths
                             if os.path.abspath(os.path.join(self.root,path)) in self._analysis_cache.get("layerInputs",{})
                             or globs.matches(path,scene_patterns)} if changed_paths is not None and not force else None
            assets_changed = bool(asset_changes) or (asset_changes is None and bool(scene_patterns))
            candidate_files = changed_paths if changed_paths is not None and not force else set(previous_files) | set(cur)
            changed_files = {rel for rel in candidate_files
                             if (previous_files.get(rel,{}).get("sha256"), previous_files.get(rel,{}).get("parser")) !=
                                (cur.get(rel,{}).get("sha256"), cur.get(rel,{}).get("parser"))}
            if pending_input is not None:
                changed_files.update(pending_input["changed"])
            scoped_body = bool(changed_files and changed_files <= old_texts.keys() and changed_files <= cur.keys() and not docs and not force
                               and not assets_changed and not review_only
                               and not any(name.startswith(('parse.', 'file-meta.', 'analysis.')) for name in self.runtime_changes)
                               and not (ds.issues and self.execution_basis and self.execution_basis.get("blockedFiles")
                                        and "*" not in self.execution_basis["blockedFiles"]))
            scoped_fallback = ("forced-or-runtime-input" if force else "document-input" if docs else
                               "no-compatible-python-source-publication" if not scoped_body else "")
            reference_files = set()
            reference_owners = set(changed_files)
            scoped_deltas = {}
            scoped_reference_seconds = 0.0
            body_graph = refs.Graph()
            if scoped_body:
                for rel in changed_files:
                    before,after = previous_files[rel],cur[rel]
                    text = snapshot.read_text(self.root,rel)
                    edits = diffmod.line_edits(old_texts[rel],text)
                    shape = lambda entry,move:[{k:diffmod.move_line(v,edits) if move and k in ("line","end") else v
                        for k,v in s.items() if k not in ("body","value")} for s in entry.get("symbols",[])]
                    if before.get("error") or after.get("error") or shape(before,True) != shape(after,False):
                        scoped_body = False
                        scoped_fallback = "declaration-or-parse-change"
                        break
                    scoped_deltas[rel] = edits
                    reference_files.add(rel)
            if scoped_body and reference_files:
                reference_started = time.perf_counter()
                reference_layers = refs.layers(ds)
                reference_files = {rel for rel in reference_files if refs.layer_of(rel,reference_layers)}
                prior_refs = {rel:ledger.read_table(self.root,refs.PYTHON_RECORDS + "/" + rel + ".row",None) for rel in reference_files}
                if any(value is None for value in prior_refs.values()):
                    scoped_body = False
                    scoped_fallback = "missing-reference-record"
                elif reference_files:
                    selected_cache = {}
                    refs.python(self.root,cur,reference_layers,body_graph,selected_cache,only_files=reference_files)
                    reference_owners.update(selected_cache)
                    for rel,old in prior_refs.items():
                        retained = selected_cache[rel][4]
                        edits = scoped_deltas[rel]
                        moved_decls = [dict(d,line=diffmod.move_line(d["line"],edits),end=diffmod.move_line(d["end"],edits))
                                       for d in old["syntax"]["declarations"]]
                        moved_edges = tuple((a,b,diffmod.move_line(line,edits),write,guess) for a,b,line,write,guess in old["edges"])
                        if moved_decls != retained["syntax"]["declarations"] or moved_edges != retained["edges"]:
                            scoped_body = False
                            scoped_fallback = "reference-topology-change"
                            break
                scoped_reference_seconds = time.perf_counter() - reference_started
            deltas = {rel:cur[rel]["delta"]["edits"] for rel in changed_files
                      if rel in cur and rel in old_index and cur[rel].get("delta",{}).get("positionOnly")
                      and cur[rel]["delta"]["previous"] == old_index[rel]["sha256"]}
            position_update = (bool(deltas) and len(deltas) == len(changed_files) and not docs and not force
                               and not ds.issues and self.last is not None and self._analysis is not None
                               and self.map_data is not None and self.meta is not None
                               and all(rel in self._analysis_cache.get("fileMeta",{}) and rel in self.meta.file_records
                                       for rel in deltas)
                               and "spans" in self._analysis_cache.get("relationMeta",{}).get("refs",{}))
            if position_update:
                inputs = self._analysis_cache.get("layerInputs",{})
                if changed_paths is not None:
                    position_update = not any(os.path.abspath(os.path.join(self.root,path)) in inputs for path in changed_paths)
                else:
                    for path,(fingerprint,_) in inputs.items():
                        try:
                            stat = os.stat(path)
                            if (stat.st_mtime_ns,stat.st_ctime_ns,stat.st_size) != fingerprint[:3]:
                                position_update = False
                                break
                        except FileNotFoundError:
                            position_update = False
                            break
            mark("diff")
            if (led is not None and not changes and not docs and not changed_files and not assets_changed and not force
                    and self.last is not None and self._analysis is not None and not review_changed and not review_only and not config_changed and not self.runtime_changes):
                self.last = PassResult(led["rev"], False, [], [], [], [], self.last.findings, self.last.notes, self.last.base)
                return self.last
            # 문서 본문만 바뀌었고 표·코드는 그대로면 전역 코드 그래프와 규칙 판정을 재사용한다.
            # 표 행의 내용/위치까지 같아야 하므로 scope·member·rule 변경은 항상 전체 판정으로 간다.
            doc_structure = self._last_doc_structure
            if doc_structure is None and getattr(ds,'_stored',None) is not None:
                doc_structure = bytes.fromhex(ds._stored['structure'])
            if docs or doc_structure is None:
                structure_hash = hashlib.sha256()
                for row in ds.rows:
                    structure_hash.update(repr((row.doc, row.kind, row.line, sorted(row.cells.items()))).encode("utf-8"))
                    if row.kind in {"architecture", "architecture-graph"}:
                        structure_hash.update(row.parsed.get("inputHash", "").encode("ascii"))
                    structure_hash.update(b"\0")
                for issue in ds.issues:
                    structure_hash.update(repr((issue.code, issue.file, issue.line, issue.message)).encode("utf-8"))
                    structure_hash.update(b"\0")
                structure_hash.update(repr(ds.suppressed).encode("utf-8"))
                doc_structure = structure_hash.digest()
            code_hashes = {rel: entry.get("sha256") for rel, entry in (cur.summaries() if isinstance(cur,ledger.SourceIndex) else cur.items()) if entry.get("unit") == "심볼"}
            text_only = (self.last is not None and self._analysis is not None and not force and not assets_changed and not changes and bool(docs)
                         and not ds.issues and doc_structure == self._last_doc_structure
                         and code_hashes == self._last_code_hashes)
            review_refresh = ((review_only or review_changed or config_changed) and not force
                              and self.last is not None and self._analysis is not None
                              and not assets_changed and not changes and not docs and not changed_files
                              and doc_structure == self._last_doc_structure and code_hashes == self._last_code_hashes)
            if scoped_body:
                self.meta = metamod.refresh_body(self.root,ds,None,cur,changed_files,
                                                 self._analysis_cache.setdefault("fileMeta",{}),scoped_deltas)
                if self.meta is None:
                    scoped_body = False
                    scoped_fallback = "metadata-shape-or-record-mismatch"
            scoped_sources = None
            scoped_graph = None
            if (changed_files and not force and not docs and not assets_changed
                    and not review_only and self.last is not None and self.map_data is not None
                    and all(f.endswith((".py",".cs")) for f in changed_files)):
                if pending_input and pending_input["compatible"]:
                    saved = committed_input or change_store.read(self.root,pending_input["id"])
                    expected = saved["after"]
                    same = all((cur.get(f) or {}).get("sha256") == expected.get(f,{}).get("sha256")
                               for f in pending_input["scope"])
                    if (same and changed_files <= pending_input["changed"] and
                            (saved["diagnosed"] or pending_input["scope"] <= pending_input["referenceScope"])):
                        committed_input,input_commit = saved,pending_input["id"]
                        scoped_graph = refs.Graph(**saved["graph"])
                        scoped_sources = pending_input["scope"]
                    else:
                        committed_input = None
                if committed_input is None:
                    requested = changed_files | (pending_input["scope"] if pending_input else set())
                    graph_cache = {"previousFiles":{f:previous_files.get(f,{}) for f in requested}}
                    if scoped_body:
                        scoped_graph = body_graph
                        scoped_sources = set(reference_owners)
                        graph_cache["beforeEdges"] = {(file,*row) for file,saved in prior_refs.items() for row in saved["edges"]} if reference_files else set()
                    else:
                        scoped_graph = refs.build(self.root,ds,cur,self.unity,graph_cache,only_files=requested)
                        scoped_sources = set(graph_cache["scopeFiles"])
                    source_before = {f:previous_files[f] for f in scoped_sources if f in previous_files}
                    source_after = {f:cur[f] for f in scoped_sources if f in cur}
                    before_scope = graph_cache.get("beforeScope",scoped_sources)
                    before_edges = graph_cache.get("beforeEdges",())
                    if pending_input and pending_input["compatible"] and not pending_input["diagnosed"]:
                        # An interrupted body pass may have committed only the
                        # changed owner's reference fragment. Re-diagnose the
                        # affected SQL scope, retaining its original before facts.
                        abandoned = change_store.read(self.root,pending_input["id"])
                        source_before.update(abandoned["before"])
                        before_scope = set(before_scope) | pending_input["scope"]
                        before_edges = set(before_edges) | set(abandoned["before_edges"])
                    units = [dict(u,data=refs.compilation_data(u)) for u in scoped_graph.compilations]
                    for file in scoped_sources:
                        try:
                            with open(os.path.join(self.root,file),"rb") as stream:
                                actual = hashlib.sha256(stream.read()).hexdigest()
                        except FileNotFoundError:
                            actual = None
                        if actual != source_after.get(file,{}).get("sha256"):
                            raise ValueError("source changed during input preparation: " + file)
                    input_commit = change_store.commit(self.root,input_basis,source_before,source_after,
                        before_scope,scoped_sources,vars(scoped_graph),before_edges,units,
                        reference_scope=reference_files if scoped_body else scoped_sources)
                    committed_input = change_store.read(self.root,input_commit)
                    scoped_graph = refs.Graph(**committed_input["graph"])
                # The judge consumes the committed snapshot, not live mutable cache rows.
                for file,entry in committed_input["after"].items(): cur[file] = entry
                self.input_commit = input_commit
                if scoped_body: scoped_sources = None
            runtime_only = bool(self.runtime_changes and not force and not docs and not changed_files
                                and not assets_changed and self.last is not None and self.map_data is not None)
            reused_diagnosis = True
            if runtime_only:
                findings, notes, analysis, blocked = list(self.last.findings), list(self.last.notes), None, bool(ds.issues)
                self.stage_work = {'runtimeOnly': True, 'fullGraphBuilds': 0, 'fullMetadataBuilds': 0}
            elif scoped_body:
                judge = checkmod.Judge(self.root,ds.scoped(changed_files),manifest["files"] if manifest else None,cur,
                    diffmod.compare({f:manifest["files"][f] for f in changed_files if f in manifest["files"]},
                                    {f:cur[f] for f in changed_files}) if manifest else [],self.unity,
                    (manifest or {}).get("label"),member_cache=self._member_cache,rule_cache=self._rule_cache,
                    analysis_cache=self._analysis_cache,persistent=True)
                if ds.issues:
                    judge._members(changed_files)
                    judge._flush_checks(prune=False)
                    member = lambda f:not f.rule and f.code in ("W2","W3","W4","W8") and f.file in cur
                    existing = self.last.findings
                    at = next((i for i,f in enumerate(existing) if member(f)),len(ds.issues))
                    replaced = [f for f in existing if member(f) and f.file not in changed_files] + judge.findings
                    replaced.sort(key=lambda f:f.file)
                    findings = [f for f in existing[:at] if not member(f)] + replaced + [f for f in existing[at:] if not member(f)]
                else:
                    judge.meta = self.meta
                    findings = judge.run_positions(self.last.findings,scoped_deltas,body=True)
                self.member_work,self.rule_work = dict(judge.member_work),dict(judge.rule_work)
                notes,analysis,blocked = self.last.notes,None,bool(ds.issues)
                self.stage_work = {"bodyUpdate":len(changed_files),"sqlScopedRestart":len(changed_files),
                                   "analysisFiles":sorted(reference_owners),"fullGraphBuilds":0,"fullMetadataBuilds":0,
                                   "selectedReferenceSeconds":round(scoped_reference_seconds,4)}
            elif scoped_sources is not None:
                selected = {f:cur[f] for f in sorted(scoped_sources) if f in cur}
                base = {f:manifest["files"][f] for f in scoped_sources if f in manifest["files"]} if manifest else None
                judge = checkmod.Judge(self.root,ds.scoped(scoped_sources),base,selected,
                    diffmod.compare(base,selected) if base is not None else [],self.unity,
                    (manifest or {}).get("label"),member_cache=self._member_cache,rule_cache=self._rule_cache,
                    analysis_cache=AnalysisCache(),persistent=True)
                scoped_contract_errors = (ds.issues and self.execution_basis and self.execution_basis.get("blockedFiles")
                                          and "*" not in self.execution_basis["blockedFiles"])
                if committed_input and committed_input["diagnosed"]:
                    findings = [checkmod.Finding(*row) for row in committed_input["findings"]]
                    rows = refs.layers(ds)
                    file_layers = [refs.layer_of(f,rows) for f in scoped_graph.files]
                    analysis = layers.Analysis(scoped_graph,rows,[r.name if r else None for r in file_layers],
                        committed_input["bad_edges"],committed_input["status"])
                    self.meta = metamod.build(self.root,ds,selected,analysis,{}, {},only_files=scoped_sources)
                elif ds.issues and not scoped_contract_errors:
                    judge._members(scoped_sources)
                    judge._coverage()
                    judge.findings.extend(checkmod.Finding("P1",f,1,"파싱 실패: " + entry["error"], producer="check.parse_errors")
                                          for f,entry in selected.items() if entry.get("error"))
                    judge._flush_checks(prune=False)
                    rows = refs.layers(ds)
                    file_layers = [refs.layer_of(f,rows) for f in scoped_graph.files]
                    analysis = layers.Analysis(scoped_graph,rows,[r.name if r else None for r in file_layers])
                    owners = {'check.members', 'check.coverage', 'check.parse_errors'}
                    affected = lambda f:f.file in scoped_sources and f.producer in owners
                    findings = [f for f in self.last.findings if not affected(f)] + judge.findings
                    self.meta = metamod.build(self.root,ds,selected,analysis,{}, {},only_files=scoped_sources)
                else:
                    findings,notes,analysis,blocked = judge.run(self.last.findings,scoped_sources,scoped_graph,cur)
                    self.meta = judge.meta
                notes,blocked = self.last.notes,bool(ds.issues)
                self.member_work,self.rule_work = dict(judge.member_work),dict(judge.rule_work)
                self.stage_work = {"sqlScopedRestart":len(changed_files),"analysisFiles":sorted(scoped_sources),
                                   "fullGraphBuilds":0,"fullMetadataBuilds":0,"relationshipUpdate":len(scoped_sources),
                                   "inputCommit":input_commit,"resumedCommit":bool(pending_input and input_commit==pending_input["id"]),
                                   "diagnosisReused":bool(committed_input and committed_input["diagnosed"])}
            elif position_update:
                previous = self._analysis
                graph = refs.move_positions(previous.graph,deltas)
                analysis = layers.Analysis(graph,previous.rows,previous.file_layer,previous.bad_edges,previous.status)
                self.meta = metamod.move_positions(self.meta,cur,deltas,self._analysis_cache["fileMeta"],
                                                  self._analysis_cache["relationMeta"])
                judge = checkmod.Judge(self.root,ds,manifest["files"] if manifest else None,cur,[],self.unity,
                                       (manifest or {}).get("label"),member_cache=self._member_cache,
                                       rule_cache=self._rule_cache,analysis_cache=self._analysis_cache,persistent=True)
                findings = judge.run_positions(self.last.findings,deltas)
                self.member_work,self.rule_work = dict(judge.member_work),dict(judge.rule_work)
                notes,blocked = self.last.notes,False
                self.stage_work = {"positionUpdate": len(deltas)}
                # 이전 판정은 불변 입력으로 유지한다. 다음 의미 변경의 shape/graph 대조가
                # 현재 위치와 참조를 검증하므로 원래 위치로 복원한 입력도 안전하게 재사용한다.
            elif review_refresh:
                # Approval, code, and scene inputs are unchanged. Draft review
                # findings are replaced below; retain the approved judgement.
                findings = [f for f in self.last.findings if f.code not in ("A1", "A2")
                            and not f.message.startswith("대기본: ")]
                notes, analysis = self.last.notes, self._analysis
                blocked = any(f.code.startswith(("D", "P")) for f in findings)
                self.stage_work = {"reviewUpdate": 1}
            elif text_only:
                judge = checkmod.Judge(self.root, ds, manifest["files"] if manifest else None, cur, [], self.unity,
                                       (manifest or {}).get("label"), analysis_cache=self._analysis_cache)
                judge.run_docs()
                judge._review()
                doc_rules = {r.cells["규칙"] for r in ds.of("rules")
                             if r.cells["대상"] in ("문서경로", "문서내용")}
                self.meta = metamod.build(self.root, ds, cur, self._analysis,
                                          self._analysis_cache.setdefault("fileMeta", {}),
                                          self._analysis_cache.setdefault("relationMeta", {}))
                judge.meta = self.meta
                judge._limits()
                findings = [f for f in self.last.findings if f.rule not in doc_rules and f.code not in ("A1", "A2", "S1", "S2", "S4")]
                findings.extend(judge.findings)
                notes = list(dict.fromkeys(self.last.notes + judge.notes))
                analysis, blocked = self._analysis, False
            else:
                reused_diagnosis = False
                scoped_contract_errors = (ds.issues and self.execution_basis
                    and self.execution_basis.get("blockedFiles") and "*" not in self.execution_basis["blockedFiles"])
                if scoped_contract_errors:
                    cached = self._doc_cache.get("_valid_declarations")
                    if cached is None or cached[0] is not ds:
                        import copy
                        valid_declarations = copy.copy(ds)
                        valid_declarations.issues = []
                        cached = (ds, valid_declarations)
                        self._doc_cache["_valid_declarations"] = cached
                    valid_declarations = cached[1]
                    # These are resolved behavior-link errors, not malformed
                    # declarations. Run all code/behavior checks and retain
                    # every contract error and outstanding verification duty.
                    findings, notes, analysis, blocked = self._judge(valid_declarations, manifest, cur,asset_changes)
                    findings.extend(checkmod.Finding(i.code, i.file, i.line, i.message, producer="check.documents") for i in ds.issues)
                    blocked = True
                    notes = list(notes) + ["승인 계약의 국소 연결 오류를 유지하면서 코드·검증 의무 판정을 계속함"]
                else:
                    findings, notes, analysis, blocked = self._judge(ds, manifest, cur,asset_changes)
                if changed_files:
                    self.stage_work["fullFallbackReason"] = scoped_fallback or "unproven-input-scope"
            if reused_diagnosis and (self.runtime_changes or (ds.issues and changed_files and ds.of('behaviors'))):
                findings, notes, analysis = self.refresh_runtime(ds, manifest, cur, findings, notes, analysis)
            standards_work = {}
            self.standard_findings = self.standard_findings if runtime_only and not self.stage_work.get('runtimeMetadata') and not config_changed else standards.inspect(self.root, self.meta, cur, config,
                self._analysis_cache.setdefault('publication', {}), standards_work)
            self.stage_work['structureStandards'] = standards_work
            findings = [f for f in findings if not f.rule.startswith('STRUCTURE:')]
            for item in self.standard_findings:
                values = dict(item, metric=item['metric'])
                message_key = 'finding.unavailable' if item.get('unavailable') else 'finding.limit'
                message = localization.message(message_key, 'en', **values)
                findings.append(checkmod.Finding('P1' if item.get('unavailable') else 'S4', item['file'], item['line'],
                    message, 'STRUCTURE:' + item['rule'], 'check.standards'))
            approved_findings = [f for f in findings if f.code not in ("A1", "A2")
                                 and not f.message.startswith("대기본: ")]
            review_findings = []
            if mode["authority"] == "document":
                review_findings = [checkmod.Finding(code, file, line, message, producer="check.review")
                                   for code, file, line, message in review.findings(self.root)]
                approved_errors = {(i.code, i.file, i.line, i.message) for i in ds.issues}
                review_findings.extend(checkmod.Finding(i.code, i.file, i.line, "대기본: " + i.message, producer="check.documents")
                    for i in self.review_ds.issues if (i.code, i.file, i.line, i.message) not in approved_errors)
            findings = sorted(approved_findings + review_findings,key=lambda f:(f.file,f.line,f.code,f.message,f.rule))
            keyed = [(checkmod.finding_key(f), f) for f in findings]
            if input_commit is not None:
                current_findings = [(f.code,f.file,f.line,f.message,f.rule) for f in findings]
                previous_findings = [(f.code,f.file,f.line,f.message,f.rule) for f in self.last.findings]
                if not change_store.complete(self.root,input_commit,current_findings,previous_findings,
                                             getattr(analysis,"status",{}),getattr(analysis,"bad_edges",())):
                    raise ValueError("newer source commit exists; stale diagnosis rejected")
            mark("judge")
            publication_work = self.stage_work['publicationCache'] = {}
            publication_cache = self._analysis_cache.setdefault('publication',{})
            ledger_metrics = self.stage_work['ledgerPublication'] = {}
            if rebuilding:
                led.pop("rebuildPending",None)
            if led is None:
                led = ledger.start(None, cur, hashes, [k for k, _ in keyed])
                ledger.save(self.root, led,metrics=ledger_metrics)
                rev, new, resolved = 0, [], []
            elif (not changes and not docs and not changed_files and not assets_changed and not force
                  and not review_changed and not review_only and not config_changed and not self.runtime_changes):
                rev, new, resolved = led["rev"], [], []
            else:
                rev, new, resolved = ledger.record(self.root, led, trigger, cur, hashes, changes, docs, keyed, blocked,metrics=ledger_metrics)
            self._ledger = led
            self._ledger_stamp = ledger.stamp(self.root)
            mark("ledgerWrite")
            if mode["authority"] == "code":
                new = [f for f in new if workflow.reflection_finding(f)]
                resolved = [k for k in resolved if workflow.reflection_finding({"code": k.split("|", 1)[0]})]
            first_seen = {k: led["reported"][k]["rev"] for k, _ in keyed if k in led["reported"]}
            base = manifest["name"] if manifest else None
            places = self.meta.places if self.meta is not None else None
            if mode["authority"] == "document" and not blocked and not any(f.code.startswith(("D", "P")) for f in findings):
                phase.advance(self.root, ds, findings, places)
            runtime_header = runtime_only and not self.stage_work.get('runtimeGeometry')
            if self.meta is not None and not review_refresh and not (runtime_only and not self.stage_work.get('runtimeMetadata')):
                metamod.write(self.root, self.meta,set(deltas) if position_update else
                              scoped_sources if scoped_sources is not None else
                              changed_files if self.stage_work.get("bodyUpdate") == len(changed_files) and changed_files else None)
            if not runtime_only:
                design.publish(self.root,ds,cur,refs.source_records,scoped_sources if scoped_sources is not None else changed_files if scoped_body else None)
            mark("structureStore")
            mark("places")
            map_started = time.perf_counter()
            map_calls = self.stage_work['mapCalls'] = {}
            finding_values = [(f.code,f.file,f.line,f.message,f.rule) for f in findings]
            assigned = None
            try:
                st = os.stat(os.path.join(self.root, phase.STATE_FILE))
                self._phase_input = (phase.STATE_FILE, st.st_mtime_ns, st.st_size, st.st_ctime_ns)
            except FileNotFoundError:
                self._phase_input = None
            def build_phases(dirty):
                nonlocal assigned
                assigned = phase.assign(ds, findings, places) if not ds.issues else None
                return {'current': phase.as_dict(ds, findings, places, assigned)}
            phase_view = cachemod.POLICY.partition('publication-phases',
                {'current': (hashes, finding_values, places, self._phase_input)}, publication_cache,
                build_phases, publication_work)['current']
            mark('phaseAssign'); map_calls['phaseAssign'] = publication_work['publication-phases']['built']
            source_headers = dict(cur.summaries()) if isinstance(cur, ledger.SourceIndex) else cur
            report_sources = {file:source_headers.get(file, {}).get('sha256') for file in {f.file for f in findings}}
            def build_report(dirty):
                return {'current': report.build(self.root, trigger, base, ds, findings, notes, new=new, resolved=resolved, rev=rev,
                                changes=len(changes), places=places,
                                source_cache=self._analysis_cache.setdefault("reportTexts",{}),current=cur,assigned=assigned,
                                previous=self._analysis_cache.get("reportData") if position_update or
                                ((self.stage_work.get("bodyUpdate") or scoped_sources is not None) and not docs and not force) else None,
                                unchanged_docs=not docs and not force,document_hashes=hashes)}
            template = cachemod.POLICY.partition('publication-report',
                {'current': (hashes, finding_values, notes, base, report_sources, phase_view)},
                publication_cache, build_report, publication_work)['current']
            data = dict(template, command=trigger, time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                rev=rev, changes=len(changes), new=[{'code':f.code,'file':f.file,'line':f.line,'message':f.message} for f in new],
                resolved=list(resolved), findings=[dict(item) for item in template['findings']])
            mark('reportBuild'); map_calls['reportBuild'] = publication_work['publication-report']['built']
            data["priority"] = cachemod.POLICY.partition('publication-priority',
                {'ranking':(mode['authority'],[(f.code,f.file,f.line,f.message,f.rule) for f in findings])},
                publication_cache,lambda changed:{'ranking':priority.build(findings,mode['authority'])},
                publication_work)['ranking']
            mark('priorityBuild'); map_calls['priorityBuild'] = publication_work['publication-priority']['built']
            priority_rows = {r["findingId"]: r for r in data["priority"]["findingPriority"]}
            for item in data["findings"]:
                key = checkmod.finding_key(checkmod.Finding(item["code"], item["file"], item["line"], item["message"], rule=item["rule"]))
                work = priority_rows[key]
                item["priority"] = {k: work[k] for k in ("id", "priorityRank", "priorityBand", "actionKind", "evidenceStatus", "mustFix", "modeIndependent", "blocksResolution", "requiredAction", "repairInstruction") if k in work}
            mark('priorityAttach'); map_calls['priorityAttach'] = 1
            stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            previous_map = self.map_data
            deferred_map = (input_commit is not None and (scoped_body or scoped_sources is not None)
                            and not self.stage_work.get('runtimeGeometry')) or runtime_header
            if deferred_map:
                header={key:previous_map[key] for key in ('units','phases','implementationPlans','comparison') if key in previous_map}
                header.update(rev=rev,stamp=stamp,notes=list(notes))
                self.map_data=Projection(self.root,header,cur,self.presentation)
                self.map_data['phases']=phase_view
            elif position_update:
                self.map_data = codemap.move_positions(previous_map,findings,cur,deltas,stamp,first_seen,rev,self._map_positions)
                self.map_data["phases"] = phase_view
            elif self.stage_work.get("bodyUpdate") and previous_map is not None:
                self.map_data = codemap.refresh_body(previous_map,findings,cur,changed_files,stamp,first_seen,rev,self._map_positions,
                                                     scoped_deltas if scoped_body else None)
                self.map_data["notes"] = list(notes)
                self.map_data["phases"] = phase_view
            elif (text_only or review_refresh) and previous_map is not None:
                self.map_data = codemap.refresh_body(previous_map,findings,cur,(),stamp,first_seen,rev,self._map_positions)
                self.map_data["notes"] = list(notes)
                self.map_data["phases"] = phase_view
                self.map_data["units"] = [] if mode["authority"] == "code" else [review.as_dict(u) for u in review.units(self.root)]
            else:
                self.map_data = codemap.data(analysis, findings, notes, stamp, first_seen, rev, cur,
                                             [] if mode["authority"] == "code" else [review.as_dict(u) for u in review.units(self.root)],
                                             phase_view if not ds.issues else None, self.meta)
            mark('mapStructure'); map_calls['mapStructure'] = int(not deferred_map)
            rebuild_positions = not deferred_map and not position_update and not self.stage_work.get("bodyUpdate") and not text_only and not review_refresh
            if rebuild_positions:
                self._map_positions = codemap.position_index(self.map_data)
            mark('mapPositionIndex'); map_calls['mapPositionIndex'] = int(rebuild_positions)
            self.map_data['implementationPlans'] = review.cached_implementation_plans(ds,cur,self.root,self.execution_basis,
                publication_cache,publication_work,only_files=changed_files if (scoped_body or scoped_sources is not None) and 'publication-plans' not in self.runtime_changes else None
                ) if not self.execution_basis or self.execution_basis['status'] == 'ready' else []
            if self.execution_basis and self.execution_basis['status'] != 'ready':
                publication_cache.pop('publication-plans',None)
            mark('implementationPlans'); map_calls['implementationPlans'] = publication_work.get('publication-plans',{}).get('built',0)
            self.map_data['documentLinks'] = cachemod.POLICY.partition('publication-document-links',
                {'current': (hashes, [row for row in finding_values if row[-1] == 'DOC22'])}, publication_cache,
                lambda dirty:{'current': codemap.document_links(ds, findings)}, publication_work)['current']
            self.map_data["executionBasis"] = self.execution_basis
            self.map_data["documentReview"] = {"findings": [as_dict(f) for f in review_findings],
                "hashes": dict(self.review_hashes), "waiting": sum(f.code == "A1" for f in review_findings),
                "wrong": sum(f.code == "A2" for f in review_findings)}
            data["executionBasis"] = self.execution_basis
            data["documentReview"] = self.map_data["documentReview"]
            data["approvedFindings"] = [as_dict(f) for f in approved_findings]
            data["implementationPlans"] = self.map_data["implementationPlans"]
            review_keys = {checkmod.finding_key(f) for f in review_findings}
            for item in data["findings"]:
                finding = checkmod.Finding(item["code"], item["file"], item["line"], item["message"], rule=item["rule"])
                item["origin"] = "documentReview" if checkmod.finding_key(finding) in review_keys else "approved"
                if item["origin"] == "documentReview":
                    lines = self.review_ds.texts.get(item["file"], [])
                    item["snippet"] = lines[item["line"]-1].strip()[:200] if 0 < item["line"] <= len(lines) else ""
            self.map_data["workflow"] = mode
            self.map_data["priority"] = data["priority"]
            mark('reviewAttach'); map_calls['reviewAttach'] = 1
            self.pipeline_work['mapBuild'] = round(time.perf_counter()-map_started,4)
            self.pipeline_work['mapBuildResidual'] = round(self.pipeline_work['mapBuild']-sum(self.pipeline_work[name] for name in map_calls),4)
            if mode["authority"] == "code":
                def build_comparison(dirty):
                    return {'current': reconciliation.build(self.root, ds, findings, cur, blocked,
                    previous_map.get("comparison") if position_update or self.stage_work.get("bodyUpdate") or scoped_sources is not None or text_only else None,
                    deltas if position_update else dict.fromkeys(scoped_sources,()) if scoped_sources is not None else dict.fromkeys(changed_files,()) if self.stage_work.get("bodyUpdate") or text_only else None,
                    unchanged_docs=not docs and not force)}
                self.map_data['comparison'] = cachemod.POLICY.partition('publication-comparison',
                    {'current': (hashes, finding_values, blocked, marker, base,
                        [(file, entry.get('sha256')) for file, entry in sorted(source_headers.items())])},
                    publication_cache, build_comparison, publication_work)['current']
            else:
                self.map_data.pop("comparison", None)
            self._workflow_marker = marker
            self._settings_marker = config_marker
            self.map_data["standardFindings"] = self.standard_findings
            mark("comparison")
            data["completion"] = report.completion(findings, self.map_data.get("comparison"), mode["authority"], rev)
            self.map_data["completion"] = data["completion"]
            report.write(self.root, data)
            self._analysis_cache["reportData"] = data
            mark("report")
            # A docs-only report may replace latest.json; keep the published UI
            # annotations separate from that report and from SQL code structure.
            ledger.write_json(self.root, snapshot.REPORT_ROOT + "/map-annotations.json", {
                "rev": rev, "mapStamp": self.map_data["stamp"], "base": base or "",
                "notes": list(notes), "units": self.map_data["units"], "phases": self.map_data["phases"],
                "workflow": mode, "comparison": self.map_data.get("comparison"),
                "priorityElapsed": data["priority"]["elapsedSeconds"],
                "findingProducers": [f.producer for f in findings],
                "producerNotes": self._analysis_cache.get('producerNotes', {}),
                "producerSuppressed": self._analysis_cache.get('producerSuppressed', {}),
                "implementationPlans": self.map_data["implementationPlans"],
                "standardFindings": self.standard_findings,
                "publicationCache": {domain:{owner:entry[0] for owner,entry in entries.items()}
                                     for domain,entries in publication_cache.items()},
                "publicationVersions": {domain:cachemod.POLICY.versions[domain] for domain in publication_cache},
                "documentLinks": self.map_data["documentLinks"],
                "executionBasis": self.execution_basis,
                "documentReview": self.map_data["documentReview"]})
            if deferred_map:
                rows=refs.layers(ds)
                owned=set() if runtime_header else changed_files if scoped_body else scoped_sources
                file_layers={file:(refs.layer_of(file,rows).name if refs.layer_of(file,rows) else None) for file in owned}
                folders={key:dict(node.counts) for key,node in getattr(self.meta,'nodes',{}).items() if node.kind=='폴더'}
                for node in getattr(self.meta,'nodes',{}).values():
                    if node.kind=='파일' and node.parent in folders:
                        for name in ('메서드','변수'):
                            folders[node.parent][name]=folders[node.parent].get(name,0)+node.counts.get(name,0)
                work=dict(commit=input_commit or 0,body=scoped_body or runtime_header,files=file_layers,layers=[r.name for r in rows],
                          deltas=scoped_deltas if scoped_body else {},folders={} if scoped_body or runtime_header else folders)
                tuples=[(f.code,f.file,f.line,f.message,f.rule) for f in findings]
                seen={row:first_seen.get(checkmod.finding_key(f),0) for row,f in zip(tuples,findings)}
                map_store.enqueue(self.root,rev,stamp,work,tuples,seen,previous_map['rev'],self._analysis_cache.get('reportTexts'))
                self.stage_work['mapQueuedFiles']=len(owned)
                self.presentation.notify()
                if 'publication-html' in self.runtime_changes:
                    self.presentation.flush()
                    codemap.write(self.root,self.map_data,self.live_url)
            else:
                # Whole-scope initialization/rebuild is distinct from source deltas.
                with self.presentation.lock:
                    codemap.publish_sql(self.root, self.map_data, findings, previous_map if not isinstance(previous_map,Projection) else None,
                                        self._analysis_cache.get("reportTexts"))
                    codemap.write(self.root, self.map_data, self.live_url)
                    self.presentation.revision=rev
            mark("mapWrite")
            packed = getattr(previous_map, 'packed', None)
            if packed is None and previous_map is not None and 'decls' in previous_map:
                packed = zlib.compress(marshal.dumps(codemap.live_data(previous_map)),1)
            self.previous_map = {"rev":previous_map.get("rev"), "packed":packed} if packed is not None else None
            mark("previousMapStore")
            self.last = PassResult(rev, True, changes, docs, new, resolved, findings, notes, base or "")
            if input_commit is not None and self.input_runtime is None:
                change_store.acknowledge(self.root,input_commit)
            elif input_commit is None and pending_input is not None and (force or docs or assets_changed):
                change_store.rechecked(self.root,pending_input["id"],rev,input_basis)
            self._last_doc_structure, self._last_code_hashes, self._analysis = doc_structure, code_hashes, analysis
            return self.last

    def previous_delta(self, rev):
        """현재 프로세스가 게시한 판 사이의 전송 델타를 반환한다. 재시작 전 판은 현재 지도 응답으로 연결한다."""
        descriptor = self.previous_map
        if descriptor is None or str(descriptor["rev"]) != str(rev):
            return None
        packed = descriptor.get('deltaPacked')
        if packed is None:
            previous = marshal.loads(zlib.decompress(descriptor['packed']))
            previous['priority'] = dict(previous.pop('prioritySummary',{}),groups=previous.pop('priorityGroups',[]))
            data=codemap.delta(previous,self.map_data)
            descriptor['deltaPacked']=zlib.compress(marshal.dumps(data),1)
            descriptor.pop('packed',None)
        else:
            data=marshal.loads(zlib.decompress(packed))
        if data.get("rev") != (self.map_data or {}).get("rev"):
            return None
        return data

    def refresh_review(self, progress=None):
        """체크 뒤 승인 의존 지적과 판·장부·보고서·지도를 공통 게시 경로로 갱신한다."""
        if self.last is not None:
            self.run("체크", review_only=True, progress=progress)

    def since(self, client):
        """받는 쪽이 마지막으로 받은 판 뒤의 새 지적·해소(2.10). 장부 잠금 안에서 읽고 쓴다. 돌려주는 값: (판, 새 지적, 해소 열쇠)."""
        with ledger.locked(self.root):
            stamp = ledger.stamp(self.root)
            led = self._ledger if self._ledger is not None and stamp == self._ledger_stamp else ledger.load(self.root,lazy=True)
            if led is None or self.last is None:
                return 0, [], []
            current = [(checkmod.finding_key(f), f) for f in workflow.task_findings(self.root, self.last.findings)]
            previous = led["clients"].get(client)
            rev, new, resolved = ledger.since(led, client, current)
            if workflow.state(self.root)["authority"] == "code":
                resolved = [k for k in resolved if workflow.reflection_finding({"code": k.split("|", 1)[0]})]
            if previous != rev:
                ledger.save(self.root, led,{"reported":set(),"resolved":set(),"clients":{client}})
                stamp = ledger.stamp(self.root)
            self._ledger,self._ledger_stamp = led,stamp
            return rev, new, resolved
