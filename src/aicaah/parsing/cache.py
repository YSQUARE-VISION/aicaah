"""공용 캐시 정책: 산출물별 구현 의존성·입력·스키마와 분석 게시 경계(SPEC-36)."""
import ast
import hashlib
import json
import sys
import time
from functools import wraps
from pathlib import Path


def produces(domain):
    """Keep finding ownership through partial checks without changing their public identity."""
    def decorate(action):
        @wraps(action)
        def run(judge, *args, **kwargs):
            first, notes, suppressed = len(judge.findings), len(judge.notes), judge.suppressed
            result = action(judge, *args, **kwargs)
            for finding in judge.findings[first:]:
                finding.producer = domain
            judge.analysis_cache.setdefault('producerNotes', {})[domain] = list(judge.notes[notes:])
            judge.analysis_cache.setdefault('producerSuppressed', {})[domain] = judge.suppressed - suppressed
            return result
        return run
    return decorate


class CachePolicy:
    """프로세스 시작의 구현 의존성을 고정하고 메모리/SQL에 같은 입력 지문을 제공한다."""

    CHECKS = ('_parse_errors', '_scope_changes', '_changes_documented', '_stage_done', '_members',
              '_regression', '_constants', '_rules', '_overview', '_coverage', '_layers', '_shaders',
              '_limits', '_interfaces', '_pipeline', '_behaviors', '_review')
    CONSUMERS = {
        'python-refs': ('analysis.graph',),
        'analysis.graph': ('analysis.metadata', 'check.layers', 'check.behaviors'),
        'analysis.metadata': ('check.limits', 'check.interfaces', 'check.pipeline', 'check.standards'),
        'file-meta.py': ('analysis.metadata',),
        'file-meta.cs': ('analysis.metadata',),
        'file-meta.generic': ('analysis.metadata',),
        'structure-facts': ('check.standards',),
    }
    DEFINITIONS = {
        **{'check.' + name[1:]: ('judging/check.py#Judge.' + name,) for name in CHECKS},
        'check.rules': ('judging/check.py#Judge._rules', 'judging/check.py#Judge._rule_code',
                        'judging/check.py#Judge._rule_doc_paths', 'judging/check.py#Judge._rule_doc_text',
                        'documents/docs.py#DOING'),
        'analysis.graph': ('graph/refs.py#build', 'graph/RefGraph/RefGraph.cs#*'),
        'analysis.metadata': ('judging/meta.py#build',),
        'check.documents': ('documents/docs.py#load',),
        'check.standards': ('judging/standards.py#inspect',),
        'check.standard-messages': ('output/localization.py#message', 'locales/map.json#*'),
        'restart-orchestration': ('serving/service.py#Service._run', 'serving/service.py#Service._judge',
                                  'serving/service.py#Service.refresh_runtime', 'judging/check.py#Judge.run',
                                  'serving/server.py#Server.sync', 'serving/server.py#Server.__init__',
                                  'storage/snapshot.py#current'),
        'publication-structure': ('output/codemap.py#data', 'output/codemap.py#refresh_body',
                                  'output/codemap.py#move_positions', 'serving/presentation.py#Presentation.flush'),
        'publication-report': ('output/report.py#build', 'output/report.py#write'),
        'publication-comparison': ('output/reconciliation.py#build',),
        'publication-phases': ('output/phase.py#assign', 'output/phase.py#as_dict'),
        'publication-document-links': ('output/codemap.py#document_links',),
        'publication-html': ('output/codemap.py#write',),
        'members': ('judging/check.py#Judge._members', 'judging/check.py#Judge._member_files'),
        'rules': ('judging/check.py#Judge._rule_code', 'judging/check.py#Judge._rules',
                  'judging/check.py#Judge._rule_input', 'documents/docs.py#DOING'),
        'file-meta.cs': ('judging/meta.py#_tree',),
        'file-meta.py': ('judging/meta.py#_tree', 'judging/meta.py#_python_locals'),
        'python-refs': ('graph/refs.py#python',),
        'source-records': ('graph/refs.py#source_records',),
        'parse.cs': ('parsing/parse_cs.py#parse_with_context',),
        'parse.py': ('parsing/parse_py.py#parse',),
        'parse.generic': ('parsing/languages.py#parse', 'parsing/languages.py#runtime_version'),
        'file-meta.generic': ('judging/meta.py#_tree', 'parsing/languages.py#locals_by_line'),
        'structure-facts': ('judging/meta.py#_tree', 'judging/meta.py#_python_locals', 'parsing/languages.py#locals_by_line'),
        'publication-source': ('storage/relations.py#SOURCE_ENTRY',),
        'publication-priority': ('output/priority.py#build',),
        'publication-plans': ('documents/review.py#implementation_plans', 'documents/review.py#_target',
                              'documents/review.py#REMOVING', 'documents/review.py#PLAN_WAITING'),
        'publication-map': ('storage/map_store.py#publish_sql', 'storage/map_store.py#enqueue', 'storage/map_store.py#patch_sql'),
        'publication-snippet': ('output/report.py#_snippet',),
    }
    # These are input/result transport boundaries, not judgment implementations.
    # Include the local input-key/wrapper code, but do not traverse SQL/cache plumbing.
    SHALLOW = frozenset(('judging/check.py#Judge._member_files',
                         'judging/check.py#Judge._rules', 'judging/check.py#Judge._rule_input',
                         'documents/review.py#implementation_plans',
                         'serving/service.py#Service._run', 'serving/service.py#Service._judge',
                         'serving/service.py#Service.refresh_runtime', 'judging/check.py#Judge.run',
                         'serving/server.py#Server.sync', 'serving/server.py#Server.__init__',
                         'storage/snapshot.py#current', 'serving/presentation.py#Presentation.flush'))
    PORTS = ('storage/ledger.py#', 'storage/reference_store.py#', 'graph/cache.py#', 'parsing/cache.py#')
    SCHEMA = 1

    def __init__(self, folder=None):
        """정규화 AST와 전이 의존을 한 번 읽고 작은 지문·의존 목록만 보관한다."""
        folder = Path(folder) if folder is not None else Path(__file__).resolve().parent.parent
        modules, resolved = {}, {}
        self.versions, self.dependencies = {}, {}
        for domain, roots in self.DEFINITIONS.items():
            pending, selected = list(roots), {}
            while pending:
                identity = pending.pop()
                if identity in selected or identity.startswith(self.PORTS):
                    continue
                if identity in resolved:
                    selected[identity], dependencies = resolved[identity]
                    pending.extend(dependencies)
                    continue
                dependency_start = len(pending)
                file, qualified = identity.split('#', 1)
                if not file.endswith('.py'):
                    selected[identity] = hashlib.sha256((folder / file).read_bytes()).hexdigest()
                    resolved[identity] = selected[identity], ()
                    continue
                if qualified in ('__file__', '__name__', '__package__'):
                    continue
                if '.__dataclass_fields__' in qualified:
                    pending.append(file + '#' + qualified.split('.__dataclass_fields__', 1)[0])
                    continue
                if file not in modules:
                    tree = ast.parse((folder / file).read_text(encoding='utf-8-sig'))
                    definitions, imports = {}, {}
                    for node in ast.walk(tree):
                        if isinstance(node, (ast.Module, ast.ClassDef)):
                            prefix = node.name + '.' if isinstance(node, ast.ClassDef) else ''
                            for child in node.body:
                                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                                    definitions[prefix + child.name] = child
                                elif isinstance(child, (ast.Assign, ast.AnnAssign)):
                                    targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                                    for target in targets:
                                        if isinstance(target, ast.Name):
                                            definitions[prefix + target.id] = child
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                imports.setdefault(alias.asname or alias.name.split('.')[0], set()).add(
                                    alias.name if alias.asname else alias.name.split('.')[0])
                        elif isinstance(node, ast.ImportFrom) and node.module:
                            prefix = file.split('/')[:-node.level] if node.level else []
                            module = '.'.join(prefix + [node.module])
                            for alias in node.names:
                                if alias.name == '*':
                                    raise ValueError('Unbounded cache import: ' + file)
                                imports.setdefault(alias.asname or alias.name, set()).add(module + '.' + alias.name)
                    modules[file] = (tree, definitions, imports)
                tree, definitions, imports = modules[file]
                owner = qualified.split('.')[0] if '.' in qualified else ''
                if qualified == '*':
                    node = tree
                else:
                    if qualified not in definitions:
                        parts = qualified.split('.')
                        prefix = next(('.'.join(parts[:end]) for end in range(len(parts)-1, 0, -1)
                                       if '.'.join(parts[:end]) in definitions), None)
                        if prefix is None:
                            raise ValueError('Missing cache dependency: ' + identity)
                        pending.append(file + '#' + prefix)
                        continue
                    node = definitions[qualified]
                # AST locations are excluded; docstrings and comments are not executable inputs.
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                        if child.func.id in ('eval', 'exec', '__import__', 'globals', 'locals'):
                            raise ValueError('Unbounded cache dependency: ' + identity)
                        if child.func.id == 'getattr' and child.args and isinstance(child.args[0], ast.Name):
                            name = child.args[0].id
                            attribute = child.args[1].value if len(child.args) > 1 and isinstance(child.args[1], ast.Constant) else None
                            if name in ('self', 'cls') and owner:
                                target = owner + '.' + attribute if isinstance(attribute, str) else owner
                                if target in definitions:
                                    pending.append(file + '#' + target)
                            for imported in imports.get(name, ()):
                                target = imported.replace('.', '/') + '.py'
                                if (folder / target).is_file() and attribute not in ('__file__', '__name__', '__package__'):
                                    pending.append(target + '#' + (attribute if isinstance(attribute, str) else '*'))
                    body = getattr(child, 'body', None)
                    if isinstance(body, list) and body and isinstance(body[0], ast.Expr):
                        if isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                            body.pop(0)
                selected[identity] = ast.dump(node, include_attributes=False)
                if identity in self.SHALLOW:
                    resolved[identity] = selected[identity], tuple(pending[dependency_start:])
                    continue
                owner = qualified.split('.')[0] if '.' in qualified else (
                    qualified if isinstance(node, ast.ClassDef) else '')
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                        names = [child.id]
                    elif isinstance(child, ast.Attribute):
                        names, current = [], child
                        while isinstance(current, ast.Attribute):
                            names.insert(0, current.attr)
                            current = current.value
                        if not isinstance(current, ast.Name):
                            continue
                        names.insert(0, current.id)
                    else:
                        continue
                    if names[0] in ('self', 'cls') and owner and len(names) > 1:
                        target = owner + '.' + names[1]
                        if target in definitions:
                            pending.append(file + '#' + target)
                    elif names[0] in definitions:
                        pending.append(file + '#' + names[0])
                    elif names[0] in imports:
                        for imported in imports[names[0]]:
                            dotted = (imported + ('.' + '.'.join(names[1:]) if len(names) > 1 else '')).split('.')
                            for end in range(len(dotted), 0, -1):
                                dependency = '/'.join(dotted[:end]) + '.py'
                                if (folder / dependency).is_file():
                                    target = '.'.join(dotted[end:])
                                    if target or qualified == '*':
                                        pending.append(dependency + '#' + (target or '*'))
                                    break
                resolved[identity] = selected[identity], tuple(pending[dependency_start:])
            self.dependencies[domain] = tuple(sorted(selected))
            encoded = json.dumps([self.SCHEMA, sys.version_info[:3], sorted(selected.items())],
                                 ensure_ascii=False, separators=(',', ':'))
            self.versions[domain] = hashlib.sha256(encoded.encode('utf-8')).hexdigest()

    def changed(self, previous):
        """Compare producer manifests, including removed/new domains; never use a whole-engine hash."""
        changed = {name for name in self.versions.keys() | previous.keys()
                   if self.versions.get(name) != previous.get(name)}
        pending = list(changed)
        while pending:
            for consumer in self.CONSUMERS.get(pending.pop(), ()):
                if consumer not in changed:
                    changed.add(consumer)
                    pending.append(consumer)
        return changed

    def key(self, domain, inputs):
        """등록된 구현·스키마와 실제 자료 입력을 묶는다. 미등록 영역은 재사용하지 않는다."""
        encoded = json.dumps([self.versions[domain], inputs], ensure_ascii=False, sort_keys=True,
                             separators=(',', ':'))
        return hashlib.sha256(encoded.encode('utf-8')).hexdigest()

    def partition(self, domain, inputs, retained, build, work=None, scope=None):
        """소유자별 변경 조각만 함께 생성하고 성공한 현재 집합만 원자적으로 교체한다."""
        started = time.perf_counter()
        previous = retained.get(domain, {})
        if scope is not None and not inputs.keys() <= scope:
            raise ValueError('Cache input outside publication scope: ' + domain)
        keys = {owner:self.key(domain, value) for owner,value in inputs.items()}
        changed = {owner for owner,key in keys.items() if owner not in previous or previous[owner][0] != key}
        keyed = time.perf_counter()
        values = build(changed) if changed else {}
        if values.keys() != changed:
            raise ValueError('Incomplete cache publication: ' + domain)
        current = {owner:(key,values[owner]) if owner in changed else previous[owner] for owner,key in keys.items()}
        if scope is not None:
            current.update((owner,entry) for owner,entry in previous.items() if owner not in scope)
        retained[domain] = current
        if work is not None:
            work[domain] = dict(built=len(changed), reused=len(current)-len(changed),
                                removed=len(previous.keys()-current.keys()),
                                keySeconds=round(keyed-started,6), buildSeconds=round(time.perf_counter()-keyed,6))
        return {owner:entry[1] for owner,entry in current.items()}


POLICY = CachePolicy()

