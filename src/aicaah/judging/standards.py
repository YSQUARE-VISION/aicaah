"""언어와 독립된 구조 표준. 기존 공통 메타데이터에 설정만 적용한다."""
import os
from parsing import globs, settings
from parsing import cache as cachemod
from storage import ledger
from judging import meta as metamod

KINDS = {"폴더":"folder", "파일":"file", "클래스":"class", "인터페이스":"interface", "메서드":"function", "변수":"variable"}
COUNTS = {"files":"file", "folders":"folder", "classes":"class", "interfaces":"interface", "functions":"function", "variables":"variable"}


def matches(path, pattern):
    """폴더 자체와 그 하위 glob을 같은 범위로 취급한다."""
    return globs.matches(path, [pattern]) or (pattern.endswith("/**") and path == pattern[:-3])


def evaluate(nodes, config):
    """공통 마디의 직접/재귀 수량과 명시 모듈 경계를 판정한다."""
    settings.validate(config)
    sources = [settings.relative(path) for path in config['sources']]
    extensions = {ext for lang in config['languages'] for ext in settings.EXTENSIONS[lang]}
    def included(node):
        path = (node.file or node.key) or '.'
        return (any(source == '.' or path == source or path.startswith(source+'/') for source in sources)
                and not any(matches(path, pattern) for pattern in config.get('exclude', []))
                and (not node.file or os.path.splitext(node.file)[1].lower() in extensions))
    nodes = {key:node for key,node in nodes.items() if included(node)}
    kinds = {key:KINDS.get(n.kind) for key,n in nodes.items()}
    children = {}
    for key,n in nodes.items():
        if n.parent != key: children.setdefault(n.parent, []).append(key)
    modules = config["structure"]["modules"]
    module_paths = {"" if settings.relative(m["path"]) == "." else settings.relative(m["path"]) for m in modules}
    out = []
    for rule in config["standards"]["rules"]:
        if not rule["enabled"]: continue
        targets = [(path, None) for path in sorted(module_paths)] if rule["unit"] == "module" else [
            (key,n) for key,n in nodes.items() if kinds[key] == rule["unit"]]
        for key,node in targets:
            path = ((node.file or key) if node is not None else key) or "."
            if not matches(path, rule["scope"]): continue
            if any(matches(path, x["scope"]) for x in rule.get("exceptions", [])): continue
            overrides = [x for x in rule.get("overrides", []) if matches(path, x["scope"])]
            maximum = rule["max"]
            if overrides:
                priority = max(x["priority"] for x in overrides)
                selected = [x for x in overrides if x["priority"] == priority]
                if len(selected) != 1: raise ValueError("Ambiguous overrides for " + rule["id"] + ": " + path)
                maximum = selected[0]["max"]
            metric, recursive = rule["metric"], rule["depth"] == "recursive"
            if metric in ("parameters", "locals"):
                count_key = "매개변수" if metric == "parameters" else "지역 변수"
                if count_key not in node.counts:
                    out.append({"rule":rule["id"], "file":path, "line":node.line or 1, "unit":rule["unit"],
                                "metric":metric, "actual":None, "maximum":maximum, "depth":rule["depth"],
                                "target":key, "source":settings.FILE, "unavailable":True})
                    continue
                actual = node.counts[count_key]
            elif metric == "modules":
                candidates = [p for p in module_paths if p != key and (not key or p.startswith(key.rstrip("/") + "/"))]
                actual = len(candidates if recursive else [p for p in candidates if not any(
                    p.startswith(other + "/") for other in candidates if other != p)])
            else:
                pending = list(children.get(key, [])); selected = set()
                while pending:
                    candidate = pending.pop()
                    if candidate in selected: continue
                    # A direct module owns the subtree until another declared module begins.
                    if rule["unit"] == "module" and not recursive and candidate in module_paths: continue
                    selected.add(candidate)
                    if recursive or rule["unit"] == "module" or (
                            rule["unit"] == "folder" and kinds[candidate] == "file" and metric not in ("files", "folders")):
                        pending.extend(children.get(candidate, []))
                actual = sum(kinds[k] == COUNTS[metric] for k in selected)
            if actual > maximum:
                out.append({"rule":rule["id"], "file":path, "line":node.line or 1 if node is not None else 1,
                            "unit":rule["unit"], "metric":metric, "actual":actual, "maximum":maximum,
                            "depth":rule["depth"], "target":key, "source":settings.FILE})
    return sorted(out, key=lambda row:(row["rule"], row["target"]))


def inspect(root, metadata, current, config, retained, work):
    """기존 파일 메타데이터를 공유하고 변경된 파일의 구조 조각만 교체한다."""
    if not config or not any(rule['enabled'] for rule in config['standards']['rules']):
        retained.pop('structure-facts', None)
        return []
    summaries = current.summaries() if isinstance(current, ledger.SourceIndex) else current.items()
    sources = [settings.relative(path) for path in config['sources']]
    extensions = {ext for lang in config['languages'] for ext in settings.EXTENSIONS[lang]}
    inputs = {file:[entry.get('sha256'), entry.get('parser')] for file,entry in summaries
              if entry.get('unit') == '심볼' and not entry.get('error')
              and os.path.splitext(file)[1].lower() in extensions
              and any(source == '.' or file.startswith(source+'/') for source in sources)
              and not any(matches(file, pattern) for pattern in config.get('exclude', []))}
    def build(changed):
        values = {}
        for file in changed:
            record = metadata.file_records.get(file) if metadata is not None else None
            if record is None:
                record = ledger.read_table(root, metamod.FILE_RECORDS + '/' + file + '.row', None)
            if record is None:
                raise ValueError('Structure metadata unavailable: ' + file)
            values[file] = record['nodes']
        return values
    parts = cachemod.POLICY.partition('structure-facts', inputs, retained, build, work)
    nodes = {}
    for rows in parts.values():
        for row in rows:
            if row['key'] not in nodes:
                nodes[row['key']] = metamod.Node(**dict(row, modifiers=tuple(row.get('modifiers', ()))))
    result = evaluate(nodes, config)
    for row in result:
        row['source'] = settings.configuration_path(root).name
    return result
