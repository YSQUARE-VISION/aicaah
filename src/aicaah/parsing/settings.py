"""버전 있는 프로젝트 설정. 언어 추출과 독립된 구조·수량 정책 계약."""
import json
import os
from pathlib import Path

FILE = "aicaah.json"
LEGACY_FILE = "specconformance.json"
VERSION = "0.1"
LOCALES = ("en", "ko", "zh", "ja")
LANGUAGES = ("python", "csharp", "javascript", "typescript", "java", "go")
EXTENSIONS = {"python":[".py"], "csharp":[".cs"], "javascript":[".js", ".jsx", ".mjs", ".cjs"],
              "typescript":[".ts", ".tsx", ".mts", ".cts"], "java":[".java"], "go":[".go"]}
METRICS = {"folder":("files", "folders", "modules", "classes", "interfaces", "functions", "variables"),
           "module":("files", "modules", "classes", "interfaces", "functions", "variables"),
           "file":("classes", "interfaces", "functions", "variables"),
           "class":("functions", "variables", "classes"), "interface":("functions", "variables"),
           "function":("parameters", "locals")}
EXCLUDES = ["**/node_modules/**", "**/.git/**", "**/__pycache__/**", ".spec-conformance/**", "**/.venv/**"]


def defaults():
    """새 프로젝트의 관측 기본값. 기존 프로젝트의 규칙을 대체하지 않는다."""
    return {"schemaVersion":1, "locale":"en", "languages":list(LANGUAGES), "sources":["src"],
            "exclude":list(EXCLUDES), "structure":{"modules":[]}, "standards":{"rules":[]}}


def relative(value, pattern=False):
    """프로젝트 내부 상대 경로·glob만 허용한다."""
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError("Expected a nonempty relative path")
    value = value.replace("\\", "/")
    if value.startswith("/") or ":" in value or ".." in value.split("/") or "\x00" in value:
        raise ValueError("Path must stay inside the project: " + value)
    if not pattern and any(c in value for c in "*?[]"):
        raise ValueError("Source and module paths must be folders: " + value)
    return value.rstrip("/") or "."


def _keys(value, allowed, required, label):
    """오타·미지정 필수 필드를 기본값으로 숨기지 않는다."""
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise ValueError("Invalid fields in " + label)


def _limit(value):
    """0은 유효한 한도이고 null은 미지정이다."""
    if value is not None and (type(value) is not int or value < 0):
        raise ValueError("Limit must be a nonnegative integer or null")


def validate(value):
    """설정 전체를 엄격히 검사하고 입력 객체를 반환한다."""
    _keys(value, ("schemaVersion", "locale", "languages", "sources", "exclude", "structure", "standards"),
          ("schemaVersion", "locale", "languages", "sources", "structure", "standards"), "project")
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
        raise ValueError("Unsupported configuration schemaVersion")
    if value["locale"] not in LOCALES:
        raise ValueError("Unsupported display language")
    for field in ("languages", "sources", "exclude"):
        items = value.get(field, [])
        if not isinstance(items, list) or any(not isinstance(x, str) for x in items) or len(set(items)) != len(items):
            raise ValueError("Expected unique strings: " + field)
        if field != "exclude" and not items:
            raise ValueError("At least one value required: " + field)
    if set(value["languages"]) - set(LANGUAGES):
        raise ValueError("Unsupported programming language")
    for path in value["sources"]: relative(path)
    for path in value.get("exclude", []): relative(path, pattern=True)
    _keys(value["structure"], ("modules",), ("modules",), "structure")
    if not isinstance(value["structure"]["modules"], list):
        raise ValueError("Modules must be a list")
    ids, paths = set(), set()
    for module in value["structure"]["modules"]:
        _keys(module, ("id", "path"), ("id", "path"), "module")
        key, path = module["id"], relative(module["path"])
        if not isinstance(key, str) or not key or key in ids or path in paths:
            raise ValueError("Module names and paths must be unique")
        if not any(source == "." or path == source or path.startswith(source + "/") for source in value["sources"]):
            raise ValueError("Module must be inside a configured source folder")
        ids.add(key); paths.add(path)
    _keys(value["standards"], ("rules",), ("rules",), "standards")
    if not isinstance(value["standards"]["rules"], list):
        raise ValueError("Rules must be a list")
    ids = set()
    for rule in value["standards"]["rules"]:
        _keys(rule, ("id", "unit", "metric", "max", "scope", "depth", "enabled", "reason", "overrides", "exceptions"),
              ("id", "unit", "metric", "max", "scope", "depth", "enabled"), "rule")
        if not isinstance(rule["id"], str) or not rule["id"] or rule["id"] in ids:
            raise ValueError("Rule IDs must be unique nonempty strings")
        ids.add(rule["id"])
        if not isinstance(rule["unit"], str) or rule["unit"] not in METRICS or rule["metric"] not in METRICS[rule["unit"]]:
            raise ValueError("Unsupported unit/metric")
        if rule["depth"] not in ("direct", "recursive") or type(rule["enabled"]) is not bool:
            raise ValueError("Invalid rule depth or enabled flag")
        relative(rule["scope"], pattern=True); _limit(rule["max"])
        if rule["enabled"] and rule["max"] is None:
            raise ValueError("An enabled rule requires an explicit limit")
        for field in ("overrides", "exceptions"):
            if not isinstance(rule.get(field, []), list): raise ValueError("Expected a list: " + field)
        for override in rule.get("overrides", []):
            _keys(override, ("scope", "max", "priority"), ("scope", "max", "priority"), "override")
            relative(override["scope"], pattern=True); _limit(override["max"])
            if override["max"] is None or type(override["priority"]) is not int:
                raise ValueError("Override requires a limit and integer priority")
        for exception in rule.get("exceptions", []):
            _keys(exception, ("scope", "reason"), ("scope", "reason"), "exception")
            relative(exception["scope"], pattern=True)
            if not isinstance(exception["reason"], str) or not exception["reason"].strip():
                raise ValueError("An exception requires a reason")
    return value


def configuration_path(root):
    """새 설정 또는 기존 단일 설정을 선택하며 두 설정의 동시 존재는 거절한다."""
    current, legacy = Path(root) / FILE, Path(root) / LEGACY_FILE
    if current.exists() and legacy.exists():
        raise ValueError('Both aicaah.json and specconformance.json exist; keep one configuration file')
    return legacy if legacy.exists() else current


def load(root):
    """없는 설정은 None, 잘못된 설정은 오류. 기존 프로젝트 동작을 보존한다."""
    path = configuration_path(root)
    if not path.exists(): return None
    return validate(json.loads(path.read_text(encoding="utf-8-sig")))


def inside(root, relative_path):
    """상대 경로뿐 아니라 심볼릭 링크로 프로젝트 밖에 쓰는 것도 거절한다."""
    base = Path(root).resolve()
    path = (base / relative(relative_path)).resolve()
    if os.path.commonpath((str(base), str(path))) != str(base):
        raise ValueError("Resolved path is outside the project")
    return path


def schema():
    """설정 UI·라이브러리가 공유하는 유효 선택지와 현재 형식 버전."""
    return {"schemaVersion":1, "product":"AICAAH", "version":VERSION, "locales":list(LOCALES), "languages":list(LANGUAGES),
            "metrics":METRICS, "depths":["direct", "recursive"], "configurationFile":FILE}
