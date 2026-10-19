"""언어 중립 JSON 입구. 설치 라이브러리들이 같은 엔진을 사용한다."""
import json
import sys
from parsing import settings, languages
from storage import snapshot
from documents import docs
from judging import meta, standards


def dispatch(root, request):
    """규약 1 요청을 검증하고 구조·분석·능력 결과를 반환한다."""
    if not isinstance(request, dict) or (type(request.get("schemaVersion")) is not int or request.get("schemaVersion") != 1) or set(request) - {"schemaVersion", "method", "params"}:
        raise ValueError("Unsupported request schema")
    method, values = request.get("method"), request.get("params", {})
    if not isinstance(values, dict): raise ValueError("params must be an object")
    if method == "capabilities":
        return dict(settings.schema(), languages=languages.available())
    if method == "parse":
        if set(values) != {"file", "source"} or not all(isinstance(x, str) for x in values.values()):
            raise ValueError("parse requires file and source strings")
        return {"symbols":[s.to_dict() for s in languages.parse(values["source"], values["file"])]}
    if method == "settings":
        if values: raise ValueError("settings takes no params")
        return settings.load(root)
    if method == "structure":
        if values: raise ValueError("structure takes no params")
        from serving import service
        instance = service.Service(root)
        result = instance.run("library", force=False)
        return {"rev":result.rev, "findings":[service.as_dict(f) for f in result.findings], "standards":instance.standard_findings}
    raise ValueError("Unknown API method: " + str(method))


def command(args):
    """stdout는 단일 JSON 응답이며 오류는 성공 결과와 구분한다."""
    try:
        request = json.load(sys.stdin)
        result = dispatch(args.root, request)
        print(json.dumps({"schemaVersion":1, "result":result}, ensure_ascii=False)); return 0
    except Exception as error:
        print(json.dumps({"schemaVersion":1, "error":{"code":"invalid-request", "message":str(error)}}, ensure_ascii=False)); return 2
