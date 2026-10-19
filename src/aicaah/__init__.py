"""AICAAH — AI Coding Agent Architecture Harness. Isolated project API."""
import json
from pathlib import Path
import subprocess
import sys

__version__ = "0.1"


class Client:
    """명시한 프로젝트에 대해 버전 있는 공통 API를 호출한다."""

    def __init__(self, root, python=None, timeout=120):
        """프로젝트·런타임·호출 제한을 고정한다."""
        self.root, self.python, self.timeout = str(Path(root).resolve()), python or sys.executable, timeout

    def request(self, method, **params):
        """쉘 없이 엔진 프로세스를 호출하고 오류 응답을 예외로 전달한다."""
        result = subprocess.run([self.python, "-X", "utf8", str(Path(__file__).with_name("engine.py")),
                                 "--root", self.root, "api"],
            input=json.dumps({"schemaVersion":1, "method":method, "params":params}),
            capture_output=True, text=True, encoding="utf-8", timeout=self.timeout)
        try: value = json.loads(result.stdout)
        except ValueError as error: raise RuntimeError(result.stderr or result.stdout) from error
        if result.returncode or "error" in value: raise RuntimeError(value.get("error", {}).get("message", result.stderr))
        return value["result"]


def main():
    """설치된 콘솔 명령도 기존 engine.py 입구로 전달한다."""
    return subprocess.call([sys.executable, "-X", "utf8", str(Path(__file__).with_name("engine.py")), *sys.argv[1:]])
