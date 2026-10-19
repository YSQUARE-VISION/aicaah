"""프로젝트 구조 설정의 원자 저장과 낙관적 경쟁 검사."""
import hashlib
import json
import os
import tempfile
from parsing import settings
from storage import ledger


def fingerprint(root):
    """설정 저장 경쟁을 검사하는 내용 지문."""
    path = settings.configuration_path(root)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def _save(root, config, expected):
    """검증 후 같은 디렉터리에서 원자 교체하며 설정 변경 경쟁을 거절한다."""
    settings.validate(config)
    target = settings.inside(root, settings.configuration_path(root).name)
    for folder in config["sources"]: settings.inside(root, folder)
    if fingerprint(root) != expected: raise ValueError("settings.conflict")
    data = (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    name = None
    try:
        with tempfile.NamedTemporaryFile(dir=str(target.parent), prefix=".spec-settings-", delete=False) as stream:
            name = stream.name
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        if fingerprint(root) != expected: raise ValueError("settings.conflict")
        os.replace(name, target); name = None
    finally:
        if name is not None: os.unlink(name)


def save(root, config, expected):
    """공용 프로젝트 자물쇠 안에서 설정의 같은 판을 원자 교체한다."""
    settings.validate(config)
    with ledger.locked(root):
        _save(root, config, expected)
