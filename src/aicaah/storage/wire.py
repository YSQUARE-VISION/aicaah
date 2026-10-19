"""Python/C# 추출기 사이의 길이 지정 바이너리 값 스트림."""
import struct


def write(path, value):
    """작업 트리를 UTF-8 문자열·64비트 수·컨테이너 태그로 기록한다."""
    def emit(stream, item):
        if item is None: stream.write(b"\x00")
        elif isinstance(item, bool): stream.write(bytes([2 if item else 1]))
        elif isinstance(item, int): stream.write(b"\x03" + struct.pack("<q", item))
        elif isinstance(item, float): stream.write(b"\x04" + struct.pack("<d", item))
        elif isinstance(item, str):
            data = item.encode("utf-8")
            stream.write(b"\x05" + struct.pack("<I", len(data)) + data)
        elif isinstance(item, (list, tuple)):
            stream.write(b"\x06")
            for child in item: emit(stream, child)
            stream.write(b"\x08")
        elif isinstance(item, dict):
            stream.write(b"\x07")
            for key, child in item.items():
                if not isinstance(key, str): raise TypeError("wire key must be string")
                emit(stream, key)
                emit(stream, child)
            stream.write(b"\x08")
        else: raise TypeError("unsupported wire value")
    with open(path, "wb") as stream:
        stream.write(b"AIKR")
        emit(stream, value)


def read(path):
    """손상·중복 키·후행 바이트를 거부하고 바이너리 결과 트리를 복원한다."""
    def exact(stream, count):
        data = stream.read(count)
        if len(data) != count: raise ValueError("truncated wire value")
        return data
    def value(stream, tag, depth):
        if depth > 256: raise ValueError("wire nesting limit")
        if tag == 0: return None
        if tag in (1, 2): return tag == 2
        if tag == 3: return struct.unpack("<q", exact(stream, 8))[0]
        if tag == 4: return struct.unpack("<d", exact(stream, 8))[0]
        if tag == 5:
            size = struct.unpack("<I", exact(stream, 4))[0]
            if size > 268435456: raise ValueError("wire string limit")
            return exact(stream, size).decode("utf-8")
        if tag in (6, 7):
            out = [] if tag == 6 else {}
            while True:
                next_tag = exact(stream, 1)[0]
                if next_tag == 8: return out
                child = value(stream, next_tag, depth + 1)
                if tag == 6: out.append(child)
                else:
                    if not isinstance(child, str) or child in out: raise ValueError("invalid wire key")
                    out[child] = value(stream, exact(stream, 1)[0], depth + 1)
        raise ValueError("invalid wire tag")
    with open(path, "rb") as stream:
        if exact(stream, 4) != b"AIKR": raise ValueError("invalid wire magic")
        out = value(stream, exact(stream, 1)[0], 0)
        if stream.read(1): raise ValueError("trailing wire bytes")
        return out
