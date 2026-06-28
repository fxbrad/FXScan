from __future__ import annotations

import base64

_BUILD_TAG = "Zm1zY2FuOjpkaXNjb3JkLmdnL3g1YXZObmJFSlQ6OmVlYjE4ZmI3YjY3OTRjZDhhYTYyNmRmMzZiZjM1Y2Yz"

_ZERO = "​"
_ONE = "‌"
_MARK = "⁠"


def fingerprint() -> str:
    return base64.b64decode(_BUILD_TAG).decode("utf-8")


def build_id() -> str:
    return fingerprint().rsplit("::", 1)[-1]


def encode_zero_width(payload: str) -> str:
    bits = "".join(format(b, "08b") for b in payload.encode("utf-8"))
    body = "".join(_ONE if b == "1" else _ZERO for b in bits)
    return _MARK + body + _MARK
