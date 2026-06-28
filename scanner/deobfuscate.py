from __future__ import annotations

import base64
import binascii
import math
import re

_HEX_SEQ = re.compile(r'(?:\\x[0-9A-Fa-f]{2}){6,}')
_DEC_SEQ = re.compile(r'(?:\\\d{2,3}){6,}')
_STRING_CHAR = re.compile(r'string\.char\s*\(([\s\d,]+)\)')
_B64_BLOB = re.compile(r'[A-Za-z0-9+/]{24,}={0,2}')


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(1 for ch in s if 32 <= ord(ch) < 127 or ch in "\t\n\r")
    return printable / len(s)


def decode_candidates(text: str) -> list[tuple[str, str]]:
    """Return (method, decoded_text) for each obfuscated payload found in text.

    Only decodings that yield mostly-printable output are returned, so random
    base64-looking asset data does not produce noise.
    """
    out: list[tuple[str, str]] = []

    for m in _HEX_SEQ.finditer(text):
        try:
            decoded = bytes(
                int(b, 16) for b in re.findall(r'\\x([0-9A-Fa-f]{2})', m.group(0))
            ).decode("utf-8", "replace")
        except ValueError:
            continue
        if _printable_ratio(decoded) > 0.85:
            out.append(("hex-escape", decoded))

    for m in _DEC_SEQ.finditer(text):
        try:
            decoded = bytes(
                int(b) for b in re.findall(r'\\(\d{2,3})', m.group(0)) if int(b) < 256
            ).decode("utf-8", "replace")
        except ValueError:
            continue
        if _printable_ratio(decoded) > 0.85:
            out.append(("decimal-escape", decoded))

    for m in _STRING_CHAR.finditer(text):
        nums = [int(n) for n in re.findall(r'\d+', m.group(1)) if int(n) < 256]
        if len(nums) >= 6:
            decoded = bytes(nums).decode("utf-8", "replace")
            if _printable_ratio(decoded) > 0.85:
                out.append(("string.char", decoded))

    seen_b64: set[str] = set()
    for m in _B64_BLOB.finditer(text):
        blob = m.group(0)
        if blob in seen_b64 or len(blob) % 4 != 0:
            continue
        seen_b64.add(blob)
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            continue
        if _printable_ratio(decoded) > 0.9 and any(c.isalpha() for c in decoded):
            out.append(("base64", decoded))

    return out


def high_entropy_strings(text: str, min_len: int, threshold: float) -> list[str]:
    hits: list[str] = []
    for token in re.findall(r'["\'`]([^"\'`\n]{%d,})["\'`]' % min_len, text):
        if shannon_entropy(token) >= threshold:
            hits.append(token)
    return hits
