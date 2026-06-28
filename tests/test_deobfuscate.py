import base64

from scanner.deobfuscate import decode_candidates, high_entropy_strings, shannon_entropy


def test_base64_decoded():
    payload = "loadstring(getpayload())"
    blob = base64.b64encode(payload.encode()).decode()
    text = f'local x = "{blob}"'
    results = dict(decode_candidates(text))
    assert any(payload in v for v in results.values())
    assert "base64" in results


def test_string_char_decoded():
    text = "local s = string.char(104,101,108,108,111,95,119,111,114,108,100)"
    results = decode_candidates(text)
    assert any(method == "string.char" and "hello_world" in dec for method, dec in results)


def test_hex_escape_decoded():
    text = r'local s = "\x6c\x6f\x61\x64\x73\x74\x72\x69\x6e\x67"'
    results = decode_candidates(text)
    assert any("loadstring" in dec for _, dec in results)


def test_high_entropy_flagged():
    blob = "aZ9k2Lp7Qw3Xy8Rt1Bn6Vc4Md0Fg5Hj2Kl8Sd7Pq3Wz9Xc1Vb6Nm4Tr0Yu8Io2Ap"
    text = f'local k = "{blob}"'
    hits = high_entropy_strings(text, min_len=40, threshold=4.0)
    assert blob in hits


def test_plain_text_not_high_entropy():
    text = 'local msg = "this is a perfectly normal english sentence used as a label"'
    hits = high_entropy_strings(text, min_len=40, threshold=4.6)
    assert hits == []


def test_entropy_monotonic():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("ab12cd34")
