from scanner.config import load_config
from scanner.rules import scan_text


def cfg():
    return load_config("config.yaml")


def categories(findings):
    return {f.category for f in findings}


def rule_ids(findings):
    return {f.rule_id for f in findings}


def test_clean_code_has_no_high_signal():
    text = "local function f(n) print('hello ' .. n) end\nRegisterNetEvent('a')"
    findings = scan_text(cfg(), text, "clean.lua")
    assert all(f.severity in ("info", "low") for f in findings)


def test_loadstring_flagged():
    findings = scan_text(cfg(), "local f = loadstring(payload)", "x.lua")
    assert "dynamic_exec" in categories(findings)


def test_discord_webhook_flagged():
    text = "PerformHttpRequest('https://discord.com/api/webhooks/1/2')"
    findings = scan_text(cfg(), text, "x.lua")
    assert "exfiltration" in categories(findings)


def test_os_execute_flagged_high():
    findings = scan_text(cfg(), "os.execute('rm -rf /')", "x.lua")
    osf = [f for f in findings if f.rule_id == "os_execute"]
    assert osf and osf[0].severity == "high"


def test_decoded_base64_triggers_dynamic_exec():
    import base64
    blob = base64.b64encode(b"loadstring(remote())").decode()
    findings = scan_text(cfg(), f'local b = "{blob}"', "x.lua")
    decoded_hits = [f for f in findings if f.decoded and f.category == "dynamic_exec"]
    assert decoded_hits
    assert "decoded payload" in decoded_hits[0].explanation
