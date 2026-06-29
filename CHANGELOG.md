# Changelog

## 1.0.0 - 2026-06-29

First public release.

- Web dashboard for scanning a resources folder or a whole server.
- Detection for remote code loaders, Discord/Telegram exfiltration, hidden admin
  grants, OS/file access, and obfuscated payloads.
- Deobfuscation pass: decodes base64 / hex / `string.char` and re-scans the
  result, plus entropy scoring for packed strings.
- Severity weighting with combo escalation, and an allowlist so framework code
  doesn't bury real findings.
- Exportable single-file HTML report.
- All detection rules live in `config.yaml`; add your own without writing code.
- `start.bat` one-click launcher for Windows.
