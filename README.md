# FXScan

[![tests](https://github.com/fxbrad/FXScan/actions/workflows/tests.yml/badge.svg)](https://github.com/fxbrad/FXScan/actions/workflows/tests.yml)

A local tool for checking FiveM resources before you put them on your server.
It scans a resources folder (or a whole server) and flags the things backdoors
usually rely on: remote code loaders, Discord/Telegram exfiltration, hidden
admin grants, OS/file access, and obfuscated payloads.

It runs entirely on your own machine. Nothing is uploaded anywhere.

## Running it

On Windows, double-click `start.bat`. It finds Python, installs what it needs
the first time, starts the tool, and opens it in your browser.

To run it manually (any OS):

```
pip install -r requirements.txt
python web/app.py
```

Then go to http://127.0.0.1:5000, point it at a folder, and hit Scan. The
results page lets you filter by severity, open any file to see the exact lines
that tripped a rule (including anything that was hidden behind base64 or other
encoding), and export a single-file HTML report.

## Reading the results

Findings are weighted by severity, and the scanner pays attention to
*combinations*. A single `PerformHttpRequest` is normal; a `PerformHttpRequest`
whose response gets passed to `load()` is a remote code loader, and that gets
flagged as critical. Known framework code (the `citizen` runtime, etc.) is
scanned but kept out of the score so it doesn't bury the things that matter.

Treat the output as leads to review, not a verdict. A high score means "go look
at this file", not "this is definitely malware".

## Adding your own checks

All the detection rules live in `config.yaml` alongside the rest of the
settings. Each rule is a small block of fields, so you can add new patterns
without touching any Python. See `CONTRIBUTING.md` for the format.

## Running the tests

```
pip install -r requirements-dev.txt
python -m pytest tests
```
