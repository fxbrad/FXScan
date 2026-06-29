# Adding detection rules

All detection lives in `config.yaml`. To make the scanner catch something new,
add one rule block under `rules:` - no Python required.

## A rule has six fields

```yaml
  - id: my_rule              # unique, lowercase_with_underscores
    category: exfiltration   # groups the finding; used by combos (any string)
    severity: high           # info | low | medium | high | critical
    pattern: 'evil\.example' # Python regex, matched against file text
    description: "What this detects"
    recommendation: "What the reviewer should check or do"
```

Copy an existing block, change the six fields, save. The config is validated on
load: a missing field, a bad regex, an unknown severity, or a duplicate id stops
the scanner with a clear error message pointing at your rule.

## Tips

Patterns are Python regex, so escape literal dots (`discord\.com`) and watch
your backslashes inside quotes.

Get the severity right. Something that's often legitimate, like
`PerformHttpRequest`, should be `low`. Save `high` and `critical` for things
that are almost never innocent, like `os.execute` or a known backdoor signature.

If two weak signals are dangerous together, don't bump them both to critical.
Leave them low and add a combo under `settings.combos` instead:

```yaml
combos:
  - when: [my_category, dynamic_exec]
    escalate_to: critical
```

A file that has at least one finding from each listed category gets its worst
finding bumped up to `escalate_to`.

You don't need a separate rule for obfuscated versions. Rules also run against
base64 / hex / `string.char` content after it's decoded.

## Allowlisting false positives

If a rule fires on known-good framework code, add a path glob to
`settings.allowlist_globs` (scanned but not scored) or a file's sha256 to
`settings.allowlist_hashes` (skipped entirely). Prefer narrow globs.

## Before submitting

Run the tests:

```
pip install -r requirements-dev.txt
python -m pytest tests
```
