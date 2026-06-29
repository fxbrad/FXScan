# Security Policy

## Reporting a vulnerability

If you find a security issue in FXScan itself, please don't open a public issue.
Report it privately first so it can be fixed before it's public:

- Message a maintainer in the Discord: https://discord.gg/x5avNnbEJT

Include what you found, how to reproduce it, and the impact as you see it. You'll
get a reply as soon as possible, and credit if you'd like it once a fix is out.

## Scope

FXScan is a heuristic scanner. It flags patterns that backdoors commonly rely on,
but a clean result is not a guarantee that a resource is safe, and a finding is
not proof that a resource is malicious. Always review flagged code yourself.

Reports about the detection rules (false positives, or backdoor techniques the
scanner misses) are welcome as normal issues or pull requests. See
CONTRIBUTING.md for how to add or improve a rule.
