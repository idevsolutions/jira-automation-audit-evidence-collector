# Contributing

Thank you for helping improve the collector.

## Before opening an issue

- Confirm the problem with the newest tagged release.
- Remove all tenant, user, rule, issue, URL, cookie, and credential data.
- Do not attach HAR files or real Audit Log output.
- Prefer `--schema-only` output and synthetic fixtures when reporting a response
  shape change.

Security or privacy problems must follow [SECURITY.md](SECURITY.md), not a
public issue.

## Development

The project requires Python 3.10 or later and the IANA timezone database. On a
clean Windows Python installation, run `py -m pip install tzdata` first. The
collector itself otherwise uses only the standard library.

```powershell
py -m unittest discover -s tests -p "test_*.py"
py collect_automation_audit.py --version
```

Pull requests should:

- include tests for behavior changes;
- preserve fail-closed mapping;
- avoid real Atlassian tenant data;
- update the README, schema, and changelog when contracts change;
- retain the unsupported-endpoint warning.

By contributing, you agree that your contribution is licensed under the
Apache License 2.0.
