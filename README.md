# Jira Automation Audit Evidence Collector

[![Tests](https://github.com/idevsolutions/jira-automation-audit-evidence-collector/actions/workflows/test.yml/badge.svg)](https://github.com/idevsolutions/jira-automation-audit-evidence-collector/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Independent, local administrator utility for preparing Jira Automation Audit
Log evidence for offline analysis.

> [!WARNING]
> This project is not affiliated with, endorsed by, or supported by Atlassian.
> It calls an undocumented Jira Cloud Automation `internal-api` endpoint that
> may change or stop working without notice. Do not use it as a production API
> integration or unattended synchronization service.

`collect_automation_audit.py` prepares runtime evidence when Jira's normal
Audit Log download is not sufficient for the selected period. Its output can be
imported by compatible offline analyzers, including Automation Manager Free.

The collector calls an undocumented Atlassian Automation `internal-api`
endpoint. It can change without notice. It is an administrator utility, not a
supported Atlassian API integration, and it is never called by the Forge app.

## Source of truth

- Collector: [`collect_automation_audit.py`](collect_automation_audit.py)
- Tests: [`tests/test_collect_automation_audit.py`](tests/test_collect_automation_audit.py)

This repository is the source of truth. Documentation sites should link to a
tagged release so fixes, tests, and security warnings stay versioned together.

## Requirements

- Python 3.10 or later.
- No collector-specific runtime packages. Python must have access to an IANA
  timezone database.
- An Atlassian account that can open the global Jira Automation Audit Log.
- A classic Atlassian API token owned by that account.

Most Linux and macOS installations provide IANA timezone data through the
operating system. A clean Windows Python installation may need:

```powershell
py -m pip install tzdata
```

## Authentication

Use the email address and API token of an account that can open the global Jira
Automation audit log. The token is read only from environment variables.

```powershell
$env:ATLASSIAN_EMAIL = Read-Host "Atlassian account email"
$secureToken = Read-Host "Atlassian API token" -AsSecureString
$env:ATLASSIAN_API_TOKEN = [System.Net.NetworkCredential]::new("", $secureToken).Password
```

The collector does not accept a token on the command line and does not write
tokens, cookies, URLs, user data, rule values, or associated-item values to its
detail output.

## Collection modes

All examples use an explicit ISO-8601 period and an IANA timezone. Choose a
period that matches the period you intend to analyze.

### 1. Overview — fastest estate-wide evidence

```powershell
py collect_automation_audit.py `
  --site "https://example.atlassian.net" `
  --timezone "America/Sao_Paulo" `
  --mode list `
  --from-time "2026-11-01T03:00:00.000Z" `
  --to-time "2026-12-01T03:00:00.000Z" `
  --output "C:\audit\automation-audit-logs-november.csv"
```

This mode paginates execution rows and preserves Atlassian's reported
`automationStepUsage.totalSteps` when available. Large collections are split
into CSV parts. Import every generated part together.

### 2. Complete detail — slow, execution-path evidence

```powershell
py collect_automation_audit.py `
  --site "https://example.atlassian.net" `
  --timezone "America/Sao_Paulo" `
  --mode detail `
  --from-time "2026-11-01T03:00:00.000Z" `
  --to-time "2026-11-02T03:00:00.000Z" `
  --output "C:\audit\automation-audit-details-one-day.json"
```

This mode makes one additional detail request for each selected execution. It
is intentionally much slower on large estates. The output is split into
bounded JSON parts and can be resumed when intact existing parts belong to the
same collection.

### 3. Rule-filtered detail — recommended investigation workflow

```powershell
py collect_automation_audit.py `
  --site "https://example.atlassian.net" `
  --timezone "America/Sao_Paulo" `
  --mode detail `
  --from-time "2026-11-01T03:00:00.000Z" `
  --to-time "2026-12-01T03:00:00.000Z" `
  --rule-id "00000000-0000-0000-0000-000000000000" `
  --output "C:\audit\automation-audit-details-selected-rule.json"
```

Repeat `--rule-id` to collect more than one rule. The Analyzer labels this
evidence as rule-scoped and does not present it as complete estate coverage.

## Import into Automation Manager Free

1. Import the Automation configuration JSON first.
2. Add all overview CSV parts, if collected.
3. Add all detailed JSON parts, if collected.
4. Correlate the Audit Log evidence.

Overview CSV and detail JSON are complementary. The overview remains
authoritative for execution and official step totals. Matching detail traces
explain the executed path without counting the run or its steps twice.

## Operational notes

- The observed internal list page maximum is 50 records.
- `CONFIG_CHANGE` rows are administrative and are skipped.
- `IN_PROGRESS` rows are incomplete and are skipped.
- HTTP 429, transient 5xx responses, and network timeouts are retried.
- `--max-records` is useful for validation samples; omit it for the complete
  selected period.
- `--schema-only` inspects field paths from one page without writing tenant
  values.
- Output filenames must start with `automation-audit-logs-` or
  `automation-audit-details-`. Repository Git rules ignore those evidence
  files, but administrators must still store and handle them as sensitive Jira
  operational data.

Run the collector tests with:

```powershell
py -m unittest discover -s tests -p "test_*.py"
```

Clear credentials from the current shell when finished:

```powershell
Remove-Item Env:ATLASSIAN_EMAIL -ErrorAction SilentlyContinue
Remove-Item Env:ATLASSIAN_API_TOKEN -ErrorAction SilentlyContinue
```

## Security and privacy

- The token is accepted only through environment variables and is never
  accepted as a command-line argument.
- The collector validates mapped records and fails closed instead of emitting
  a misleading partial contract when the response shape is unknown.
- Detailed output excludes user data, URLs, cookies, tokens, rule values, and
  associated-item values.
- Output still contains Jira operational metadata and must be treated as
  sensitive administrative data.
- Never attach real Audit evidence, HAR files, cookies, or tokens to a public
  issue. See [SECURITY.md](SECURITY.md).

## Supported output contracts

- Overview CSV: analyzer-compatible execution rows with Atlassian-reported
  automation steps when available.
- Detailed JSON: `automation-audit-detail/0.2`, split into a complete set of
  bounded parts for large collections.

The JSON contract is documented in
[`schemas/automation-audit-detail-0.2.schema.json`](schemas/automation-audit-detail-0.2.schema.json).

## Project status

The collector is experimental because its upstream endpoint is unsupported.
Versioning applies to this collector's CLI and output contracts; it cannot make
the Atlassian endpoint stable.

See [CHANGELOG.md](CHANGELOG.md) for released behavior and
[CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.
