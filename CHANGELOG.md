# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for its CLI and output contracts.

## [Unreleased]

## [0.2.0] - 2026-11-13

### Added

- Paginated POST collection for the global Jira Automation Audit Log.
- Overview CSV collection with Atlassian-reported automation steps.
- Detailed execution traces using the `automation-audit-detail/0.2` contract.
- Server-side filtering by one or more rule UUIDs.
- Bounded CSV and JSON part files for large collections.
- Compatible detailed-part reuse when resuming an interrupted collection.
- Retry handling for throttling, transient server errors, and network timeouts.
- Explicit skipping of administrative `CONFIG_CHANGE` and incomplete
  `IN_PROGRESS` records.
- Schema-only inspection that does not write tenant values.
- Privacy-safe output mapping and fail-closed schema validation.

[Unreleased]: https://github.com/idevsolutions/jira-automation-audit-evidence-collector/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/idevsolutions/jira-automation-audit-evidence-collector/releases/tag/v0.2.0
