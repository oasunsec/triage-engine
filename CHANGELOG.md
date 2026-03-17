# Changelog

All notable changes to this project will be documented in this file.

## [3.0.0] - 2026-03-17

Initial public release of Triage Engine.

### Added

- Public GitHub-ready README with local Python, Docker, and CLI quick start paths
- Sanitized screenshot gallery for the review queue, baseline case, attack case, finding detail, incident detail, and HTML report
- Demo redaction support for public-safe screenshots and report exports
- Runtime mode indicator for local Python and Docker execution
- PowerShell encoded command preview decoding for clearer investigation evidence
- Public example environment file and release-quality documentation under `docs/`

### Improved

- HTML report rendering stability for generated public reports
- Startup experience with a Windows PowerShell launcher
- Public repository hygiene, ignore rules, and clone-ready structure

### Security

- Public-facing path sanitization to avoid leaking local machine paths in UI and reports

