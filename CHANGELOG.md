# Changelog

## 0.2.0 — Days 3–4

### Added
- Provenance-aware NetworkX graph for endpoints, resources, identifiers, schemas, properties and security schemes.
- Safe local schema-reference inspection and JSON graph export (`map-api`).
- Passive specification-based security hypotheses (`assess`) for explicit public operations, object-identifier candidates and potentially sensitive fields.
- Structured request/response evidence models.
- GET-only HTTP client with explicit hostname allowlist, dry-run by default, explicit execution opt-in, timeout, rate limit, request budget, disabled redirects, TLS verification and bounded response capture.
- `http-get` CLI command.
- Automated graph, assessment, HTTP safety and CLI tests.

### Changed
- Project version bumped to `0.2.0`.
- README, architecture documentation, development roadmap and repository guide updated.

### Safety notes
- Passive findings are hypotheses, not confirmed vulnerabilities.
- No network traffic is sent unless `http-get` is invoked with `--execute` and an exact `--allow-host` value.
- Only GET requests are supported in this milestone.
