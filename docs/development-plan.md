# Development Plan

## Completed

- **Days 1–2:** OpenAPI loading, validation, normalization, local `$ref` handling, Pydantic models, CLI, and parser tests.
- **Days 3–4:** Relationship graph, explicit/inferred provenance, passive security assessment, JSON exports, and scoped GET execution.
- **Days 5–6:** Local vulnerable API lab, secure comparison endpoint, and a loopback-only two-principal BOLA checker with dry-run default and explicit execution.

## v0.6.0 delivered — Authentication Engine foundation

- Environment-backed profiles for Bearer, Basic, API Key (header/query/cookie) and cookie credentials.
- Configuration validation, unique profile names and fail-closed handling for missing secrets.
- Safe profile inspection that lists environment variable names but never resolves or prints secret values.
- Profile-backed scoped GET requests through `http-get --auth-config ... --auth-profile ...`.
- Two distinct Bearer profiles can be selected directly by BOLA/BFLA sweep commands.
- Request evidence redacts authorization headers, configured authentication headers, cookies and credential query parameters.
- Added an example profile file and automated tests.

Known limitations: profiles are currently selected one at a time by `http-get`; BOLA/BFLA sweeps still use their existing token arguments. Interactive login, OAuth token refresh, automatic session renewal and multi-user orchestration are not implemented yet. Basic auth is encoded for HTTP Basic and is not encryption; use HTTPS outside localhost labs.

## Next milestones

1. Expand authorization sweeps from two profiles to multi-identity / role matrices and support non-Bearer schemes where appropriate.
2. Generate candidate object-level authorization tests from OpenAPI paths and identifier parameters.
3. Add BOPLA checks and stronger mass-assignment validation.
4. Add response comparison, evidence correlation and confidence scoring.
5. Introduce safe test data setup/teardown and reproducible workflow execution.
6. Integrate AI for contextual test planning and explanation, keeping deterministic checks as the source of truth.


## v0.4.0 delivered scope

- Multi-endpoint BOLA sweep and low/high role response comparison (GET-only, loopback-only).
- Explicit local PATCH mass-assignment probe with dry-run default.
- Non-destructive quote-only SQLi canary (GET-only).
- Nine-case benign query parameter robustness fuzzing.
- Offline JWT header/claim inspection without signature verification.
- Expanded local lab: BOLA vulnerable/protected routes, admin-only route for BFLA, vulnerable/allowlisted profile PATCH routes, and harmless search endpoint.

Known limitations: BOLA/BFLA sweeps are triage tools, not automatic vulnerability proof; BOLA needs meaningful object identifiers supplied via `--path-value`. BFLA currently compares GET endpoints only and requires a role policy review. SQLi probing is intentionally conservative and cannot rule out injection. JWT inspection is decode-only.


## v0.7.0 implementation status

The v0.7.0 release adds a loopback-only, GET-only multi-profile `role-matrix` command. It compares response status and JSON property visibility across 2–10 authentication profiles. Evidence retains property paths and response metadata/fingerprints, not response values or credentials. Differences remain triage signals because the intended authorization policy must be supplied and reviewed by the assessor. Full workflow-aware BOLA/BFLA/BOPLA verification, policy-as-code, and safe stateful request generation remain future work.

## v0.8.0 implementation status

- Added `generate-tests` for deterministic offline test-plan generation.
- Added parameter inventory and heuristic object-identifier candidates from OpenAPI path parameters.
- Added candidate BOLA, BFLA, BOPLA, mass-assignment and parameter-constraint checks.
- Added inferred POST collection-to-item GET workflows, explicitly marked as inferred.
- Output includes prerequisites, evidence suggestions, risk labels and execution policy metadata.
- Generation sends no HTTP requests, resolves no credentials and does not invoke Ollama.

Known limitations: workflow inference currently uses conservative path-template matching; it does not infer arbitrary data dependencies, pagination, authentication refresh, or stateful setup/teardown. The generated plan is a review artifact, not an executable test runner or vulnerability verdict.
