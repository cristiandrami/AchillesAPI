# Development Plan

## Completed

- **Days 1–2:** OpenAPI loading, validation, normalization, local `$ref` handling, Pydantic models, CLI, and parser tests.
- **Days 3–4:** Relationship graph, explicit/inferred provenance, passive security assessment, JSON exports, and scoped GET execution.
- **Days 5–6:** Local vulnerable API lab, secure comparison endpoint, and a loopback-only two-principal BOLA checker with dry-run default and explicit execution.

## Next milestones

1. Introduce reusable authentication profiles rather than passing two raw bearer tokens to a single check.
2. Generate candidate object-level authorization tests from OpenAPI paths and identifier parameters.
3. Add safe test data setup/teardown and reproducible evidence records.
4. Extend active testing carefully to BFLA and BOPLA scenarios.
5. Add response comparison, redaction, and report generation.
6. Integrate AI for contextual test prioritization and explanation, keeping deterministic checks as the source of truth.


## v0.4.0 delivered scope

- Multi-endpoint BOLA sweep and low/high role response comparison (GET-only, loopback-only).
- Explicit local PATCH mass-assignment probe with dry-run default.
- Non-destructive quote-only SQLi canary (GET-only).
- Nine-case benign query parameter robustness fuzzing.
- Offline JWT header/claim inspection without signature verification.
- Expanded local lab: BOLA vulnerable/protected routes, admin-only route for BFLA, vulnerable/allowlisted profile PATCH routes, and harmless search endpoint.

Known limitations: BOLA/BFLA sweeps are triage tools, not automatic vulnerability proof; BOLA needs meaningful object identifiers supplied via `--path-value`. BFLA currently compares GET endpoints only and requires a role policy review. SQLi probing is intentionally conservative and cannot rule out injection. JWT inspection is decode-only.
