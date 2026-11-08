## 0.44.0 — Correzioni dashboard PDF / AI / risultati precedenti

- Extra dashboard installa automaticamente ReportLab per export PDF.
- HTML/PDF inline in scheda nuova; download senza lasciare il workspace.
- `ai-correlate` riceve un assessment HTTP precedente (non il manifest YAML) e adatta i metadati delle osservazioni in modo sanitizzato.
- Selettore dei risultati precedenti nella UI con verifiche dei prerequisiti.
- Errori espliciti per output Ollama vuoto o JSON non valido; nessun uso cloud.
- Test regressione e mock Ollama locale.

## 0.42.0 — Guided disposable-resource workflows

- Wizard visuale a quattro schermate per manifest senza segnaposto.
- Preflight lato server e messaggi in italiano, tipi e limiti dal contratto OpenAPI.
- Configurazioni avanzate nascoste per semplicità; laboratorio sempre indipendente.
- Nuovi test di validazione del workflow guidato e test reale GET/POST/DELETE.

## 0.39.0 — Strict target/dashboard separation

- Removed lab lifecycle actions, bundled demo loading, hardcoded target URLs and automatic lab test-secret environment injection from dashboard.
- Standalone lab delivered separately and starts only from terminal.
- Dashboard tool registry still supports OpenAPI-driven discovery, authorized GET assessment, configured disposable write workflows and reports.
- Updated browser labels, Italian documentation and regression tests for lab-independent operation.

## v0.38.0
- Dashboard locale Control Center, avvio/stop lab e Ollama, catalogo strumenti, runner controllato, laboratorio indipendente, guida italiana.

## 0.37.0

Dashboard locale, state engine con mutazioni approvate, policy verifier, agent v2; dettagli in RELEASE_NOTES_v0.37.0.md.

# 0.31.0

- Added offline scope, workflow DAG, coverage, differential analysis, benchmark and coverage-guided next actions.
- Optional DNS/IP CIDR preflight in SafeHTTPClient; additional HTTP metadata redaction.
- Detailed Italian v0.31 user guide and regression tests. See RELEASE_NOTES_v0.31.0.md for limits.

## [0.23.0] - 2026-11-07
- Workflows con 1–5 mutazioni successive su fixture verificate, cleanup best effort.
- Inventory OWASP API offline, miglioramento probe format/minLength.
- Motore deterministic bounded follow-up e `agent-review`, `--agent-budget`.
- Scope/budget preflight nei workflow prima di contattare l'autenticazione dinamica.
- Test unitari e integrazione real HTTP, nuova guida v0.23.

## 0.12.0 — Disposable Workflow Engine (2026-11-07)

- CRUD workflow discovery and non-executable YAML draft generation.
- Opt-in disposable POST/GET/PATCH/PUT/DELETE lifecycle with explicit policy.
- BOLA/BFLA and mass assignment checks with verified resource ID and cleanup attempt.
- One-command integration with `auto-assess` and shared request cap.
- Better safety constraints, clear cleanup failure signaling, independent integration tests.
- Italian workflow and command reference documentation.

## 0.11.0 — Adaptive Assessment Foundation (2026-11-07)

- New schema-aware active assessment engine independent of the training lab.
- Scoped GET-only checks: auth, CORS, input validation, error and property disclosure.
- Optional operator context for test IDs and authorization policies.
- Independent HTTP integration tests, new guide and updated CLI.

## 0.10.2 — Full Local Training Lab (2026-11-07)

- Fully documented local FastAPI training target with vulnerable and protected endpoints.
- PowerShell scripts to start API, optional Ollama and automated demos.
- Authentication-aware matching for the generic GET assessment engine.
- Additional lab and engine regression tests, docs, and OpenAPI export.

## 0.10.1 — Generic Assessment Foundation (2026-11-07)

- New `auto-assess` OpenAPI-driven dry-run and authorized GET execution.
- Security test proposals and passive hypotheses included in generic output.
- Profile-based, metadata-only multi-identity GET observations.
- Simple inline explanations on all Python functions plus Italian code guide.
- Broader cross-API tests and updated README.

# Changelog

## 0.5.0 — Local AI foundation

- Added a loopback-only Ollama client using Python's standard library; no cloud AI SDK or API key.
- Added best-effort credential/PII redaction before local model inference.
- Added structured-response validation and explicit advisory-only AI semantics.
- Added `ai-analyze` for local OpenAPI interpretation.
- Added `scan` for passive OpenAPI assessment with optional local AI analysis.
- Added Kali systemd configuration, Ollama Modelfile, and local-AI setup/troubleshooting guide.
- Kept the v0.4.0 deterministic scanner, local lab, and constrained checks.
- Added mocked tests for local-only endpoint enforcement, redaction, response validation and CLI behavior.

## 0.4.0

- Added BOLA/BFLA sweep, safe SQLi canary, benign parameter fuzzing, mass-assignment check and offline JWT inspection.

## [0.6.0] - Authentication Engine foundation

- Added environment-backed Bearer, Basic, API Key and cookie authentication profiles.
- Added safe profile inspection and profile-backed scoped GET requests.
- Added redaction for request authorization material and credential query parameters.
- Added profile examples, documentation and automated tests.
- OAuth refresh, interactive login and multi-step session renewal remain out of scope for this release.

## [0.7.0] - 2026-11-06
### Added
- Multi-profile `role-matrix` authorization comparison for GET endpoints.
- JSON property visibility comparison and sanitized structural evidence for BOPLA triage.
- CLI profile selection, path placeholder values and JSON report output.
### Security
- Role matrix is loopback-only, GET-only, redirect-disabled and does not persist response values or credentials.

## [0.8.0] - 2026-11-06

### Added
- Deterministic offline `generate-tests` command for OpenAPI-driven security test planning.
- Candidate BOLA, BFLA, BOPLA, mass-assignment and parameter-constraint checks.
- Inferred POST collection-to-item GET workflows with explicit inference confidence.
- Machine-readable JSON test plans with prerequisites, evidence guidance, risk labels and manual-review gates.
- Explicit generation policy metadata: no HTTP requests, no credential resolution and no AI invocation.

### Security and scope
- Generated cases are proposals, not findings or proof of vulnerabilities.
- No generated case is executed automatically. Stateful/write checks require disposable fixtures, policy review and teardown.

## [0.9.0] - 2026-11-06

### Added
- Offline `analyze-evidence` command for deterministic analysis of captured HTTP response bundles.
- Detection indicators for credentialed wildcard CORS, missing baseline browser security headers on HTML, missing HSTS on captured HTTPS responses, technology disclosure headers, server errors, and common SQL/debug/stack-trace error markers.
- Severity/confidence labels, deduplication by endpoint and rule, response status summaries, and machine-readable JSON output.
- Example response evidence bundle and regression tests.

### Security and limitations
- Evidence analysis sends no requests and does not resolve authentication profiles.
- Response bodies are inspected in memory only; report output contains marker names, not body excerpts or raw header values.
- Input is capped at 1,000 responses and 64 KiB body preview per response.
- Indicators require manual validation; no result is automatically marked as a confirmed vulnerability.

## [0.10.0] - AI Intelligence Engine
- Added `ai-correlate` to correlate OpenAPI metadata with deterministic captured-response evidence using loopback-only Ollama.
- Added bounded, schema-validated outputs for correlations, false-positive checks, next steps and limitations.
- Preserved offline target boundary, sanitization and advisory-only model semantics.

## 0.16.0 — Intelligent planning and independent API laboratory
- New offline `intelligent-plan`: bounded schema-based payload candidates, path/query examples, heuristic response-to-path dependencies and check selection.
- New offline `adaptive-review`: prioritized follow-ups from HTTP observation metadata.
- `auto-assess` now includes the intelligent plan and evidence-based follow-up queue in its JSON report.
- Added a separate deliberately vulnerable Harbor Inventory FastAPI training app, generated OpenAPI spec, reviewed disposable workflow, authentication profiles and PowerShell scripts.
- Added Italian end-to-end guide and independent regression tests.
- **Not yet implemented:** autonomous OAuth2 lifecycle, arbitrary business logic analysis, general multi-step orchestrator, production-grade PDF reporting. The v0.16 number denotes a development milestone, not a certification of production readiness.

## [0.20.0] - 2026-11-07

- Dynamic OAuth2 client-credentials and JSON-login profiles with scope restrictions, environment-only credentials and bounded acquisition attempts.
- `auth-draft`, `journey-discover`, `journey-assess` CLI commands independent of lab-specific routes.
- Runtime read-only JSON Pointer dataflow; reviewed disposable writes remain delegated to `workflow-assess`.
- Passive response-contract field/type checks; bounded adaptive repeat checks for GET HTTP 5xx.
- Integrated `--journey-config` and `--adaptive-verify` with `auto-assess` budgets.
- Additional FastAPI lab and end-to-end tests; complete Italian user guide.

## [0.27.0] - 2026-11-08
- v0.24: conservative offline professional report (JSON/Markdown/HTML/optional PDF).
- v0.25: evidence-based review queue (`vulnerability-triage`).
- v0.26: candidate producer/consumer dependency map (`workflow-map`).
- v0.27: deterministic policy-gated review (`ai-prioritize`) with optional local-only Ollama advice.
- Integrated triage and dependency metadata into `auto-assess`; added regression tests.

## [0.34.0] — 2026-11-08
- Added safe multi-resource disposable fixture execution with ID capture, read verification, explicit policy checks and reverse cleanup.
- Added scoped advanced vulnerability GET assessment and offline OWASP-aware evidence triage.
- Added bounded read-only autonomous-agent follow-ups and local-only Ollama advisory.
- Added integrated `auto-assess --multi-resource-config` and independent nested-resource lab.
- No general-purpose attack exploitation or unsupervised LLM write execution.

## 0.40.0

- Unified independent guided dashboard with file upload + paste flows, editable authentication template, bounded per-job secrets and clearer errors.
- CLI auto-assess no-manifest UnboundLocalError fixed. Independent API still external.

## 0.41.0

- Browser manifest wizard: CRUD discovery, YAML draft, validation, import and download.
- Hard block for unreviewed REVIEW_/TODO_ manifest placeholders before writes.
- Numeric inputs clamped to documented limits, backend validation errors rendered in Italian.
- Actionable job failures for auth, scope, budget, cleanup, YAML and connectivity.
- Dedicated Italian guide and regression tests; standalone API lab remains external.
