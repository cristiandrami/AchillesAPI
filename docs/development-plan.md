# Development plan

## Day 1 — Project foundation

- [x] Create Python package layout.
- [x] Configure `pyproject.toml`, development tools, and CLI entry point.
- [x] Add example OpenAPI document.
- [x] Add README and development documentation.

## Day 2 — OpenAPI intelligence

- [x] Load YAML and JSON specifications.
- [x] Validate OpenAPI 3.x documents.
- [x] Resolve local JSON Pointer references.
- [x] Extract operations and metadata.
- [x] Merge path-level and operation-level parameters.
- [x] Resolve inherited and operation-level security requirements.
- [x] Extract security scheme definitions.
- [x] Export normalized JSON from the CLI.
- [x] Add automated tests.

## Day 3 — Endpoint and resource relationship graph

- [x] Identify path-template variables and candidate object identifiers.
- [x] Extract request and response schema properties.
- [x] Resolve local schema references safely (no remote fetches).
- [x] Build a NetworkX graph with typed nodes and edges.
- [x] Label explicit facts separately from inferred relationships.
- [x] Export graph as JSON for inspection.
- [x] Add graph tests.

## Day 4 — Safe HTTP execution foundation

- [x] Define an exact hostname allowlist and explicit execution opt-in.
- [x] Add structured request/response evidence models.
- [x] Add an HTTP client with timeout, request budget, and rate limit.
- [x] Make dry-run the default and restrict this milestone to GET.
- [x] Disable redirects, retain TLS verification, and cap captured response data.
- [x] Add a CLI command and safety tests for dry-run and scope enforcement.

## Day 5 — Controlled local integration testing

- [ ] Create a local deliberately vulnerable API fixture.
- [ ] Add integration tests that never contact external systems.
- [ ] Validate evidence serialization and response redaction.
- [ ] Add repeatable test scenarios for authorization boundaries.
