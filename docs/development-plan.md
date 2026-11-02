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

- [ ] Identify path-template variables and candidate object identifiers.
- [ ] Extract request and response schema properties.
- [ ] Resolve schema references safely.
- [ ] Build a NetworkX graph with typed nodes and edges.
- [ ] Label explicit facts separately from inferred relationships.
- [ ] Export graph as JSON for inspection.

## Day 4–5 — HTTP execution foundation

- [ ] Define explicit target allowlist and authorization boundary.
- [ ] Add request/response evidence models.
- [ ] Add safe HTTP client with timeout, request budget, and rate limit.
- [ ] Add dry-run mode and read-only defaults.
- [ ] Create integration tests against a local deliberately vulnerable API.
