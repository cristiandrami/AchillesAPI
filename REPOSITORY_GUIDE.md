# AchillesAPI — Repository Guide

## 1. Project overview

**AchillesAPI** is an open-source, Python-based project exploring how deterministic API security assessment can be combined with context-aware analysis and AI assistance.

The project is designed to help security testers understand an API before testing it. Its long-term direction is to build a structured representation of API resources, operations, identifiers, schemas, and security requirements, then use that context to support focused security assessments.

The name refers to the **Achilles' heel**: the weak point in something that otherwise appears strong. In the context of API security, AchillesAPI aims to identify weaknesses that may be hidden in an API's design, object relationships, or authorization model.

## 2. Current project status

The repository currently contains the Day 1–4 foundation (version `0.2.0`): OpenAPI ingestion, a provenance-aware relationship graph, passive specification-based checks, and a conservative HTTP execution primitive.

Implemented capabilities:

- Load OpenAPI documents in YAML and JSON formats.
- Validate OpenAPI 3.x documents, using `openapi-spec-validator` when installed.
- Resolve local JSON Pointer `$ref` references.
- Reject remote `$ref` references rather than retrieving external resources implicitly.
- Extract and normalize API operations and endpoint metadata.
- Collect path-level and operation-level parameters, including override behavior.
- Extract request-body and response metadata.
- Extract server definitions, tags, and operation IDs.
- Resolve root-level and operation-level security requirements.
- Preserve the important distinction between inherited security and an explicit `security: []` declaration.
- Export normalized API metadata as JSON.
- Build a NetworkX graph of endpoints, resources, identifiers, schemas, properties, and security schemes.
- Label graph facts as explicit or inferred and export the graph as JSON.
- Run passive checks for missing/disabled security, object-identifier candidates, and potentially sensitive properties.
- Provide a scoped HTTP client: GET-only, exact host allowlist, dry-run by default, explicit execution opt-in, timeout, rate limit, request budget, disabled redirects, TLS verification, and bounded response capture.
- Store structured request/response evidence and redact sensitive response headers.
- Provide CLI commands and automated tests.

**Important:** passive findings are hypotheses, not confirmed vulnerabilities. HTTP execution is intentionally limited and must only be used against systems for which the operator has explicit authorization.

## 3. Repository layout

```text
.
├── .github/workflows/tests.yml   # Continuous integration workflow
├── docs/
│   ├── architecture.md           # Current architecture and design decisions
│   └── development-plan.md       # Milestones and implementation roadmap
├── examples/
│   └── sample_api.yaml           # Example OpenAPI 3.x document
├── src/achillesapi/
│   ├── core/
│   │   ├── openapi.py            # OpenAPI loading, validation and normalization
│   │   ├── graph.py              # Endpoint/resource/schema relationship graph
│   │   ├── assessment.py         # Passive specification-based checks
│   │   └── http.py               # Scoped, conservative HTTP client
│   ├── models/
│   │   ├── api.py                # Normalized OpenAPI data models
│   │   └── evidence.py           # Request, response and finding models
│   ├── utils/
│   ├── __init__.py
│   └── cli.py                    # CLI commands
├── tests/                        # Parser, graph, assessment and HTTP tests
├── pyproject.toml                # Package metadata and dependencies
├── README.md                     # User-facing project introduction
├── REPOSITORY_GUIDE.md           # This repository guide
└── LICENSE                       # MIT license
```

## 4. Architecture

The current processing pipeline is:

```text
OpenAPI YAML / JSON
        |
        v
    File loader
        |
        v
 Specification validator
        |
        v
  Local $ref resolver
        |
        v
 Endpoint normalizer
        |
        +--> Endpoint metadata
        +--> Parameters and request bodies
        +--> Security schemes and requirements
        +--> Server definitions
        |
        +--> NetworkX relationship graph
        +--> Passive security hypotheses
        +--> Scoped HTTP execution and evidence
        |
        v
 CLI summaries / JSON exports
```

The main implementation areas are:

- `src/achillesapi/core/openapi.py`: loads, validates and normalizes OpenAPI.
- `src/achillesapi/core/graph.py`: builds and serializes the API relationship graph.
- `src/achillesapi/core/assessment.py`: emits passive security hypotheses from specification metadata.
- `src/achillesapi/core/http.py`: provides the explicit-scope, GET-only HTTP execution layer.
- `src/achillesapi/models/`: contains normalized API and evidence models.
- `src/achillesapi/cli.py`: exposes all capabilities through the `achillesapi` command.
- `tests/`: covers parser, graph, assessment and HTTP safety behavior.

## 5. Requirements and setup

Requirements:

- Python 3.11 or newer.
- [`uv`](https://docs.astral.sh/uv/) is recommended for environment and dependency management.

Clone the repository and install the development dependencies:

```bash
git clone <your-repository-url>
cd achillesapi
uv sync --extra dev
```

Alternatively, install it with pip in a virtual environment:

```bash
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
.venv\\Scripts\\Activate.ps1

python -m pip install -e ".[dev]"
```

## 6. Running AchillesAPI

Analyze the included example specification:

```bash
uv run achillesapi analyze-openapi examples/sample_api.yaml
```

Export the normalized representation to a JSON file:

```bash
uv run achillesapi analyze-openapi examples/sample_api.yaml --output reports/sample.json
```

Build a relationship graph:

```bash
uv run achillesapi map-api examples/sample_api.yaml --output reports/api-graph.json
```

Run passive checks without sending network traffic:

```bash
uv run achillesapi assess examples/sample_api.yaml --output reports/assessment.json
```

Create a dry-run GET request plan (no request is sent):

```bash
uv run achillesapi http-get https://api.example.test/health --allow-host api.example.test
```

To send the request, only for a host you are explicitly authorized to test, add
`--execute`:

```bash
uv run achillesapi http-get https://api.example.test/health --allow-host api.example.test --execute
```

Display the installed version:

```bash
uv run achillesapi version
```

## 7. Testing and code quality

Run the test suite:

```bash
uv run pytest -v
```

Run lint checks:

```bash
uv run ruff check .
```

The GitHub Actions workflow runs the automated tests across supported Python versions. The parser tests cover valid and invalid specifications, endpoint extraction, parameter merging, security inheritance and overrides, local references, and rejection of remote references.

## 8. Security design principles

AchillesAPI is intended for legitimate security assessment and authorized testing. The current parser follows conservative defaults:

- Importing a specification must not trigger requests to the API described by that specification.
- Remote `$ref` values are rejected; only local references are resolved.
- Parsing and analysis are kept separate from active testing.
- HTTP execution requires an exact hostname allowlist and explicit `--execute` opt-in; dry-run is the default.
- Only GET is supported in this milestone. Redirects are disabled and TLS verification is enabled.
- Timeouts, request budgets, rate limits, and bounded response previews reduce accidental impact.
- AI-generated observations should be treated as hypotheses, not confirmed vulnerabilities. A finding must be supported by reproducible technical evidence.

## 9. Current limitations

- Only OpenAPI 3.x is supported; Swagger 2.0 is not currently supported.
- Only local JSON Pointer references are resolved.
- Graph resource grouping and identifier matching are heuristic; inferred edges do not prove application data flow or authorization behavior.
- Passive checks intentionally cover a limited set of signals and may miss complex composed schemas or runtime behavior.
- HTTP execution does not yet construct authenticated requests, populate parameter values, follow pagination, or test non-GET methods.
- No vulnerability is confirmed by the passive assessment alone.
- Full OpenAPI conformance validation depends on the declared `openapi-spec-validator` dependency being installed. The minimal fallback used in offline development is not a replacement for full validation.

## 10. Planned direction

The next development milestones are expected to build on the current foundation:

1. **Controlled local integration testing:** validate the HTTP client against a local deliberately vulnerable API without external traffic.
2. **Context-aware test planning:** use graph relationships to build safe, reviewable authorization test cases.
3. **Authenticated test sessions:** add credentials and principal contexts with secret-safe handling.
4. **AI-assisted reasoning:** prioritize hypotheses and explain relationships while keeping evidence and vulnerability confirmation deterministic.
5. **Reporting:** produce structured findings with reproducible evidence and remediation guidance.

The roadmap in `docs/development-plan.md` is the source of truth for milestone tracking.

## 11. License

AchillesAPI is distributed under the MIT License. See [LICENSE](LICENSE).
