# AchillesAPI
AI-assisted, context-aware API security assessment framework for automated vulnerability discovery and intelligent REST API security testing.


## 1. Project overview

**AchillesAPI** is an open-source, Python-based project exploring how deterministic API security assessment can be combined with context-aware analysis and AI assistance.

The project is designed to help security testers understand an API before testing it. Its long-term direction is to build a structured representation of API resources, operations, identifiers, schemas, and security requirements, then use that context to support focused security assessments.

The name refers to the **Achilles' heel**: the weak point in something that otherwise appears strong. In the context of API security, AchillesAPI aims to identify weaknesses that may be hidden in an API's design, object relationships, or authorization model.

## 2. Current project status

The repository currently contains the Day 1–2 foundation (version `0.1.0`). It focuses on importing and normalizing OpenAPI 3.x specifications.

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
- Provide a command-line interface and automated tests.

**Important:** this milestone is an offline specification analyzer. It does not send requests to the target API and does not yet perform active vulnerability testing.

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
│   │   └── openapi.py            # OpenAPI loading, validation and normalization
│   ├── models/
│   │   └── api.py                # Typed data models
│   ├── utils/                    # Shared utilities
│   ├── __init__.py
│   └── cli.py                    # CLI commands
├── tests/
│   └── test_openapi.py           # Automated tests for the parser
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
        v
 CLI summary / normalized JSON
```

The main implementation areas are:

- `src/achillesapi/core/openapi.py`: loads the specification, validates it, resolves local references, and extracts normalized endpoint information.
- `src/achillesapi/models/api.py`: defines the Pydantic models used to represent parsed APIs, endpoints, parameters, and security metadata.
- `src/achillesapi/cli.py`: exposes the functionality through the `achillesapi` command.
- `tests/`: verifies parsing behavior and important edge cases.

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
- Future active checks should require an explicitly configured and authorized target.
- Future test execution should include safe defaults, request limits, and clear control over which operations are in scope.
- AI-generated observations should be treated as hypotheses, not confirmed vulnerabilities. A finding must be supported by reproducible technical evidence.

## 9. Current limitations

- Only OpenAPI 3.x is supported; Swagger 2.0 is not currently supported.
- Only local JSON Pointer references are resolved.
- Nested response and request schemas are not yet fully transformed into a graph of resources and properties.
- The current release does not perform HTTP traffic generation or active security tests.
- Full OpenAPI conformance validation depends on the declared `openapi-spec-validator` dependency being installed. The minimal fallback used in offline development is not a replacement for full validation.

## 10. Planned direction

The next development milestones are expected to build on the normalized specification model:

1. **Endpoint relationship engine:** represent endpoints, resources, identifiers, and schema properties as a graph.
2. **Context-aware security analysis:** use the graph to identify candidate authorization and object-access test cases.
3. **Deterministic test execution:** introduce controlled HTTP testing for explicitly authorized targets.
4. **AI-assisted reasoning:** use local or configurable AI assistance to prioritize hypotheses and explain relationships, while keeping evidence and vulnerability confirmation deterministic.
5. **Reporting:** produce structured findings with reproducible evidence and remediation guidance.

The roadmap in `docs/development-plan.md` is the source of truth for milestone tracking.

## 11. License

AchillesAPI is distributed under the MIT License. See [LICENSE](LICENSE).
