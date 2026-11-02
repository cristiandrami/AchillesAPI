# AchillesAPI

**AI-assisted, context-aware API security assessment framework for
automated vulnerability discovery and intelligent REST API security
testing.**

AchillesAPI is a Python-based project designed to help security testers
understand REST APIs, map their attack surface, identify potentially
interesting security weaknesses, and progressively automate API security
assessments.

The project is being developed incrementally. The current scope (Days
1--4, version 0.2.0) focuses on OpenAPI analysis, API relationship
mapping, passive security observations, and a deliberately constrained
HTTP GET client.

> **Project status:** AchillesAPI is an early-stage framework. Findings
> produced by its passive assessment are leads for further
> investigation, not proof that a vulnerability exists.

------------------------------------------------------------------------

## Table of contents

-   [Goals](#goals)
-   [Current capabilities](#current-capabilities)
-   [Requirements](#requirements)
-   [Installation](#installation)
-   [Quick start](#quick-start)
-   [CLI commands](#cli-commands)
-   [Understanding the API graph](#understanding-the-api-graph)
-   [Visualizing the graph with
    Gephi](#visualizing-the-graph-with-gephi)
-   [HTTP client safety model](#http-client-safety-model)
-   [Project structure](#project-structure)
-   [Current limitations](#current-limitations)
-   [Roadmap](#roadmap)
-   [Responsible use](#responsible-use)

------------------------------------------------------------------------

## Goals

AchillesAPI aims to provide a workflow that connects API specification
analysis with practical security testing.

The long-term direction is to:

1.  Parse and normalize API definitions.
2.  Build a structured model of endpoints, resources, identifiers,
    properties, and security schemes.
3.  Identify potential security test cases from the API structure.
4.  Execute controlled tests against explicitly authorized targets.
5.  Use AI to help prioritize, explain, and generate context-aware
    tests.
6.  Produce useful evidence and professional assessment reports.

The project is inspired by the idea of the *Achilles' heel*: identifying
weaknesses hidden inside systems that may otherwise appear robust.

------------------------------------------------------------------------

## Current capabilities

### 1. OpenAPI parsing and normalization

AchillesAPI can load OpenAPI 3.x documents in YAML or JSON format and
extract structured API information.

The parser handles information such as:

-   API metadata and servers.
-   Paths and HTTP operations.
-   Operation identifiers and tags.
-   Path-level and operation-level parameters.
-   Request bodies and response definitions.
-   Security requirements and security schemes.
-   Local JSON Pointer `$ref` references.

Remote `$ref` references are rejected by the current implementation.
This avoids silently retrieving external documents while parsing an API
definition.

The normalized representation is intended to give later analysis
components a consistent input, regardless of how the original OpenAPI
document is organized.

### 2. Endpoint and resource relationship graph

The relationship engine turns the normalized API model into a graph.

Depending on the information available in the specification, graph
elements can represent:

-   Endpoints and HTTP methods.
-   Resources and nested resources.
-   Identifiers, such as `userId` or `orderId`.
-   Schema properties.
-   Security schemes.
-   Relationships between these elements.

The engine distinguishes between two kinds of relationships:

-   **Explicit:** directly supported by information in the OpenAPI
    document.
-   **Inferred:** derived by the analysis engine from naming or
    structural patterns.

This distinction is important. An inferred relationship is a useful
lead, but it must not be treated as a confirmed fact.

The graph can be exported as JSON for programmatic use and further
visualization.

### 3. Passive security assessment

The passive assessment inspects the API model and its relationships to
identify areas that may deserve manual or active testing.

Examples include:

-   Operations with no security requirement declared.
-   Operations that explicitly disable inherited security with
    `security: []`.
-   Endpoints containing object identifiers that may be relevant to
    BOLA/IDOR testing.
-   Potentially sensitive properties exposed in response schemas.
-   Potentially sensitive properties accepted in request schemas.

These observations are not confirmed vulnerabilities. For example, an
endpoint with no security requirement in an OpenAPI document may still
be protected by controls implemented outside the specification.

### 4. Constrained HTTP GET client

AchillesAPI includes an initial HTTP client intended for controlled
interaction with API endpoints.

The current safety-oriented behavior includes:

-   GET requests only.
-   Dry-run mode by default.
-   Explicit host allowlisting.
-   Real execution only when the execution flag is supplied.
-   Request timeout.
-   Request-rate limiting.
-   A maximum request limit.
-   Redirects disabled.
-   TLS certificate verification enabled.
-   A maximum captured response size.
-   Redaction of sensitive request headers in recorded evidence.

This is an initial HTTP foundation, not yet a full authenticated API
testing engine.

------------------------------------------------------------------------

## Requirements

-   Python 3.11 or newer.
-   `uv` for dependency and project environment management.
-   Git (to clone the repository).

The project uses `uv` to manage its dependencies and virtual
environment. You do not need to create or activate a virtual environment
manually.

------------------------------------------------------------------------

## Installation

Clone the repository:

``` bash
git clone https://github.com/USERNAME/AchillesAPI.git
cd AchillesAPI
```

Install the project dependencies:

``` bash
uv sync --extra dev
```

Check that the CLI is available:

``` bash
uv run achillesapi version
```

Run the test suite:

``` bash
uv run pytest -v
```

Replace `USERNAME` with the GitHub account or organization that hosts
the repository.

### Installing uv on Kali Linux

If `uv` is not already installed, follow the official installation
instructions:

<https://docs.astral.sh/uv/getting-started/installation/>

After installation, open a new terminal (or reload the shell
configuration) and verify:

``` bash
uv --version
```

------------------------------------------------------------------------

## Quick start

The repository includes a sample OpenAPI document at:

``` text
examples/sample_api.yaml
```

Use it to try the main analysis commands.

### Analyze an OpenAPI document

``` bash
uv run achillesapi analyze-openapi examples/sample_api.yaml
```

To save the normalized output:

``` bash
mkdir -p reports

uv run achillesapi analyze-openapi \
  examples/sample_api.yaml \
  --output reports/normalized-api.json
```

### Generate the API relationship graph

``` bash
uv run achillesapi map-api \
  examples/sample_api.yaml \
  --output reports/api-graph.json
```

### Run the passive security assessment

``` bash
uv run achillesapi assess \
  examples/sample_api.yaml \
  --output reports/assessment.json
```

### Preview an HTTP GET request

The following command runs in dry-run mode unless the execution option
is supplied:

``` bash
uv run achillesapi http-get \
  https://api.example.test/health \
  --allow-host api.example.test
```

To send the request for real, add the execution flag:

``` bash
uv run achillesapi http-get \
  https://api.example.test/health \
  --allow-host api.example.test \
  --execute
```

Only use real execution against systems for which you have explicit
authorization.

> CLI options may evolve as the project develops. Use
> `uv run achillesapi --help` and the help output of each subcommand as
> the authoritative reference for the checked-out version.

------------------------------------------------------------------------

## CLI commands

  ---------------------------------------------------------------------------------
  Command                                       Purpose
  --------------------------------------------- -----------------------------------
  `uv run achillesapi version`                  Display the installed project
                                                version.

  `uv run achillesapi analyze-openapi <file>`   Parse and normalize an OpenAPI
                                                document.

  `uv run achillesapi map-api <file>`           Build and export the API
                                                relationship graph.

  `uv run achillesapi assess <file>`            Run passive security checks against
                                                the API model.

  `uv run achillesapi http-get <url>`           Preview or perform a constrained
                                                HTTP GET request.
  ---------------------------------------------------------------------------------

For complete command options:

``` bash
uv run achillesapi --help
uv run achillesapi analyze-openapi --help
uv run achillesapi map-api --help
uv run achillesapi assess --help
uv run achillesapi http-get --help
```

------------------------------------------------------------------------

## Understanding the API graph

The `map-api` command exports a JSON representation of the graph. This
file is structured data; it is not itself an image or an interactive
diagram.

For example:

``` bash
mkdir -p reports

uv run achillesapi map-api \
  examples/sample_api.yaml \
  --output reports/api-graph.json
```

The JSON can be inspected with a text editor or processed by scripts. To
explore the graph visually, convert it to GraphML and open it with a
graph visualization application such as Gephi.

### Visualizing with Gephi

1.  Generate `reports/api-graph.json` using `map-api`.
2.  Convert the JSON graph to GraphML using a compatible converter.
3.  Open Gephi.
4.  Select **File → Open** and choose the `.graphml` file.
5.  In the Overview workspace, choose a layout such as **ForceAtlas 2**.
6.  Run the layout to distribute the nodes.
7.  Use the Appearance panel to style nodes by their type and inspect
    their connections.

Gephi download: <https://gephi.org/users/download/>

### GraphML conversion

If the repository contains the JSON-to-GraphML helper script, run it
from the repository root using the actual path and filename present in
your checkout. For example:

``` bash
uv run python scripts/json_to_graphml.py \
  reports/api-graph.json \
  reports/api-graph.graphml
```

The converter must match the graph JSON schema produced by the same
AchillesAPI version. If the script is not present in your checkout, do
not assume the example command will work: use a compatible converter or
add the helper script to the repository first.

------------------------------------------------------------------------

## HTTP client safety model

The HTTP client is intentionally limited at this stage.

-   A request is not sent unless real execution is explicitly enabled.
-   The destination host must be included in the allowlist.
-   Only GET is currently supported.
-   Redirects are disabled to avoid silently following a request to
    another host.
-   TLS verification remains enabled.
-   Timeouts and response-size limits reduce the risk of hanging
    requests or excessive response capture.
-   Sensitive headers are redacted from evidence where supported.

The allowlist is a scope safeguard, not proof of authorization. The
operator remains responsible for ensuring that the target and test
activity are authorized.

------------------------------------------------------------------------

## Project structure

The exact tree may evolve during development. The main logical
components are:

``` text
AchillesAPI/
├── examples/
│   └── sample_api.yaml
├── docs/
│   ├── architecture.md
│   └── development-plan.md
├── src/
│   └── achillesapi/
│       ├── core/
│       │   ├── openapi.py
│       │   ├── graph.py
│       │   └── http.py
│       ├── models/
│       │   └── api.py
│       └── cli.py
├── tests/
├── .github/
│   └── workflows/
│       └── tests.yml
├── pyproject.toml
├── uv.lock
└── README.md
```

Some modules and filenames may differ depending on the current
repository revision. Consult the checked-out source tree for the
definitive structure.

### Main components

-   `core/openapi.py`: OpenAPI loading, reference handling, and endpoint
    normalization.
-   `models/api.py`: structured models for parsed API information.
-   `core/graph.py`: graph construction and relationship representation.
-   `core/http.py`: constrained HTTP GET functionality.
-   `cli.py`: command-line interface.

------------------------------------------------------------------------

## Current limitations

AchillesAPI is still under active development. The current version does
not yet provide:

-   Automated authenticated testing with multiple user identities.
-   Confirmed BOLA/IDOR exploitation or verification.
-   Complete BFLA or BOPLA test workflows.
-   Automated request generation for every operation and parameter
    combination.
-   AI-driven test generation or prioritization.
-   Full crawling or endpoint discovery from a live application.
-   A complete professional report-generation pipeline.
-   A graphical interface integrated into the CLI.

Passive findings should be manually validated. OpenAPI documents may be
incomplete, inaccurate, or unaware of security controls implemented
outside the API specification.

------------------------------------------------------------------------

## Roadmap

The next development stages are expected to include:

### Day 5 -- Local vulnerable API and validation

Create a deliberately vulnerable API in a local lab environment, with
separate user identities and controlled test data. Use it to validate
whether AchillesAPI can identify relevant BOLA/IDOR test candidates.

### Subsequent stages

-   Authentication profiles and multiple test identities.
-   Context-aware test-case generation.
-   Active BOLA/IDOR, BFLA, and BOPLA checks.
-   Evidence collection and reproducible findings.
-   AI-assisted analysis and test prioritization.
-   Professional report generation.

The roadmap is indicative and may change as implementation and testing
reveal new requirements.

------------------------------------------------------------------------

## Responsible use

AchillesAPI is intended for authorized security testing, controlled
labs, and defensive API assessment.

Only analyze API definitions and send requests to systems you own or are
explicitly authorized to test. Do not interpret a passive observation as
a confirmed vulnerability without appropriate validation and evidence.

------------------------------------------------------------------------

## License

MIT. See [LICENSE](LICENSE).
