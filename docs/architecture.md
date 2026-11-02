# Architecture — Day 1–2

## Scope

The first milestone implements ingestion and normalization only. It deliberately
has no active scanner, no target authentication handling, and no LLM integration.

## Components

### File loader

`core.openapi.load_openapi()` reads YAML or JSON from a local file. YAML is
loaded with `yaml.safe_load`; JSON uses the standard library parser. The loader
rejects non-object documents and validates the OpenAPI document when validation
is enabled.

### Specification validation

`openapi-spec-validator` is the full validator and is a declared runtime
dependency. A small structural fallback exists only to keep local development
possible in offline environments where dependencies cannot be installed. The
fallback checks document shape, not complete OpenAPI conformance.

### Reference resolver

Only local JSON Pointer references (`#/...`) are resolved. Remote references
are rejected rather than downloaded. This is an intentional security and
reproducibility decision: importing an untrusted API description must not cause
unexpected outbound network traffic.

### Normalizer

`parse_openapi()` produces Pydantic models:

- `ParsedAPI`: API-level metadata, servers, security schemes, endpoints.
- `EndpointInfo`: one HTTP operation and its metadata.
- `ParameterInfo`: normalized path/query/header/cookie parameter.
- `SecurityRequirementInfo`: scheme-to-scope mapping.
- `SecuritySchemeInfo`: named authentication mechanism.

Path-level and operation-level parameters are merged by `(name, in)`, with
operation-level definitions overriding path-level definitions. Operation-level
security overrides root security. An explicit `security: []` is represented
separately from an omitted security field.

## Data flow

```text
Local YAML/JSON
   -> safe loader
   -> OpenAPI validator
   -> local reference resolver
   -> normalized Pydantic models
   -> CLI summary and JSON export
```

## Next architectural milestone

The next step is an endpoint relationship graph. It should represent operations,
path parameters, request/response object schemas, and candidate resource
identifiers. The graph must distinguish facts explicitly declared in OpenAPI
from hypotheses inferred from naming conventions or AI.
