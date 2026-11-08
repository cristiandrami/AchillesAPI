"""Load, validate, and normalize OpenAPI 3.x documents.

The parser intentionally resolves only local JSON Pointer references. It never
fetches remote references, which keeps parsing deterministic and avoids making
unexpected network requests while processing an untrusted specification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import yaml
try:
    from openapi_spec_validator import validate_spec
except ImportError:  # Allows parser development in offline environments.
    validate_spec = None  # type: ignore[assignment]

from achillesapi.models.api import (
    EndpointInfo,
    ParameterInfo,
    ParsedAPI,
    SecurityRequirementInfo,
    SecuritySchemeInfo,
)

HTTP_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
)


class OpenAPIParseError(ValueError):
    """Raised when an OpenAPI document cannot be loaded or normalized."""



def _basic_validate_spec(spec: dict[str, Any]) -> None:
    """Perform minimal structural checks when the optional validator is unavailable.

    Full OpenAPI conformance validation is provided by openapi-spec-validator,
    which is installed through the project dependencies. This fallback keeps
    the parser usable in offline/minimal development environments.
    """
    # IN PRATICA: Controlla i campi minimi della specifica quando il validatore completo non è disponibile.
    # SICUREZZA: Non contatta direttamente l'API target.

    version = spec.get("openapi")
    info = spec.get("info")
    paths = spec.get("paths")
    if not isinstance(version, str) or not version.startswith("3."):
        raise OpenAPIParseError("The document must declare an OpenAPI 3.x version.")
    if not isinstance(info, dict) or not isinstance(info.get("title"), str):
        raise OpenAPIParseError("The document must define info.title.")
    if not isinstance(info.get("version"), str):
        raise OpenAPIParseError("The document must define info.version.")
    if not isinstance(paths, dict):
        raise OpenAPIParseError("The document must define paths as an object.")
    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            raise OpenAPIParseError(f"Invalid API path: {path!r}.")
        if not isinstance(path_item, dict):
            raise OpenAPIParseError(f"Path item {path!r} must be an object.")


def load_openapi(file_path: str | Path, *, validate: bool = True) -> dict[str, Any]:
    """Load an OpenAPI YAML/JSON file and optionally validate its structure."""
    # IN PRATICA: Legge il file YAML/JSON e verifica che contenga una specifica OpenAPI valida.
    # SICUREZZA: Non contatta direttamente l'API target.

    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(path)

    try:
        with path.open("r", encoding="utf-8") as file:
            if path.suffix.lower() == ".json":
                spec = json.load(file)
            else:
                spec = yaml.safe_load(file)
    except (json.JSONDecodeError, yaml.YAMLError, UnicodeDecodeError) as exc:
        raise OpenAPIParseError(f"Unable to parse specification: {exc}") from exc

    if not isinstance(spec, dict):
        raise OpenAPIParseError("The OpenAPI document must contain a YAML/JSON object.")

    if validate:
        if validate_spec is not None:
            try:
                validate_spec(spec)
            except Exception as exc:
                raise OpenAPIParseError(f"OpenAPI validation failed: {exc}") from exc
        else:
            _basic_validate_spec(spec)

    return spec


def _resolve_local_ref(document: dict[str, Any], value: Any) -> Any:
    """Resolve a local JSON Pointer $ref; leave ordinary objects unchanged."""
    # IN PRATICA: Segue un riferimento locale dello Swagger senza scaricare risorse da Internet.
    # SICUREZZA: Non contatta direttamente l'API target.

    if not isinstance(value, dict) or "$ref" not in value:
        return value

    ref = value["$ref"]
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise OpenAPIParseError(
            f"Only local JSON Pointer references are supported; received {ref!r}."
        )

    current: Any = document
    try:
        for token in ref[2:].split("/"):
            token = unquote(token.replace("~1", "/").replace("~0", "~"))
            current = current[token]
    except (KeyError, TypeError) as exc:
        raise OpenAPIParseError(f"Unresolvable local reference: {ref}") from exc

    if not isinstance(current, dict):
        raise OpenAPIParseError(f"Reference {ref} does not resolve to an object.")

    # Sibling fields alongside $ref are retained as OpenAPI allows useful
    # annotations beside references in some contexts.
    return {**current, **{key: item for key, item in value.items() if key != "$ref"}}


def _resolve_ref_chain(
    document: dict[str, Any], value: Any, *, max_depth: int = 20
) -> Any:
    """Resolve chained local references while protecting against cycles."""
    # IN PRATICA: Segue più riferimenti collegati, fermandosi in caso di ciclo.
    # SICUREZZA: Non contatta direttamente l'API target.

    seen: set[str] = set()
    current = value
    for _ in range(max_depth):
        if not isinstance(current, dict) or "$ref" not in current:
            return current
        ref = current["$ref"]
        if ref in seen:
            raise OpenAPIParseError(f"Circular reference detected: {ref}")
        seen.add(ref)
        current = _resolve_local_ref(document, current)
    raise OpenAPIParseError("Reference chain exceeded the maximum resolution depth.")


def _merge_parameters(
    document: dict[str, Any],
    path_parameters: Any,
    operation_parameters: Any,
) -> list[ParameterInfo]:
    """Merge path- and operation-level parameters, with operation overrides."""
    # IN PRATICA: Unisce i parametri comuni del path con quelli specifici dell'operazione.
    # SICUREZZA: Non contatta direttamente l'API target.

    merged: dict[tuple[str, str], ParameterInfo] = {}
    for raw_parameter in [*(path_parameters or []), *(operation_parameters or [])]:
        parameter = _resolve_ref_chain(document, raw_parameter)
        if not isinstance(parameter, dict):
            continue
        name = parameter.get("name")
        location = parameter.get("in")
        if not isinstance(name, str) or not isinstance(location, str):
            continue
        try:
            parsed = ParameterInfo.model_validate(parameter)
        except Exception as exc:  # Pydantic gives useful detail in the chained error.
            raise OpenAPIParseError(
                f"Invalid parameter definition for {name!r} ({location}): {exc}"
            ) from exc
        merged[(name, location)] = parsed
    return list(merged.values())


def _normalize_security(
    raw_security: Any,
) -> tuple[list[SecurityRequirementInfo], bool]:
    """Normalize security requirements and preserve an explicit empty list."""
    # IN PRATICA: Distingue autenticazione richiesta, assente o disattivata esplicitamente.
    # SICUREZZA: Non contatta direttamente l'API target.

    if raw_security is None:
        return [], False
    if raw_security == []:
        return [], True
    if not isinstance(raw_security, list):
        raise OpenAPIParseError("Security requirements must be an array.")

    requirements: list[SecurityRequirementInfo] = []
    for requirement in raw_security:
        if not isinstance(requirement, dict):
            continue
        requirements.append(
            SecurityRequirementInfo(
                schemes={
                    str(scheme): [str(scope) for scope in scopes]
                    for scheme, scopes in requirement.items()
                    if isinstance(scopes, list)
                }
            )
        )
    return requirements, False


def parse_openapi(spec: dict[str, Any]) -> ParsedAPI:
    """Convert a validated OpenAPI 3.x dictionary into normalized metadata."""
    # IN PRATICA: Trasforma lo Swagger in un elenco uniforme di endpoint, parametri e requisiti di autenticazione.
    # SICUREZZA: Non contatta direttamente l'API target.

    openapi_version = spec.get("openapi")
    if not isinstance(openapi_version, str) or not openapi_version.startswith("3."):
        raise OpenAPIParseError("Only OpenAPI 3.x documents are supported.")

    info = spec.get("info")
    if not isinstance(info, dict) or not isinstance(info.get("title"), str):
        raise OpenAPIParseError("The OpenAPI document must define info.title.")

    root_servers = spec.get("servers", [])
    if not isinstance(root_servers, list):
        root_servers = []

    components = spec.get("components", {}) or {}
    raw_schemes = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
    security_schemes: list[SecuritySchemeInfo] = []
    if isinstance(raw_schemes, dict):
        for name, raw_scheme in raw_schemes.items():
            scheme = _resolve_ref_chain(spec, raw_scheme)
            if isinstance(scheme, dict):
                security_schemes.append(
                    SecuritySchemeInfo.model_validate({"scheme_name": name, **scheme})
                )

    endpoints: list[EndpointInfo] = []
    paths = spec.get("paths", {}) or {}
    if not isinstance(paths, dict):
        raise OpenAPIParseError("The OpenAPI paths field must be an object.")

    for path, raw_path_item in paths.items():
        path_item = _resolve_ref_chain(spec, raw_path_item)
        if not isinstance(path_item, dict):
            continue

        path_servers = path_item.get("servers", root_servers)
        if not isinstance(path_servers, list):
            path_servers = root_servers

        for method, raw_operation in path_item.items():
            normalized_method = str(method).lower()
            if normalized_method not in HTTP_METHODS:
                continue
            operation = _resolve_ref_chain(spec, raw_operation)
            if not isinstance(operation, dict):
                continue

            parameters = _merge_parameters(
                spec,
                path_item.get("parameters", []),
                operation.get("parameters", []),
            )

            # Operation-level security overrides root security. An explicit []
            # means authentication is intentionally not required for the op.
            raw_security = operation.get("security", spec.get("security"))
            security, security_disabled = _normalize_security(raw_security)

            operation_servers = operation.get("servers", path_servers)
            if not isinstance(operation_servers, list):
                operation_servers = path_servers

            request_body = operation.get("requestBody")
            if request_body is not None:
                request_body = _resolve_ref_chain(spec, request_body)

            endpoints.append(
                EndpointInfo(
                    path=str(path),
                    method=normalized_method.upper(),
                    operation_id=operation.get("operationId"),
                    summary=operation.get("summary"),
                    description=operation.get("description"),
                    tags=operation.get("tags", []) or [],
                    parameters=parameters,
                    request_body=request_body,
                    responses=operation.get("responses", {}) or {},
                    security=security,
                    security_is_explicitly_disabled=security_disabled,
                    servers=operation_servers,
                )
            )

    return ParsedAPI(
        title=info["title"],
        version=str(info.get("version", "unknown")),
        openapi_version=openapi_version,
        description=info.get("description"),
        servers=root_servers,
        security_schemes=security_schemes,
        endpoints=endpoints,
    )


def analyze_openapi_file(file_path: str | Path, *, validate: bool = True) -> ParsedAPI:
    """Convenience function: load, validate, and normalize a specification."""
    # IN PRATICA: Unisce lettura, validazione e normalizzazione in un solo passaggio.
    # SICUREZZA: Non contatta direttamente l'API target.

    return parse_openapi(load_openapi(file_path, validate=validate))
