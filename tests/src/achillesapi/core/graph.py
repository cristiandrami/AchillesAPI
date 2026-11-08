"""Build a provenance-aware relationship graph from an OpenAPI document.

The graph describes the API surface; it does not prove that a vulnerability
exists. Edges carry a ``source`` attribute (``explicit`` or ``inferred``).
"""

from __future__ import annotations

import re
from typing import Any

import networkx as nx

from achillesapi.models.api import EndpointInfo, ParsedAPI

_ID_SUFFIX = re.compile(r"(?:id|uuid|key)$", re.IGNORECASE)
_HTTP_SUCCESS = {"200", "201", "202", "203", "204", "206", "2XX"}


def _endpoint_id(endpoint: EndpointInfo) -> str:
    """In pratica: Crea un identificatore stabile per ogni coppia metodo e percorso.

    Attenzione: Non contatta direttamente l'API target.
    """
    return f"endpoint:{endpoint.method}:{endpoint.path}"


def _decode_pointer_token(token: str) -> str:
    """In pratica: Decodifica un pezzo di percorso usato nei riferimenti JSON Pointer.

    Attenzione: Non contatta direttamente l'API target.
    """
    return token.replace("~1", "/").replace("~0", "~")


def _resolve_schema(spec: dict[str, Any], schema: Any, depth: int = 0) -> Any:
    """Resolve local schema refs for inspection only; never fetch remote refs."""
    # IN PRATICA: Trova lo schema effettivo quando compare un riferimento a un componente.
    # SICUREZZA: Non contatta direttamente l'API target.
    if depth > 20 or not isinstance(schema, dict):
        return schema
    ref = schema.get("$ref")
    if not isinstance(ref, str):
        return schema
    if not ref.startswith("#/"):
        return {"x-achillesapi-unresolved-ref": ref}
    current: Any = spec
    try:
        for token in ref[2:].split("/"):
            current = current[_decode_pointer_token(token)]
    except (KeyError, TypeError):
        return {"x-achillesapi-unresolved-ref": ref}
    if not isinstance(current, dict):
        return {"x-achillesapi-unresolved-ref": ref}
    siblings = {key: value for key, value in schema.items() if key != "$ref"}
    return {**current, **siblings}


def _walk_properties(
    spec: dict[str, Any], schema: Any, prefix: str = "", depth: int = 0
) -> list[tuple[str, dict[str, Any]]]:
    """In pratica: Visita ricorsivamente i campi di uno schema, con limiti per evitare loop.

    Attenzione: Non contatta direttamente l'API target.
    """
    if depth > 12 or not isinstance(schema, dict):
        return []
    resolved = _resolve_schema(spec, schema)
    if not isinstance(resolved, dict):
        return []
    properties = resolved.get("properties", {})
    found: list[tuple[str, dict[str, Any]]] = []
    if isinstance(properties, dict):
        for name, raw_property in properties.items():
            if not isinstance(name, str) or not isinstance(raw_property, dict):
                continue
            full_name = f"{prefix}.{name}" if prefix else name
            prop = _resolve_schema(spec, raw_property)
            if not isinstance(prop, dict):
                continue
            found.append((full_name, prop))
            found.extend(_walk_properties(spec, prop, full_name, depth + 1))
    items = resolved.get("items")
    if isinstance(items, dict):
        found.extend(_walk_properties(spec, items, f"{prefix}[]" if prefix else "[]", depth + 1))
    return found


def _content_schemas(spec: dict[str, Any], value: Any) -> list[dict[str, Any]]:
    """Extract JSON-like schemas from requestBody or response objects."""
    # IN PRATICA: Seleziona gli schemi JSON tra i media type di request e response.
    # SICUREZZA: Non contatta direttamente l'API target.
    if not isinstance(value, dict):
        return []
    value = _resolve_schema(spec, value)
    content = value.get("content", {}) if isinstance(value, dict) else {}
    schemas: list[dict[str, Any]] = []
    if isinstance(content, dict):
        for media_type, media in content.items():
            if not isinstance(media, dict) or not isinstance(media.get("schema"), dict):
                continue
            if "json" in str(media_type).lower() or "+json" in str(media_type).lower():
                schemas.append(media["schema"])
    return schemas


def _resource_for_path(path: str) -> list[str]:
    """Return collection/sub-collection templates inferred from path segments."""
    # IN PRATICA: Stima la risorsa rappresentata dal percorso, senza affermare che sia certa.
    # SICUREZZA: Non contatta direttamente l'API target.
    segments = [segment for segment in path.strip("/").split("/") if segment]
    resources: list[str] = []
    normalized: list[str] = []
    for segment in segments:
        is_identifier = segment.startswith("{") and segment.endswith("}")
        normalized.append("{}" if is_identifier else segment)
        # An identifier selects an object in the preceding collection; a static
        # segment after it introduces a nested collection (e.g. /users/{}/orders).
        if not is_identifier:
            resources.append("/" + "/".join(normalized))
    return list(dict.fromkeys(resources))


def build_api_graph(parsed: ParsedAPI, spec: dict[str, Any]) -> nx.MultiDiGraph:
    """Create a directed multigraph of endpoints, resources, schemas and auth."""
    # IN PRATICA: Collega endpoint, risorse e schemi in un grafo per identificare possibili relazioni.
    # SICUREZZA: Non contatta direttamente l'API target.
    graph = nx.MultiDiGraph(name="AchillesAPI relationship graph", version="1")
    components = spec.get("components", {})
    schemas = components.get("schemas", {}) if isinstance(components, dict) else {}

    for schema_name, schema in schemas.items() if isinstance(schemas, dict) else []:
        if not isinstance(schema_name, str) or not isinstance(schema, dict):
            continue
        schema_id = f"schema:{schema_name}"
        graph.add_node(schema_id, type="schema", name=schema_name, source="explicit")
        for prop_name, prop in _walk_properties(spec, schema):
            prop_id = f"property:{schema_name}:{prop_name}"
            graph.add_node(
                prop_id,
                type="property",
                name=prop_name,
                schema=schema_name,
                data_type=prop.get("type", "unknown"),
                format=prop.get("format"),
                read_only=bool(prop.get("readOnly", False)),
                write_only=bool(prop.get("writeOnly", False)),
                source="explicit",
            )
            graph.add_edge(schema_id, prop_id, relation="HAS_PROPERTY", source="explicit")

    for scheme in parsed.security_schemes:
        scheme_id = f"security:{scheme.scheme_name}"
        graph.add_node(
            scheme_id,
            type="security_scheme",
            name=scheme.scheme_name,
            scheme_type=scheme.type,
            http_scheme=scheme.scheme,
            source="explicit",
        )

    for endpoint in parsed.endpoints:
        endpoint_id = _endpoint_id(endpoint)
        graph.add_node(
            endpoint_id,
            type="endpoint",
            method=endpoint.method,
            path=endpoint.path,
            operation_id=endpoint.operation_id,
            summary=endpoint.summary,
            source="explicit",
        )

        for resource_path in _resource_for_path(endpoint.path):
            resource_id = f"resource:{resource_path}"
            graph.add_node(resource_id, type="resource", path=resource_path, source="inferred")
            graph.add_edge(
                endpoint_id, resource_id, relation="OPERATES_ON", source="inferred",
                evidence=f"Path template {endpoint.path}",
            )

        for parameter in endpoint.path_parameters:
            parameter_id = f"identifier:{endpoint.path}:{parameter.name}"
            candidate = bool(_ID_SUFFIX.search(parameter.name))
            graph.add_node(
                parameter_id,
                type="identifier",
                name=parameter.name,
                location="path",
                candidate_object_identifier=candidate,
                required=parameter.required,
                source="explicit",
            )
            graph.add_edge(endpoint_id, parameter_id, relation="USES_IDENTIFIER", source="explicit")

        for requirement in endpoint.security:
            for scheme_name, scopes in requirement.schemes.items():
                scheme_id = f"security:{scheme_name}"
                if scheme_id not in graph:
                    graph.add_node(
                        scheme_id,
                        type="security_scheme",
                        name=scheme_name,
                        source="inferred",
                    )
                graph.add_edge(
                    endpoint_id, scheme_id, relation="REQUIRES_SECURITY", source="explicit",
                    scopes=scopes,
                )

        for raw in (endpoint.request_body,):
            for schema in _content_schemas(spec, raw):
                schema_ref = schema.get("$ref") if isinstance(schema, dict) else None
                if isinstance(schema_ref, str) and schema_ref.startswith("#/components/schemas/"):
                    schema_name = _decode_pointer_token(schema_ref.rsplit("/", 1)[-1])
                    schema_id = f"schema:{schema_name}"
                    graph.add_node(schema_id, type="schema", name=schema_name, source="explicit")
                    graph.add_edge(
                        endpoint_id, schema_id, relation="ACCEPTS_SCHEMA", source="explicit"
                    )
                for prop_name, prop in _walk_properties(spec, schema):
                    prop_id = f"request-property:{endpoint.method}:{endpoint.path}:{prop_name}"
                    graph.add_node(
                        prop_id, type="request_property", name=prop_name,
                        data_type=prop.get("type", "unknown"),
                        read_only=bool(prop.get("readOnly", False)),
                        write_only=bool(prop.get("writeOnly", False)), source="explicit",
                    )
                    graph.add_edge(
                        endpoint_id, prop_id, relation="ACCEPTS_PROPERTY", source="explicit"
                    )

        for status, response in endpoint.responses.items():
            if status not in _HTTP_SUCCESS or not isinstance(response, dict):
                continue
            for schema in _content_schemas(spec, response):
                schema_ref = schema.get("$ref") if isinstance(schema, dict) else None
                if isinstance(schema_ref, str) and schema_ref.startswith("#/components/schemas/"):
                    schema_name = _decode_pointer_token(schema_ref.rsplit("/", 1)[-1])
                    schema_id = f"schema:{schema_name}"
                    graph.add_node(schema_id, type="schema", name=schema_name, source="explicit")
                    graph.add_edge(
                        endpoint_id, schema_id, relation="RETURNS_SCHEMA", source="explicit"
                    )
                for prop_name, prop in _walk_properties(spec, schema):
                    prop_id = f"response-property:{endpoint.method}:{endpoint.path}:{prop_name}"
                    graph.add_node(
                        prop_id, type="response_property", name=prop_name,
                        data_type=prop.get("type", "unknown"),
                        read_only=bool(prop.get("readOnly", False)),
                        write_only=bool(prop.get("writeOnly", False)), source="explicit",
                    )
                    graph.add_edge(
                        endpoint_id, prop_id, relation="RETURNS_PROPERTY", source="explicit"
                    )

    # Link endpoint path identifiers to similarly named schema properties.
    # This is a heuristic relationship, not proof of object-level authorization.
    identifiers = [
        (node_id, attrs)
        for node_id, attrs in graph.nodes(data=True)
        if attrs.get("type") == "identifier" and attrs.get("candidate_object_identifier")
    ]
    properties = [
        (node_id, attrs)
        for node_id, attrs in graph.nodes(data=True)
        if attrs.get("type") in {"property", "request_property", "response_property"}
    ]
    for identifier_id, identifier in identifiers:
        normalized = identifier["name"].lower()
        for property_id, prop in properties:
            prop_name = str(prop.get("name", "")).split(".")[-1].lower()
            identifier_suffix = re.search(r"(id|uuid|key)$", normalized)
            property_suffix = re.search(r"(id|uuid|key)$", prop_name)
            same_identifier_kind = bool(
                identifier_suffix and property_suffix
                and identifier_suffix.group(1) == property_suffix.group(1)
            )
            if normalized == prop_name or normalized.rstrip("s") == prop_name.rstrip("s") or (
                same_identifier_kind
                and prop_name in {"id", "uuid", "key"}
            ):
                graph.add_edge(
                    identifier_id, property_id, relation="MAY_IDENTIFY",
                    source="inferred",
                    evidence=f"Matching names: {identifier['name']} / {prop_name}",
                )
    return graph


def graph_to_dict(graph: nx.MultiDiGraph) -> dict[str, Any]:
    """Serialize the graph in a stable, human-readable JSON structure."""
    # IN PRATICA: Converte il grafo in dati JSON serializzabili.
    # SICUREZZA: Non contatta direttamente l'API target.
    nodes = [
        {"id": node_id, **dict(sorted(attrs.items()))}
        for node_id, attrs in sorted(graph.nodes(data=True), key=lambda item: item[0])
    ]
    edges = [
        {"from": source, "to": target, **dict(sorted(attrs.items()))}
        for source, target, _key, attrs in sorted(
            graph.edges(keys=True, data=True), key=lambda item: (item[0], item[1], item[2])
        )
    ]
    return {
        "graph": graph.graph.get("name"),
        "version": graph.graph.get("version"),
        "nodes": nodes,
        "edges": edges,
    }
