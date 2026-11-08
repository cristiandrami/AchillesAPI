from pathlib import Path

from achillesapi.core.graph import build_api_graph, graph_to_dict
from achillesapi.core.openapi import analyze_openapi_file, load_openapi

EXAMPLES = Path(__file__).parents[1] / "examples"


def test_builds_endpoint_resource_and_identifier_graph() -> None:
    path = EXAMPLES / "sample_api.yaml"
    parsed = analyze_openapi_file(path)
    graph = build_api_graph(parsed, load_openapi(path))
    assert "endpoint:GET:/users/{userId}" in graph
    assert "resource:/users" in graph
    identifier = "identifier:/users/{userId}:userId"
    assert graph.nodes[identifier]["candidate_object_identifier"] is True
    assert any(data["relation"] == "USES_IDENTIFIER" for *_, data in graph.edges(data=True))


def test_graph_serialization_labels_inferred_edges() -> None:
    path = EXAMPLES / "sample_api.yaml"
    payload = graph_to_dict(build_api_graph(analyze_openapi_file(path), load_openapi(path)))
    assert payload["nodes"]
    assert any(edge["source"] == "inferred" for edge in payload["edges"])
    assert all("id" in node and "type" in node for node in payload["nodes"])


def test_resolves_schema_refs_and_keeps_edge_endpoints_separate_from_provenance() -> None:
    from achillesapi.core.graph import build_api_graph, graph_to_dict
    from achillesapi.core.openapi import parse_openapi

    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Schema API", "version": "1"},
        "paths": {
            "/users/{userId}": {
                "parameters": [{"name": "userId", "in": "path", "required": True,
                                "schema": {"type": "string"}}],
                "get": {"responses": {"200": {"description": "ok", "content": {
                    "application/json": {"schema": {"$ref": "#/components/schemas/User"}}
                }}}},
            }
        },
        "components": {"schemas": {"User": {"type": "object", "properties": {
            "id": {"type": "string"}, "email": {"type": "string", "format": "email"}
        }}}},
    }
    payload = graph_to_dict(build_api_graph(parse_openapi(spec), spec))
    assert any(node["id"] == "property:User:id" for node in payload["nodes"])
    assert any(edge.get("relation") == "RETURNS_SCHEMA" and edge.get("from") ==
               "endpoint:GET:/users/{userId}" and edge.get("source") == "explicit"
               for edge in payload["edges"])
    assert any(edge.get("relation") == "MAY_IDENTIFY" and edge.get("source") == "inferred"
               for edge in payload["edges"])
