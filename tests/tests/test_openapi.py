from pathlib import Path

import pytest

from achillesapi.core.openapi import (
    OpenAPIParseError,
    analyze_openapi_file,
    load_openapi,
    parse_openapi,
)

EXAMPLES = Path(__file__).parents[1] / "examples"


def test_load_and_validate_sample_spec() -> None:
    spec = load_openapi(EXAMPLES / "sample_api.yaml")
    assert spec["info"]["title"] == "AchillesAPI Demo Service"


def test_extracts_expected_endpoints() -> None:
    parsed = analyze_openapi_file(EXAMPLES / "sample_api.yaml")
    assert parsed.endpoint_count == 4
    assert {(item.method, item.path) for item in parsed.endpoints} == {
        ("GET", "/users/{userId}"),
        ("PATCH", "/users/{userId}"),
        ("GET", "/users/{userId}/orders"),
        ("GET", "/admin/users"),
    }


def test_merges_path_and_operation_parameters() -> None:
    parsed = analyze_openapi_file(EXAMPLES / "sample_api.yaml")
    patch = next(item for item in parsed.endpoints if item.method == "PATCH")
    assert {(item.name, item.location) for item in patch.parameters} == {
        ("userId", "path"),
        ("fields", "query"),
    }
    assert patch.path_parameters[0].required is True


def test_root_security_is_inherited_and_operation_can_disable_it() -> None:
    parsed = analyze_openapi_file(EXAMPLES / "sample_api.yaml")
    get_user = next(item for item in parsed.endpoints if item.operation_id == "getUser")
    admin = next(item for item in parsed.endpoints if item.operation_id == "getAllUsers")
    assert get_user.security[0].schemes == {"bearerAuth": []}
    assert admin.security == []
    assert admin.security_is_explicitly_disabled is True


def test_extracts_security_scheme() -> None:
    parsed = analyze_openapi_file(EXAMPLES / "sample_api.yaml")
    assert len(parsed.security_schemes) == 1
    assert parsed.security_schemes[0].scheme_name == "bearerAuth"
    assert parsed.security_schemes[0].scheme == "bearer"


def test_resolves_local_parameter_reference() -> None:
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Ref API", "version": "1"},
        "paths": {
            "/items/{itemId}": {
                "parameters": [{"$ref": "#/components/parameters/ItemId"}],
                "get": {"responses": {"200": {"description": "ok"}}},
            }
        },
        "components": {
            "parameters": {
                "ItemId": {
                    "name": "itemId",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                }
            }
        },
    }
    parsed = parse_openapi(spec)
    assert parsed.endpoints[0].parameters[0].name == "itemId"


def test_rejects_external_references() -> None:
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "External Ref API", "version": "1"},
        "paths": {
            "/items": {
                "parameters": [{"$ref": "https://example.invalid/parameter.json"}],
                "get": {"responses": {"200": {"description": "ok"}}},
            }
        },
    }
    with pytest.raises(OpenAPIParseError, match="Only local"):
        parse_openapi(spec)


def test_rejects_non_openapi_3_document() -> None:
    with pytest.raises(OpenAPIParseError, match="OpenAPI 3.x"):
        parse_openapi({"swagger": "2.0", "info": {"title": "Old", "version": "1"}})


def test_missing_file_raises_file_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        load_openapi(EXAMPLES / "does-not-exist.yaml")
