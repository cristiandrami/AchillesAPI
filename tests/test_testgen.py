from achillesapi.core.openapi import parse_openapi
from achillesapi.core.testgen import generate_test_plan


def _spec():
    return {
        "openapi": "3.0.3",
        "info": {"title": "Generator test", "version": "1"},
        "paths": {
            "/accounts": {
                "post": {"operationId": "createAccount", "requestBody": {"required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AccountInput"}}}},
                    "responses": {"201": {"description": "created"}}}
            },
            "/accounts/{accountId}": {
                "parameters": [{"name": "accountId", "in": "path", "required": True,
                                "schema": {"type": "string"}}],
                "get": {"operationId": "getAccount", "responses": {"200": {"description": "ok",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Account"}}}}}},
                "patch": {"operationId": "updateAccount", "requestBody": {"content": {
                    "application/json": {"schema": {"$ref": "#/components/schemas/AccountInput"}}}},
                    "responses": {"200": {"description": "ok"}}},
            },
            "/admin/reports": {"get": {"operationId": "adminReports", "responses": {"200": {"description": "ok"}}}},
        },
        "components": {"schemas": {
            "AccountInput": {"type": "object", "properties": {
                "displayName": {"type": "string"}, "isAdmin": {"type": "boolean", "readOnly": True},
                "apiToken": {"type": "string"}}},
            "Account": {"type": "object", "properties": {
                "id": {"type": "string"}, "email": {"type": "string"},
                "refreshToken": {"type": "string", "writeOnly": True}}},
        }},
    }


def test_generates_authorization_property_and_mass_assignment_cases():
    spec = _spec()
    plan = generate_test_plan(parse_openapi(spec), spec)
    categories = {case["category"] for case in plan["test_cases"]}
    assert {"BOLA", "BFLA", "BOPLA", "MASS_ASSIGNMENT"} <= categories
    assert plan["execution_policy"]["executed"] is False
    assert plan["execution_policy"]["network_requests_sent"] == 0


def test_infers_collection_to_item_workflow():
    spec = _spec()
    plan = generate_test_plan(parse_openapi(spec), spec)
    assert plan["summary"]["workflow_count"] == 1
    assert plan["workflows"][0]["confidence"] == "inferred_path_relationship"


def test_generation_is_deterministic_and_does_not_emit_secret_values():
    spec = _spec()
    parsed = parse_openapi(spec)
    first = generate_test_plan(parsed, spec)
    second = generate_test_plan(parsed, spec)
    assert first == second
    serialized = str(first)
    assert "apiToken" in serialized
    assert "actual-secret-value" not in serialized


def test_identifier_heuristic_avoids_words_that_merely_end_in_id():
    spec = {
        "openapi": "3.0.3", "info": {"title": "Names", "version": "1"},
        "paths": {"/items/{valid}": {
            "parameters": [{"name": "valid", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "get": {"responses": {"200": {"description": "ok"}}},
        }, "/items/{itemId}": {
            "parameters": [{"name": "itemId", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "get": {"responses": {"200": {"description": "ok"}}},
        }},
    }
    plan = generate_test_plan(parse_openapi(spec), spec)
    names = [item["parameter"] for item in plan["discovery"]["object_identifier_candidates"]]
    assert names == ["itemId"]
