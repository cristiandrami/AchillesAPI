import json

import httpx
import pytest

from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.core.authorization import _field_paths, authorization_matrix
from achillesapi.core.advanced import AdvancedCheckError


def test_field_paths_extracts_nested_names_without_values():
    assert _field_paths({"id": 1, "profile": {"email": "secret", "roles": ["user"]}}) == {
        "id", "profile", "profile.email", "profile.roles", "profile.roles[]"
    }


def test_matrix_requires_two_profiles():
    with pytest.raises(AdvancedCheckError, match="At least two"):
        authorization_matrix({"paths": {}}, "http://127.0.0.1:8000", {
            "alice": AuthenticationMaterial()
        }, {})


def test_matrix_requires_loopback():
    with pytest.raises(AdvancedCheckError, match="loopback"):
        authorization_matrix({"paths": {}}, "https://example.com", {
            "alice": AuthenticationMaterial(), "admin": AuthenticationMaterial()
        }, {})


def test_matrix_compares_property_visibility_and_does_not_store_values(monkeypatch):
    class FakeClient:
        def __init__(self, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def get(self, url, headers, params, cookies):
            if headers.get("Authorization") == "Bearer admin":
                return httpx.Response(200, json={"id": "1", "isAdmin": True, "email": "private"})
            return httpx.Response(200, json={"id": "1", "email": "alice@example.test"})

    monkeypatch.setattr("achillesapi.core.authorization.httpx.Client", FakeClient)
    result = authorization_matrix(
        {"paths": {"/users/{user_id}": {"get": {"operationId": "getUser"}}}},
        "http://127.0.0.1:8000", {
            "alice": AuthenticationMaterial(headers={"Authorization": "Bearer alice"}),
            "admin": AuthenticationMaterial(headers={"Authorization": "Bearer admin"}),
        }, {"user_id": "user-1"},
    )
    endpoint = result["endpoints"][0]
    assert result["requests"] == 2
    assert {x["field"] for x in endpoint["property_visibility_differences"]} == {"isAdmin"}
    rendered = json.dumps(result)
    assert "alice@example.test" not in rendered
    assert "private" not in rendered
    assert "Bearer admin" not in rendered
