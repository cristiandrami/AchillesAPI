import pytest

from achillesapi.core.http import SafeHTTPClient, ScopeError


def test_http_client_defaults_to_dry_run() -> None:
    client = SafeHTTPClient(allowed_hosts={"api.example.test"})
    evidence = client.request("GET", "https://api.example.test/users")
    assert evidence.executed is False
    assert evidence.response is None
    assert "no network request" in evidence.notes[0].lower()


def test_http_client_rejects_host_outside_allowlist() -> None:
    client = SafeHTTPClient(allowed_hosts={"api.example.test"})
    with pytest.raises(ScopeError, match="not in the explicit allowlist"):
        client.request("GET", "https://other.example.test/users")


def test_http_client_rejects_non_get_methods() -> None:
    client = SafeHTTPClient(allowed_hosts={"api.example.test"})
    with pytest.raises(ScopeError, match="Only GET"):
        client.request("POST", "https://api.example.test/users")


def test_execution_captures_bounded_body_and_redacts_sensitive_headers(monkeypatch) -> None:
    import httpx

    class FakeResponse:
        status_code = 200
        headers = httpx.Headers({"content-type": "application/json", "set-cookie": "secret=1"})
        encoding = "utf-8"

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def iter_bytes(self):
            yield b"123456789"

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def stream(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr("achillesapi.core.http.httpx.Client", FakeClient)
    client = SafeHTTPClient(allowed_hosts={"api.example.test"}, max_body_bytes=5)
    evidence = client.request("GET", "https://api.example.test/data", execute=True)
    assert evidence.executed is True
    assert evidence.response is not None
    assert evidence.response.body_preview == "12345"
    assert evidence.response.body_truncated is True
    assert evidence.response.headers["set-cookie"] == "[REDACTED]"


def test_auth_material_is_used_but_redacted_in_evidence(monkeypatch) -> None:
    import httpx

    captured = {}

    class FakeResponse:
        status_code = 200
        headers = httpx.Headers({"content-type": "application/json"})
        encoding = "utf-8"

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def iter_bytes(self):
            yield b"ok"

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def stream(self, method, url, **kwargs):
            captured.update(method=method, url=url, **kwargs)
            return FakeResponse()

    monkeypatch.setattr("achillesapi.core.http.httpx.Client", FakeClient)
    client = SafeHTTPClient(allowed_hosts={"api.example.test"})
    evidence = client.request(
        "GET", "https://api.example.test/items", execute=True,
        headers={"Authorization": "Bearer top-secret", "X-Partner-Key": "header-secret"},
        params={"api_key": "query-secret", "page": "2"},
        cookies={"session": "cookie-secret"},
        sensitive_query_names={"api_key"},
        sensitive_header_names={"X-Partner-Key"},
    )
    assert captured["headers"]["Authorization"] == "Bearer top-secret"
    assert captured["params"]["api_key"] == "query-secret"
    assert captured["cookies"]["session"] == "cookie-secret"
    assert evidence.request.headers["Authorization"] == "[REDACTED]"
    assert evidence.request.headers["X-Partner-Key"] == "[REDACTED]"
    assert "query-secret" not in evidence.request.url
    assert "%5BREDACTED%5D" in evidence.request.url
    assert "page=2" in evidence.request.url
