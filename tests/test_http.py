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
