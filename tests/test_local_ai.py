from __future__ import annotations

import json
from pathlib import Path

import pytest

from achillesapi.ai.local import LocalAIError, analyze_with_ollama
from achillesapi.ai.sanitizer import sanitize
from achillesapi.core.openapi import analyze_openapi_file

EXAMPLES = Path(__file__).parents[1] / "examples"


def test_sanitizer_redacts_sensitive_keys_and_common_secrets() -> None:
    source = {
        "Authorization": "Bearer super-secret-token",
        "description": "Contact test@example.com; token=abc123 and eyJabcdefgh.abcdefgh.signature",
        "nested": {"client_secret": "dont-send-me", "summary": "public"},
    }
    result = sanitize(source)
    assert result["Authorization"] == "[REDACTED]"
    assert "test@example.com" not in result["description"]
    assert "abc123" not in result["description"]
    assert "eyJabcdefgh" not in result["description"]
    assert result["nested"]["client_secret"] == "[REDACTED]"
    assert result["nested"]["summary"] == "public"
    assert source["Authorization"].startswith("Bearer")  # no mutation


def test_remote_endpoint_is_rejected_before_network(monkeypatch: pytest.MonkeyPatch) -> None:
    api = analyze_openapi_file(EXAMPLES / "sample_api.yaml")
    with pytest.raises(LocalAIError, match="only http"):
        analyze_with_ollama(api, [], endpoint="https://api.ollama.com")
    with pytest.raises(LocalAIError, match="only http"):
        analyze_with_ollama(api, [], endpoint="http://192.0.2.10:11434")


def test_local_ollama_request_and_structured_response(monkeypatch: pytest.MonkeyPatch) -> None:
    api = analyze_openapi_file(EXAMPLES / "sample_api.yaml")
    response_payload = {
        "message": {
            "content": json.dumps({
                "executive_summary": "Analisi locale completata.",
                "risk_observations": ["Verificare autorizzazione oggetto."],
                "recommended_tests": ["Eseguire test BOLA con due identità."],
                "limitations": ["Analisi basata sulla specifica, non su traffico runtime."],
            })
        }
    }

    class FakeResponse:
        status = 200

        def read(self, _limit: int) -> bytes:
            return json.dumps(response_payload).encode()

    class FakeConnection:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            assert host in {"127.0.0.1", "localhost", "::1"}
            assert port == 11434
            assert timeout == 120.0
            self.request_body = b""

        def request(self, method: str, path: str, body: bytes, headers: dict[str, str]) -> None:
            assert method == "POST"
            assert path == "/api/chat"
            assert headers["Content-Type"] == "application/json"
            self.request_body = body
            sent = json.loads(body)
            assert sent["model"] == "achilles-local"
            assert sent["stream"] is False
            assert sent["options"]["num_ctx"] == 4096
            assert "[REDACTED]" in sent["messages"][0]["content"] or "[REDACTED]" in sent["messages"][1]["content"]

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            pass

    monkeypatch.setattr("achillesapi.ai.local.http.client.HTTPConnection", FakeConnection)
    result = analyze_with_ollama(
        api,
        [{"category": "AUTH-001", "token": "do-not-send"}],
    )
    assert result["executive_summary"] == "Analisi locale completata."
    assert result["model_assessment_is_not_a_finding"] is True


def test_invalid_model_response_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    api = analyze_openapi_file(EXAMPLES / "sample_api.yaml")

    class FakeResponse:
        status = 200

        def read(self, _limit: int) -> bytes:
            return json.dumps({"message": {"content": '{"executive_summary":"only"}'}}).encode()

    class FakeConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None: pass
        def request(self, *_args: object, **_kwargs: object) -> None: pass
        def getresponse(self) -> FakeResponse: return FakeResponse()
        def close(self) -> None: pass

    monkeypatch.setattr("achillesapi.ai.local.http.client.HTTPConnection", FakeConnection)
    with pytest.raises(LocalAIError, match="missing fields"):
        analyze_with_ollama(api, [])


def test_non_loopback_hostname_is_rejected_without_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    api = analyze_openapi_file(EXAMPLES / "sample_api.yaml")
    monkeypatch.setattr("achillesapi.ai.local.socket.getaddrinfo", lambda *_a, **_k: pytest.fail("DNS must not be used"))
    with pytest.raises(LocalAIError, match="only http"):
        analyze_with_ollama(api, [], endpoint="http://ollama.internal:11434")
