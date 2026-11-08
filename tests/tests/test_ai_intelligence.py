from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from achillesapi.ai.intelligence import correlate_with_ollama
from achillesapi.ai.local import LocalAIError
from achillesapi.cli import app
from achillesapi.core.detection import analyze_response_evidence
from achillesapi.core.openapi import analyze_openapi_file

EXAMPLES = Path(__file__).parents[1] / "examples"
runner = CliRunner()


def test_intelligence_correlation_uses_sanitized_local_context(monkeypatch: pytest.MonkeyPatch) -> None:
    api = analyze_openapi_file(EXAMPLES / "sample_api.yaml")
    report = analyze_response_evidence({"responses": [{
        "method": "GET", "path": "/api/items/1", "status_code": 500,
        "headers": {"Authorization": "Bearer secret-value"},
        "body_preview": "SQL syntax error password=do-not-send",
    }]})
    payload = {"message": {"content": json.dumps({
        "executive_summary": "Correlazione consultiva.",
        "cross_correlations": ["Verificare la gestione degli errori sugli endpoint autenticati."],
        "false_positive_checks": ["Verificare se il 500 è transitorio."],
        "next_steps": ["Riprodurre in ambiente autorizzato."],
        "limitations": ["Evidenze limitate al campione fornito."],
    })}}

    class FakeResponse:
        status = 200
        def read(self, _limit: int) -> bytes:
            return json.dumps(payload).encode()

    class FakeConnection:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            assert host == "127.0.0.1" and port == 11434
        def request(self, method: str, path: str, body: bytes, headers: dict[str, str]) -> None:
            sent = json.loads(body)
            serialized = json.dumps(sent)
            assert method == "POST" and path == "/api/chat"
            assert "secret-value" not in serialized
            assert "do-not-send" not in serialized
        def getresponse(self) -> FakeResponse: return FakeResponse()
        def close(self) -> None: pass

    monkeypatch.setattr("achillesapi.ai.intelligence.http.client.HTTPConnection", FakeConnection)
    result = correlate_with_ollama(api, report)
    assert result["model_assessment_is_not_a_finding"] is True
    assert result["execution_authorized"] is False
    assert result["cross_correlations"]


def test_intelligence_rejects_remote_endpoint() -> None:
    api = analyze_openapi_file(EXAMPLES / "sample_api.yaml")
    report = analyze_response_evidence({"responses": []})
    with pytest.raises(LocalAIError, match="only http"):
        correlate_with_ollama(api, report, endpoint="https://example.com")


def test_cli_ai_correlate_rejects_remote_before_network(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.json"
    evidence.write_text('{"responses": []}', encoding="utf-8")
    output = tmp_path / "report.json"
    result = runner.invoke(app, [
        "ai-correlate", str(EXAMPLES / "sample_api.yaml"), str(evidence),
        "--endpoint", "https://example.com", "--output", str(output),
    ])
    assert result.exit_code == 1
    assert "only http" in result.output
    assert not output.exists()
