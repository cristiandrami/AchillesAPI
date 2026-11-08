from fastapi.testclient import TestClient
import pytest

from achillesapi.core.bola import BolaCheckError, check_bola
from achillesapi.lab.app import app

client = TestClient(app)


def test_local_lab_exposes_intentionally_vulnerable_and_secure_routes() -> None:
    vulnerable = client.get(
        "/api/orders/order-bob", headers={"Authorization": "Bearer alice-token"}
    )
    secure = client.get(
        "/api/secure/orders/order-bob", headers={"Authorization": "Bearer alice-token"}
    )
    assert vulnerable.status_code == 200
    assert vulnerable.json()["owner"] == "bob"
    assert secure.status_code == 403


def test_bola_checker_confirms_vulnerable_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_request(url: str, token: str, timeout: float):
        del url, timeout
        response = client.get(
            "/api/orders/order-bob", headers={"Authorization": f"Bearer {token}"}
        )
        from achillesapi.core.bola import PrincipalResponse
        return PrincipalResponse(
            status_code=response.status_code, elapsed_ms=1.0, body=response.text
        )

    monkeypatch.setattr("achillesapi.core.bola._request", fake_request)
    result = check_bola(
        "http://127.0.0.1:8000/api/orders/order-bob",
        owner_token="bob-token",
        other_token="alice-token",
    )
    assert result.status == "confirmed_bola"
    assert result.confirmed_vulnerability is True


def test_bola_checker_does_not_flag_secure_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_request(url: str, token: str, timeout: float):
        del url, timeout
        response = client.get(
            "/api/secure/orders/order-bob", headers={"Authorization": f"Bearer {token}"}
        )
        from achillesapi.core.bola import PrincipalResponse
        return PrincipalResponse(
            status_code=response.status_code, elapsed_ms=1.0, body=response.text
        )

    monkeypatch.setattr("achillesapi.core.bola._request", fake_request)
    result = check_bola(
        "http://localhost:8000/api/secure/orders/order-bob",
        owner_token="bob-token",
        other_token="alice-token",
    )
    assert result.status == "protected_for_other_principal"
    assert result.confirmed_vulnerability is False


def test_bola_checker_rejects_non_loopback_targets() -> None:
    with pytest.raises(BolaCheckError, match="restricted to localhost"):
        check_bola(
            "https://example.com/api/orders/order-bob",
            owner_token="bob-token",
            other_token="alice-token",
        )


def test_bola_checker_rejects_identical_tokens() -> None:
    with pytest.raises(BolaCheckError, match="must be different"):
        check_bola(
            "http://127.0.0.1:8000/api/orders/order-bob",
            owner_token="same-token",
            other_token="same-token",
        )


def test_local_lab_openapi_can_be_parsed(tmp_path) -> None:
    import json
    from pathlib import Path

    from achillesapi.core.openapi import analyze_openapi_file

    document = client.get("/openapi.json").json()
    spec_path = tmp_path / "lab-openapi.json"
    spec_path.write_text(json.dumps(document), encoding="utf-8")
    parsed = analyze_openapi_file(spec_path)
    assert parsed.title == "AchillesAPI Local Security Lab"
    assert parsed.endpoint_count == 7


def test_local_lab_bfla_role_boundary() -> None:
    low = client.get("/api/admin/metrics", headers={"Authorization": "Bearer alice-token"})
    high = client.get("/api/admin/metrics", headers={"Authorization": "Bearer admin-token"})
    assert low.status_code == 403
    assert high.status_code == 200


def test_local_lab_mass_assignment_vulnerable_and_secure_controls() -> None:
    headers = {"Authorization": "Bearer alice-token"}
    vulnerable = client.patch("/api/profiles/alice", json={"is_admin": True}, headers=headers)
    secure = client.patch("/api/secure/profiles/alice", json={"is_admin": True}, headers=headers)
    assert vulnerable.status_code == 200
    assert vulnerable.json()["is_admin"] is True
    assert secure.status_code == 422
