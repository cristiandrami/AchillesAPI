"""Exercise the complete local lab, including deliberate failures and controls."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from achillesapi.core.generic import build_generic_plan, execute_generic_gets
from achillesapi.core.openapi import load_openapi, parse_openapi
from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.lab.full_app import app, PROFILES, REPORTS

client = TestClient(app)


def bearer(username: str) -> dict[str, str]:
    """Build a fake Bearer header; this is never used against real APIs."""
    return {"Authorization": f"Bearer {username}-token"}


def test_training_lab_openapi_matches_the_code():
    """Every operation in the exported Swagger must exist in the running app."""
    source = Path(__file__).resolve().parents[1] / "examples/full_lab_openapi.json"
    document = load_openapi(source)
    assert document == app.openapi()
    parsed = parse_openapi(document)
    assert parsed.endpoint_count >= 18
    assert len(parsed.security_schemes) == 4
    plan = build_generic_plan(parsed, base_url="http://127.0.0.1:8000")
    assert plan["summary"]["manual_only"] >= 3


def test_bola_vulnerable_and_secure_control():
    """Alice reads Bob's order on the vulnerable route, but not the secure route."""
    bad = client.get("/api/orders/order-bob", headers=bearer("alice"))
    good = client.get("/api/secure/orders/order-bob", headers=bearer("alice"))
    owner = client.get("/api/secure/orders/order-bob", headers=bearer("bob"))
    assert bad.status_code == 200 and bad.json()["owner"] == "bob"
    assert good.status_code == 403
    assert owner.status_code == 200


def test_bfla_vulnerable_and_secure_control():
    """The vulnerable admin endpoint allows Alice; secure endpoint blocks her."""
    assert client.get("/api/admin/audit", headers=bearer("alice")).status_code == 200
    assert client.get("/api/admin/metrics", headers=bearer("alice")).status_code == 403
    assert client.get("/api/admin/metrics", headers=bearer("admin")).status_code == 200


def test_bopla_vulnerable_and_secure_control():
    """Vulnerable route exposes a hidden field; secure route omits it."""
    bad = client.get("/api/profiles/bob", headers=bearer("alice"))
    good = client.get("/api/secure/profiles/bob", headers=bearer("bob"))
    assert "private_note" in bad.json()
    assert "private_note" not in good.json()
    assert client.get("/api/secure/profiles/bob", headers=bearer("alice")).status_code == 403


def test_mass_assignment_and_protected_patch():
    """The vulnerable PATCH changes is_admin while the secure PATCH refuses it."""
    before = PROFILES["alice"].copy()
    try:
        bad = client.patch("/api/profiles/alice", headers=bearer("alice"), json={"is_admin": True})
        assert bad.status_code == 200
        assert PROFILES["alice"]["is_admin"] is True
        good = client.patch("/api/secure/profiles/alice", headers=bearer("alice"), json={"is_admin": True})
        assert good.status_code == 422
    finally:
        PROFILES["alice"] = before


def test_sql_error_signal_is_simulated_not_a_real_database():
    """Quote produces an intentional server error, without SQL execution."""
    params = {"q": "'"}
    assert client.get("/api/search", headers=bearer("alice"), params=params).status_code == 500
    assert client.get("/api/secure/search", headers=bearer("alice"), params=params).status_code == 200


def test_query_constraints_and_nonstandard_sku():
    """Exercise OpenAPI-aware boundary checks and a nonstandard object key."""
    assert client.get("/api/inventory", params={"limit": 0}).status_code == 422
    assert client.get("/api/inventory", params={"limit": 20}).status_code == 200
    assert client.get("/api/catalog/SKU-1001").status_code == 200
    assert client.get("/api/catalog/missing").status_code == 404


def test_multiple_auth_schemes():
    """Basic, API key and cookie routes each accept their correct credentials."""
    assert client.get("/api/basic/account", auth=("lab-user", "lab-pass")).status_code == 200
    assert client.get("/api/partner/summary", headers={"X-API-Key": "partner-demo-key"}).status_code == 200
    assert client.get("/api/session/me", cookies={"sessionid": "alice-session"}).status_code == 200
    assert client.get("/api/partner/summary", headers=bearer("alice")).status_code == 401


def test_post_get_workflow_requires_owner():
    """Create an isolated report and confirm the GET checks ownership."""
    REPORTS.clear()
    try:
        create = client.post("/api/reports", headers=bearer("alice"), json={"title": "Demo"})
        assert create.status_code == 201
        url = "/api/reports/" + create.json()["report_ref"]
        assert client.get(url, headers=bearer("alice")).status_code == 200
        assert client.get(url, headers=bearer("bob")).status_code == 403
    finally:
        REPORTS.clear()


def test_generic_executor_selects_only_matching_auth_schemes():
    """A Bearer identity should not be sent to a Basic, cookie or API key route."""
    plan = build_generic_plan(parse_openapi(app.openapi()), path_values={
        "order_id": "order-bob", "username": "bob", "sku": "SKU-1001",
        "report_ref": "missing",
    })
    report = execute_generic_gets(
        plan, base_url="http://127.0.0.1:8000",
        allowed_hosts={"127.0.0.1"},
        identities={"alice": AuthenticationMaterial(headers={"Authorization": "Bearer alice-token"})},
        allow_insecure_http=True,
    )
    sent_to = {row["path"] for row in report["observations"]}
    assert "/api/orders/{order_id}" in sent_to
    assert "/api/basic/account" not in sent_to
    assert "/api/partner/summary" not in sent_to
    assert "/api/session/me" not in sent_to
    assert "/health" in sent_to
    assert report["requests_sent"] == 0
    assert report["skipped_auth_mismatch"]
