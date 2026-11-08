import base64
import json

import pytest

from achillesapi.core.advanced import (
    AdvancedCheckError,
    inspect_jwt,
    mass_assignment_check,
    require_loopback,
)


def _segment(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def test_jwt_inspection_is_explicitly_unverified():
    token = f"{_segment({'alg': 'HS256', 'typ': 'JWT'})}.{_segment({'sub': 'alice'})}.signature"
    result = inspect_jwt(token)
    assert result["signature_verified"] is False
    assert result["claims_trusted"] is False
    assert any("No exp" in warning for warning in result["warnings"])


def test_jwt_rejects_non_compact_token():
    with pytest.raises(AdvancedCheckError):
        inspect_jwt("not-a-jwt")


def test_active_checks_reject_non_loopback():
    with pytest.raises(AdvancedCheckError):
        require_loopback("https://example.com")


def test_mass_assignment_is_dry_run_by_default():
    result = mass_assignment_check(
        "http://127.0.0.1:8000/api/profile",
        {"displayName": "Test", "isAdmin": True},
    )
    assert result["executed"] is False
    assert "isAdmin" in result["fields"]


def test_mass_assignment_rejects_empty_body():
    with pytest.raises(AdvancedCheckError):
        mass_assignment_check("http://127.0.0.1:8000/api/profile", {})


def test_bola_sweep_requires_loopback_before_requests():
    from achillesapi.core.advanced import bola_sweep

    with pytest.raises(AdvancedCheckError):
        bola_sweep({"paths": {}}, "https://example.com", "a", "b", {})


def test_bfla_sweep_requires_distinct_tokens():
    from achillesapi.core.advanced import bfla_sweep

    with pytest.raises(AdvancedCheckError):
        bfla_sweep({"paths": {}}, "http://127.0.0.1:8000", "same", "same", {})
