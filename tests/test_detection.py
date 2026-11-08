import pytest

from achillesapi.core.detection import EvidenceAnalysisError, analyze_response_evidence


def test_detects_credentialed_wildcard_cors_without_persisting_values():
    report = analyze_response_evidence({"responses": [{
        "method": "GET", "path": "/private", "status_code": 200,
        "headers": {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
        "body_preview": "secret-value-must-not-appear"
    }]})
    assert any(item["finding_id"] == "CORS-001" for item in report["findings"])
    assert "secret-value-must-not-appear" not in str(report)
    assert report["executed_requests"] == 0


def test_detects_stack_trace_by_marker_only():
    report = analyze_response_evidence({"responses": [{
        "method": "GET", "path": "/error", "status_code": 500,
        "headers": {"Content-Type": "text/plain"},
        "body_preview": "Traceback (most recent call last):\n File /srv/private.py line 42"
    }]})
    assert any(item["finding_id"] == "LEAK-STACK_TRACE" for item in report["findings"])
    assert "/srv/private.py" not in str(report)


def test_html_security_headers_are_reviewed_case_insensitively():
    report = analyze_response_evidence({"responses": [{
        "method": "GET", "path": "/", "status_code": 200,
        "headers": {"Content-Type": "text/html"}, "body_preview": "ok"
    }]})
    ids = {item["finding_id"] for item in report["findings"]}
    assert {"HDR-001", "HDR-002", "HDR-003"}.issubset(ids)


def test_rejects_invalid_bundle_and_status():
    with pytest.raises(EvidenceAnalysisError):
        analyze_response_evidence({})
    with pytest.raises(EvidenceAnalysisError):
        analyze_response_evidence({"responses": [{"status_code": 700}]})


def test_limits_bundle_size():
    with pytest.raises(EvidenceAnalysisError):
        analyze_response_evidence({"responses": [{}] * 1001})
