from pathlib import Path

from achillesapi.core.assessment import assess_api
from achillesapi.core.openapi import analyze_openapi_file

EXAMPLES = Path(__file__).parents[1] / "examples"


def test_passive_assessment_flags_explicitly_public_operation_and_idor_candidate() -> None:
    parsed = analyze_openapi_file(EXAMPLES / "sample_api.yaml")
    findings = assess_api(parsed)
    categories = {finding.category for finding in findings}
    assert "AUTH-001" in categories
    assert "AUTHZ-001" in categories
    assert all(finding.status == "hypothesis" for finding in findings)
