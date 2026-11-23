"""RC9 access-matrix interactive JSON import, individual removal and sample compatibility."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from achillesapi.core.access_matrix_rc4 import preflight_rules
from achillesapi.dashboard.server import create_app

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "northstar-access-matrix.rules.json"
STATIC = ROOT / "src" / "achillesapi" / "dashboard" / "static"


def test_northstar_example_is_a_valid_access_matrix(tmp_path):
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    assert len(data["rules"]) == 14
    assert {r["expected_owner"] for r in data["rules"]} == {"allow", "deny"}
    from yaml import safe_dump

    operations = {r["operation"] for r in data["rules"]}
    paths = {}
    for operation in operations:
        assert operation.startswith("GET ")
        path = operation[4:]
        import re
        parameters = [
            {"name": name, "in": "path", "required": True,
             "schema": {"type": "string"}}
            for name in re.findall(r"\{([^{}]+)\}", path)
        ]
        paths[path] = {"get": {"parameters": parameters,
                               "responses": {"200": {"description": "OK"}}}}
    spec = tmp_path / "spec.yaml"
    spec.write_text(safe_dump({"openapi": "3.0.3", "info": {"title": "Matrix test", "version": "1"},
                               "paths": paths}), encoding="utf-8")
    profiles = {"owner", "other", "colleague", "manager", "finance", "other_manager"}
    normalized = preflight_rules(spec, data, profile_names=profiles)
    assert len(normalized) == len(data["rules"])
    assert any(r["expected_owner"] == "deny" and r["expected_other"] == "deny"
               for r in normalized)


def test_dashboard_html_exposes_import_export_delete(tmp_path):
    from fastapi.testclient import TestClient

    with TestClient(create_app(tmp_path / "dashboard"),
                    base_url="http://127.0.0.1:8766") as client:
        response = client.get("/")
        assert response.status_code == 200
        html = response.text
        for element_id in ("matrixImportFile", "matrixExport", "matrixRulesList",
                           "matrixAdd", "matrixClear", "matrixGenerate"):
            assert f'id="{element_id}"' in html
        assert 'src="/assets/app.js?v=rc27-multiflow-1"' in html
        js = client.get("/assets/app.js").text
        for symbol in ("importMatrixJSON", "validateMatrixPayload", "invalidateGeneratedMatrix",
                       "matrix-rule-remove", "matrixRules.splice(index,1)", "downloadMatrixJSON"):
            assert symbol in js
        assert "Elimina regola" in js


def test_matrix_editor_real_js_dom_scenarios():
    if not shutil.which("node"):
        pytest.skip("Node.js unavailable to test browser-side JS")
    process = subprocess.run(["node", str(ROOT / "tests/js_matrix_import_remove.cjs")],
                             capture_output=True, text=True, timeout=15, check=False)
    assert process.returncode == 0, process.stdout + process.stderr
    assert "matrix editor DOM scenarios passed" in process.stdout


def test_example_is_free_of_tokens_and_is_under_matrix_limit():
    text = EXAMPLE.read_text(encoding="utf-8")
    assert "Bearer " not in text and "lab-acme-employee" not in text
    assert len(text.encode("utf-8")) <= 128 * 1024
    data = json.loads(text)
    assert len(data["rules"]) <= 20
    assert len({r["id"] for r in data["rules"]}) == len(data["rules"])


def test_matrix_json_uploaded_and_dry_run_on_local_http_with_approval(tmp_path):
    """A config generated in the browser must actually execute in offline mode.

    The user may allow plaintext HTTP for a local lab; no network call is made.
    """
    import time
    from fastapi.testclient import TestClient

    spec = {"openapi": "3.0.3", "info": {"title": "Local QA", "version": "1"},
            "paths": {"/items/{item_id}": {"get": {
                "parameters": [{"name": "item_id", "in": "path", "required": True,
                                "schema": {"type": "string"}}],
                "responses": {"200": {"description": "OK"}}}}}}
    auth = {"profiles": [{"name": "owner", "type": "bearer", "token": "local-test-a"},
                         {"name": "other", "type": "bearer", "token": "local-test-b"}]}
    policy = {"rules": [{"id": "local-rule", "operation": "GET /items/{item_id}",
                         "owner": "owner", "other": "other", "expected_owner": "allow",
                         "expected_other": "deny", "path_values": {"item_id": "test-1"}}]}
    with TestClient(create_app(tmp_path / "dashboard"),
                    base_url="http://127.0.0.1:8766") as client:
        token = client.get("/api/bootstrap").json()["csrf_token"]
        headers = {"x-achilles-token": token}
        identifiers = []
        for kind, item in (("openapi", spec), ("auth", auth), ("config", policy)):
            response = client.post("/api/import-text", headers=headers, json={
                "kind": kind, "name": f"{kind}.json", "content": json.dumps(item)})
            assert response.status_code == 200, response.text
            identifiers.append(response.json()["id"])
        job = client.post("/api/control/jobs", headers=headers, json={
            "action": "access-matrix", "specification_id": identifiers[0],
            "auth_config_id": identifiers[1], "config_id": identifiers[2],
            "config_usage": "context", "base_url": "http://127.0.0.1:8795",
            "allow_host": "127.0.0.1", "allow_insecure_http": True, "execute": False})
        assert job.status_code == 200, job.text
        for _ in range(100):
            state = client.get("/api/jobs/" + job.json()["id"]).json()
            if state["status"] != "running":
                break
            time.sleep(0.06)
        assert state["status"] == "complete", state
        report = client.get("/api/results/" + job.json()["id"]).json()
        assert report["status"] == "dry_run"
        assert report["requests_sent"] == 0
        assert len(report["rules"]) == 1
