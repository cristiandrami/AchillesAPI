"""Regression: ID input must auto-populate even if POST response is not documented."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from achillesapi.dashboard.manifest_builder import discover_manifest_candidates
from achillesapi.dashboard.server import create_app
from test_rc9_independent_enterprise import SPEC

HERE = Path(__file__).parent
LAB = HERE / 'fixtures' / 'independent-api-lab' / 'openapi.json'


def _candidate_with_schema(tmp_path):
    file = tmp_path / 'documented.json'
    file.write_text(json.dumps(SPEC))
    return next(c for c in discover_manifest_candidates(str(file)) if c['create'].endswith('/projects'))


def test_discovery_preserves_undeclared_id_hints(tmp_path):
    candidate = next(c for c in discover_manifest_candidates(str(LAB)) if c['create']=='POST /projects')
    assert candidate['ready']
    assert candidate['id_schema_pointers'] == []
    assert candidate['id_candidates'][:2] == ['project_ref','id']
    documented = _candidate_with_schema(tmp_path)
    assert documented['id_schema_pointers'] == ['/data/id']
    assert documented['id_candidates'][0] == '/data/id'


def test_dashboard_autofill_with_real_dom_helpers(tmp_path):
    """Run the unmodified JS helper code against a minimal DOM, not a rewrite."""
    if not shutil.which('node'):
        pytest.skip('node is unavailable')
    undocumented = next(c for c in discover_manifest_candidates(str(LAB)) if c['create']=='POST /projects')
    documented = _candidate_with_schema(tmp_path)
    multi = {**documented, 'create': 'POST /multi', 'id_schema_pointers':['/data/tenantId','/data/id']}
    missing = {**undocumented, 'create': 'POST /unmapped', 'id_schema_pointers': [], 'id_candidates': []}
    conventional = {**undocumented, 'create':'POST /expenses', 'path_parameter':'expense_id',
                    'id_schema_pointers':[], 'id_candidates':['expense_id','id','expenseId']}
    payload = {'undocumented': undocumented, 'documented': documented, 'multi':multi,
               'missing':missing, 'conventional':conventional}
    result = subprocess.run(['node', str(HERE/'js_creation_id_autofill_regression.cjs')],
        input=json.dumps(payload), text=True, capture_output=True, timeout=12)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '7 DOM scenarios passed' in result.stdout


def test_dashboard_serves_fresh_script_and_wizard(tmp_path):
    with TestClient(create_app(tmp_path/'dashboard'), base_url='http://127.0.0.1:8766') as client:
        html = client.get('/').text
        js = client.get('/assets/app.js').text
        # Cache version updates are expected; verify that the current script
        # is referenced and its actual implementation retains the functionality.
        assert 'src="/assets/app.js?v=rc27-multiflow-1"' in html
        assert 'guideApplyIdentifierSuggestion();' in js
        assert 'guideApplyIdentifierSuggestion(true);' in js
        assert 'guideIdentifierSuggestion(candidate)' in js
        assert 'Non è un valore del server' not in js  # no false certainty in UI
