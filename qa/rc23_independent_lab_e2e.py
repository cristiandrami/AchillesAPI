"""End-to-end, in-process HTTP validation on an independent synthetic FastAPI lab.

The test imports the *lab's* FastAPI application, creates disposable resources,
exercises the owner/other/protected controls, confirms evidence classification,
then performs reverse-order cleanup. No production target or external network.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from achillesapi.core.evidence_verification_rc22 import verify_controlled_cases


def load_independent_lab():
    lab = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "independent-api-lab" / "app.py"
    module_spec = importlib.util.spec_from_file_location("achilles_rc23_independent_lab", lab)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Independent laboratory application is missing")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module.app


def run_independent_lab_e2e() -> dict[str, Any]:
    """Return a compact, redacted report; throw on unexpected test behavior."""
    client = TestClient(load_independent_lab())
    owner = {"Authorization": "Bearer demo-owner"}
    other = {"Authorization": "Bearer demo-other"}
    project_id = None
    ticket_id = None
    project_cleaned = False
    ticket_cleaned = False
    try:
        project = client.post('/projects', json={'label':'rc23-approved-disposable-project'}, headers=owner)
        assert project.status_code == 201, 'Failed to create disposable project'
        project_id = project.json()['id']
        ticket = client.post(f'/projects/{project_id}/tickets',
            json={'label':'rc23-disposable-ticket','project':project_id}, headers=owner)
        assert ticket.status_code == 201, 'Failed to create disposable dependent ticket'
        ticket_id = ticket.json()['id']
        cases=[]
        for kind, object_id, path, protected in (
            ('project',project_id,'/projects/','/secure/projects/'),
            ('ticket',ticket_id,'/tickets/','/secure/tickets/')):
            owner_response=client.get(path+object_id,headers=owner)
            other_response=client.get(path+object_id,headers=other)
            other_replay=client.get(path+object_id,headers=other)
            negative=client.get(protected+object_id,headers=other)
            owner_marker=owner_response.json().get('id') == object_id if owner_response.status_code==200 else False
            other_marker=other_response.json().get('id') == object_id if other_response.status_code==200 else False
            replay_marker=other_replay.json().get('id') == object_id if other_replay.status_code==200 else False
            assert owner_marker and other_marker and replay_marker, f'{kind}: expected vulnerable BOLA control'
            assert negative.status_code == 403, f'{kind}: expected protected comparator to deny other identity'
            cases.append({
                'operation':f'GET {path}{{{kind}_ref}}',
                'category':'BOLA','case_id':f'lab-{kind}',
                'expected_other':'deny',
                'control':{'owner_status':owner_response.status_code,'marker_verified':owner_marker,
                           'negative_control_denied':negative.status_code==403},
                'attempt':{'other_status':other_response.status_code,'marker_verified':other_marker},
                'replay':{'same_identity':True,'same_object_marker':replay_marker},
            })
        verified=verify_controlled_cases(cases)
        assert verified['unique_cases']==2
        assert verified['classification_counts']=={'confirmed_policy_violation':2}
        # Independent protected negative control must not be reported as a violation.
        safe=verify_controlled_cases([{
            'operation':'GET /secure/projects/{project_ref}', 'category':'BOLA',
            'case_id':'lab-secure-project','expected_other':'deny',
            'control':{'owner_status':200,'marker_verified':True,'negative_control_denied':True},
            'attempt':{'other_status':403,'marker_verified':False},
            'replay':{'same_identity':True,'same_object_marker':False},
        }])
        assert safe['observations'][0]['status']=='observed_expected'
        return {'engine':'achilles-rc23-independent-lab-e2e',
                'validated_endpoints': ['POST /projects','POST /projects/{project_ref}/tickets',
                    'GET /projects/{project_ref}','GET /tickets/{ticket_ref}',
                    'GET /secure/projects/{project_ref}','GET /secure/tickets/{ticket_ref}',
                    'DELETE /tickets/{ticket_ref}','DELETE /projects/{project_ref}'],
                'vulnerable_controls_confirmed':verified['classification_counts']['confirmed_policy_violation'],
                'safe_controls_passed':1,'requests_to_external_network':0,
                'validation':'real_lab_app_testclient',
                'notes':['Independent synthetic lab, not Northstar nor a real enterprise target.',
                         'Evidence records were derived from actual HTTP responses, not from Ollama.']}
    finally:
        # Cleanup must be attempted even when an assertion or verification fails.
        if ticket_id:
            removed=client.delete('/tickets/'+ticket_id,headers=owner)
            ticket_cleaned=removed.status_code in (204,404)
        if project_id:
            removed=client.delete('/projects/'+project_id,headers=owner)
            project_cleaned=removed.status_code in (204,404)
        if ticket_id and not ticket_cleaned or project_id and not project_cleaned:
            raise RuntimeError('Independent lab cleanup could not be verified')


if __name__=='__main__':
    print(json.dumps(run_independent_lab_e2e(),ensure_ascii=False,indent=2))
