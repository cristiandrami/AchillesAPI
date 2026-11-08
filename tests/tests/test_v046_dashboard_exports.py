"""Export any completed dashboard job, not only auto-assess plans."""
import json
import time
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app

SPEC = {
    'openapi': '3.0.3', 'info': {'title': 'Independent target', 'version': '1'},
    'paths': {'/hello': {'get': {'responses': {'200': {'description': 'OK'}}}}},
}


def test_dashboard_offline_inventory_export_html_pdf(tmp_path):
    client = TestClient(create_app(tmp_path / 'dashboard'), base_url='http://127.0.0.1:8766')
    csrf = client.get('/api/bootstrap').json()['csrf_token']
    headers = {'x-achilles-token': csrf}
    imported = client.post('/api/import-text', headers=headers,
        json={'kind': 'openapi', 'content': json.dumps(SPEC)}).json()
    response = client.post('/api/control/jobs', headers=headers,
        json={'action': 'security-inventory', 'specification_id': imported['id']})
    assert response.status_code == 200, response.text
    job_id = response.json()['id']
    for _ in range(180):
        job = client.get('/api/jobs/' + job_id).json()
        if job['status'] != 'running':
            break
        time.sleep(0.05)
    assert job['status'] == 'complete', job
    html = client.get(f'/api/export/{job_id}/html')
    pdf = client.get(f'/api/export/{job_id}/pdf')
    assert html.status_code == 200, html.text[:450]
    assert pdf.status_code == 200, pdf.text[:450] if pdf.status_code != 200 else ''
    assert 'tool_analysis' in html.text
    assert pdf.content.startswith(b'%PDF')
    assert 'inline' in pdf.headers.get('content-disposition', '')
