"""Real Chromium smoke: remediation deep-links and non-blocking suite without a target API.

Uses a mock dashboard backend: it does not send HTTP traffic to the API under test.
"""
from pathlib import Path
import json
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'src/achillesapi/dashboard/static'
with sync_playwright() as playwright:
    browser = playwright.chromium.launch(executable_path='/usr/bin/chromium', headless=True, args=['--no-sandbox'])
    page = browser.new_page(viewport={'width': 1300, 'height': 960})
    errors = []
    page.on('pageerror', lambda err: errors.append(str(err)))
    soup = BeautifulSoup((ASSETS / 'index.html').read_text(), 'html.parser')
    for tag in soup.select('script[src],link[rel=stylesheet]'):
        tag.decompose()
    page.set_content(str(soup))
    page.evaluate('''() => {
      window.sentSuites = [];
      window.fetch=async function(url,opts={}){
       const path=String(url);let value={};
       if(path.includes('/api/bootstrap'))value={csrf_token:'mock-token'};
       else if(path.includes('/api/control/tools'))value=[{name:'auto-assess',category:'offline',requirements:'spec',active:false,writes:false,ai:false}];
       else if(path.includes('/api/control/services'))value={ollama:'offline',ollama_models:[],ollama_loaded_models:[],ollama_message:'',ollama_process:'not-managed',ollama_installed:false};
       else if(path.includes('/api/jobs'))value=[];
       else if(path.includes('/api/control/suite')&&opts.method==='POST'){
         window.sentSuites.push(JSON.parse(opts.body));value={id:'a'.repeat(32),total:76,display_name:'Mock suite'};
       }
       else if(path.includes('/api/control/suite/preflight'))value={summary:{ready:2,blocked:1,waiting_for_result:0,disabled:0,not_applicable:0},tasks:[{action:'rc13-assess',state:'blocked',reason:'Le sonde JSON PATCH richiedono campi selezionati in Mass Assignment'}]};
       return new Response(JSON.stringify(value),{status:200,headers:{'content-type':'application/json'}});
      }
    }''')
    for js in ['app.js', 'issue-guide.js', 'workflow-autopilot.js']:
        page.add_script_tag(content=(ASSETS / js).read_text())
    page.evaluate('window.dispatchEvent(new Event("DOMContentLoaded"))')
    page.evaluate("specId='mock-id';csrf='mock-token';")
    # A direct validation error must show exactly where to fix it and open the hidden PATCH drawer.
    page.evaluate("show('Per le sonde PATCH seleziona i campi da autorizzare in Mass Assignment.',true,'suiteStatus')")
    panel = page.locator('#suiteStatus__guidance')
    assert 'Mass Assignment' in panel.inner_text()
    panel.locator('button[data-issue-go="massAssignmentPanel"]').click()
    assert page.locator('#bodyProbeWizard').evaluate('(el)=>el.open'), 'The PATCH settings must be expanded by deep-link'
    assert page.evaluate('location.hash') == '#massAssignmentPanel'
    # All three features selected, but none approved: suite runs offline without writes/PATCH.
    page.locator('#suiteActive').check()
    page.locator('#suiteWrites').check()
    page.locator('#suiteRc13Body').check()
    page.locator('#suiteRc17Agent').check()
    page.locator('#suiteRun').click()
    page.wait_for_function('window.sentSuites.length===1')
    payload = page.evaluate('window.sentSuites[0]')
    assert not payload['include_active'], payload
    assert not payload['include_writes'], payload
    assert not payload['rc13_body_probes'], payload
    assert not payload['rc17_agent_followups'], payload
    page.wait_for_function("document.getElementById('suiteStatus').textContent.includes('offline')")
    page.wait_for_function("document.getElementById('suiteStatus__guidance')?.textContent.includes('Sonde JSON PATCH')")
    assert page.locator('#suiteStatus__guidance button[data-issue-go="massAssignmentPanel"]').count()
    # Offline suite may execute; the user must clearly see excluded work, without silent approvals.
    assert 'esclusi' in page.locator('#suiteExecutionNotice').inner_text()
    # HTTP scope approved, but auth missing: only writes are skipped, GET HTTP may proceed.
    page.locator('#baseUrl').fill('http://127.0.0.1:8000')
    page.locator('#allowHost').fill('127.0.0.1')
    page.locator('#suiteAck').check()
    page.locator('#suiteWritesAck').check()
    page.locator('#suiteRun').click()
    page.wait_for_function('window.sentSuites.length===2')
    payload = page.evaluate('window.sentSuites[1]')
    assert payload['include_active'], payload
    assert not payload['include_writes'], payload
    assert not payload['rc13_body_probes'], payload
    # Accepted/approved fixture and matching field list: PATCH is allowed to reach backend.
    page.evaluate('''() => {
      authId='mock-auth';savedWorkflows=[{specId:'mock-id',configId:'mock-workflow',label:'Project',requiredRequests:8}];
      renderSavedWorkflows();$('suiteWorkflowSelect').value='0';$('bodyProbeWorkflowSelect').value='0';
      bodyProbeFields=['resource.note'];bodyProbeSource='mock-id|mock-workflow';
    }''')
    page.locator('#suiteRun').click()
    page.wait_for_function('window.sentSuites.length===3')
    payload = page.evaluate('window.sentSuites[2]')
    assert payload['include_active'] and payload['include_writes'], payload
    assert payload['rc13_body_probes'] and payload['rc13_body_fields']==['resource.note'], payload
    assert payload['config']['approve_writes'] and payload['config']['acknowledgment'], payload
    # A generic server-side failure still carries actionable navigation.
    page.evaluate("show('Environment variable missing for profile owner',true,'suiteStatus')")
    assert page.locator('#suiteStatus__guidance button[data-issue-go="step3"]').count()==1
    assert not errors, errors
    print('PASS Chromium: guided PATCH links, expanded drawer, safe offline downgrade, GET-only skip, fully approved PATCH, auth error link')
    browser.close()
