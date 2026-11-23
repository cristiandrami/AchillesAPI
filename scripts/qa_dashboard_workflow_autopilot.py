from pathlib import Path
from playwright.sync_api import sync_playwright
import json
from bs4 import BeautifulSoup
repo=Path(__file__).resolve().parents[1]
static=repo/'src/achillesapi/dashboard/static'
c=lambda p,field:{'create':'POST /'+p,'read':'GET /'+p+'/{id}','delete':'DELETE /'+p+'/{id}','mutation':'PATCH /'+p+'/{id}','mutation_field_specs':{field:{'type':'string'}},'mutation_field_count':1,'ready':True,'required_path_params':[],'id_candidates':['id'],'id_schema_pointers':['/id'],'write_action_candidates':['POST /'+p+'/{id}/approve'],'marker_candidates':['name'],'field_specs':{'name':{'type':'string'}},'required':['name'],'body_example':{'name':'test'},'path_parameter':'id','read_get_risk':None}
data=[c('projects','note'),c('tickets','description')]; incomplete=c('projects/archive','status');incomplete['delete']=None;incomplete['ready']=False;data.append(incomplete)
with sync_playwright() as pw:
  browser=pw.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
  page=browser.new_page(viewport={'width':1280,'height':940});errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
  soup=BeautifulSoup((static/'index.html').read_text(),'html.parser')
  for el in soup.select('script[src],link[rel=stylesheet]'):el.decompose()
  page.set_content(str(soup))
  page.evaluate('''() => {window.fetch=async function(path,options={}){const u=String(path);let v={};if(u.includes('bootstrap'))v={csrf_token:'x'};if(u.includes('/api/control/manifest/candidates/'))v={candidates:window.mockCandidates||[],write_operations:[]};if(u.includes('/api/summary/'))v={endpoints:(window.mockCandidates||[]).map(c=>({method:'GET',path:c.read.split(' ',2)[1]}))};return new Response(JSON.stringify(v),{status:200,headers:{'content-type':'application/json'}})}}''')
  page.add_script_tag(content=(static/'app.js').read_text())
  page.add_script_tag(content=(static/'workflow-autopilot.js').read_text())
  page.evaluate('window.dispatchEvent(new Event("DOMContentLoaded"))')
  page.evaluate('([a,b,c]) => {window.mockCandidates=[a,b,c]}',data)
  page.evaluate('''async () => {await useSpec({id:'mock',title:'Mock API',operations:12});}''')
  assert page.locator('#workflowDetectedCount').inner_text().startswith('3 workflow'),page.locator('#workflowDetectedCount').inner_text()
  assert page.locator('#workflowDetectedList .workflow-preview-card').count()==3
  assert page.locator('#massWorkflowSelect option').count()==3
  assert page.locator('#bflaWorkflowSelect option').count()==3
  assert page.locator('#accessWorkflowSelect option').count()==3
  assert 'PATCH /projects/{id}' in page.locator('#massWorkflowPreview').inner_text()
  page.locator('#massAutoFields input[value="note"]').check()
  assert 'note' in json.loads(page.locator('#guidedMutationBody').input_value())
  page.locator('#guidedMutationBody').fill('{"note":"custom-one"}')
  page.locator('#bflaWorkflowSelect').select_option('1')
  page.locator('#guidedBflaPolicyAck').check()
  page.locator('#massWorkflowSelect').select_option('1')
  assert page.locator('#massAutoFields input[value="description"]').count()==1
  page.locator('#massAutoFields input[value="description"]').check()
  page.locator('#massWorkflowSelect').select_option('0')
  assert page.locator('#guidedMutationBody').input_value()=='{"note":"custom-one"}'
  assert page.locator('#bflaWorkflowSelect').input_value()=='1'
  assert page.locator('#guidedBflaPolicyAck').is_checked()
  page.locator('#accessWorkflowSelect').select_option('1')
  assert page.locator('#matrixOperation').input_value()=='GET /tickets/{id}'
  page.locator('#massWorkflowSelect').select_option('2')
  assert 'Solo discovery' in page.locator('#massWorkflowPreview').inner_text()
  assert page.locator('#massConfigureSelected').is_disabled()
  assert page.locator('#guidedDrawer').get_attribute('open') is None, 'Incomplete workflow must not open approved wizard'
  page.locator('#massWorkflowSelect').select_option('0')
  page.locator('#massConfigureSelected').click()
  assert page.locator('#guidedDrawer').get_attribute('open') is not None
  assert page.locator('#guidedCandidate').input_value()=='0'
  page.evaluate('''() => {savedWorkflows=[{specId:'mock',candidateIndex:0,label:'Projects',configId:'p',requiredRequests:5},{specId:'mock',candidateIndex:1,label:'Tickets',configId:'t',requiredRequests:5}];renderSavedWorkflows();window.AchillesWorkflowUX.refresh(manifestCandidates,savedWorkflows);}''')
  page.locator('#suiteWorkflowSelectAuto').select_option('1')
  assert page.locator('#suiteWorkflowSelect').input_value()=='1',page.locator('#suiteWorkflowSelect').input_value()
  page.locator('#rc13WorkflowSelectAuto').select_option('0')
  assert page.locator('#rc13WorkflowSelect').input_value()=='0'
  assert not errors, errors
  # Screenshot omitted: this is a functional UI smoke test, not a visual benchmark.
  print('PASS Chromium: automatic discovery 3 workflows (including incomplete), independent BOLA/BFLA/Mass, PATCH fields/body, wizard, scoped suite selection')
  browser.close()
