from pathlib import Path
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
import json
root=Path(__file__).resolve().parents[1]/'src/achillesapi/dashboard/static'
soup=BeautifulSoup((root/'index.html').read_text(),'html.parser')
for t in soup.select('script[src],link[rel=stylesheet]'):t.decompose()
c=lambda path,field:{'create':'POST /'+path,'read':'GET /'+path+'/{id}','delete':'DELETE /'+path+'/{id}','mutation':'PATCH /'+path+'/{id}','mutation_field_specs':{field:{'type':'string'}},'ready':True,'required_path_params':[],'id_candidates':['id'],'id_schema_pointers':['/id'],'write_action_candidates':['POST /'+path+'/{id}/approve'],'marker_candidates':['name'],'field_specs':{'name':{'type':'string'}},'required':['name'],'body_example':{'name':'test'},'path_parameter':'id','read_get_risk':None}
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox']);page=browser.new_page()
 errors=[];page.on('pageerror',lambda exc:errors.append(str(exc)))
 page.set_content(str(soup))
 page.add_script_tag(content="""window.fetch=async function(path,options={}){let v={};let u=String(path);if(u.includes('bootstrap'))v={csrf_token:'x'};if(u.includes('/api/control/manifest/candidates/'))v={candidates:window.mockCandidates,write_operations:[]};if(u.includes('/api/summary/'))v={endpoints:[]};return new Response(JSON.stringify(v),{status:200,headers:{'content-type':'application/json'}})};""")
 page.add_script_tag(content=(root/'app.js').read_text())
 page.evaluate('window.dispatchEvent(new Event("DOMContentLoaded"))')
 page.evaluate('''async ([a,b])=>{window.mockCandidates=[a,b];specId='abc';await guideDiscover();}''',[c('projects','note'),c('tickets','description')])
 assert page.locator('#massWorkflowSelect option').count()==2
 assert page.locator('#bflaWorkflowSelect option').count()==2
 page.locator('#guidedMutationInsert').click()
 page.locator('#guidedMutationBody').fill('{"note":"custom-one"}')
 page.locator('#guidedMutationExpectedDeny').check()
 page.locator('#bflaWorkflowSelect').select_option('1')
 page.locator('#guidedBflaAction').select_option('POST /tickets/{id}/approve')
 page.locator('#guidedBflaPolicyAck').check()
 page.locator('#massWorkflowSelect').select_option('1')
 assert 'description' in page.locator('#guidedMutationField').input_value()
 page.locator('#massWorkflowSelect').select_option('0')
 assert page.locator('#guidedMutationBody').input_value()=='{"note":"custom-one"}'
 assert page.locator('#guidedMutationExpectedDeny').is_checked()
 assert page.locator('#bflaWorkflowSelect').input_value()=='1'
 assert page.locator('#guidedBflaPolicyAck').is_checked()
 page.evaluate('''()=>{savedWorkflows=[{specId:'abc',label:'Progetti',configId:'p',requiredRequests:5},{specId:'abc',label:'Ticket',configId:'t',requiredRequests:5}];renderSavedWorkflows()}''')
 page.locator('#rc13WorkflowSelect').select_option('0')
 page.locator('#suiteWorkflowSelect').select_option('1')
 page.locator('#workflowRunSelect').select_option('0')
 assert page.locator('#rc13WorkflowSelect').input_value()=='0'
 assert page.locator('#suiteWorkflowSelect').input_value()=='1'
 assert page.locator('#workflowRunSelect').input_value()=='0'
 assert not errors,errors
 print('PASS: independent Mass Assignment, BFLA, analysis, suite and run selections')
 browser.close()
