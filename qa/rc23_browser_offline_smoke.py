"""Real Chromium DOM smoke, without local HTTP navigation.

Some managed execution environments block Chromium navigation to localhost.
This isolates the production workflow selector code and visualizes real DOM
interaction, while the FastAPI endpoints are tested separately via TestClient.
"""
from __future__ import annotations

from pathlib import Path


def run_offline_browser_smoke() -> dict:
    from playwright.sync_api import sync_playwright
    root=Path(__file__).resolve().parents[1]
    scripts=root/'src/achillesapi/dashboard/static'
    html='''<!doctype html><html><body>
      <div id="dest"></div><p id="autopilotStatus"></p>
      <div id="autopilotChecks"></div><div id="autopilotWorkflows"></div>
      <div id="workflowDetectedList"></div><div id="workflowDetectedCount"></div>
      <div id="workflowCreatePreview"></div><div id="accessWorkflowPreview"></div>
      <div id="massWorkflowPreview"></div><div id="bflaWorkflowPreview"></div>
      <div id="rc13WorkflowSelectPreview"></div><div id="suiteWorkflowSelectPreview"></div>
      <div id="massAutoFields"></div><div id="massWorkflowStatus"></div>
      <textarea id="guidedMutationBody"></textarea><select id="guidedMutation"></select>
      <section id="authMatrixSection"></section><section id="massAssignmentPanel"></section>
      <section id="bflaPanel"></section><section id="workflowCreateSection"></section>
      <section id="fullSuite"></section><section id="step1"></section>
      <select id="accessWorkflowSelect"></select>
      <select id="massWorkflowSelect"><option value="0">A</option><option value="1">B</option></select>
      <select id="bflaWorkflowSelect"><option value="0">A</option><option value="1">B</option></select>
      <select id="rc13WorkflowSelectAuto"></select><select id="suiteWorkflowSelectAuto"></select>
      <select id="matrixOperation"><option value="GET /tickets/{ticket_ref}">ticket</option><option value="GET /projects/{project_ref}">project</option></select>
      </body></html>'''
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-sandbox','--disable-dev-shm-usage'],
            executable_path='/usr/bin/chromium' if Path('/usr/bin/chromium').exists() else None)
        try:
            page=browser.new_page()
            errors=[]
            page.on('pageerror',lambda err:errors.append(str(err)))
            page.set_content(html)
            page.evaluate('''window.AchillesIssueGuide={navigate:(section,field)=>{
                document.querySelector('#dest').textContent=section+':'+(field||'');}};''')
            page.add_script_tag(content=(scripts/'workflow-autopilot.js').read_text())
            page.add_script_tag(content=(scripts/'autopilot-rc23.js').read_text())
            # UI discovery order intentionally opposite the backend order.
            page.evaluate('''window.AchillesWorkflowUX.refresh([
              {create:'POST /projects/{project_ref}/tickets',read:'GET /tickets/{ticket_ref}',
               mutation:'PATCH /tickets/{ticket_ref}',delete:'DELETE /tickets/{ticket_ref}',
               ready:true,write_action_candidates:['POST /projects/{project_ref}/tickets'],
               mutation_field_specs:{note:{type:'string'}}},
              {create:'POST /projects',read:'GET /projects/{project_ref}',
               mutation:'PATCH /projects/{project_ref}',delete:'DELETE /projects/{project_ref}',
               ready:true,write_action_candidates:['POST /projects','PATCH /projects/{project_ref}'],
               mutation_field_specs:{note:{type:'string'}}}],[]);
              window.fetch=async()=>({ok:true,json:async()=>({
                 workspace:{api:{operations:12},workflow_candidates:[
                   {resource:'/projects',create:'POST /projects',read:'GET /projects/{project_ref}',
                    cleanup:'DELETE /projects/{project_ref}',mutations:['PATCH /projects/{project_ref}']},
                   {resource:'/projects/{project_ref}/tickets',create:'POST /projects/{project_ref}/tickets',
                    read:'GET /tickets/{ticket_ref}',cleanup:'DELETE /tickets/{ticket_ref}',
                    mutations:['PATCH /tickets/{ticket_ref}']}],
                    groups:[{id:'mass_assignment',status:'requires_input',candidate_count:2,
                    issues:[{title:'Campi PATCH',instructions:'Seleziona workflow',section:'massAssignmentPanel',field:'massWorkflowSelect'}]}]}})});
            ''')
            page.evaluate("window.AchillesAutopilot.refresh('dummy-import-id')")
            page.wait_for_function("document.querySelectorAll('.autopilot-flow').length===2")
            page.locator('.autopilot-flow').first.get_by_role('button',name='Mass Assignment').click()
            assert page.locator('#massWorkflowSelect').input_value()=='1'
            assert page.locator('#dest').inner_text()=='massAssignmentPanel:massWorkflowSelect'
            page.locator('.autopilot-flow').nth(1).get_by_role('button',name='Accessi').click()
            assert page.locator('#accessWorkflowSelect').input_value()=='0'
            assert page.locator('#dest').inner_text()=='authMatrixSection:accessWorkflowSelect'
            assert not errors,errors
            return {'engine':'achilles-rc23-browser-dom-smoke',
                    'result':'passed','workflow_cards':2,'javascript_errors':len(errors),
                    'test_type':'real_chromium_with_simulated_backend',
                    'limitations':['This test does not prove browser-to-live-dashboard interoperability.']}
        finally:
            browser.close()


if __name__=='__main__':
    import json
    print(json.dumps(run_offline_browser_smoke(),indent=2))
