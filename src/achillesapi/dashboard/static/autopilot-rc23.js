'use strict';
/* Read-only state derived from the imported Swagger; no HTTP to the target.
 * Never set authentication, policies, approvals or write fixtures on behalf of users.
 */
(() => {
 const $=id=>document.getElementById(id);
 const sections={
  bola:'authMatrixSection', mass_assignment:'massAssignmentPanel',
  bfla:'bflaPanel', disposable_workflows:'workflowCreateSection',
  read_only_http:'fullSuite', scanners:'securityScannerOptionsSection',
  local_ai:'agentOptionsSection',openapi:'step1'
 };
 const names={
  openapi:'Specifica API',read_only_http:'Letture HTTP',bola:'Accessi tra utenti (BOLA)',
  bfla:'Funzioni riservate (BFLA)',mass_assignment:'Campi modificabili (Mass Assignment)',
  disposable_workflows:'Risorse temporanee e cleanup',scanners:'Scanner input',local_ai:'Agente AI locale'
 };
 const state={spec:'', data:null};
 function node(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);if(cls)e.className=cls;return e;}
 function go(section,field){
  if(window.AchillesIssueGuide?.navigate){window.AchillesIssueGuide.navigate(section,field);return;}
  window.location.hash=section;$(section)?.scrollIntoView({block:'start',behavior:'smooth'});
 }
 function action(text,section,field,scope,operation){const b=node('button',text,'secondary');b.type='button';
  b.addEventListener('click',()=>{
   if(scope&&operation)window.AchillesWorkflowUX?.selectWorkflow?.(scope,operation);
   go(section,field);
  });return b;}
 function fill(data){
  state.data=data;const workspace=data.workspace;
  $('autopilotStatus').textContent=`${workspace.api.operations} operazioni analizzate · ${workspace.workflow_candidates.length} workflow · nessuna richiesta al target`;
  const host=$('autopilotChecks');host.replaceChildren();
  for(const group of workspace.groups){
   if(group.status==='not_applicable')continue;
   const card=node('div',undefined,'autopilot-check');
   card.append(node('strong',(names[group.id]||group.id)+' · '+group.candidate_count+' candidati'));
   const label=group.status==='ready'?'Pronto per l’analisi offline':'Richiede dati per i test attivi';
   card.append(node('p',label,'helper'));
   const missing=group.issues||[];
   if(missing.length){
    const summary=node('details');summary.append(node('summary',missing.length+' prerequisiti per l’esecuzione attiva'));
    for(const issue of missing){
     const line=node('div',undefined,'autopilot-issue');
     line.append(node('p',issue.title+' — '+issue.instructions));
     line.append(action('Vai a: '+issue.title,issue.section,issue.field));summary.append(line);
    }card.append(summary);
   }
   card.append(action('Apri sezione',sections[group.id]||'fullSuite'));
   host.append(card);
  }
  const flows=$('autopilotWorkflows');flows.replaceChildren();
  if(!workspace.workflow_candidates.length){
    flows.append(node('p','Nessun workflow POST → GET con risorsa identificabile nello Swagger. Puoi comunque analizzare tutte le operazioni di lettura.'));
  }
  for(const wf of workspace.workflow_candidates){
   const card=node('div',undefined,'autopilot-flow');
   card.append(node('strong',wf.resource));
   card.append(node('p',[wf.create,wf.read,wf.cleanup||'DELETE assente'].join(' · '),'helper'));
   if(wf.status==='blocked_missing_cleanup')card.append(node('p','Senza DELETE affidabile non vengono proposte scritture automatiche.','helper'));
   const links=node('div',undefined,'buttons');
   links.append(action('Accessi', 'authMatrixSection','accessWorkflowSelect','access',wf.read));
   if(wf.mutations?.length)links.append(action('Mass Assignment','massAssignmentPanel','massWorkflowSelect','mass',wf.mutations[0]));
   links.append(action('Funzioni riservate','bflaPanel','bflaWorkflowSelect','bfla',wf.create));
   links.append(action('Prepara fixture','workflowCreateSection','guidedCandidate','suite',wf.create));
   card.append(links);flows.append(card);
  }
 }
 async function refresh(id){
  state.spec=id||'';
  if(!id){$('autopilotStatus').textContent='Importa lo Swagger per creare il piano.';return;}
  try{
   const res=await fetch('/api/control/autopilot/'+encodeURIComponent(id),{cache:'no-store'});
   const data=await res.json();
   if(state.spec!==id)return;
   if(!res.ok)throw Error(data.detail||'Piano non disponibile');
   fill(data);
  }catch(e){$('autopilotStatus').textContent='Piano non disponibile: '+String(e.message).slice(0,180);}
 }
 window.AchillesAutopilot={refresh, get data(){return state.data;}};
})();
