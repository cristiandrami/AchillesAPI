'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const src = fs.readFileSync(path.join(__dirname,'../src/achillesapi/dashboard/static/app.js'),'utf8');
function section(a,b){const start=src.indexOf(a);const end=src.indexOf(b,start);assert(start!==-1&&end>start,'missing source region '+a);return src.slice(start,end);}
const reset = section('function guideStartAnother(){','// A Swagger can expose');
const launch = section('function resetWorkflowRunApprovals(){','function renderSavedWorkflows(){');
const code = `${reset}\n${launch}`;
class El {
 constructor(){this.value='';this.textContent='';this.checked=false;this.hidden=false;this.disabled=false;this.open=false;this.children=[];this.style={};}
 replaceChildren(){this.children=[];}
 focus(){this.focused=true;}
 scrollIntoView(){}
}
const elements=new Map();
const $=id=>{if(!elements.has(id))elements.set(id,new El());return elements.get(id)};
for(const k of ['guidedConfirm','guidedRiskAck','guidedProbeApprove','guidedProbeOrphan','guidedDeny'])$(k).checked=true;
for(const k of ['guidedResponseExample','guidedMutationBody','guidedId'])$(k).value='old draft';
$('guidedCandidate').value='0';
$('workflowSaved').value='0';
$('baseUrl').value='https://example.test';$('allowHost').value='example.test';
$('maxRequests').value='50';
const requests=[];
const script = `
const $ = context.$;
let savedWorkflows=[{label:'Projects',configId:'config-a',specId:'openapi-1',candidateIndex:0,requiredRequests:6,selected:true},
 {label:'Documents',configId:'config-b',specId:'openapi-1',candidateIndex:1,requiredRequests:8,selected:true}];
let preparedCampaign=null,specId='openapi-1',authId='auth-1',guidedIdCandidateKey='old',guidedCandidate={create:'POST /projects'};
const manifestCandidates=[{ready:true,create:'POST /projects'},{ready:true,create:'POST /documents'}];
const guideClear=()=>{};
const guideInvalidate=()=>{$('guidedResult').hidden=true};
const guideGo=(step)=>{$('guidedProgress').textContent=step+' di 4'};
const guideUpdateCandidate=()=>{guidedCandidate=manifestCandidates[Number($('guidedCandidate').value)];};
const catalog=[{name:'multi-resource-assess',active:true,writes:true}];
const clampNumeric=()=>50;
const currentConfig=()=>({action:'should-be-overridden',acknowledgment:false,approve_writes:false,config_usage:'wrong'});
const request=context.request;
const refresh=async()=>{};
const show=(s,err,id)=>{$(id).textContent=s;$(id).error=err};
${code}
(async()=>{
  guideStartAnother();
  if ($('guidedCandidate').value!=='1') throw Error('Did not select next unsaved candidate');
  if ($('guidedProgress').textContent!=='1 di 4') throw Error('Did not return to Step 1');
  if (!$('guidedDrawer').open)throw Error('Drawer was not reopened');
  if ($('guidedId').value!==''||$('guidedConfirm').checked||$('guidedProbeApprove').checked)throw Error('Previous draft approvals/id persisted');
  if (savedWorkflows.length!==2||savedWorkflows[0].configId!=='config-a')throw Error('Existing saved workflows were erased');
  updateWorkflowRunControls();
  if ($('workflowRunSingle').disabled)throw Error('Single workflow action disabled');
  let blocked=false;
  try{await launchSingleWorkflow()}catch(e){blocked=e.message.includes('Conferma entrambe')}
  if(!blocked||context.requests.length)throw Error('Started a write without the two approvals');
  $('workflowRunHttpAck').checked=true;$('workflowRunWritesAck').checked=true;
  await launchSingleWorkflow();
  if(context.requests.length!==1)throw Error('Expected one single-workflow launch');
  const first=context.requests[0];
  if(first.action!=='multi-resource-assess'||first.config_id!=='config-a'||!first.acknowledgment||!first.approve_writes||!first.execute) throw Error('Wrong single launch payload');
  if($('workflowRunHttpAck').checked||$('workflowRunWritesAck').checked)throw Error('Approval was not cleared after launch');
  preparedCampaign={configId:'config-combined',specId,selectionKey:workflowSelectionKey(),requiredRequests:14,resources:2};
  updateWorkflowRunControls();if($('workflowRunCombined').disabled)throw Error('Combined action not enabled');
  savedWorkflows[0].selected=false;
  invalidatePreparedCampaign();
  if(!$('workflowRunCombined').disabled)throw Error('Stale campaign still executable after selection change');
  let stale=false;try{await launchMultiWorkflow()}catch(e){stale=e.message.includes('selezione')};if(!stale)throw Error('Stale selection not rejected');
  savedWorkflows[0].selected=true;
  preparedCampaign={configId:'config-combined',specId,selectionKey:workflowSelectionKey(),requiredRequests:14,resources:2};
  $('workflowRunHttpAck').checked=true;$('workflowRunWritesAck').checked=true;
  await launchMultiWorkflow();
  if(context.requests.length!==2||context.requests[1].config_id!=='config-combined')throw Error('Wrong combined launch payload');
  return 'OK';
})()`;
vm.runInNewContext(script,{context:{ $, requests,request:async (url,params)=>{if(url!=='/api/control/jobs')throw Error('unexpected path');requests.push(JSON.parse(params.body));return{id:'stub-job-'+requests.length};}},console}, {timeout: 4500}).then(result=>{assert.equal(result,'OK');console.log('Workflow UX: 12 controller checks passed (no target HTTP).')}).catch(e=>{console.error(e);process.exitCode=1});
