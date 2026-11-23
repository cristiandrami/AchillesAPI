'use strict';
// Single-source-of-truth wizard: no hidden shared state between separate panels.
const $=id=>document.getElementById(id);
const displayTaskName=name=>window.AchillesPublicNames?.action(name) || String(name||'');
let csrf='',specId='',authId='',configId='',selectedJob='',evidenceJob='',catalog=[],authTemplate='',manifestCandidates=[],writeInventory=[];
let matrixGetOps=[],matrixRules=[],matrixAuthProfiles=[],matrixGeneratedConfigId="";let savedWorkflows=[],preparedCampaign=null;let previousJobs=[]; // Each workflow is isolated by its uploaded configuration ID.
window.AchillesDashboardCSRF=()=>csrf;
const reqText={spec:'Richiede Swagger/OpenAPI',both:'Richiede Swagger e un report precedente',report:'Richiede un report precedente', 'spec-config':'Richiede Swagger e una configurazione YAML', 'report-config':'Richiede report e configurazione YAML','config:json':'Richiede evidenze YAML/JSON',scope:'Richiede URL e hostname','auth-only':'Richiede auth.yaml','config-report':'Richiede un benchmark JSON e un report precedente'};
const explanations={
 'auto-assess':'Assessment principale: pianifica le verifiche e, con autorizzazione, esegue GET sicure e controlli selezionati.',
 'multi-resource-assess':'Crea risorse di test collegate, confronta i permessi e le cancella. Richiede resources.yaml approvato.',
 'workflow-assess':'Esegue il ciclo CRUD di una risorsa temporanea e il cleanup.',
 'journey-assess':'Segue una sequenza di GET e trasferisce identificativi dalle risposte.',
 'advanced-vuln-assess':'Valuta controlli applicabili ed evidenze di sicurezza con criteri conservativi.',
 'agent-loop-v2':'Propone e verifica follow-up GET autorizzati, con massimo due cicli.',
 'autonomous-agent':'Esegue follow-up limitati tra le GET già considerate autorizzate.',
 'security-inventory':'Mostra le categorie di controllo suggerite dallo Swagger. Non invia richieste.',
 'generate-tests':'Produce il piano dei possibili test senza eseguirli.',
 'workflow-map':'Esamina possibili dipendenze tra le operazioni.',
 'workflow-graph':'Valida un manifesto di risorse e l’ordine di cleanup.',
 'coverage-report':'Misura quali endpoint hanno effettivamente prodotto osservazioni.',
 'ai-correlate':'Confronta Swagger con le risposte HTTP già osservate. Prima esegui auto-assess in modalità ATTIVA e seleziona il suo risultato nel campo Analisi precedente. NON serve un manifest.',
 'ai-analyze':'Legge soltanto Swagger e chiede al modello Ollama locale un riepilogo dei rischi. Non richiede un assessment precedente.',
 'ai-prioritize':'Partendo da un assessment precedente, ordina le verifiche ancora da fare. Può usare Ollama se abiliti AI.',
 'scan':'Analizza Swagger senza contattare l’API; l’opzione AI aggiunge un parere Ollama. Non richiede risultati precedenti.',
 'autonomous-agent':'Usa le osservazioni di un precedente auto-assess per proporre verifiche GET già autorizzate.',
 'agent-loop-v2':'Ripete solo GET già osservate con errore 5xx o accesso anonimo inatteso. Se nessuna osservazione richiede conferma, termina correttamente senza inviare richieste.',
 'ai-prioritize':'Usa lo Swagger e un risultato precedente per distinguere anomalie GET da test ancora non coperti. Se non trova anomalie, mostra comunque le verifiche mancanti. Ollama è facoltativo.',
 'auth-draft':'Genera una bozza di configurazione dei profili di autenticazione.',
 'scope-audit':'Verifica che URL e host siano coerenti con il perimetro autorizzato.',
 'rc13-assess':'Analisi approfondita API: combina verifiche sugli input GET, matrice degli accessi, workflow temporanei approvati e copertura effettiva. Puoi selezionare sonde PATCH dal wizard. Ollama è facoltativo e i risultati compaiono nel dossier AI.'
};
function show(text,isError=false,at='globalMessage'){
 const target=$(at);if(!target)return;
 target.textContent=window.AchillesPublicNames?.text(text)||text;target.classList.toggle('error',isError);
 // Unified, actionable remediation for both client and server errors.
 if(window.AchillesIssueGuide){
  if(isError)window.AchillesIssueGuide.report(text,at);
  else window.AchillesIssueGuide.clear(at);
 }
}
const fieldNames={rate:'Richieste al secondo',max_requests:'Numero massimo di richieste',budget:'Budget follow-up',profiles:'Identità da confrontare',secrets:'Credenziali',config_id:'Manifest',auth_config_id:'auth.yaml',specification_id:'Swagger',base_url:'Base URL',allow_host:'Hostname autorizzato'};
function formatError(detail,status){
 if(Array.isArray(detail))return detail.map(e=>{
   const key=(e.loc||[]).filter(x=>x!=='body').join('.');
   const pretty=fieldNames[key]||key||'Campo';
   const limit=e.ctx||{};
   if(e.type==='less_than_equal')return `${pretty}: massimo consentito ${limit.le}. Correggi il valore e riprova.`;
   if(e.type==='greater_than_equal')return `${pretty}: minimo consentito ${limit.ge}. Correggi il valore e riprova.`;
   if(e.type==='too_long'||e.type==='list_too_long')return `${pretty}: troppi elementi (massimo ${limit.max_length||'previsto'}).`;
   if(e.type==='missing')return `${pretty}: campo obbligatorio mancante.`;
   return `${pretty}: valore non valido (${e.msg||e.type||'controlla il campo'}).`;
 }).join('\n');
 if(typeof detail==='string'&&detail.trim())return detail;
 if(status===413)return 'File troppo grande: riduci dimensioni del file e riprova.';
 if(status===403)return 'Sessione dashboard scaduta: aggiorna la pagina e ripeti.';
 if(status===404)return 'File o risultato non trovato: ricaricalo nella dashboard.';
 if(status===409)return 'Un assessment è già in corso: attendi la fine prima di avviarne un altro.';
 if(status===422)return 'Uno o più campi non sono validi. Verifica i valori inseriti.';
 if(status>=500)return 'Errore interno della dashboard: controlla il terminale in cui è avviata.';
 return 'Richiesta non riuscita (HTTP '+status+'). Controlla le impostazioni e riprova.';
}
function clampNumeric(id){const el=$(id);const min=Number(el.min),max=Number(el.max);let n=Number(el.value);if(el.value.trim()===''||!Number.isFinite(n))n=Number(el.defaultValue)||min;if(n>max)n=max;if(n<min)n=min;el.value=String(n);el.setCustomValidity('');return n}
function prepareNumerics(){for(const id of ['rate','maxRequests','agentBudget']){const el=$(id);el.addEventListener('input',()=>{if(el.value==='')return;const val=Number(el.value);if(Number.isFinite(val)&&val>Number(el.max))el.value=el.max;if(Number.isFinite(val)&&val<Number(el.min)&&el.value!=='0')el.value=el.min});el.addEventListener('change',()=>clampNumeric(id));el.addEventListener('paste',()=>queueMicrotask(()=>clampNumeric(id)));}}

async function request(path,options={}){const headers={...(options.headers||{})};if(options.method==='POST')headers['x-achilles-token']=csrf;let resp;try{resp=await fetch(path,{...options,headers})}catch(e){throw Error('Dashboard non raggiungibile: '+e.message)}const type=resp.headers.get('content-type')||'';if(!type.includes('application/json'))throw Error('Risposta inattesa dal server ('+resp.status+')');const obj=await resp.json();if(!resp.ok)throw Error(formatError(obj.detail,resp.status));return obj}
async function upload(input,path){const f=input.files?.[0];if(!f)return null;const form=new FormData();form.append('file',f);if(path==='/api/upload'&&f.name.toLowerCase().endsWith('.zip'))form.append('root',$('specBundleRoot')?.value.trim()||'');return request(path,{method:'POST',body:form})}
async function importText(kind,id){const content=$(id).value.trim();if(!content)throw Error('Incolla prima il contenuto YAML/JSON');return request('/api/import-text',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({kind,content,name:'contenuto-incollato.yaml'})})}
async function useSpec(data){specId=data.id;guidedIdCandidateKey='';matrixRules=[];matrixGetOps=[];matrixGeneratedConfigId="";selectedJob='';evidenceJob='';configId='';if($('manifestEditor'))$('manifestEditor').value='';savedWorkflows=[];preparedCampaign=null;localWorkflowState.mass.clear();localWorkflowState.bfla.clear();resetWorkflowRunApprovals();renderSavedWorkflows();$('workflowSavedStatus').textContent='Nuovo Swagger: prepara uno o più workflow relativi a questa API.';$('specState').textContent=`✓ ${data.title} · ${data.operations} operazioni riconosciute`+(data.bundle?` · ZIP OpenAPI: ${data.files?.length||0} file, principale ${data.root}`:'');manifestCandidates=[];writeInventory=[];$('manifestWriteInventory').textContent='';$('guidedWriteInventory').textContent='';$('manifestCandidatesState').textContent='Swagger importato: puoi cercare workflow CRUD.';const details=await request('/api/summary/'+specId);const box=$('operationsList');box.replaceChildren();for(const op of details.endpoints){if(op.method==='GET')matrixGetOps.push(op);const row=document.createElement('div');row.className='operation';const method=document.createElement('b');method.textContent=op.method;row.append(method,document.createTextNode(op.path));box.append(row)}renderMatrixOptions();try{await guideDiscover()}catch(error){show('Risorse temporanee non rilevate: '+error.message,true,'massWorkflowStatus');$('bflaWorkflowStatus').textContent='Workflow non rilevati.'}window.AchillesWorkflowUX?.refresh(manifestCandidates,savedWorkflows);window.AchillesAutopilot?.refresh(specId);window.AchillesAutoConfigure?.refresh(specId);show('Swagger importato correttamente. Workflow e campi pertinenti disponibili automaticamente nelle singole sezioni.')}
async function useAuth(data){invalidateGeneratedMatrix();authId=data.id;const descriptions=data.descriptions||data.profiles||[];let envs=[];let names=[];for(const item of descriptions){if(typeof item==='string'){names.push(item);continue}names.push(item.name);envs.push(...(item.environment_variables||[]))}envs=[...new Set(envs)];matrixAuthProfiles=[...new Set(names)];$('authState').textContent='✓ Profili configurati: '+names.join(', ')+(envs.length?' · segreti richiesti: '+envs.join(', '):'');$('profiles').value=names.join(', ');for(const id of ['manifestOwner','manifestOther']){const select=$(id);select.replaceChildren();if(id==='manifestOther'){const none=document.createElement('option');none.value='';none.textContent='Nessuna';select.append(none)}for(const name of names){const opt=document.createElement('option');opt.value=name;opt.textContent=name;select.append(opt)}}const box=$('secretFields');box.replaceChildren();for(const name of envs){const label=document.createElement('label');label.textContent=name;const field=document.createElement('input');field.type='password';field.dataset.secret=name;field.placeholder='Inserisci il valore, non viene salvato sul server';field.autocomplete='off';label.append(field);box.append(label)}renderMatrixOptions();renderLocalBfla();show('File auth.yaml valido. Se hai usato token: nel file, non serve compilare altri campi; le eventuali variabili ambiente restano opzionali.')}
function toolDetails(){const obj=catalog.find(x=>x.name===$('toolSelect').value);if(!obj)return;
 // Progressive disclosure: only task-relevant controls in the main workspace.
 const needsReport=['report','both','report-config','config-report'].includes(obj.requirements);
 $('previousJobWrap').hidden=!needsReport;
 $('pathValuesWrap').hidden=!['access-probe','auto-assess','injection-assess','rc15-scan','rc16-access-auto'].includes(obj.name);
 if($('rc16ExpectedWrap'))$('rc16ExpectedWrap').hidden=!['rc16-assess','rc16-access-auto'].includes(obj.name);
 $('agentBudgetWrap').hidden=!['autonomous-agent','agent-loop-v2','auto-assess'].includes(obj.name);
 $('aiSettings').hidden=!(obj.ai||obj.name==='auto-assess'||obj.name==='scan');
 $('toolRC13Options').hidden=obj.name!=='rc13-assess';
 if($('toolRC15Options'))$('toolRC15Options').hidden=obj.name!=='rc15-scan';
 // Offline tools never inherit active-network state from the previous tool.
 const offline=!obj.active;
 if($('injectionDrawer'))$('injectionDrawer').hidden=obj.name!=='injection-assess';
 $('execute').checked=offline?false:$('execute').checked;
 $('execute').disabled=offline;
 $('execute').closest('label').hidden=offline;
 $('toolAck').closest('label').hidden=offline;
 $('toolWrites').closest('label').hidden=offline;
 $('toolDry').hidden=offline;
 $('runTool').textContent=offline?'Esegui analisi offline': 'Avvia verifica selezionata';
 $('modeExplanation').textContent=offline
   ?'MODALITÀ OFFLINE: il controllo non contatta l’API. Non servono conferme di rete.'
   :'MODALITÀ DI RETE DISPONIBILE: prepara scope e autorizzazione. Per iniziare puoi usare il piano senza traffico.';
$('toolName').textContent=displayTaskName(obj.name);$('toolInfo').textContent=obj.help?.purpose||explanations[obj.name]||`Strumento ${obj.category}: consulta l’output per controlli e risultati.`;
 const prior=$('previousJob')?.closest('.toolinfo');
 if(prior)prior.hidden=!['both','report','report-config','config-report'].includes(obj.requirements);
 const aiMandatory=['ai-correlate','ai-analyze'].includes(obj.name);
 if(aiMandatory){$('modeExplanation').textContent='Questo strumento usa SEMPRE Ollama locale; controlla Stato Ollama e Modello. Non invia richieste alla API target.';}
 $('requirements').textContent=(obj.help?.requires||reqText[obj.requirements]||obj.requirements)+(obj.active?' · Può inviare richieste con conferma':' · Analisi offline')+(obj.writes?' · Modifica risorse di test e richiede cleanup':'');$('toolWrites').disabled=!(obj.writes||obj.name==='auto-assess'||obj.name==='rc15-scan');if($('toolWrites').disabled)$('toolWrites').checked=false;$('toolAI').disabled=!obj.ai;if(!obj.ai)$('toolAI').checked=false}
function filterTools(){const category=$('categorySelect').value;const current=$('toolSelect').value;const select=$('toolSelect');select.replaceChildren();for(const tool of catalog.filter(t=>!category||t.category===category)){const opt=document.createElement('option');opt.value=tool.name;opt.textContent=displayTaskName(tool.name);select.append(opt)}if([...select.options].some(x=>x.value===current))select.value=current;toolDetails()}
function secrets(){const entries={};for(const input of document.querySelectorAll('[data-secret]'))if(input.value)entries[input.dataset.secret]=input.value;return entries}
function currentConfig(execute){return {action:$('toolSelect').value,specification_id:specId||null,assessment_id:evidenceJob||null,config_id:configId||null,access_rules_id:matrixGeneratedConfigId||null,auth_config_id:authId||null,base_url:$('baseUrl').value.trim(),allow_host:$('allowHost').value.trim(),execute,acknowledgment:$('toolAck').checked,approve_writes:$('toolWrites').checked,max_requests:clampNumeric('maxRequests'),rate:clampNumeric('rate'),budget:clampNumeric('agentBudget'),profiles:$('profiles').value.split(',').map(x=>x.trim()).filter(Boolean),path_values:$('pathValues').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean),ai:$('toolAI').checked,model:$('ollamaModel').value.trim(),allow_insecure_http:$('insecure').checked,config_usage:$('configUsage').value,injection_families:[...document.querySelectorAll('#injectionFamilyOptions input:checked')].map(x=>x.value),rc15_callback_base:$('rc15ToolCallbackBase')?.value.trim()||null,rc15_callback_observer:$('rc15ToolObserver')?.value.trim()||null,rc15_fixture_file:$('rc15ToolFile')?.value.trim()||null,rc15_fixture_marker:$('rc15ToolMarker')?.value.trim()||null,rc15_callback_approved:!!$('rc15ToolCallbackAck')?.checked,rc15_approve_xml_oast:!!$('rc15ToolXMLAck')?.checked,expected_other: ['rc16-assess','rc16-access-auto'].includes($('toolSelect').value)?$('rc16ExpectedOther').value:'unknown',secrets:secrets()}}
async function run(execute){const obj=catalog.find(t=>t.name===$('toolSelect').value);if(!obj)throw Error('Seleziona uno strumento');execute=Boolean(execute&&obj.active);const params=currentConfig(execute);
 if(['access-matrix','verify-access-policy'].includes(obj.name)&&matrixGeneratedConfigId){params.config_id=matrixGeneratedConfigId;params.config_usage='context';}
 if(obj.name==='access-probe'&&matrixGeneratedConfigId&&matrixRules.length){const r=matrixRules[0];params.operation=r.operation;params.profiles=[r.owner,r.other];params.expected_owner=r.expected_owner||'allow';params.expected_other=r.expected_other;params.path_values=Object.entries(r.path_values||{}).map(([k,v])=>`${k}=${v}`);}
if(!execute)params.approve_writes=false;
 if(obj.name==='rc15-scan'){
   if(execute&&params.approve_writes&&(!configId||params.config_usage!=='rc15-security'))throw Error('Per le scritture degli scanner importa le fixture YAML, seleziona la configurazione degli scanner e approva le scritture.');
   if(execute&&(params.rc15_callback_base||params.rc15_callback_observer)&&!params.rc15_callback_approved)throw Error('Per le callback conferma esplicitamente il consenso SSRF/XXE.');
 }
 if(obj.name==='rc16-assess'&&(params.config_usage!=='multi-resource'||!configId))throw Error('I test delle risorse temporanee richiedono un resources.yaml multi-risorsa approvato. Prepara e valida il caso di prova.');
 if(obj.name==='rc13-assess'){
   const body=execute&&$('toolRC13Body').checked;
   if(body){requireBodyProbeFields();
    if(!params.approve_writes||!$('toolRC13BodyAck').checked)
     throw Error('Per le sonde PATCH devi autorizzare le scritture e confermare separatamente il consenso alle sonde.');}
   params.rc13_body_probes=body;
   params.rc13_body_fields=body?approvedBodyProbeFields():[];
   params.rc13_max_requests=Math.max(5,Math.min(1000,Number($('rc13Budget').value)||150));
 }
 if(['spec','both','spec-config'].includes(obj.requirements)&&!specId)throw Error('Passaggio 1: importa prima lo Swagger/OpenAPI');if(['spec-config','report-config','config:json','config-report'].includes(obj.requirements)&&!params.config_id)throw Error('Passaggio 4: importa il manifesto YAML/JSON richiesto');if(['report','both','report-config','config-report'].includes(obj.requirements)&&!evidenceJob)throw Error('Questo controllo analizza un risultato esistente. 1) Esegui auto-assess (attivo per correlazioni HTTP). 2) In “Analisi precedente”, seleziona il risultato completato. 3) Avvia questo controllo.');
 if(obj.name==='ai-correlate'){
  const prev=previousJobs.find(x=>x.id===evidenceJob);
  if(!prev||!['auto-assess','advanced-vuln-assess'].includes(prev.action||prev.mode)||!prev.active||!(prev.http_observations>0))throw Error('Per ai-correlate serve un auto-assess ATTIVO con osservazioni HTTP. Esegui auto-assess con “Esegui richieste HTTP”, attendi il completamento e seleziona quel job. Un piano offline non basta.');
 }if(execute&&(!params.acknowledgment||!params.base_url||!params.allow_host))throw Error('Per inviare richieste servono URL, hostname autorizzato e conferma dello scope');if(execute&&obj.writes&&!params.approve_writes)throw Error('Questo workflow modifica dati: spunta “Approvo esplicitamente le scritture” solo dopo aver controllato il manifest e il cleanup.');
 if(execute&&params.approve_writes&&params.action==='auto-assess'){
  const missing=[];
  if(!configId)missing.push('configurazione per creare e cancellare le risorse (segui «Crea un test di sicurezza» qui sopra)');
  if(!authId)missing.push('auth.yaml (passaggio 3)');
  if(!params.acknowledgment)missing.push('conferma dell’autorizzazione');
  if(!['multi-resource','workflow'].includes(params.config_usage))missing.push('tipo manifest multi-resource o workflow');
  if(missing.length)throw Error('Per eseguire anche POST/PATCH/DELETE manca: '+missing.join('; ')+'. Per sole GET togli la spunta “Approvo esplicitamente le scritture”.');
 }
const result=await request('/api/control/jobs',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(params)});show('Avviato '+displayTaskName(params.action)+' · ID '+result.id.slice(0,10)+' · controlla Risultati.');$('toolMessage').textContent='Job avviato: '+result.id;await refresh()}
// La suite possiede impostazioni/consensi propri: non dipende dai checkbox
// di un singolo strumento, che possono essere nascosti o disabilitati.
function suiteConfig(active){
 return {
  action:'auto-assess',specification_id:specId||null,assessment_id:null,
  config_id:configId||null,access_rules_id:matrixGeneratedConfigId||null,auth_config_id:authId||null,
  base_url:$('baseUrl').value.trim(),allow_host:$('allowHost').value.trim(),
  execute:Boolean(active),acknowledgment:Boolean(active&&$('suiteAck').checked),
  approve_writes:Boolean(active&&$('suiteWrites').checked&&$('suiteWritesAck').checked),
  max_requests:clampNumeric('maxRequests'),rate:clampNumeric('rate'),budget:clampNumeric('agentBudget'),
  profiles:$('profiles').value.split(',').map(x=>x.trim()).filter(Boolean),
  path_values:$('pathValues').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean),
  ai:$('suiteAI').checked,model:$('ollamaModel').value.trim(),
  allow_insecure_http:$('insecure').checked,config_usage:$('configUsage').value,
  injection_families:[...document.querySelectorAll('#injectionFamilyOptions input:checked')].map(x=>x.value),
  rc15_callback_base:active&&$('rc15CallbackAck').checked&&$('rc15CallbackObserver').value.trim()?$('rc15CallbackBase').value.trim()||null:null,rc15_callback_observer:active&&$('rc15CallbackAck').checked&&$('rc15CallbackBase').value.trim()?$('rc15CallbackObserver').value.trim()||null:null,rc15_callback_approved:!!(active&&$('rc15CallbackAck').checked&&$('rc15CallbackBase').value.trim()&&$('rc15CallbackObserver').value.trim()),expected_other:$('rc16ExpectedOther')?.value||'deny',secrets:secrets()
 };
}
function updateSuiteOptions(){
 const active=$('suiteActive').checked,writes=$('suiteWrites').checked;
 $('suiteAckWrap').hidden=!active;
 $('suiteWritesAckWrap').hidden=!active||!writes;
 const status=active?(writes?'Suite HTTP con scritture autorizzate: richiede anche auth.yaml, manifest e due conferme esplicite.':'Suite HTTP di lettura: richiede scope e conferma specifica qui sotto.'):'Suite offline: non contatta il target e non richiede autorizzazioni HTTP.';
 $('suiteModeDescription').textContent=status;
}
// Mostriamo il piano prima di avviare: nessuna richiesta HTTP al target.
async function previewSuite(){
 if(!specId)throw Error('Importa prima una specifica OpenAPI.');
 const active=$('suiteActive').checked, cfg=suiteConfig(active);
 const params=new URLSearchParams({auth_config_id:authId||'',config_id:configId||'',
  access_rules_id:matrixGeneratedConfigId||'',
  config_usage:cfg.config_usage,active:String(active),writes:String($('suiteWrites').checked),
  ai:String($('suiteAI').checked),base_url:cfg.base_url,allow_host:cfg.allow_host,
  authorized:String(cfg.acknowledgment),optional:String($('suiteOptional').checked),
  budget:String(Math.max(1,Math.min(600,Number($('suiteBudget').value)||300))),
  max_requests:String(cfg.max_requests)});
 const data=await request('/api/control/suite/preflight/'+encodeURIComponent(specId)+'?'+params.toString());
 const counts=data.summary;
 $('suitePreviewResult').textContent=`Preflight offline · ${counts.ready} pronti · ${counts.blocked} da configurare · ${counts.waiting_for_result} in attesa di risultati · ${counts.disabled} disabilitati · ${counts.not_applicable} non applicabili. Pronto NON significa verificato.`;
 const container=$('suitePreviewTasks');container.replaceChildren();
 const wrapper=document.createElement('details');wrapper.open=true;
 const heading=document.createElement('summary');heading.textContent='Mostra/nascondi '+data.tasks.length+' task del piano';wrapper.append(heading);
 for(const task of data.tasks){const line=document.createElement('div');line.className='job';
   const info=document.createElement('div');const name=document.createElement('strong');name.textContent=displayTaskName(task.action);
   const subtitle=document.createElement('div');subtitle.className='helper';subtitle.textContent=task.state+' · '+(window.AchillesPublicNames?.text(task.reason||task.network_mode)||task.reason||task.network_mode);
   info.append(name,subtitle);line.append(info);
   if(task.state==='blocked'||task.state==='waiting_for_result'){
    const guide=window.AchillesIssueGuide;
    if(guide){
     const helper=guide.card(task.reason||'Prerequisito mancante','suitePreviewResult');
     line.append(helper);
    }
   }
   wrapper.append(line)}
 if($('suiteRc13').checked){
  const line=document.createElement('div');line.className='job';
  const info=document.createElement('div');const name=document.createElement('strong');
  name.textContent='Analisi approfondita API · copertura, input e autorizzazioni';
  const subtitle=document.createElement('div');subtitle.className='helper';
  try{
   const rc13=await request('/api/control/rc13/plan',{method:'POST',
    headers:{'content-type':'application/json'},body:JSON.stringify(cfg)});
   subtitle.textContent='Piano dell’analisi approfondita disponibile · '+(rc13.catalog?.operations_total||0)+
    ' operazioni documentate · '+(active?'test HTTP solo con scope/consensi confermati':'solo offline')+
    ' · nessuna richiesta inviata durante il preflight';
  }catch(e){subtitle.textContent='Analisi approfondita da configurare · '+String(e.message).slice(0,240)}
  info.append(name,subtitle);line.append(info);wrapper.append(line);
  heading.textContent='Mostra/nascondi '+(data.tasks.length+1)+' controlli pianificati (compresa l’analisi approfondita)';
 }
 container.append(wrapper);
 // The preflight is read-only: show potential omissions without creating manifests.
 if(window.AchillesIssueGuide){
  const missing=[];
  if($('suiteRc13Body').checked&&!Object.keys(allApprovedBodyProbeFields(savedWorkflows.filter(w=>w.specId===specId).map(w=>w.configId))).length)
   missing.push({label:'Sonde JSON PATCH',message:'In Mass Assignment apri «Verifica campi JSON con sonde PATCH», scegli un workflow con cleanup e seleziona i campi. Se non lo fai, solo questa famiglia di test verrà esclusa.'});
  if($('suiteWrites').checked&&(!$('suiteWritesAck').checked||!authId||!$('suiteWorkflowSelect').value))
   missing.push({label:'Workflow con scritture',message:'Prepara e salva una risorsa temporanea con cleanup, importa auth.yaml al Passaggio 3 e autorizza le scritture nella Suite completa. Gli altri test possono partire.'});
  window.AchillesIssueGuide.renderList(missing,'suitePreviewResult');
 }
}

// L'arresto è cooperativo: non si uccide un task mentre completa il cleanup.
async function stopSuite(){
 const id=$('suiteStop').dataset.suiteId;
 if(!id)throw Error('Nessuna suite attiva.');
 const result=await request('/api/control/suite/'+encodeURIComponent(id)+'/stop',
  {method:'POST',headers:{'content-type':'application/json'},body:'{}'});
 $('suiteStatus').textContent=result.message;
 $('suiteStop').disabled=true;
 await refresh();
}
// Selezione esplicita dei campi: derivata dallo Swagger e dalle mutazioni
// delle risorse temporanee già approvate, non da file YAML aggiuntivi.
let bodyProbeFields=[];
let bodyProbeSource='';
// Per-spec/per-manifest approval; switching the select never discards another selection.
const bodyProbeSelections=new Map();
const bodyProbeDiscovered=new Map();
function allApprovedBodyProbeFields(ids){
 const result={};
 for(const id of ids){const chosen=bodyProbeSelections.get(specId+'|'+id)||[];if(chosen.length)result[id]=chosen.slice(0,4);}
 return result;
}
function renderBodyProbeCoverage(){
 const target=$('bodyProbeCoverage');if(!target)return;target.replaceChildren();
 const workflows=savedWorkflows.filter(w=>w.specId===specId);
 if(!workflows.length){target.textContent='Nessun caso temporaneo salvato: crea e approva prima una risorsa con cleanup.';return;}
 const total=workflows.filter(w=>(bodyProbeSelections.get(specId+'|'+w.configId)||[]).length).length;
 const summary=document.createElement('strong');summary.textContent=total+' di '+workflows.length+' workflow con campi PATCH approvati';target.append(summary);
 for(const [index,w] of savedWorkflows.entries()){
  if(w.specId!==specId)continue;
  const row=document.createElement('div');row.className='body-probe-coverage-row';
  const chosen=bodyProbeSelections.get(specId+'|'+w.configId)||[];
  const caption=document.createElement('span');caption.textContent=(w.label||w.name||'Workflow '+(index+1))+' · '+(chosen.length?chosen.length+' campi approvati':'nessun campo approvato');
  const jump=document.createElement('button');jump.type='button';jump.className='secondary';jump.textContent='Configura';
  jump.onclick=()=>{const select=$('bodyProbeWorkflowSelect');select.value=String(index);select.dispatchEvent(new Event('change'));$('bodyProbeWizard').open=true;};
  row.append(caption,jump);target.append(row);
 }
}

let bodyProbeLifecycleBudget=0;
let bodyProbeRules=0;
let bodyProbeAvailable=[];
async function detectBodyProbeFields(){
 if(!specId)throw Error('Carica prima lo Swagger al passaggio 1.');
 const wf=await scopedWorkflowConfig('bodyProbeWorkflowSelect');
 const key=specId+'|'+wf.configId;
 const data=await request('/api/control/rc13/body-fields',{method:'POST',
  headers:{'content-type':'application/json'},body:JSON.stringify({...suiteConfig(false),config_id:wf.configId,config_usage:'multi-resource'})});
 const target=$('bodyProbeOptions');target.replaceChildren();
 if(bodyProbeSource!==key){bodyProbeSource=key;bodyProbeFields=(bodyProbeSelections.get(key)||[]).slice();}
 bodyProbeDiscovered.set(key,(data.fields||[]).map(f=>f.key));
 bodyProbeLifecycleBudget=Number(data.workflow_request_budget)||0;
 bodyProbeRules=Number(data.authorization_rule_count)||0;
 const available=(data.fields||[]);
 bodyProbeAvailable=available;
 if(!available.length){const line=document.createElement('p');line.textContent=data.message||'Nessun campo JSON PATCH idoneo.';target.append(line);
  for(const reason of data.diagnostics||[]){const item=document.createElement('p');item.className='helper';item.textContent='• '+reason;target.append(item);}}
 for(const field of available){
  const label=document.createElement('label');label.className='check';
  const input=document.createElement('input');input.type='checkbox';input.value=field.key;
  input.checked=bodyProbeFields.includes(field.key);
  input.onchange=()=>{if(input.checked){if(bodyProbeFields.length>=4){input.checked=false;return show('Al massimo quattro campi per campagna.',true,'bodyProbeHint');}bodyProbeFields.push(field.key);}
   else bodyProbeFields=bodyProbeFields.filter(x=>x!==field.key);
   bodyProbeSelections.set(key,bodyProbeFields.slice());
   renderBodyProbeCoverage();
   $('rc13Body').checked=false;
   $('rc13BodyAck').checked=false;
   updateBodyProbeBudget();
  };
  const source=field.source==='openapi_marker'?' · ⚠ campo marker: ripristino verificato obbligatorio'
   :field.source==='openapi'?' · suggerito dallo Swagger (PATCH temporanea guidata)':' · già configurato';
  label.append(input,document.createTextNode(' '+field.resource+' · '+field.operation+' · '+field.field+source));
  const help=document.createElement('small');help.className='helper';help.textContent=field.reason||'';label.append(help);target.append(label);
 }
 $('bodyProbeHint').textContent=data.message+' Nessuna richiesta HTTP inviata.';
 renderBodyProbeCoverage();updateBodyProbeBudget();
}
function updateBodyProbeBudget(){
 const count=approvedBodyProbeFields().length;
 if(!count)return;
 // POST, GET, PATCH, DELETE and confirmed cleanup are already budgeted per fixture.
 // Each chosen field uses two payloads and an independent full fixture.
 // Schema-derived fields add a temporary PATCH (three calls); a marker-field
 // PATCH needs two more calls to restore and confirm the original marker.
 const probes=approvedBodyProbeFields().reduce((total,key)=>{
  const option=bodyProbeAvailable.find(field=>field.key===key);
  const extra=option?.source==='manifest'?0:3+(option?.restore_marker?2:0);
  return total+2*(bodyProbeLifecycleBudget+extra);
 },0);
 const minimum=bodyProbeLifecycleBudget+probes+2*bodyProbeRules+5;
 const standalone=$('rc13Budget'),suite=$('suiteRc13Budget');
 if(minimum<=1000)standalone.value=String(Math.max(Number(standalone.value)||150,minimum));
 if(minimum<=300)suite.value=String(Math.max(Number(suite.value)||100,minimum));
 $('bodyProbeHint').textContent=`${count} campi selezionati · budget stimato almeno ${minimum} richieste (incluso cleanup). `+
   (minimum>300?'Per la suite il budget massimo è 300: riduci i campi o suddividi la campagna. ':'')+
   'Conferma le autorizzazioni nella sezione Analisi approfondita o nella Suite completa. Nessun test avviato.';
}
function approvedBodyProbeFields(){
 const idx=$('bodyProbeWorkflowSelect').value;const wf=idx===''?null:savedWorkflows[Number(idx)];if(!wf)return [];
 return (bodyProbeSelections.get(specId+'|'+wf.configId)||[]).slice();
}
function requireBodyProbeFields(){
 if($('configUsage').value==='workflow')return; // Legacy workflows.yaml has explicitly reviewed restricted_fields; backend validates cases.
 if(!approvedBodyProbeFields().length)throw Error('Sonde JSON PATCH non pronte. Mass Assignment → apri «Verifica campi JSON con sonde PATCH» → scegli un workflow salvato → «Aggiorna i campi rilevati» → seleziona i campi. Se la lista dei workflow è vuota, vai in «Prepara risorse temporanee» e salva una fixture con DELETE di cleanup. Non serve caricare workflows.yaml.');
}
function rc13Request(active){
 const config=suiteConfig(active);
 config.acknowledgment=active&&$('rc13Ack').checked;
 config.approve_writes=active&&$('rc13Writes').checked&&$('rc13WriteAck').checked;
 return {config,active,writes:active&&$('rc13Writes').checked,
   body_probes:active&&$('rc13Body').checked&&$('rc13BodyAck').checked,
   body_probe_fields:active&&$('rc13Body').checked?approvedBodyProbeFields():[],
   ai:$('rc13AI').checked||$('rc17Agent').checked,
   agent_followups:active&&$('rc17Agent').checked,
   agent_rounds:Math.max(1,Math.min(3,Number($('rc17Rounds').value)||2)),
   agent_budget:Math.max(2,Math.min(60,Number($('rc17Budget').value)||24)),
   max_requests:Math.max(5,Math.min(1000,Number($('rc13Budget').value)||150)),
   rc15_callback_base:$('rc15CallbackBase').value.trim()||null,
   rc15_callback_observer:$('rc15CallbackObserver').value.trim()||null,
   rc15_fixture_file:$('rc15FixtureFile').value.trim()||null,
   rc15_fixture_marker:$('rc15FixtureMarker').value.trim()||null,
   rc15_callback_approved:$('rc15CallbackAck').checked};
}
async function planRC13(){
 if(!specId)throw Error('Carica prima lo Swagger/OpenAPI.');
 const scoped=$('rc13WorkflowSelect').value!==''?await scopedWorkflowConfig('rc13WorkflowSelect'):null;
 const data=await request('/api/control/rc13/plan',{method:'POST',
  headers:{'content-type':'application/json'},body:JSON.stringify({...suiteConfig(false),config_id:scoped?.configId||null,config_usage:'multi-resource'})});
 const types=data.test_types||{}, catalog=data.catalog||{};
 const rows=[`API: ${data.api_name||'OpenAPI'}`,
  `Operazioni documentate: ${catalog.operations_total||0} · Piano offline, 0 richieste HTTP`,
  `Sonde JSON PATCH: ${approvedBodyProbeFields().length} campi scelti nel wizard, richiedono consenso alle scritture e alle sonde`,
  ...Object.entries(types).map(([name,info])=>`${name}: ${info.available?'disponibile':'richiede configurazione'}${info.cases!==undefined?' · '+info.cases+' casi':''}`)];
 $('rc13PlanSummary').replaceChildren(...rows.map(text=>{const div=document.createElement('div');div.className='helper';div.textContent=text;return div}));
 $('rc13Status').textContent='Piano dell’analisi approfondita pronto. Nessuna verifica HTTP eseguita.';
}
async function runRC13(){
 if(!specId)throw Error('Carica prima lo Swagger/OpenAPI.');
 const active=$('rc13Active').checked;
 const payload=rc13Request(active);payload.config.config_id=null;payload.config.config_usage='multi-resource';
 if($('rc13WorkflowSelect').value!==''){const workflow=await scopedWorkflowConfig('rc13WorkflowSelect');payload.config.config_id=workflow.configId;payload.config.config_usage='multi-resource';}
 if(!active&&($('rc13Writes').checked||$('rc13Body').checked))throw Error('Per i test con scritture abilita prima le verifiche HTTP.');
 if(active&&(!payload.config.acknowledgment||!payload.config.base_url||!payload.config.allow_host))throw Error('Conferma l’autorizzazione e compila Base URL e host autorizzato.');
 if(payload.writes&&!payload.config.config_id)throw Error('Scegli il workflow da testare nella sezione Analisi approfondita.');
 if(payload.writes&&!payload.config.approve_writes)throw Error('Approva esplicitamente le scritture sulle risorse temporanee.');
 if($('rc13Body').checked&&!($('rc13BodyAck').checked&&payload.writes))throw Error('Le sonde JSON richiedono il consenso dedicato e le scritture approvate.');
 if(payload.agent_followups&&(!active||!payload.ai))throw Error('I follow-up AI richiedono una scansione HTTP autorizzata e il modello Ollama locale.');
 if(payload.body_probes){requireBodyProbeFields();if($('rc13WorkflowSelect').value==='__all__')throw Error('Le sonde JSON PATCH richiedono un singolo workflow: selezionalo qui.');const wf=await scopedWorkflowConfig('rc13WorkflowSelect');if(bodyProbeSource!==specId+'|'+wf.configId)throw Error('Per i test PATCH scegli lo stesso workflow configurato nelle sonde JSON PATCH.');}
 if(payload.rc15_callback_base||payload.rc15_callback_observer){
  if(!active||!payload.rc15_callback_approved||!payload.rc15_callback_base||!payload.rc15_callback_observer)
   throw Error('Per SSRF inserisci callback URL, observer locale e autorizzazione alle callback con i test HTTP attivi.');
 }
 if(Boolean(payload.rc15_fixture_file)!==Boolean(payload.rc15_fixture_marker))
  throw Error('La fixture traversal richiede sia il nome *.txt sia il marker ACHILLES_FIXTURE_*.');
 const data=await request('/api/control/rc13/run',{method:'POST',
  headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
 $('rc13Status').textContent=`Analisi approfondita avviata · job ${data.id.slice(0,12)}. Risultati e suggerimenti AI nella sezione «Dossier AI» del job.`;
 $('rc13OpenAI').disabled=false;
 $('rc13OpenAI').onclick=()=>window.open('/job/'+encodeURIComponent(data.id)+'/ai','_blank','noopener,noreferrer');
 await refresh();
}
// A single optional test must never prevent the approved remainder of a suite.
// Unsafe operations are ALWAYS omitted, never authorized automatically.
async function prepareSuiteLaunch(){
 if(!specId)throw Error('Passaggio 1: carica una specifica OpenAPI prima di avviare la suite.');
 const skipped=[];
 const skip=(label,message,section='fullSuite',kind='action')=>skipped.push({label,message,section,kind});
 let include_active=$('suiteActive').checked;
 if(include_active&&(!$('baseUrl').value.trim()||!$('allowHost').value.trim()||!$('suiteAck').checked)){
  throw Error('Per avviare tutti i test HTTP: al Passaggio 2 inserisci Base URL e host autorizzato; in Suite completa conferma lo scope. Per eseguire intenzionalmente un piano offline, disattiva «Esegui verifiche HTTP sul target».');
 }
 if(include_active && $('rc15CallbackAck').checked &&
    (!$('rc15CallbackBase').value.trim() || !$('rc15CallbackObserver').value.trim())){
   skip('Callback SSRF/XXE','Apri «Callback SSRF/XXE · server locale», avvia il collector e compila entrambe le URL. Senza due URL non verranno eseguite le callback.','securityScannerOptionsSection');
 }
 if(include_active && !$('rc15CallbackAck').checked &&
     ($('rc15CallbackBase').value.trim() || $('rc15CallbackObserver').value.trim())){
   skip('Callback SSRF/XXE','Configura «Callback SSRF/XXE» e conferma il consenso dedicato, oppure esegui i restanti scanner senza callback.','securityScannerOptionsSection');
 }
 const params=suiteConfig(include_active);
 params.config_id=null;
 params.config_usage='multi-resource';
 let include_writes=Boolean($('suiteWrites').checked);
 let workflow_config_ids=[];
 if(include_writes&&!include_active){
  include_writes=false;
  skip('Scritture non eseguite','Passaggio 2: compila URL e host, poi conferma lo scope HTTP in «Suite completa».');
 }
 if(include_writes&&!authId){
  include_writes=false;
  skip('Scritture non eseguite','Passaggio 3: importa auth.yaml con le identità di test.');
 }
 if(include_writes&&!$('suiteWritesAck').checked){
  include_writes=false;
  skip('Scritture non eseguite','Suite completa: approva esplicitamente POST/PATCH/DELETE e la pulizia delle fixture.');
 }
 if(include_writes){
  // Never restrict BFLA/BOPLA to the workflow selected in a different panel.
  // Each approved, saved manifest is executed separately with its own cleanup.
  const all=savedWorkflows.filter(w=>w.specId===specId);
  // A POST endpoint is NOT itself a disposable workflow. Only proposals with
  // POST + GET-by-ID + DELETE can safely become managed temporary fixtures.
  // Incomplete operations remain in the inventory rather than masquerading as
  // ready-to-configure workflows or blocking otherwise authorized campaigns.
  const savedCandidateIndexes=new Set(all.map(w=>w.candidateIndex).filter(Number.isInteger));
  const pendingLifecycles=manifestCandidates.map((candidate,index)=>({candidate,index}))
    .filter(({candidate,index})=>candidate.ready && candidate.create && candidate.read && candidate.delete
                             && !savedCandidateIndexes.has(index));
  if(pendingLifecycles.length){
   const examples=pendingLifecycles.slice(0,4).map(({candidate})=>candidate.create).join(', ');
   skip('Risorse temporanee senza dati di prova',
    pendingLifecycles.length+' cicli di creazione/lettura/cancellazione hanno bisogno di dati di prova approvati ('+examples+'). Le verifiche di lettura e i workflow già autorizzati partono comunque.',
    'workflowCreateSection');
  }
  const nonDisposable=manifestCandidates.filter(candidate=>
      candidate.create && (!candidate.ready || !candidate.read || !candidate.delete));
  if(nonDisposable.length){
   const examples=nonDisposable.slice(0,4).map(candidate=>candidate.create).join(', ');
   skip('Operazioni di scrittura senza cleanup sicuro',
     nonDisposable.length+' operazioni non costituiscono workflow temporanei completi ('+examples+'). Nessun invio POST viene eseguito senza una procedura di recupero e un caso di test approvati. Sono presenti nella copertura, non sono falsi workflow da configurare.',
     'autoconfigPanel','information');
  }
  const imported=(configId&&$('configUsage').value==='multi-resource')?[configId]:[];
  workflow_config_ids=[...new Set([...all.map(w=>w.configId),...imported].filter(Boolean))];
  if(workflow_config_ids.length>20){
   include_writes=false;workflow_config_ids=[];
   skip('Limite casi di prova','La campagna accetta 20 manifest approvati per volta. Suddividi l’elenco in più campagne, senza ignorare silenziosamente gli altri.','workflowManageSection');
  }else if(!workflow_config_ids.length){
   include_writes=false;
   skip('Nessuna risorsa temporanea approvata','Per eseguire test che creano o modificano dati è necessario un caso di prova verificabile, completo di eliminazione finale. La suite esegue comunque tutti i test senza scritture per i quali hai dato il consenso.','workflowCreateSection');
  }else{
   params.config_id=workflow_config_ids[0];
   params.config_usage='multi-resource';
  }
 }
 if(!include_writes){params.config_id=null;params.approve_writes=false;}
 // PATCH is an active write probe and cannot be implicitly enabled for the
 // complete set of manifests just because a single panel approved one field.
 let rc13_body_probes=Boolean($('suiteRc13Body').checked);
 let rc13_body_fields=[];
 const rc13_body_fields_by_workflow=allApprovedBodyProbeFields(workflow_config_ids);
 if(rc13_body_probes){
  if(!$('suiteRc13').checked||!include_writes){
   rc13_body_probes=false;
   skip('Sonde PATCH non avviate','Richiedono analisi approfondita, identità, cleanup approvato e consenso alle scritture. Gli altri controlli continuano.','massAssignmentPanel');
  }else if(!Object.keys(rc13_body_fields_by_workflow).length){
   rc13_body_probes=false;
   skip('Sonde PATCH non avviate','Seleziona e approva almeno un campo PATCH in «Mass Assignment». Le selezioni ora rimangono salvate per ogni workflow.','massAssignmentPanel');
  }else{
   const missing=workflow_config_ids.filter(id=>!rc13_body_fields_by_workflow[id]);
   if(missing.length)skip('Copertura PATCH parziale',missing.length+' workflow senza campi PATCH approvati: gli altri workflow configurati vengono eseguiti. Apri Mass Assignment per aggiungere gli altri.','massAssignmentPanel','information');
   rc13_body_fields=Object.values(rc13_body_fields_by_workflow)[0].slice();
  }
 }
 let rc17_agent_followups=$('suiteRc17Agent').checked;
 if(rc17_agent_followups && (!include_active||!$('suiteAI').checked||!$('suiteRc13').checked)){
  rc17_agent_followups=false;
  skip('Follow-up agente AI','Nella Suite completa servono verifiche HTTP attive, Analisi approfondita e Ollama locale. Disattiva il follow-up AI se non ti serve.');
 }
 if(rc17_agent_followups){
  const rcBudget=Math.max(5,Math.min(300,Number($('suiteRc13Budget').value)||100));
  if(rcBudget<29){
   rc17_agent_followups=false;
   skip('Follow-up agente AI','Aumenta il budget dell’analisi approfondita nella Suite completa: deve coprire almeno 24 richieste AI e 5 richieste di controllo.');
  }else{
   try{
    const ai=await request('/api/control/services');
    if(ai.ollama!=='online'||(Array.isArray(ai.ollama_models)&&!ai.ollama_models.includes(params.model))){
     rc17_agent_followups=false;
     skip('Follow-up agente AI','Nella sezione «Agente AI locale» avvia Ollama e scegli un modello già installato. La suite può eseguire i test non-AI senza attendere Ollama.');
    }
   }catch(error){
    rc17_agent_followups=false;
    skip('Follow-up agente AI','Il servizio Ollama non è verificabile: controlla il modello locale nella sezione Agente AI. Altri test restano disponibili.');
   }
  }
 }
 return {params,skipped,include_active,include_writes,workflow_config_ids,rc13_body_probes,rc13_body_fields,rc13_body_fields_by_workflow,rc17_agent_followups};
}
async function runSuite(){
 const ready=await prepareSuiteLaunch();
 const {params,skipped,include_active,include_writes,rc13_body_probes,rc13_body_fields,rc17_agent_followups}=ready;
 // Extra approvals remain mandatory on the backend; no checkbox is changed here.
 const payload={config:params,workflow_config_ids:ready.workflow_config_ids||[],include_active,include_writes,include_rc13:$('suiteRc13').checked,
  rc17_agent_followups,rc17_agent_rounds:2,rc17_agent_budget:24,
  rc13_body_probes,rc13_body_fields,rc13_body_fields_by_workflow:ready.rc13_body_fields_by_workflow,
  rc13_max_requests:Math.max(5,Math.min(300,Number($('suiteRc13Budget').value)||100)),
  include_ai:$('suiteAI').checked,include_optional:$('suiteOptional').checked,
  max_total_requests:Math.max(1,Math.min(600,parseInt($('suiteBudget').value,10)||300)),
  max_runtime_seconds:60*Math.max(1,Math.min(120,parseInt($('suiteRuntime').value,10)||30))};
 const result=await request('/api/control/suite',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
 $('suiteStop').dataset.suiteId=result.id;$('suiteStop').disabled=false;
 const mode=include_active?(include_writes?'HTTP con workflow di scrittura':'HTTP di sola lettura'):'offline';
 show('Suite avviata · modalità '+mode+' · '+(result.display_name||result.id.slice(0,12))+' · '+result.total+' funzionalità considerate.',false,'suiteStatus');
 $('suiteExecutionNotice').textContent=skipped.length
  ? skipped.length+' note sulla copertura: i controlli configurati e autorizzati sono stati inoltrati, gli altri sono distinguibili per motivo e azione. Nessuna richiesta non approvata viene inviata.'
  : 'Tutti i gruppi di test esplicitamente selezionati sono stati inoltrati all’orchestratore; consulta i risultati per il dettaglio dei task.';
 window.AchillesIssueGuide?.renderList(skipped,'suiteStatus');
 await refresh();
}

function explainJobError(raw){
 const e=window.AchillesPublicNames?.text(raw)||String(raw||'');const lower=e.toLowerCase();
 if(lower.includes('environment variable')||lower.includes('required by profile'))return 'Credenziale mancante: controlla auth.yaml e compila tutti i token/password richiesti nel Passaggio 3. Dettaglio: '+e.slice(-280);
 if(lower.includes('scope')||lower.includes('allow-host')||lower.includes('outside approved'))return 'Target fuori scope: verifica Base URL e Host autorizzato al Passaggio 2. '+e.slice(-180);
 if(lower.includes('budget')||lower.includes('max-requests'))return 'Budget HTTP insufficiente nella campagna corrente: il limite include tutte le richieste già inviate. Apri «Suite completa → Budget complessivo» e avvia una NUOVA campagna con budget adeguato; il retry non può recuperare il credito consumato. '+e.slice(-180);
 if(lower.includes('cleanup')||lower.includes('marker'))return 'Non è stato possibile verificare con sicurezza la risorsa temporanea: controlla il manifest e il report per l’eventuale cleanup manuale. '+e.slice(-230);
 if(lower.includes('connection refused')||lower.includes('connecterror'))return 'API non raggiungibile: assicurati che il laboratorio/target sia avviato e che l’URL sia corretto. '+e.slice(-160);
 if(lower.includes('yaml')||lower.includes('manifest'))return 'Configurazione del test non valida: segui la procedura guidata per ricrearla oppure apri le opzioni avanzate. '+e.slice(-240);
 if(lower.includes('assessment needs an openapi-derived plan'))return 'Questo strumento richiede il piano OpenAPI. Genera prima un piano con auto-assess (anche offline), oppure aggiorna la versione del framework. '+e.slice(-180);
 if(lower.includes('no_supported_actions')||lower.includes('no_supported_candidate'))return 'Nessuna anomalia GET riproducibile da approfondire nei risultati selezionati. È un esito normale: controlla coverage-report e usa next-actions per scoprire gli endpoint non ancora testati.';
 if(lower.includes('no such option: --ai'))return 'Incompatibilità di opzioni AI tra dashboard e CLI. Controlla la versione installata della dashboard. '+e.slice(-180);
 if(lower.includes('expecting value')||lower.includes('jsondecodeerror'))return 'Il file delle evidenze o la risposta del modello non è JSON valido. Per ai-correlate scegli come analisi precedente un auto-assess ATTIVO completato, non auth.yaml o resources.yaml. '+e.slice(-180);
 if(lower.includes('local model did not return')||lower.includes('invalid json')||lower.includes('response has no message')||lower.includes('risposta vuota'))return 'Ollama è raggiungibile ma non ha restituito JSON utilizzabile. Controlla il modello selezionato e riprova. '+e.slice(-220);
 if(lower.includes('ollama')||lower.includes('model'))return 'Problema con Ollama locale: avvia il servizio, verifica il nome del modello e usa “Aggiorna stato”. '+e.slice(-220);
 return 'Lo strumento ha terminato con errore. Verifica i parametri e le evidenze del job. Dettaglio: '+e.slice(-350);
}
async function refresh(){
 try{
  const jobs=await request('/api/jobs');previousJobs=jobs.filter(j=>j.status==='complete'&&j.action!=='full-suite');updatePreviousJobs();
  const box=$('jobsList');box.replaceChildren();if(!jobs.length){box.textContent='Nessun job presente.';return}
  const runningSuite=jobs.find(j=>j.action==='full-suite'&&j.status==='orchestrating'&&!j.stop_requested);
  $('suiteStop').disabled=!runningSuite;
  if(runningSuite)$('suiteStop').dataset.suiteId=runningSuite.id;
  const parents=jobs.filter(j=>j.action==='full-suite');const bySuite=new Map();for(const j of jobs){if(j.suite_id){if(!bySuite.has(j.suite_id))bySuite.set(j.suite_id,[]);bySuite.get(j.suite_id).push(j)}}
  function addJob(job,into){const row=document.createElement('div');row.className='job';const title=document.createElement('div');const b=document.createElement('b');b.textContent=job.action==='full-suite'?(job.display_name||'Suite · '+job.id.slice(0,12)):displayTaskName(job.action||job.mode);const status=document.createElement('div');status.textContent=job.action==='full-suite'?`${job.status} · ${job.completed_steps||0}/${job.total||0} funzioni · ${displayTaskName(job.current_step||'conclusa')}`:`${job.status} · ${job.id.slice(0,8)}`;status.className='helper';title.append(b,status);if(job.error){const error=document.createElement('small');const explanation=explainJobError(job.error);
  error.textContent=explanation;title.append(error);
  if(window.AchillesIssueGuide)title.append(window.AchillesIssueGuide.card(explanation,'globalMessage'));
 }row.append(title);if(job.action==='full-suite'||job.status==='complete'){const btn=document.createElement('button');btn.textContent=job.action==='full-suite'?'Apri suite interattiva in nuova scheda':'Esplora in nuova scheda';btn.onclick=()=>window.open('/job/'+encodeURIComponent(job.id),'_blank','noopener,noreferrer');row.append(btn)}if(job.action==='full-suite'){const ai=document.createElement('button');ai.textContent='Dossier AI (nuova scheda)';ai.onclick=()=>window.open('/job/'+encodeURIComponent(job.id)+'/ai','_blank','noopener,noreferrer');row.append(ai)}if(job.status==='complete'&&job.action!=='full-suite'){const select=document.createElement('button');select.textContent='Seleziona per export';select.onclick=()=>viewJob(job.id);row.append(select)}into.append(row)}
  for(const parent of [...parents].reverse()){
   const group=document.createElement('details');group.className='suite-job-group';const summary=document.createElement('summary');summary.textContent=(parent.display_name||'Suite · '+parent.id.slice(0,12))+' · '+parent.status+' · '+(parent.completed_steps||0)+'/'+(parent.total||0)+' task';group.append(summary);
   addJob(parent,group);
   const children=bySuite.get(parent.id)||[];
   const details=document.createElement('details');details.className='suite-children';const label=document.createElement('summary');label.textContent='Mostra/nascondi tutti i '+children.length+' job figli';details.append(label);for(const item of [...children].reverse())addJob(item,details);group.append(details);box.append(group)
  }
  for(const item of [...jobs].reverse().filter(j=>j.action!=='full-suite'&&!j.suite_id))addJob(item,box)
 }catch(e){show(e.message,true)}
}

function updatePreviousJobs(){
 const select=$('previousJob');if(!select)return;
 const current=evidenceJob;select.replaceChildren();
 const none=document.createElement('option');none.value='';none.textContent='Seleziona il risultato da usare come EVIDENZA (non il report da visualizzare)';select.append(none);
 for(const job of [...previousJobs].reverse().filter(j=>!specId||j.specification_id===specId)){
   const opt=document.createElement('option');opt.value=job.id;
   opt.textContent=displayTaskName(job.action||job.mode)+' · '+job.id.slice(0,8)+(job.http_observations>0?' · '+job.http_observations+' risposte HTTP':job.active?' · nessuna osservazione HTTP':' · offline');select.append(opt);
 }
 const matching=previousJobs.filter(j=>!specId||j.specification_id===specId);
 if(matching.some(j=>j.id===current))select.value=current;
 else {evidenceJob='';const latest=[...matching].reverse().find(j=>j.active&&j.action==='auto-assess'&&j.http_observations>0);
   if(latest){evidenceJob=latest.id;select.value=latest.id;}}

}
function openExport(kind){
 if(!selectedJob)return show('Prima scegli un job completato nel Passaggio 5.',true);
 const path='/api/export/'+encodeURIComponent(selectedJob)+'/'+encodeURIComponent(kind);
 const tab=window.open(path,'_blank','noopener,noreferrer');
 if(!tab)show('Il browser ha bloccato la nuova scheda. Consenti i popup locali per 127.0.0.1:8766.',true);
}
function resultExplanation(result){
 const lines=[];
 const observed=result?.execution_report?.observations||[];
 const count=Number(result?.requests_sent??result?.execution_report?.requests_sent??0);
 const actionable=result?.actions||result?.proposed_actions||[];
 if(result?.execution_report||result?.requests_sent!==undefined)lines.push('Richieste al target: '+count+'.');
 if(Array.isArray(observed))lines.push('Osservazioni HTTP salvate: '+observed.filter(x=>x&&typeof x.status==='number').length+'.');
 if(result?.engine==='agent-v2-v0.37'||result?.engine==='deterministic-agent-v0.34'){
   const executable=actionable.filter(x=>x.action==='authorized_get_candidate'||x.operation&&x.reason==='recheck_server_error').length;
   lines.push('Agente: '+executable+' candidate GET verificabili; '+actionable.length+' azioni/proposte totali.');
   if(!executable)lines.push('Nessuna anomalia GET supportata da ripetere con le evidenze attuali. Non significa che la API sia sicura.');
 }
 if(result?.interpretation)lines.push(result.interpretation);
 if(result?.next_step)lines.push('Passo successivo: '+result.next_step);
 if(result?.http_observations_available!==undefined)lines.push('Risposte HTTP disponibili per prioritizzazione: '+result.http_observations_available+'.');
 if(result?.coverage_next_steps?.length)lines.push('Altre verifiche non coperte: '+result.coverage_next_steps.slice(0,5).map(x=>x.operation).join(', ')+'.');
 if(result?.ai_correlation)lines.push('AI locale: correlazione consultiva completata. Non conferma vulnerabilità.');
 if(result?.ai_advisory||result?.local_ai_advice)lines.push('AI locale: suggerimenti consultivi disponibili nei dettagli tecnici.');
 if(result?.stop_reason)lines.push('Motivo arresto: '+(result.stop_reason==='no_supported_candidate'||result.stop_reason==='no_supported_actions'?'nessuna GET anomala ripetibile con questo report':result.stop_reason)+'.');
 if(!lines.length)lines.push('Analisi offline completata. Esamina i dettagli tecnici e le operazioni che richiedono dati aggiuntivi.');
 return lines.join('\n');
}
async function viewJob(id){selectedJob=id;try{const result=await request('/api/results/'+id);$('reportName').textContent=id.slice(0,10);$('resultSummary').textContent=resultExplanation(result);$('reportPreview').textContent=JSON.stringify(result,null,2).slice(0,55000);show('Risultato caricato. Il riepilogo spiega le verifiche eseguite e i passaggi successivi.')}catch(e){show(e.message,true)}}
function ollamaMessage(message,isError=false){show(message,isError,'ollamaActionMessage')}
let ollamaLastStatus=null;
async function statusAI(){
 try{
  const state=await request('/api/control/services');ollamaLastStatus=state;
  const online=state.ollama==='online',models=state.ollama_models||[],picker=$('ollamaModelPicker');
  $('ollamaStatusBadge').dataset.state=online?'online':'offline';
  $('ollamaStatus').textContent=online?'Attivo':state.ollama_managed?'In avvio':'Non raggiungibile';
  $('ollamaDetail').textContent=state.ollama_message||'Servizio locale 127.0.0.1:11434';
  $('modelList').textContent=models.length?models.join(' · '):'Nessun modello rilevato';
  $('ollamaLoadedModels').textContent=(state.ollama_loaded_models||[]).length?'Modelli attualmente in memoria: '+state.ollama_loaded_models.join(', '):'';
  const old=$('ollamaModel').value.trim();
  picker.replaceChildren();
  if(models.length){
   for(const model of models){const opt=document.createElement('option');opt.value=model;opt.textContent=model;picker.append(opt)}
   const preferred=models.includes(old)?old:(models.includes('achilles-local:latest')?'achilles-local:latest':models.includes('qwen3:8b')?'qwen3:8b':models[0]);
   picker.value=preferred;
   if(!models.includes(old))$('ollamaModel').value=preferred;
  }else{const opt=document.createElement('option');opt.value='';opt.textContent=online?'Installa un modello per iniziare':'Servizio offline';picker.append(opt)}
  picker.disabled=!online||!models.length;
  $('ollamaTest').disabled=!online||!models.length;
  $('ollamaStart').disabled=online||Boolean(state.ollama_managed);
  $('ollamaPrepare').disabled=!online;
  $('ollamaStop').hidden=!state.ollama_managed;
  return state;
 }catch(e){
  ollamaLastStatus=null;
  $('ollamaStatusBadge').dataset.state='offline';$('ollamaStatus').textContent='Stato sconosciuto';
  $('ollamaDetail').textContent='Impossibile verificare Ollama: '+e.message;
  $('ollamaTest').disabled=true;$('ollamaPrepare').disabled=true;
  return null;
 }
}
async function startOllama(){
 const button=$('ollamaStart');button.disabled=true;
 try{
  const result=await request('/api/control/services/ollama/start',{method:'POST'});
  ollamaMessage(result.message||'Avvio richiesto.');
  await statusAI();
  if(result.state==='starting')for(const delay of [1200,3200,6000])setTimeout(statusAI,delay);
 }catch(e){ollamaMessage(e.message,true);await statusAI()}
 finally{if(ollamaLastStatus?.ollama!=='online'&&!ollamaLastStatus?.ollama_managed)button.disabled=false}
}
async function testOllama(){
 const model=$('ollamaModelPicker').value;
 if(!model){ollamaMessage('Seleziona un modello installato.',true);return}
 const button=$('ollamaTest');button.disabled=true;
 ollamaMessage('Verifica inferenza e JSON sul modello '+model+' (nessun dato Swagger inviato).');
 try{
  const result=await request('/api/control/ollama/test',{method:'POST',
   headers:{'content-type':'application/json'},body:JSON.stringify({model})});
  ollamaMessage(result.message+' Modello: '+result.model+'.');
 }catch(e){ollamaMessage('Test fallito: '+e.message,true)}
 finally{button.disabled=false}
}

async function prepare(){try{csrf=(await request('/api/bootstrap')).csrf_token;catalog=await request('/api/control/tools');const cats=[...new Set(catalog.map(t=>t.category))].sort();for(const name of cats){const opt=document.createElement('option');opt.value=name;opt.textContent=name;$('categorySelect').append(opt)}filterTools();$('toolSelect').value='auto-assess';toolDetails();await refresh();await statusAI()}catch(e){show('Errore inizializzazione: '+e.message,true)}}
function renderWriteInventory(id,operations){
 const container=$(id);if(!container)return;container.replaceChildren();
 const heading=document.createElement('strong');heading.textContent='Operazioni di scrittura individuate ('+operations.length+')';container.append(heading);
 if(!operations.length){const p=document.createElement('p');p.textContent='Non ci sono POST/PATCH/PUT/DELETE nello Swagger.';container.append(p);return;}
 const list=document.createElement('div');list.className='operations';
 for(const item of operations){
  const row=document.createElement('div');row.className='operation';
  const method=document.createElement('b');method.textContent=item.method;row.append(method,document.createTextNode(item.operation.slice(item.method.length+1)));
  const hint=document.createElement('small');hint.textContent=item.lifecycle_mapped?' · Workflow associato':' · Nessun ciclo temporaneo completo trovato';row.append(hint);list.append(row);
 }
 container.append(list);
}
async function discoverManifest(){
 if(!specId)throw Error('Passaggio 1: carica prima uno Swagger/OpenAPI.');
 const data=await request('/api/control/manifest/candidates/'+specId);
 manifestCandidates=data.candidates||[];writeInventory=data.write_operations||[];
 renderWriteInventory('manifestWriteInventory',writeInventory);
 const select=$('manifestCandidate');select.replaceChildren();
 manifestCandidates.forEach((x,i)=>{const option=document.createElement('option');option.value=String(i);option.textContent=x.create+' → '+(x.read||'GET mancante')+' → '+(x.delete||'DELETE mancante')+(x.ready?'':' [da completare]');select.append(option)});
 if(!manifestCandidates.length){$('manifestCandidatesState').textContent='Non sono stati trovati cicli POST → GET per ID → DELETE espliciti. Se l’API ha workflow differenti, crea e importa un manifest manuale con una procedura di cleanup approvata.';return;}
 $('manifestCandidatesState').textContent='Trovati '+manifestCandidates.length+' workflow possibili. Scegline uno: saranno proposte solo operazioni dichiarate nello Swagger.';
 updateManifestFields();
}
function updateManifestFields(){
 const c=manifestCandidates[Number($('manifestCandidate').value)];if(!c)return;
 for(const [id,items,empty] of [['manifestMarker',c.marker_candidates,'Campo marker'],['manifestId',c.id_candidates,'Campo ID da verificare']]){
  const field=$(id);field.replaceChildren();if(!items.length){const opt=document.createElement('option');opt.value='';opt.textContent='Non presente: dovrai modificare il YAML';field.append(opt)}
  for(const name of items){const opt=document.createElement('option');opt.value=name;opt.textContent=name;field.append(opt)}
 }
 $('manifestState').textContent=(c.ready?'Workflow strutturalmente completo. ':'Workflow non eseguibile senza configurazione: '+c.needs.join('; ')+'. ')+'Campi obbligatori: '+(c.required.join(', ')||'nessuno')+'.';
}
async function createManifest(){
 if(!specId)throw Error('Importa prima lo Swagger al passaggio 1.');
 if(!manifestCandidates.length)throw Error('Premi prima “Trova workflow nello Swagger”.');
 const owner=$('manifestOwner').value;
 if(!owner)throw Error('Passaggio 3: carica auth.yaml e scegli l’identità che crea le risorse temporanee.');
 const payload={specification_id:specId,candidate_index:Number($('manifestCandidate').value),identity:owner,other_identity:$('manifestOther').value,marker:$('manifestMarker').value||null,identifier:$('manifestId').value||null};
 const data=await request('/api/control/manifest/draft',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
 $('manifestEditor').value=data.yaml;configId='';$('configState').textContent='Bozza modificata: importa nuovamente il manifest dopo averlo validato.';
 $('manifestState').textContent='Bozza creata. Controlla il JSON body, le proprietà marker/id, l’ownership e il funzionamento di DELETE. Poi clicca “Controlla manifest”.';
}
async function validateManifest(){
 if(!specId)throw Error('Importa prima uno Swagger.');
 if(!authId)throw Error('Importa prima auth.yaml al passaggio 3: serve per verificare che le identità del manifest esistano.');
 const content=$('manifestEditor').value.trim();if(!content)throw Error('Genera una bozza o incolla il contenuto di resources.yaml.');
 const response=await request('/api/control/manifest/validate',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({specification_id:specId,auth_config_id:authId,yaml:content})});
 $('manifestState').textContent='✓ Controllo offline superato: '+response.resources.length+' risorse, budget minimo '+response.required_requests+' richieste. Ricorda: non è un’autorizzazione a modificare dati.';
 return response;
}
async function useManifest(){
 await validateManifest();
 const content=$('manifestEditor').value.trim();
 const uploaded=await request('/api/import-text',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({kind:'config',content,name:'resources.yaml'})});
 configId=uploaded.id;$('configPaste').value=content;$('configUsage').value='multi-resource';
 $('configState').textContent='✓ resources.yaml validato e pronto per il workflow';
 $('manifestState').textContent='✓ Manifest caricato. Seleziona multi-resource-assess o auto-assess. Per eseguire scritture devi approvarle esplicitamente.';
}
function downloadManifest(){const value=$('manifestEditor').value;if(!value.trim())throw Error('Genera prima un manifest YAML.');const url=URL.createObjectURL(new Blob([value],{type:'text/yaml'}));const a=document.createElement('a');a.href=url;a.download='resources.yaml';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}

// Guided manifest workflow (v0.42). There is no target traffic during setup.
let guidedStep=1, guidedCandidate=null, guidedApprovedYaml='', guidedIdCandidateKey='';
// Local, independent workflow selections: changing a test never changes another.
const localWorkflowState={mass:new Map(),bfla:new Map()};
function localCandidate(panel){const id=panel==='mass'?'massWorkflowSelect':'bflaWorkflowSelect';const n=$(id).value;return n===''?null:(manifestCandidates[Number(n)]||null);}
function localKey(panel){return String($(panel==='mass'?'massWorkflowSelect':'bflaWorkflowSelect').value);}
function saveLocalPanel(panel){const key=localKey(panel);if(key==='')return;
 if(panel==='mass')localWorkflowState.mass.set(key,{op:$('guidedMutation').value,body:$('guidedMutationBody').value,deny:$('guidedMutationExpectedDeny').checked});
 else localWorkflowState.bfla.set(key,{action:$('guidedBflaAction').value,identity:$('guidedBflaIdentity').value,ack:$('guidedBflaPolicyAck').checked});
}
function renderLocalWorkflowChoices(){
 for(const panel of ['mass','bfla']){
  const select=$(panel==='mass'?'massWorkflowSelect':'bflaWorkflowSelect');const old=select.value;select.replaceChildren();
  for(const [i,c] of manifestCandidates.entries()){
   if(panel==='mass'&&!c.mutation)continue;
   if(panel==='bfla'&&!(c.write_action_candidates||[]).length)continue;
   const opt=document.createElement('option');opt.value=String(i);opt.textContent=(c.read||c.create)+' · '+(panel==='mass'?c.mutation:c.write_action_candidates.join(', '))+(c.ready?'':' · cleanup da configurare');select.append(opt);
  }
  if([...select.options].some(o=>o.value===old))select.value=old;
  if(!select.options.length){select.add(new Option('Nessuna risorsa compatibile nello Swagger',''));select.disabled=true;}else select.disabled=false;
 }
 renderLocalMass();renderLocalBfla();
}
function renderLocalMass(){
 const c=localCandidate('mass'),sel=$('massWorkflowSelect');
 if(!c){$('massWorkflowStatus').textContent='Nessun PATCH/PUT compatibile trovato. Carica uno Swagger con POST, GET, DELETE e PATCH/PUT.';return;}
 const state=localWorkflowState.mass.get(sel.value);const fields=c.mutation_field_specs||{};
 guideSelect($('guidedMutation'),[c.mutation],'Non eseguire PATCH/PUT');
 const f=$('guidedMutationField');f.replaceChildren();for(const [name,def] of Object.entries(fields))f.add(new Option(name+' · '+(def?.type||'string'),name));
 f.disabled=!f.options.length;$('guidedMutationInsert').disabled=!f.options.length;
 $('guidedMutation').value=state?.op||c.mutation||'';$('guidedMutationBody').value=state?.body||'';$('guidedMutationExpectedDeny').checked=!!state?.deny;
 $('massWorkflowStatus').textContent='Scelto: '+(c.read||c.create)+'. '+Object.keys(fields).length+' campi disponibili. La verifica attiva richiede un ciclo con cleanup approvato, se lo Swagger non lo contiene lo segnaliamo.';
 $('guidedMutationAvailableInfo').textContent='PATCH/PUT: '+c.mutation+'. Il body è modificabile qui, indipendentemente dalle altre sezioni.';
 $('guidedMutationFieldsHint').textContent=Object.keys(fields).join(', ')||'Nessun campo dichiarato: puoi inserire JSON di prova manualmente.';
}
function renderLocalBfla(){
 const c=localCandidate('bfla');if(!c){$('bflaWorkflowStatus').textContent='Nessuna operazione riservata compatibile nello Swagger.';return;}
 const state=localWorkflowState.bfla.get(localKey('bfla'));
 guideSelect($('guidedBflaAction'),c.write_action_candidates||[],'Non provare operazioni riservate');
 const profs=Array.from($('manifestOwner').options).map(o=>o.value).filter(Boolean);
 guideSelect($('guidedBflaIdentity'),profs,'Scegli il profilo non autorizzato');
 $('guidedBflaAction').value=state?.action||c.write_action_candidates?.[0]||'';$('guidedBflaIdentity').value=state?.identity||'';$('guidedBflaPolicyAck').checked=!!state?.ack;
 $('bflaWorkflowStatus').textContent='Scelto: '+(c.read||c.create)+'. Configura l’operazione riservata e il profilo.';
}
function localOptionsForWizard(){
 const key=$('guidedCandidate').value;
 const m=localWorkflowState.mass.get(key),b=localWorkflowState.bfla.get(key);
 return {mutation:m||{},bfla:b||{}};
}

const guideError=(message)=>{const e=$('guidedError');e.hidden=false;show('Cosa devi correggere: '+message,true,'guidedError');e.scrollIntoView({behavior:'smooth',block:'nearest'});};
const guideClear=()=>{$('guidedError').hidden=true;$('guidedError').textContent='';};
function guideGo(step){
 guideClear();guidedStep=step;
 for(let i=1;i<=4;i++)$('guidedStage'+i).hidden=i!==step;
 $('guidedProgress').textContent=step+' di 4 · '+['','Scegli la risorsa','Utenti di test','Dati temporanei','Campo ID e conferma'][step];
 $('guidedStage'+step).scrollIntoView({behavior:'smooth',block:'nearest'});
}
function guideSelect(target,choices,empty){
 target.replaceChildren();
 if(empty!==undefined){const option=document.createElement('option');option.value='';option.textContent=empty;target.append(option)}
 for(const name of choices){const option=document.createElement('option');option.value=name;option.textContent=name;target.append(option)}
}
function guideInvalidate(){guidedApprovedYaml='';$('guidedResult').hidden=true;}
async function guideDiscover(){
 guideClear();guideInvalidate();
 if(!specId)throw Error('Torna al passaggio 1 della pagina e carica lo Swagger dell’API che vuoi testare.');
 const response=await request('/api/control/manifest/candidates/'+specId);
 manifestCandidates=response.candidates||[];writeInventory=response.write_operations||[];renderLocalWorkflowChoices();
 renderWriteInventory('guidedWriteInventory',writeInventory);
 const choices=$('guidedCandidate');choices.replaceChildren();
 for(let index=0;index<manifestCandidates.length;index++){
  const c=manifestCandidates[index];const opt=document.createElement('option');opt.value=String(index);
  opt.textContent=c.create+' → '+(c.read||'GET non disponibile')+' → '+(c.delete||'DELETE non disponibile')+(c.ready?'':' · configurazione incompleta');opt.disabled=!c.ready;choices.append(opt);
 }
 if(!manifestCandidates.some(x=>x.ready)){
   $('guidedCandidateHelp').textContent='Lo Swagger non descrive un ciclo completo di creazione, lettura e cancellazione. Puoi eseguire comunque tutti i test di lettura (GET). Per scritture serve una procedura di cleanup approvata e una configurazione avanzata.';
   choices.disabled=true;$('guidedNext1').disabled=true;window.AchillesWorkflowUX?.refresh(manifestCandidates,savedWorkflows);return;
 }
 choices.disabled=false;$('guidedNext1').disabled=false;
 const first=manifestCandidates.findIndex(x=>x.ready);choices.value=String(first);guideUpdateCandidate();
 window.AchillesWorkflowUX?.refresh(manifestCandidates,savedWorkflows);
}
// The Swagger response takes precedence. When it does not document an ID,
// preserve the original automatic *suggestion* from the GET detail path.
// This is a candidate field, never a verified response value.
function guideIdentifierSuggestion(candidate){
 const declared=(candidate?.id_schema_pointers||[]).filter(Boolean);
 const hints=(candidate?.id_candidates||[]).filter(Boolean);
 if(declared.length===1)return {value:declared[0].replace(/^\//,''),
   notice:'Campo ID individuato nello schema della risposta POST: '+declared[0]+'. Da verificare sul server.'};
 if(declared.length>1){
  // A common response can contain both /data/id and /data/tenantId.
  const resourceKey=String(candidate.path_parameter||'').toLowerCase();
  const rank=x=>{const tail=x.split('/').pop().toLowerCase();return (tail==='id'?100:0)+(resourceKey&&tail===resourceKey?80:0)+(tail.endsWith('id')?10:0)-x.split('/').length;};
  const ranked=[...declared].sort((a,b)=>rank(b)-rank(a));
  return {value:ranked[0].replace(/^\//,''),
    notice:'La risposta POST dichiara più possibili ID ('+declared.join(', ')+'). Proposto '+ranked[0]+': verifica che sia l’ID della risorsa creata.'};
 }
 if(hints.length){
  const pathKey=String(candidate.path_parameter||'');
  // GET /projects/{project_ref} only specifies the lookup parameter. It does
  // NOT imply POST returns {"project_ref":...}; many APIs return {"id":...}.
  const commonId=hints.find(x=>String(x).replace(/^\//,'').toLowerCase()==='id');
  const preferred=commonId||hints[0];
  return {value:String(preferred).replace(/^\//,''),
   notice:'Campo ID suggerito automaticamente: '+preferred+'. Il parametro della GET {'+pathKey+'} non documenta la risposta POST. Il suggerimento NON è verificato: se la risposta usa un campo diverso, scegli un’alternativa o prova una creazione autorizzata.'};
 }
 return {value:'', notice:'Nessun ID documentato o suggeribile. Per rilevarlo usa una risposta reale o una creazione di prova esplicitamente autorizzata.'};
}
function guideApplyIdentifierSuggestion(force=false){
 const c=guidedCandidate;if(!c)return;
 const key=specId+'::'+c.create;
 const list=$('guidedIdHints');list.replaceChildren();
 for(const value of new Set([...(c.id_schema_pointers||[]),...(c.id_candidates||[])].filter(Boolean))){
  const option=document.createElement('option');option.value=String(value).replace(/^\//,'');list.append(option);
 }
 // Do not erase a manual value or a JSON-pointer learned from a real POST
 // when navigating back/forward through the same workflow.
 if(force||guidedIdCandidateKey!==key||!$('guidedId').value.trim()){
  const suggestion=guideIdentifierSuggestion(c);
  $('guidedId').value=suggestion.value;
  $('guidedIdNotice').textContent=suggestion.notice;
 }
 guidedIdCandidateKey=key;
}
function guideUpdateCandidate(){
 guidedCandidate=manifestCandidates.find((x,i)=>i===Number($('guidedCandidate').value))||null;
 if(!guidedCandidate)return;
 const c=guidedCandidate;
 $('guidedCandidateHelp').textContent=(c.required_path_params.length?'La POST richiede ID parent da inserire nel passo 3. ':'')+'Verrà creata UNA risorsa tramite '+c.create+', verificata tramite '+c.read+' e cancellata tramite '+c.delete+'. '+(c.read_get_risk?'GET da verificare: '+c.read_get_risk+' ':'')+'Non inizierà nessuna richiesta senza la tua approvazione finale.';
 guideApplyIdentifierSuggestion(true);
 guideInvalidate();
}
function guideUsers(){
 if(!authId)throw Error('Torna al passaggio 3 della pagina: carica auth.yaml e inserisci i token di prova.');
 const ownerOpts=[...$('manifestOwner').options].filter(x=>x.value).map(x=>x.value);
 guideSelect($('guidedOwner'),ownerOpts);
 guideSelect($('guidedOther'),ownerOpts,'Non confrontare un secondo utente');
 if(ownerOpts.length>1)$('guidedOther').value=ownerOpts[1];
}
function guideCreateField(name,details,value,required){
 const label=document.createElement('label');const headline=document.createElement('span');
 headline.textContent=name+(required?' · obbligatorio':' · facoltativo');label.append(headline);
 let input;
 if(details.enum&&details.enum.length){input=document.createElement('select');
    if(!required){const empty=document.createElement('option');empty.value='';empty.textContent='Non includere questo campo';input.append(empty)}
    for(const v of details.enum){const option=document.createElement('option');option.value=String(v);option.textContent=String(v);input.append(option)}
 }else if(details.type==='boolean'){
    input=document.createElement('select');for(const v of ['false','true']){const option=document.createElement('option');option.value=v;option.textContent=v==='true'?'Sì':'No';input.append(option)}
 }else{
   input=document.createElement('input');input.type=['integer','number'].includes(details.type)?'number':'text';
   if(details.type==='integer')input.step='1';if(details.type==='number')input.step='any';
   if(details.type==='string'&&Number.isInteger(details.maxLength))input.maxLength=details.maxLength;
   if(details.type==='string'&&Number.isInteger(details.minLength))input.minLength=details.minLength;
   if(details.minimum!==null&&details.minimum!==undefined)input.min=details.minimum;
   if(['object','array'].includes(details.type))input.placeholder='Inserisci JSON valido, es. '+(details.type==='array'?'[]':'{}');
 }
 input.dataset.guideKey=name;input.dataset.guideType=details.type;input.dataset.guideRequired=required?'yes':'no';
 if(value!==undefined&&value!==null&&String(value).indexOf('REVIEW_')!==0)input.value=String(value);
 else if(name===guidedCandidate.marker_candidates[0])input.value='verifica-temporanea';
 else input.value='';
 label.append(input);
 const help=document.createElement('small');help.textContent=(details.description||'Tipo: '+details.type)+(required?'. Devi compilare questo campo.':'. Puoi lasciarlo vuoto per non inviarlo.');label.append(help);
 return label;
}
// RC19: dedicated Mass Assignment editor, independent from the fixture wizard.
// It only creates a proposed JSON body. Actual PATCH still needs approved manifest
// and all existing write/cleanup controls.
let guidedMutationCandidateKey='';
function rc19MutationExample(def){
 const values=def?.enum||[];
 if(values.length)return values[0];
 switch(def?.type){
  case 'boolean':return false;
  case 'integer':case 'number':return 1;
  case 'array':return [];
  case 'object':return {};
  default:return 'REVIEW_VALORE_PATCH';
 }
}
function updateMutationPanel(reset=false){
 const c=localCandidate('mass');
 const operation=c?.mutation||'';
 const key=(specId||'')+'|'+localKey('mass')+'|'+operation;
 const hasChanged=reset||guidedMutationCandidateKey!==key;
 const previousSelected=$('guidedMutation').value;
 guidedMutationCandidateKey=key;
 const select=$('guidedMutation'),fieldSelect=$('guidedMutationField'),textarea=$('guidedMutationBody');
 const info=$('guidedMutationAvailableInfo'),detail=$('guidedMutationFieldsHint');
 const check=$('guidedMutationExpectedDeny');
 guideSelect(select,operation?[operation]:[],'Non eseguire PATCH/PUT');
 if(hasChanged){select.value='';textarea.value='';check.checked=false;}
 else if(previousSelected===operation)select.value=previousSelected;
 fieldSelect.replaceChildren();
 const fields=c?.mutation_field_specs||{};
 for(const [name,value] of Object.entries(fields)){
  const option=document.createElement('option');option.value=name;
  option.textContent=name+' · '+(value.type||'string');fieldSelect.append(option);
 }
 const ready=Boolean(operation);
 select.disabled=!ready;fieldSelect.disabled=!ready||!fieldSelect.options.length;
 $('guidedMutationInsert').disabled=!ready||!fieldSelect.options.length;
 check.disabled=!ready;
 if(!c){info.textContent='Prima individua e seleziona una risorsa nel pannello «Crea risorse temporanee e workflow».';
 }else if(!ready){info.textContent='Questo workflow non ha PATCH o PUT documentato per '+(c.read||c.create)+'. Nessun body da inviare: scegli un altro workflow o richiedi uno Swagger completo.';
 }else{
  info.textContent='Operazione disponibile: '+operation+'. '+Object.keys(fields).length+' campi JSON scrivibili dichiarati. Per generare il manifest serve il workflow POST → GET → DELETE e un ID valido.';
 }
 detail.textContent=Object.keys(fields).length
  ?'Campi da requestBody: '+Object.keys(fields).join(', ')+'. Seleziona un campo e aggiungilo al JSON; scegli solo campi che la policy aziendale vieta al profilo di prova.'
  :ready?'Lo Swagger non elenca proprietà JSON del PATCH/PUT. Puoi scrivere un JSON manualmente, ma la verifica attiva potrebbe essere bloccata dal preflight.':'Nessun campo PATCH per questo workflow.';
}
function mutationInsertField(){
 if(!localCandidate('mass')?.mutation)throw Error('Nessuna operazione PATCH/PUT per questa risorsa.');
 const field=$('guidedMutationField').value;
 if(!field)throw Error('Lo Swagger non dichiara campi PATCH per questa operazione.');
 const editor=$('guidedMutationBody');let body={};
 try{body=editor.value.trim()?JSON.parse(editor.value):{}}catch{throw Error('Correggi prima il JSON PATCH: non è valido.');}
 if(!body||Array.isArray(body)||typeof body!=='object')throw Error('Il body PATCH deve essere un oggetto JSON.');
 if(Object.prototype.hasOwnProperty.call(body,field))throw Error('Il campo '+field+' è già presente: modificalo direttamente nel JSON.');
 body[field]=rc19MutationExample(localCandidate('mass').mutation_field_specs?.[field]);
 editor.value=JSON.stringify(body,null,2);
 $('guidedMutation').value=localCandidate('mass').mutation;
 editor.focus();guideInvalidate();
}
function mutationTogglePolicy(){
 const checked=$('guidedMutationExpectedDeny').checked;
 if(!checked)return;
 if(!localCandidate('mass')?.mutation){$('guidedMutationExpectedDeny').checked=false;
  guideError('Per Mass Assignment è necessario un endpoint PATCH/PUT documentato. Scegli un workflow che ne disponga.');
  document.querySelector('#massAssignmentPanel').scrollIntoView({behavior:'smooth',block:'center'});return;}
 $('guidedMutation').value=localCandidate('mass').mutation;
 if(!$('guidedMutationBody').value.trim()&&$('guidedMutationField').value){
  try{mutationInsertField()}catch(e){guideError(e.message)}
 }
}

function guidePrepareBody(){
 const c=guidedCandidate;if(!c)throw Error('Scegli prima una risorsa da testare.');
 const parentBox=$('guidedParentFields');parentBox.replaceChildren();
 for(const name of c.required_path_params||[]){
  const label=document.createElement('label');label.textContent='ID parent nel path POST: '+name;
  const input=document.createElement('input');input.dataset.parentKey=name;
  input.placeholder='ID di risorsa di test già esistente';input.required=true;label.append(input);
  const guidance=(c.parent_guidance||[]).find(x=>x.parameter===name);
  const explain=document.createElement('small');explain.textContent=(guidance?.reason||'Lo Swagger descrive un parametro di percorso, ma non garantisce i valori presenti nel server.')+' '+(guidance?.how_to_resolve||[]).join(' ');
  label.append(explain);parentBox.append(label);
  const sources=guidance?.read_sources||[];
  if(sources.length){
   const block=document.createElement('details');block.className='guide-parent-help';
   const summary=document.createElement('summary');summary.textContent='Cerca un possibile ID di '+name+' tramite GET autorizzata';block.append(summary);
   const sourceLabel=document.createElement('label');sourceLabel.textContent='Endpoint candidato (suggerimento, non certezza)';
   const choices=document.createElement('select');for(const candidate of sources){const opt=document.createElement('option');opt.value=candidate.operation;opt.textContent=candidate.operation+' · '+(candidate.evidence==='response_schema'?'campo presente nello schema':'ipotesi dal nome endpoint');choices.append(opt)}
   sourceLabel.append(choices);block.append(sourceLabel);
   const pointerLabel=document.createElement('label');pointerLabel.textContent='JSON Pointer del valore nella risposta';const ptr=document.createElement('input');ptr.value=sources[0].pointer_suggestion;pointerLabel.append(ptr);block.append(pointerLabel);
   choices.onchange=()=>{ptr.value=sources.find(x=>x.operation===choices.value)?.pointer_suggestion||'/'+name};
   const consent=document.createElement('label');consent.className='check';const ack=document.createElement('input');ack.type='checkbox';consent.append(ack,document.createTextNode(' Autorizzo questa GET di sola lettura con il profilo selezionato'));block.append(consent);
   const fetchId=document.createElement('button');fetchId.type='button';fetchId.className='secondary';fetchId.textContent='Recupera ID parent';block.append(fetchId);
   const output=document.createElement('small');output.setAttribute('role','status');block.append(output);
   fetchId.onclick=async()=>{fetchId.disabled=true;try{
     const result=await request('/api/control/manifest/parent-lookup',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({
      specification_id:specId,auth_config_id:authId,candidate_index:Number($('guidedCandidate').value),
      variable:name,source_operation:choices.value,pointer:ptr.value.trim(),identity:$('guidedOwner').value,
      base_url:$('baseUrl').value.trim(),allow_host:$('allowHost').value.trim(),
      allow_insecure_http:$('insecure').checked,approve_http:ack.checked})});
     if(result.found){input.value=result.value;output.textContent='✓ Valore recuperato con GET. Controlla che appartenga alla risorsa autorizzata.';}
     else output.textContent=result.message||'Valore non trovato.';
   }catch(e){output.textContent='Recupero non riuscito: '+e.message;window.AchillesIssueGuide?.report(e.message,'guidedProbeResult',{section:'workflowCreateSection',detail:'Verifica la POST di prova e il campo ID. Inserisci soltanto identificatori di risorse temporanee autorizzate.'})}finally{fetchId.disabled=false}};
   parentBox.append(block);
  }
 }
 const fieldBox=$('guidedPayloadFields');fieldBox.replaceChildren();
 const fields=new Set([...c.required,...c.marker_candidates]);
 // Optional properties are deliberately not sent: minimize side effects.
 for(const name of fields){if(!c.field_specs[name])continue;
  fieldBox.append(guideCreateField(name,c.field_specs[name],c.body_example[name],c.required.includes(name)||c.marker_candidates.includes(name)));
 }
 guideSelect($('guidedMarker'),c.marker_candidates);
 // Mass Assignment and BFLA are configured independently in their own panels.
 // Preserve separately edited PATCH JSON when the operator returns to step 3.
 // Mutations reset only when a *different resource* is selected.
 $('guidedPayloadHelp').textContent='Sono mostrati soltanto i campi obbligatori e i campi di marcatura. Gli altri campi non vengono modificati. Il testo di marcatura serve a dimostrare che l’oggetto è stato creato dal test.';
 guideApplyIdentifierSuggestion();
}
function guideBody(){
 const body={};
 for(const input of $('guidedPayloadFields').querySelectorAll('[data-guide-key]')){
  const name=input.dataset.guideKey,kind=input.dataset.guideType,raw=input.value.trim();
  if(!raw){if(input.dataset.guideRequired==='yes')throw Error('Nella sezione «Dati temporanei», compila «'+name+'».');continue}
  if(raw.startsWith('REVIEW_')||raw.startsWith('TODO_'))throw Error('Nel campo «'+name+'» sostituisci il valore provvisorio con un dato di test vero.');
  if(kind==='integer'||kind==='number'){
    const num=Number(raw);if(!Number.isFinite(num)||kind==='integer'&&!Number.isInteger(num))throw Error('«'+name+'» deve contenere '+(kind==='integer'?'un numero intero':'un numero')+'.');body[name]=num;
  }else if(kind==='boolean')body[name]=raw==='true';
  else if(['object','array'].includes(kind)){
    try{const parsed=JSON.parse(raw);if(kind==='array'&&!Array.isArray(parsed)||kind==='object'&&(typeof parsed!=='object'||Array.isArray(parsed)||parsed===null))throw Error();body[name]=parsed}
    catch{throw Error('«'+name+'» richiede JSON valido, ad esempio '+(kind==='array'?'[]':'{}')+'.')}
  }else body[name]=raw;
 }
 return body;
}
function guideReview(){
 const c=guidedCandidate;
 $('guidedReview').textContent='Il test creerà una risorsa con '+c.create+', la leggerà con '+c.read+' e proverà a cancellarla con '+c.delete+'. Prima di DELETE, AchillesAPI controllerà ID e marcatore. Se la verifica fallisce, non cancellerà un oggetto incerto.'+(c.read_get_risk?' ATTENZIONE: '+c.read_get_risk:'');
 $('guidedRiskLabel').hidden=!c.read_get_risk;
 if(localWorkflowState.mass.get($('guidedCandidate').value)?.deny){
  $('guidedReview').textContent+=' Per Mass Assignment userò il body configurato nel pannello dedicato per questa risorsa.';
 }
 $('guidedRiskAck').checked=false;
}
function guideResponseId(){
 const raw=$('guidedResponseExample').value.trim();if(!raw)throw Error('Incolla una risposta JSON della POST per trovare l’ID.');
 let parsed;try{parsed=JSON.parse(raw)}catch{throw Error('La risposta non è JSON valido.')}
 const pointers=[];
 function walk(value,parts){if(!value||typeof value!=='object'||Array.isArray(value)||parts.length>4)return;
  for(const [key,child] of Object.entries(value)){
   const current=[...parts,key];if(/^(id|uid|uuid|guid|key|.*_id|.*Id|.*ref|.*Ref|.*Key|.*Identifier)$/i.test(key)&&['string','number'].includes(typeof child))pointers.push('/'+current.map(x=>x.replace(/~/g,'~0').replace(/\//g,'~1')).join('/'));
   if(child&&typeof child==='object'&&!Array.isArray(child))walk(child,current);
  }
 }
 walk(parsed,[]);
 if(pointers.length===1){$('guidedId').value=pointers[0].slice(1);$('guidedIdNotice').textContent='ID individuato nella risposta: '+pointers[0];return;}
 if(pointers.length>1)throw Error('La risposta contiene più possibili ID: '+pointers.join(', ')+'. Seleziona il campo relativo alla risorsa creata.');
 throw Error('Nessun ID riconoscibile nella risposta. Specifica manualmente il JSON Pointer corretto.');
}
async function guideProbeIdentifier(){
 const button=$('guidedProbeId'),out=$('guidedProbeResult');
 if(!guidedCandidate)throw Error('Scegli prima un workflow nello Swagger.');
 if(!$('guidedProbeApprove').checked||!$('guidedProbeOrphan').checked)throw Error('Per la creazione reale servono entrambe le conferme specifiche.');
 if(!authId||!specId)throw Error('Carica Swagger e auth.yaml.');
 if(!$('baseUrl').value.trim()||!$('allowHost').value.trim())throw Error('Compila Base URL e hostname autorizzato.');
 const c=guidedCandidate;
 button.disabled=true;out.textContent='Invio una POST autorizzata e provo a verificare e rimuovere la risorsa temporanea…';
 try{
  const result=await request('/api/control/manifest/probe-id',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({
   specification_id:specId,auth_config_id:authId,candidate_index:Number($('guidedCandidate').value),
   identity:$('guidedOwner').value,body:guideBody(),path_values:guideParentValues(),marker:$('guidedMarker').value,
   base_url:$('baseUrl').value.trim(),allow_host:$('allowHost').value.trim(),
   allow_insecure_http:$('insecure').checked,approve_writes:$('guidedProbeApprove').checked,
   approve_possible_orphan:$('guidedProbeOrphan').checked,
   acknowledge_get_side_effect_risk:!c.read_get_risk||$('guidedRiskAck').checked})});
  if(result.id_pointer){$('guidedId').value=result.id_pointer.replace(/^\//,'');
   $('guidedIdNotice').textContent='JSON Pointer rilevato da risposta reale: '+result.id_pointer+'. '+(result.cleanup_verified?'Risorsa rimossa.':'Cleanup NON confermato.');}
  out.textContent=result.notice+' '+(result.manual_cleanup_required?'ATTENZIONE: verifica e rimuovi manualmente la risorsa prima di ripetere. ':'')+
   'Richieste: '+result.http_attempts+' · ID: '+(result.id_pointer||'non identificato')+' · alternative: '+(result.candidate_pointers||[]).join(', ')+(result.manual_cleanup_required&&result.marker_for_cleanup?' · Marcatura per cleanup manuale: '+result.marker_for_cleanup:'');
 }catch(e){out.textContent='Test non riuscito: '+e.message+' Se la POST era già stata inviata verifica manualmente che non abbia creato una risorsa.';window.AchillesIssueGuide?.report(e.message,'guidedProbeResult',{section:'workflowCreateSection',detail:'Controlla URL, credenziali e sequenza di creazione/cleanup prima di ripetere. Se la POST è stata inviata, verifica manualmente l’eventuale risorsa creata.'})}
 finally{button.disabled=false;}
}
function guideParentValues(){const result={};for(const input of $('guidedParentFields').querySelectorAll('[data-parent-key]')){
 const value=input.value.trim();if(!/^[A-Za-z0-9_.:~-]{1,128}$/.test(value))throw Error('Compila un ID parent autorizzato, senza slash o caratteri speciali: '+input.dataset.parentKey);
 result[input.dataset.parentKey]=value;}return result;
}

async function guideFinish(){
 guideClear();guideInvalidate();
 if(!$('guidedConfirm').checked)throw Error('Per procedere devi confermare che l’API consente la creazione e la cancellazione di queste risorse temporanee.');
 const owner=$('guidedOwner').value,other=$('guidedOther').value;
 if(!owner)throw Error('Seleziona il profilo che deve creare la risorsa.');
 if(other&&other===owner&&$('guidedDeny').checked)throw Error('Scegli un secondo utente diverso dal proprietario, oppure disattiva il controllo sull’accesso.');
 if(guidedCandidate?.read_get_risk&&!$('guidedRiskAck').checked)throw Error('La GET selezionata sembra un’azione. Controlla la sua semantica e conferma separatamente il rischio nel passaggio 4.');
 const ident=$('guidedId').value.trim();if(!ident)throw Error('Indica il nome del campo ID nella risposta POST: per esempio id. La specifica OpenAPI non lo dichiara sempre.');
 const body=guideBody();const pathValues=guideParentValues();const c=guidedCandidate;const mark=$('guidedMarker').value;
 const local=localOptionsForWizard();let mutationBody=null;if(local.mutation.op){try{mutationBody=JSON.parse(local.mutation.body)}catch{throw Error('Il JSON PATCH/PUT della risorsa scelta non è valido.')}
 if(!mutationBody||Array.isArray(mutationBody)||typeof mutationBody!=='object'||!Object.keys(mutationBody).length)throw Error('La modifica richiede un oggetto JSON non vuoto.');
 if(JSON.stringify(mutationBody).includes('REVIEW_')||JSON.stringify(mutationBody).includes('TODO_'))throw Error('Sostituisci i valori REVIEW_/TODO_ con dati di test approvati nel body PATCH.');}
 if(!body[mark])throw Error('Compila il campo «'+mark+'»: serve a riconoscere la risorsa temporanea.');
 if(local.bfla.action&&!local.bfla.ack)throw Error('Per il test BFLA conferma esplicitamente la policy attesa di accesso vietato.');
 if(local.mutation.deny&&!mutationBody)throw Error('Apri «Mass Assignment · controlla i campi modificabili»: scegli un campo PATCH, aggiungilo al body JSON e controlla il valore.');
 const payload={specification_id:specId,auth_config_id:authId,candidate_index:Number($('guidedCandidate').value),identity:owner,other_identity:other,deny_other:$('guidedDeny').checked,marker:mark,identifier:ident,body,path_values:pathValues,mutation_body:mutationBody,mutation_expected_deny:!!local.mutation.deny,write_action:local.bfla.action||null,write_identity:local.bfla.action?local.bfla.identity:null,acknowledge_get_side_effect_risk:guidedCandidate?.read_get_risk&&$('guidedRiskAck').checked===true};
 const result=await request('/api/control/manifest/guided',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
 const upload=await request('/api/import-text',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({kind:'config',content:result.yaml,name:'resources.yaml'})});
 configId=upload.id;guidedApprovedYaml=result.yaml;
 const label=(c.create+' → '+c.read).slice(0,160);
 savedWorkflows.push({label,configId:upload.id,yaml:result.yaml,specId,candidateIndex:Number($('guidedCandidate').value),requiredRequests:result.required_requests,selected:true});
 bodyProbeFields=[];bodyProbeSource='';bodyProbeSelections.clear();bodyProbeDiscovered.clear();bodyProbeLifecycleBudget=0;bodyProbeAvailable=[];$('rc13Body').checked=false;$('suiteRc13Body').checked=false;
 preparedCampaign=null;resetWorkflowRunApprovals();
 renderSavedWorkflows();$('workflowSaved').value=String(savedWorkflows.length-1);
 window.AchillesWorkflowUX?.refresh(manifestCandidates,savedWorkflows);
 const probeSelect=$('bodyProbeWorkflowSelect');if(probeSelect){probeSelect.value=String(savedWorkflows.length-1);
  queueMicrotask(()=>detectBodyProbeFields().catch(e=>show(e.message,true,'bodyProbeHint')));}
 $('workflowSavedStatus').textContent='✓ Salvato «'+label+'». Puoi aprire la procedura per aggiungere altri workflow; questo non verrà perso.';
 if($('bodyProbeWizard').open)await detectBodyProbeFields().catch(e=>show(e.message,true,'bodyProbeHint'));

 $('configUsage').value='multi-resource';$('configPaste').value=result.yaml;
 $('manifestEditor').value=result.yaml;
 $('configState').textContent='✓ Manifest di risorsa temporanea pronto · creato dalla procedura guidata';
 $('manifestState').textContent='✓ Manifest generato senza segnaposto e verificato offline';
 $('categorySelect').value='';filterTools();$('toolSelect').value='multi-resource-assess';toolDetails();
 const block=$('guidedResult');block.hidden=false;block.replaceChildren();
 const title=document.createElement('strong');title.textContent='✓ Configurazione pronta. Non è stata inviata alcuna richiesta HTTP.';block.append(title);
 const details=document.createElement('p');details.textContent='Per la prova servono almeno '+result.required_requests+' richieste. Il manifest è già caricato: non devi copiare o modificare YAML.';block.append(details);
 const download=document.createElement('button');download.type='button';download.className='secondary';download.textContent='Scarica il file tecnico (facoltativo)';download.onclick=()=>{const url=URL.createObjectURL(new Blob([guidedApprovedYaml],{type:'text/yaml'}));const a=document.createElement('a');a.href=url;a.download='resources.yaml';a.click();URL.revokeObjectURL(url)};block.append(download);
 const actions=document.createElement('div');actions.className='buttons';
 const again=document.createElement('button');again.type='button';again.className='secondary';again.textContent='Configura un altro workflow (torna allo Step 1)';again.onclick=guideStartAnother;actions.append(again);
 const next=document.createElement('button');next.type='button';next.className='primary';next.textContent='Esegui il test con questo workflow';
 next.onclick=()=>{$('workflowRunSelect').value=String(savedWorkflows.length-1);updateWorkflowRunControls();Promise.resolve().then(()=>{
  $('workflowRunStatus').textContent='Workflow selezionato. Controlla il Base URL, il budget e le due autorizzazioni, poi premi «Avvia test del workflow scelto».';
  $('workflowRunPanel').scrollIntoView({behavior:'smooth',block:'center'});
 }).catch(e=>show(e.message,true,'workflowRunStatus'))};actions.append(next);block.append(actions);
}

// A fresh wizard does not delete any manifest already saved in the workflow library.
function guideStartAnother(){
 const oldIndex=Number($('guidedCandidate').value);
 guideClear();guideInvalidate();
 for(const id of ['guidedConfirm','guidedRiskAck','guidedProbeApprove','guidedProbeOrphan'])$(id).checked=false;
 for(const id of ['guidedResponseExample','guidedId'])$(id).value='';
 for(const id of ['guidedProbeResult','guidedIdNotice'])$(id).textContent='';
 $('guidedDeny').checked=true;
 $('guidedParentFields').replaceChildren();$('guidedPayloadFields').replaceChildren();
 guidedIdCandidateKey='';
 const available=manifestCandidates.map((item,i)=>item.ready?i:null).filter(x=>x!==null);
 const unsaved=available.find(i=>i!==oldIndex&&!savedWorkflows.some(w=>w.candidateIndex===i));
 const next=unsaved??available.find(i=>i!==oldIndex)??available[0];
 if(next!==undefined){$('guidedCandidate').value=String(next);guideUpdateCandidate();}
 else guidedCandidate=null;
 $('guidedDrawer').open=true;
 guideGo(1);
 $('guidedCandidate').focus();
}

// A Swagger can expose many independent CRUD cycles. Keep every validated manifest
// separately, since merging them would require a verified dependency/cleanup graph.
function resetWorkflowRunApprovals(){
 for(const id of ['workflowRunHttpAck','workflowRunWritesAck']){if($(id))$(id).checked=false;}
}
function workflowSelectionKey(){return savedWorkflows.filter(w=>w.specId===specId&&w.selected!==false).map(w=>w.configId).join('|');}
function updateWorkflowRunControls(){
 const hasAny=savedWorkflows.some(w=>w.specId===specId);
 if(hasAny&&!$('workflowRunSelect').value)$('workflowRunSelect').value=String(savedWorkflows.findIndex(w=>w.specId===specId));
 $('workflowRunSingle').disabled=!hasAny||!$('workflowRunSelect').value;
 const valid=Boolean(preparedCampaign&&preparedCampaign.specId===specId&&preparedCampaign.selectionKey===workflowSelectionKey());
 $('workflowRunCombined').disabled=!valid;
 $('workflowRunSummary').textContent=hasAny
  ?savedWorkflows.length+' workflow preparati · '+(valid?'campagna multi-workflow pronta ('+preparedCampaign.resources+' risorse; min. '+preparedCampaign.requiredRequests+' richieste)':'per i test combinati seleziona le risorse e premi «Prepara una campagna»')
  :'Configura almeno un workflow dal wizard sopra per iniziare.';
}
function invalidatePreparedCampaign(){preparedCampaign=null;resetWorkflowRunApprovals();updateWorkflowRunControls();}
async function launchWorkflowTest(configRef,requiredRequests,label){
 if(!specId||!authId)throw Error('Per avviare test di scrittura servono Swagger e auth.yaml.');
 if(!configRef)throw Error('Prepara o seleziona prima un workflow valido.');
 if(!$('workflowRunHttpAck').checked||!$('workflowRunWritesAck').checked)
  throw Error('Conferma entrambe le autorizzazioni nella sezione di esecuzione workflow.');
 if(!$('baseUrl').value.trim()||!$('allowHost').value.trim())
  throw Error('Compila Base URL e hostname autorizzato al passaggio 2.');
 if(!catalog.some(t=>t.name==='multi-resource-assess'&&t.active&&t.writes))
  throw Error('Il motore multi-resource-assess non è disponibile per test HTTP con scritture.');
 const budget=clampNumeric('maxRequests');
 if(requiredRequests>budget)throw Error('Budget insufficiente: servono almeno '+requiredRequests+' richieste HTTP per '+label+'. Alza il limite al passaggio 2 (massimo 150), oppure dividi la campagna.');
 const params={...currentConfig(true),action:'multi-resource-assess',config_id:configRef,
  config_usage:'multi-resource',execute:true,acknowledgment:true,approve_writes:true};
 show('Avvio '+label+'…',false,'workflowRunStatus');
 const result=await request('/api/control/jobs',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(params)});
 resetWorkflowRunApprovals();
 show('✓ Avviato '+label+' · Job '+result.id+'. Consulta il Passaggio 5 per i risultati.',false,'workflowRunStatus');
 await refresh();return result;
}
async function launchSingleWorkflow(){
 const selected=$('workflowRunSelect').value;
 if(selected===''||!savedWorkflows[Number(selected)])throw Error('Seleziona un workflow salvato.');
 const item=savedWorkflows[Number(selected)];if(item.specId!==specId)throw Error('Il workflow appartiene a un altro Swagger.');
 return launchWorkflowTest(item.configId,item.requiredRequests,'il workflow «'+item.label+'»');
}
async function launchMultiWorkflow(){
 const camp=preparedCampaign;
 if(!camp||camp.specId!==specId||camp.selectionKey!==workflowSelectionKey())
  throw Error('La selezione è cambiata: prepara nuovamente la campagna multi-workflow prima di avviarla.');
 return launchWorkflowTest(camp.configId,camp.requiredRequests,'la campagna multi-workflow');
}
function refreshScopedWorkflowSelectors(){
 for(const id of ['workflowRunSelect','rc13WorkflowSelect','suiteWorkflowSelect','bodyProbeWorkflowSelect']){
  const sel=$(id);if(!sel)continue;const old=sel.value;sel.replaceChildren();
  const blank=new Option(id==='workflowRunSelect'?'Scegli un workflow salvato':'Nessun workflow (solo verifiche senza fixture)','');sel.add(blank);
  savedWorkflows.forEach((w,i)=>{if(w.specId===specId)sel.add(new Option(w.label,String(i)));});
  if(['rc13WorkflowSelect','suiteWorkflowSelect'].includes(id)&&savedWorkflows.filter(w=>w.specId===specId).length>1)sel.add(new Option('Tutti i workflow salvati','__all__'));
  if([...sel.options].some(o=>o.value===old))sel.value=old;
  else if(['rc13WorkflowSelect','suiteWorkflowSelect'].includes(id)&&savedWorkflows.filter(w=>w.specId===specId).length>1)sel.value='__all__';
  else if(savedWorkflows.some(w=>w.specId===specId)&&id!=='workflowRunSelect')sel.value=String(savedWorkflows.findIndex(w=>w.specId===specId));
  else if(id==='workflowRunSelect'&&savedWorkflows.length)sel.value=String(savedWorkflows.findIndex(w=>w.specId===specId));
 }
}
async function scopedWorkflowConfig(selectId){
 const idx=$(selectId).value;if(idx==='')throw Error('Seleziona un workflow nella sezione corrente.');
 if(idx==='__all__'){
  if(!specId||!authId)throw Error('Per combinare i workflow carica Swagger e auth.yaml.');
  const selected=savedWorkflows.filter(w=>w.specId===specId);
  if(selected.length>10)throw Error('Massimo 10 risorse per campagna: dividi i workflow.');
  const result=await request('/api/control/manifest/compose',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({specification_id:specId,auth_config_id:authId,config_ids:selected.map(w=>w.configId)})});
  return {configId:result.id,specId,requiredRequests:result.required_requests,label:'Tutti i workflow salvati'};
 }
 const w=savedWorkflows[Number(idx)];if(!w||w.specId!==specId)throw Error('Il workflow selezionato non appartiene allo Swagger attuale.');
 return w;
}
function renderSavedWorkflows(){
 refreshScopedWorkflowSelectors();
 const select=$('workflowSaved');if(!select)return;
 const previous=select.value;select.replaceChildren();
 if(!savedWorkflows.length){const opt=document.createElement('option');opt.value='';opt.textContent='Non hai ancora preparato un workflow';select.append(opt);$('workflowChecklist').replaceChildren();updateWorkflowRunControls();return;}
 savedWorkflows.forEach((item,i)=>{const opt=document.createElement('option');opt.value=String(i);opt.textContent=(i+1)+'. '+item.label;select.append(opt)});
 if(savedWorkflows[Number(previous)]&&previous!=='')select.value=previous;
 const list=$('workflowChecklist');list.replaceChildren();
 savedWorkflows.forEach((item,i)=>{
  const label=document.createElement('label');label.className='check workflow-option';
  const tick=document.createElement('input');tick.type='checkbox';tick.dataset.workflowIndex=String(i);tick.checked=item.selected!==false;
  tick.onchange=()=>{item.selected=tick.checked;invalidatePreparedCampaign();};
  const info=document.createElement('span');info.textContent=(i+1)+'. '+item.label+' · min. '+item.requiredRequests+' richieste';
  label.append(tick,info);list.append(label);
 });
 updateWorkflowRunControls();
}
async function chooseSavedWorkflow(){
 const i=Number($('workflowSaved').value),item=savedWorkflows[i];
 if(!item||item.specId!==specId)throw Error('Scegli un workflow configurato per lo Swagger attuale.');
 configId=item.configId;guidedApprovedYaml=item.yaml;resetWorkflowRunApprovals();
 $('configUsage').value='multi-resource';$('manifestEditor').value=item.yaml;$('configPaste').value=item.yaml;
 $('categorySelect').value='';filterTools();$('toolSelect').value='multi-resource-assess';toolDetails();
 $('workflowSavedStatus').textContent='✓ Selezionato «'+item.label+'» ('+item.requiredRequests+' richieste minime). Per eseguirlo autorizza scope e scritture nella sezione test.';
 $('toolMessage').textContent='Workflow pronto: '+item.label+'. Inizia con il piano offline, quindi abilita l’esecuzione autorizzata.';
 if($('bodyProbeWizard').open)await detectBodyProbeFields().catch(e=>show(e.message,true,'bodyProbeHint'));
}
async function combineSavedWorkflows(){
 if(!specId||!authId)throw Error('Carica Swagger e auth.yaml per la campagna multi-workflow.');
 const selected=savedWorkflows.filter(w=>w.specId===specId&&w.selected!==false);
 if(!selected.length)throw Error('Seleziona almeno un workflow nella lista.');
 if(selected.length>10)throw Error('Il motore supporta al massimo 10 risorse per campagna.');
 const result=await request('/api/control/manifest/compose',{method:'POST',
  headers:{'content-type':'application/json'},body:JSON.stringify({specification_id:specId,
   auth_config_id:authId,config_ids:selected.map(w=>w.configId)})});
 configId=result.id;$('configUsage').value='multi-resource';
 preparedCampaign={configId:result.id,specId,selectionKey:workflowSelectionKey(),requiredRequests:result.required_requests,resources:result.resources};
 resetWorkflowRunApprovals();updateWorkflowRunControls();
 $('maxRequests').value=String(Math.min(150,Math.max(clampNumeric('maxRequests'),result.required_requests)));
 $('categorySelect').value='';filterTools();$('toolSelect').value='multi-resource-assess';toolDetails();
 $('workflowSavedStatus').textContent='✓ Campagna multi-workflow preparata: '+result.resources+
 ' risorse indipendenti · almeno '+result.required_requests+' richieste HTTP. Nessuna scrittura eseguita. '+(result.required_requests>150?'Budget superiore al massimo per singolo job: dividi la campagna. ':'')+'Conferma scope e scritture prima di avviare.';
 $('configState').textContent='✓ Manifest combinato e validato offline ('+result.resources+' workflow)';
 $('toolMessage').textContent='Campagna pronta. Imposta un numero massimo di richieste sufficiente e conferma le autorizzazioni prima di avviare.';
 if($('bodyProbeWizard').open)await detectBodyProbeFields().catch(e=>show(e.message,true,'bodyProbeHint'));
}
function selectAllWorkflows(){for(const item of savedWorkflows)item.selected=true;invalidatePreparedCampaign();renderSavedWorkflows();}

function removeSavedWorkflow(){
 const i=Number($('workflowSaved').value);if(!Number.isInteger(i)||!savedWorkflows[i])return;
 const removed=savedWorkflows.splice(i,1)[0];
 invalidatePreparedCampaign();
 if(configId===removed.configId)configId='';
 renderSavedWorkflows();$('workflowSavedStatus').textContent='Workflow rimosso dalla lista. Nessuna richiesta HTTP inviata.';
}


// v0.80: purely local OpenAPI coverage preview. Never treat candidates as vulnerabilities.
let coverageData=null;
async function checkCompatibility(){
 if(!specId)throw Error('Prima carica la specifica OpenAPI nel Passaggio 1.');
 const params=new URLSearchParams({active:String($('suiteActive').checked),writes:String($('suiteWrites').checked),ai:String($('suiteAI').checked)});
 if(authId)params.set('auth_config_id',authId);
 if(evidenceJob)params.set('assessment_id',evidenceJob);
 coverageData=await request('/api/compatibility/'+encodeURIComponent(specId)+'?'+params);
 const sum=coverageData.summary;
 $('coverageSummary').textContent=`${sum.operations} operazioni · ${sum.read_operations} letture · ${sum.write_operations} scritture · ${sum.observed_operations} endpoint con evidenze HTTP (${sum.http_coverage_percent}%). ${!sum.coverage_is_measured?'Nessuna osservazione HTTP caricata: questa NON è una verifica della sicurezza.':''}`;
 renderCoverage();
}
function renderCoverage(){
 const host=$('coverageRows');host.replaceChildren();if(!coverageData)return;
 const filter=$('coverageFilter').value;
 const operations=(coverageData.operations||[]).filter(ep=>filter==='all'||(filter==='not_observed'?ep.coverage==='not_observed':ep.applicability===filter));
 for(const ep of operations.slice(0,500)){
  const row=document.createElement('tr');
  for(const value of [ep.operation,ep.applicability,`${ep.http_observations} risposte`,[...ep.missing_inputs,...ep.suggested_checks].join(' · ')||'Nessun input richiesto dallo Swagger']){
   const cell=document.createElement('td');cell.textContent=value;row.append(cell)
  }
  row.className=ep.coverage==='observed'?'coverage-observed':'coverage-unobserved';host.append(row)
 }
 if(!operations.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=4;td.textContent='Nessuna operazione per il filtro selezionato.';tr.append(td);host.append(tr)}
}

window.addEventListener('DOMContentLoaded',()=>{
 $('massWorkflowSelect').onchange=renderLocalMass;
 $('bflaWorkflowSelect').onchange=renderLocalBfla;
 for(const id of ['guidedMutation','guidedMutationBody','guidedMutationExpectedDeny'])$(id).addEventListener(id==='guidedMutationBody'?'input':'change',()=>saveLocalPanel('mass'));
 for(const id of ['guidedBflaAction','guidedBflaIdentity','guidedBflaPolicyAck'])$(id).addEventListener('change',()=>saveLocalPanel('bfla'));
 $('simpleAdvancedToggle').onclick=()=>{
  const active=$('simpleAdvancedToggle').getAttribute('aria-expanded')==='true';
  $('simpleAdvancedToggle').setAttribute('aria-expanded',String(!active));
  $('simpleAdvancedToggle').textContent=active?'Mostra strumenti specialistici':'Nascondi strumenti specialistici';
  for(const el of document.querySelectorAll('#step4,[data-simple-advanced]'))el.classList.toggle('simple-advanced-hidden',active);
 };
 $('guidedMutation').onchange=()=>{
  if(!$('guidedMutation').value){$('guidedMutationExpectedDeny').checked=false;}
  guideInvalidate();
 };
 $('guidedMutationInsert').onclick=()=>{try{mutationInsertField();saveLocalPanel('mass')}catch(e){guideError(e.message)}};
 $('guidedMutationExpectedDeny').onchange=()=>{mutationTogglePolicy();saveLocalPanel('mass')};
 $('guidedFind').onclick=()=>guideDiscover().catch(e=>guideError(e.message));
 $('guidedCandidate').onchange=guideUpdateCandidate;
 $('guidedNext1').onclick=()=>{try{guideUsers();guideGo(2)}catch(e){guideError(e.message)}};
 $('guidedBack2').onclick=()=>guideGo(1);
 $('guidedNext2').onclick=()=>{try{if(!$('guidedOwner').value)throw Error('Seleziona l’utente proprietario.');guidePrepareBody();guideGo(3)}catch(e){guideError(e.message)}};
 $('guidedBack3').onclick=()=>guideGo(2);
 $('guidedNext3').onclick=()=>{try{guideBody();guideReview();guideGo(4)}catch(e){guideError(e.message)}};
 $('guidedBack4').onclick=()=>guideGo(3);
 $('guidedDetectId').onclick=()=>{try{guideResponseId()}catch(e){guideError(e.message)}};
 $('guidedFinish').onclick=()=>guideFinish().catch(e=>guideError(e.message));
 prepareNumerics();
 $('manifestDiscover').onclick=()=>discoverManifest().catch(e=>show(e.message,true,'manifestState'));
 $('manifestCandidate').onchange=updateManifestFields;
 $('manifestEditor').addEventListener('input',()=>{if(configId){configId='';$('configState').textContent='Manifest modificato: valida e importa nuovamente prima di eseguire.'}});
 $('manifestCreate').onclick=()=>createManifest().catch(e=>show(e.message,true,'manifestState'));
 $('manifestValidate').onclick=()=>validateManifest().catch(e=>show(e.message,true,'manifestState'));
 $('manifestUse').onclick=()=>useManifest().catch(e=>show(e.message,true,'manifestState'));
 $('manifestDownload').onclick=()=>{try{downloadManifest()}catch(e){show(e.message,true,'manifestState')}};
 async function auditLogin(what){
  const config=what==='config';const output=$(config?'rc18OidcResult':'rc18KeysResult');
  const button=$(config?'rc18OidcRun':'rc18JwksRun');
  try{
   if(!specId)throw Error('Importa prima una specifica OpenAPI');
   if(!config&&!$('rc18JWKS').value.trim())throw Error('Incolla prima le chiavi JWKS pubbliche in formato JSON.');
   button.disabled=true;output.textContent='Controllo offline in corso…';
   const payload={specification_id:specId,expected_issuer:$('rc18Issuer').value.trim(),
    metadata_json:config?$('rc18Metadata').value:'',
    jwks_json:config?'':$('rc18JWKS').value,
    previous_jwks_json:config?'':$('rc18PreviousJWKS').value};
   const result=await request('/api/rc18/oidc-audit',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
   output.textContent=JSON.stringify(result,null,2);
   show(config?'Controllo della configurazione login completato (offline).':'Controllo delle chiavi pubbliche completato (offline).');
  }catch(e){output.textContent='Controllo bloccato: '+e.message;show(e.message,true)}
  finally{button.disabled=false;}
 }
 $('rc18OidcRun').onclick=()=>auditLogin('config');
 $('rc18JwksRun').onclick=()=>auditLogin('keys');
 async function rc19Offline(action){
  const quality=action==='quality',output=$(quality?'rc19QualityResult':'rc19BenchmarkResult');
  const button=$(quality?'rc19QualityRun':'rc19BenchmarkRun');
  try{
   if(!selectedJob)throw Error('Prima seleziona un job completato in «Evidenze e report».');
   let payload={};
   if(!quality){
    try{payload.ground_truth=JSON.parse($('rc19GroundTruth').value)}
    catch{throw Error('Ground truth: inserisci un JSON valido con la lista dei casi attesi.');}
   }
   button.disabled=true;output.textContent='Verifica offline in corso…';
   const result=await request('/api/rc19/'+(quality?'quality/':'benchmark/')+encodeURIComponent(selectedJob),
    {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
   output.textContent=JSON.stringify(result,null,2);
  }catch(e){output.textContent='Verifica non eseguita: '+e.message;show(e.message,true)}
  finally{button.disabled=false;}
 }
 $('rc19QualityRun').onclick=()=>rc19Offline('quality');
 $('rc19BenchmarkRun').onclick=()=>rc19Offline('benchmark');

 $('specFile').onchange=async()=>{try{const d=await upload($('specFile'),'/api/upload');if(d)await useSpec(d)}catch(e){show('Errore Swagger: '+e.message,true)}};
 $('specPasteBtn').onclick=async()=>{try{await useSpec(await importText('openapi','specPaste'))}catch(e){show(e.message,true)}};
 $('authFile').onchange=async()=>{try{const d=await upload($('authFile'),'/api/auth-config');if(d)await useAuth(d)}catch(e){show('Errore auth.yaml: '+e.message,true)}};
 $('authPasteBtn').onclick=async()=>{try{await useAuth(await importText('auth','authPaste'))}catch(e){show(e.message,true)}};
 $('generateAuth').onclick=async()=>{try{const d=await request('/api/auth-template');authTemplate=d.yaml;$('authPaste').value=authTemplate;$('downloadAuth').disabled=false;show('Esempio generato. Modifica i nomi dei profili e clicca Importa auth.yaml incollato.')}catch(e){show(e.message,true)}};
 $('downloadAuth').onclick=()=>{const url=URL.createObjectURL(new Blob([$('authPaste').value],{type:'text/yaml'}));const link=document.createElement('a');link.href=url;link.download='auth.yaml';link.click();URL.revokeObjectURL(url)};
 $('configFile').onchange=async()=>{try{const d=await upload($('configFile'),'/api/control/config');if(d){configId=d.id;$('configState').textContent='✓ '+d.name;show('Configurazione aggiuntiva caricata.')}}catch(e){show(e.message,true)}};
 $('configPasteBtn').onclick=async()=>{try{const d=await importText('config','configPaste');configId=d.id;$('configState').textContent='✓ Manifest importato';show('Configurazione aggiuntiva importata')}catch(e){show(e.message,true)}};
 $('toolSelect').onchange=toolDetails;$('categorySelect').onchange=filterTools;
 $('workflowChoose').onclick=()=>chooseSavedWorkflow().catch(e=>show(e.message,true,'workflowSavedStatus'));
 $('workflowRemove').onclick=removeSavedWorkflow;
 $('workflowCombine').onclick=()=>combineSavedWorkflows().catch(e=>show(e.message,true,'workflowSavedStatus'));
 $('workflowSelectAll').onclick=selectAllWorkflows;
 $('workflowRunSingle').onclick=()=>launchSingleWorkflow().catch(e=>show(e.message,true,'workflowRunStatus'));
 $('workflowRunCombined').onclick=()=>launchMultiWorkflow().catch(e=>show(e.message,true,'workflowRunStatus'));
 $('workflowSaved').onchange=()=>resetWorkflowRunApprovals();
 $('workflowRunSelect').onchange=()=>{resetWorkflowRunApprovals();updateWorkflowRunControls()};
 $('advancedToggle').onclick=()=>{const now=document.body.classList.toggle('simple-mode');$('advancedToggle').setAttribute('aria-expanded',String(!now));$('advancedToggle').textContent=now?'Mostra opzioni avanzate':'Nascondi opzioni avanzate';};
 $('rc13Plan').onclick=()=>planRC13().catch(e=>show(e.message,true,'rc13Status'));
 $('rc13Run').onclick=()=>runRC13().catch(e=>show(e.message,true,'rc13Status'));
 $('bodyProbeDetect').onclick=()=>detectBodyProbeFields().catch(e=>show(e.message,true,'bodyProbeHint'));
 $('bodyProbeDetectAll').onclick=async()=>{
  if(!specId)return show('Importa prima lo Swagger.',true,'bodyProbeHint');
  const select=$('bodyProbeWorkflowSelect'),previous=select.value;let done=0,failed=0;
  for(const [index,w] of savedWorkflows.entries()){
   if(w.specId!==specId)continue;
   select.value=String(index);try{await detectBodyProbeFields();done++;}catch(e){failed++;}
  }
  select.value=previous; if(previous!==''){try{await detectBodyProbeFields();}catch(e){}}
  renderBodyProbeCoverage();
  show('Campi rilevati per '+done+' workflow; '+failed+' non analizzabili. Le selezioni esistenti sono conservate. Seleziona esplicitamente i campi che autorizzi. Nessuna richiesta HTTP inviata.',false,'bodyProbeHint');
 };
 $('toolRC13Body').onchange=()=>{if($('toolRC13Body').checked){$('toolWrites').checked=true;$('execute').checked=true;}else $('toolRC13BodyAck').checked=false;};
 $('bodyProbeWizard').addEventListener('toggle',()=>{if($('bodyProbeWizard').open&&configId)detectBodyProbeFields().catch(e=>show(e.message,true,'bodyProbeHint'));});
 $('rc13Body').onchange=()=>{if($('rc13Body').checked){$('rc13Writes').checked=true;$('rc13Active').checked=true;}};
 $('rc13Writes').onchange=()=>{if($('rc13Writes').checked)$('rc13Active').checked=true;else{$('rc13Body').checked=false;$('rc13BodyAck').checked=false;}};
 $('suiteActive').onchange=()=>{if(!$('suiteActive').checked){$('suiteWrites').checked=false;$('suiteAck').checked=false;$('suiteWritesAck').checked=false;}updateSuiteOptions();};
 $('suiteWrites').onchange=()=>{if($('suiteWrites').checked)$('suiteActive').checked=true;else $('suiteWritesAck').checked=false;updateSuiteOptions();};
 updateSuiteOptions();
 $('coverageRun').onclick=()=>checkCompatibility().catch(e=>show(e.message,true,'coverageSummary'));
 $('coverageFilter').onchange=renderCoverage;
 $('suiteRun').onclick=()=>runSuite().catch(e=>show(e.message,true,'suiteStatus'));
 $('suitePreview').onclick=()=>previewSuite().catch(e=>show(e.message,true,'suitePreviewResult'));
 $('suiteStop').onclick=()=>stopSuite().catch(e=>show(e.message,true,'suiteStatus'));
 $('runTool').onclick=()=>run($('execute').checked).catch(e=>show(e.message,true,'toolMessage'));
 $('toolDry').onclick=()=>run(false).catch(e=>show(e.message,true,'toolMessage'));
 $('refreshBtn').onclick=refresh;
 $('previousJob').onchange=()=>{evidenceJob=$('previousJob').value;if(evidenceJob)viewJob(evidenceJob)};
 $('triageBtn').onclick=async()=>{if(!selectedJob)return show('Seleziona prima un risultato',true);try{$('reportPreview').textContent=JSON.stringify(await request('/api/triage/'+selectedJob),null,2)}catch(e){show(e.message,true)}};
 for(const [kind,id] of [['html','htmlBtn'],['pdf','pdfBtn'],['json','jsonBtn'],['md','mdBtn']])$(id).onclick=()=>openExport(kind);
 $('rawBtn').onclick=()=>{if(!selectedJob)return show('Seleziona prima un job completato',true);window.open('/api/control/download/'+encodeURIComponent(selectedJob),'_blank','noopener,noreferrer')};
 $('serviceRefresh').onclick=()=>statusAI().then(s=>{if(s)ollamaMessage(s.ollama_message)});
 $('ollamaModelPicker').onchange=()=>{$('ollamaModel').value=$('ollamaModelPicker').value;ollamaMessage('Modello selezionato: '+$('ollamaModelPicker').value)};
 $('ollamaStart').onclick=startOllama;
 $('ollamaTest').onclick=testOllama;
 $('ollamaStop').onclick=async()=>{
  if(!confirm('Arrestare soltanto il processo Ollama avviato da questa dashboard?'))return;
  try{const r=await request('/api/control/services/ollama/stop',{method:'POST'});ollamaMessage(r.message);await statusAI()}
  catch(e){ollamaMessage(e.message,true)}
 };
 $('ollamaPrepare').onclick=async()=>{
  if(!ollamaLastStatus||ollamaLastStatus.ollama!=='online')return ollamaMessage('Avvia Ollama prima di preparare il modello.',true);
  if(!confirm('Scaricare llama3.2:3b e creare achilles-local? Il download usa Internet, ma non invia dati dell’API.'))return;
  try{const j=await request('/api/control/ollama/prepare',{method:'POST'});ollamaMessage('Preparazione modello avviata. Segui il job '+j.id.slice(0,10)+' nei risultati.');await refresh()}
  catch(e){ollamaMessage(e.message,true)}
 };
 prepare();setInterval(refresh,4500);setInterval(statusAI,15000);
});


// RC4 — Regole di accesso create dal modulo; nessuno deve scrivere JSON.
function renderMatrixOptions(){
 const op=$('matrixOperation'), previous=op.value;op.replaceChildren();
 for(const entry of matrixGetOps){const option=document.createElement('option');
  option.value=`${entry.method} ${entry.path}`;option.textContent=option.value;op.append(option)}
 if([...op.options].some(option=>option.value===previous))op.value=previous;
 const names=matrixAuthProfiles.length?matrixAuthProfiles:$('profiles').value.split(',').map(v=>v.trim()).filter(Boolean);
 for(const id of ['matrixOwner','matrixOther']){
  const control=$(id),selected=control.value;control.replaceChildren();
  for(const name of names){const option=document.createElement('option');option.value=name;
   option.textContent=name;control.append(option)}
  if(names.includes(selected))control.value=selected;
  else if(id==='matrixOther'&&names.length>1)control.selectedIndex=1;
 }
 renderMatrixPathFields();renderMatrixRules();renderAutoMatrixOthers();
}
function renderAutoMatrixOthers(){
 const panel=$('autoMatrixOthers');if(!panel)return;
 const owner=$('matrixOwner').value;
 const oldChecks=[...panel.querySelectorAll('input[data-auto-other]')];
 const hadChoices=oldChecks.length>0;
 const checked=new Set(oldChecks.filter(x=>x.checked).map(x=>x.value));
 const title=panel.querySelector('legend'),hint=panel.querySelector('p.helper');
 panel.replaceChildren();if(title)panel.append(title);if(hint)panel.append(hint);
 for(const profile of matrixAuthProfiles.filter(x=>x!==owner)){
  const label=document.createElement('label');label.className='check';
  const checkbox=document.createElement('input');checkbox.type='checkbox';
  checkbox.dataset.autoOther='1';checkbox.value=profile;
  checkbox.checked=!hadChoices||checked.has(profile);
  label.append(checkbox,document.createTextNode(' '+profile));panel.append(label);
 }
}
$('matrixOwner')?.addEventListener('change',renderAutoMatrixOthers);
function renderMatrixPathFields(){
 const area=$('matrixPathFields');area.replaceChildren();
 const operation=$('matrixOperation').value;
 const placeholders=[...operation.matchAll(/\{([^{}]+)\}/g)].map(result=>result[1]);
 for(const name of [...new Set(placeholders)]){
  const label=document.createElement('label');label.textContent=`Valore del parametro ${name}`;
  const input=document.createElement('input');input.dataset.matrixPath=name;
  input.placeholder='ID di una risorsa di test autorizzata';input.maxLength=128;
  label.append(input);area.append(label);
 }
}
// L'editor e il task devono restare sincronizzati: una modifica invalida il vecchio snapshot.
function invalidateGeneratedMatrix(){
 if(matrixGeneratedConfigId&&configId===matrixGeneratedConfigId){
  configId='';if($('configState'))$('configState').textContent='Matrice modificata: genera la configurazione aggiornata prima di eseguire access-matrix.';
 }
 matrixGeneratedConfigId='';
 if($('suiteMatrixHelp'))$('suiteMatrixHelp').textContent='Matrice modificata: salva nuovamente le regole per includerle nella suite. Nessuna vecchia configurazione sarà riutilizzata.';
}
function renderMatrixRules(){
 const list=$('matrixRulesList');list.replaceChildren();
 matrixRules.forEach((rule,index)=>{
  const item=document.createElement('div');item.className='matrix-rule';
  const label=document.createElement('div');label.className='matrix-rule-text';
  const line=document.createElement('strong');line.textContent=`${index+1}. ${rule.operation}`;
  const details=document.createElement('div');details.className='matrix-rule-path';
  const params=Object.entries(rule.path_values||{}).map(([name,value])=>`${name}=${value}`).join(' · ');
  details.textContent=`${rule.owner} / ${rule.other} · primo: ${rule.expected_owner||'allow'} · secondo: ${rule.expected_other}${params?' · '+params:''}`;
  label.append(line,details);
  const remove=document.createElement('button');remove.type='button';remove.className='matrix-rule-remove';
  remove.textContent='×';remove.title=`Elimina regola ${rule.id}`;
  remove.setAttribute('aria-label',`Elimina regola ${index+1}: ${rule.operation}`);
  remove.addEventListener('click',()=>{matrixRules.splice(index,1);invalidateGeneratedMatrix();renderMatrixRules();});
  item.append(label,remove);list.append(item);
 });
 $('matrixExport').disabled=!matrixRules.length;
 $('matrixStatus').textContent=`${matrixRules.length} regole predisposte. Le credenziali non entrano nella configurazione.${matrixRules.length?' Premi Genera configurazione per applicare le modifiche.':''}`;
}
function nextMatrixRuleId(){
 const used=new Set(matrixRules.map(r=>r.id));
 for(let i=1;i<=10000;i++){const id=`rule-${i}`;if(!used.has(id))return id;}
 throw Error('Impossibile generare un ID di regola univoco.');
}
function validateMatrixPayload(doc){
 if(!specId||!matrixGetOps.length)throw Error('Passaggio 1: carica lo Swagger prima di importare le regole.');
 if(!authId||!matrixAuthProfiles.length)throw Error('Passaggio 3: carica auth.yaml prima di importare le regole.');
 if(!doc||typeof doc!=='object'||Array.isArray(doc)||Object.keys(doc).some(k=>k!=='rules'))throw Error('Il file JSON deve essere un oggetto contenente soltanto "rules".');
 if(!Array.isArray(doc.rules)||doc.rules.length<1||doc.rules.length>50)throw Error('Il file JSON deve contenere da 1 a 50 regole in "rules".');
 const knownOps=new Set(matrixGetOps.map(entry=>`${entry.method} ${entry.path}`));
 const names=new Set(matrixAuthProfiles),ids=new Set();
 return doc.rules.map((raw,i)=>{
  const n=i+1;
  if(!raw||typeof raw!=='object'||Array.isArray(raw))throw Error(`Regola ${n}: deve essere un oggetto.`);
  const keys=['id','operation','path_values','owner','other','expected_owner','expected_other'];
  if(Object.keys(raw).some(key=>!keys.includes(key)))throw Error(`Regola ${n}: contiene campi non previsti dal formato della matrice.`);
  const id=raw.id===undefined?`rule-${n}`:raw.id;
  if(typeof id!=='string'||id.length<1||id.length>64||ids.has(id))throw Error(`Regola ${n}: ID assente, duplicato o troppo lungo.`);
  ids.add(id);
  if(typeof raw.operation!=='string'||!knownOps.has(raw.operation))throw Error(`Regola ${n}: ${String(raw.operation)} non è una GET presente nello Swagger caricato.`);
  if(typeof raw.owner!=='string'||typeof raw.other!=='string'||!names.has(raw.owner)||!names.has(raw.other)||raw.owner===raw.other)
   throw Error(`Regola ${n}: owner e other devono essere due profili diversi presenti in auth.yaml.`);
  const expected_owner=raw.expected_owner===undefined?'allow':raw.expected_owner;
  if(!['allow','deny'].includes(expected_owner)||!['allow','deny'].includes(raw.expected_other))
   throw Error(`Regola ${n}: expected_owner e expected_other devono essere allow o deny.`);
  const values=raw.path_values===undefined?{}:raw.path_values;
  if(!values||typeof values!=='object'||Array.isArray(values)||Object.keys(values).length>15)
   throw Error(`Regola ${n}: path_values deve essere un oggetto con non più di 15 parametri.`);
  const placeholders=[...new Set([...raw.operation.matchAll(/\{([^{}]+)\}/g)].map(m=>m[1]))];
  if(Object.keys(values).length!==placeholders.length||Object.keys(values).some(k=>!placeholders.includes(k)))
   throw Error(`Regola ${n}: path_values deve contenere esattamente i parametri ${placeholders.join(', ')||'(nessuno)'}.`);
  const cleaned={};
  for(const name of placeholders){
   const value=values[name];
   if(!(typeof value==='string'||(typeof value==='number'&&Number.isSafeInteger(value))))throw Error(`Regola ${n}: ${name} deve essere un ID testuale o intero.`);
   const str=String(value);
   if(!str||str.length>128||str==='.'||str==='..'||/[\/\\?%#\r\n]/.test(str))
    throw Error(`Regola ${n}: valore del parametro ${name} mancante o non consentito.`);
   cleaned[name]=str;
  }
  return {id,operation:raw.operation,owner:raw.owner,other:raw.other,expected_owner,expected_other:raw.expected_other,path_values:cleaned};
 });
}
async function importMatrixJSON(file){
 if(!file)return;
 if(file.size>128*1024)throw Error('File troppo grande: massimo 128 KiB.');
 let parsed;
 try{parsed=JSON.parse(await file.text())}catch{throw Error('Il file non è un JSON valido. Correggilo e riprova.');}
 const validated=validateMatrixPayload(parsed); // Atomico: non cambia nulla in caso di errore.
 matrixRules=validated;invalidateGeneratedMatrix();renderMatrixRules();
 // "Importa JSON" means the matrix is ready for the suite, not just displayed
 // in an editor. Persist the validated snapshot without replacing a workflow.
 await generateMatrix(false);
 $('matrixStatus').textContent=`✓ ${validated.length} regole importate e salvate automaticamente: la suite le riutilizzerà per access-probe, access-matrix e verify-access-policy. Nessuna richiesta HTTP inviata.`;
}
function downloadMatrixJSON(){
 if(!matrixRules.length)throw Error('Non ci sono regole da esportare.');
 const url=URL.createObjectURL(new Blob([JSON.stringify({rules:matrixRules},null,2)+'\n'],{type:'application/json'}));
 const a=document.createElement('a');a.href=url;a.download='access-matrix.rules.json';document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function addMatrixRule(){
 const operation=$('matrixOperation').value,owner=$('matrixOwner').value,other=$('matrixOther').value;
 if(!operation)throw Error('Importa lo Swagger: non ci sono operazioni GET.');
 if(!owner||!other||owner===other)throw Error('Servono due utenti differenti dal file auth.yaml.');
 if(matrixRules.length>=50)throw Error('La matrice supporta al massimo 50 regole.');
 const path_values={};
 for(const input of document.querySelectorAll('[data-matrix-path]')){
  if(!input.value.trim())throw Error('Compila l’ID della risorsa per '+input.dataset.matrixPath);
  path_values[input.dataset.matrixPath]=input.value.trim();
 }
 const newRule={id:nextMatrixRuleId(),operation,owner,other,
  expected_owner:$('matrixOwnerExpected').value,expected_other:$('matrixExpected').value,path_values};
 validateMatrixPayload({rules:[...matrixRules,newRule]});
 matrixRules.push(newRule);invalidateGeneratedMatrix();renderMatrixRules();
}
async function generateMatrix(selectTask=true){
 if(!specId||!authId)throw Error('Carica prima Swagger e auth.yaml.');
 if(!matrixRules.length)throw Error('Aggiungi almeno una regola.');
 matrixRules=validateMatrixPayload({rules:matrixRules});
 // Il server archivia la configurazione YAML/JSON come allegato opaco.
 const payload={kind:'config',name:'access-matrix.rules.json',content:JSON.stringify({rules:matrixRules})};
 const data=await request('/api/import-text',{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify(payload)});
 matrixGeneratedConfigId=data.id;
 if($('suiteMatrixHelp'))$('suiteMatrixHelp').textContent=`✓ ${matrixRules.length} regole di accesso salvate: access-probe userà una regola, access-matrix tutte e verify-access-policy le evidenze HTTP. Manifest workflow indipendenti.`;
 if(selectTask){
  configId=data.id;$('configUsage').value='context';
  $('categorySelect').value='';filterTools();
  $('toolSelect').value='access-matrix';toolDetails();
  show('Matrice generata. Puoi avviare access-matrix o la suite completa.');
 }
 $('matrixStatus').textContent=`✓ ${matrixRules.length} regole salvate. Access-probe, access-matrix e verify-access-policy nella suite useranno questa matrice, indipendentemente dai manifest workflow.`;
}
function autoMatrixIds(){
 const raw=$('autoMatrixIds').value.trim()||$('pathValues').value.trim();
 const values={};
 for(const line of raw.split(/\r?\n/).map(s=>s.trim()).filter(Boolean)){
  const match=line.match(/^([a-zA-Z_][a-zA-Z0-9_.-]{0,63})=(.{1,128})$/);
  if(!match||/[\\/?%#\r\n]/.test(match[2])||match[2]==='.'||match[2]==='..')
   throw Error('ID non valido: usa NAME=VALUE senza caratteri URL o separatori.');
  values[match[1]]=match[2];
 }
 return values;
}
async function autoGenerateMatrix(){
 if(!specId||!authId)throw Error('Importa Swagger e auth.yaml prima di generare la matrice.');
 if(!$('autoMatrixPolicyAck').checked)throw Error('Conferma prima la policy aziendale di accesso degli altri profili.');
 const profiles=matrixAuthProfiles,owner=$('matrixOwner').value||profiles[0];
 const selected=new Set([...document.querySelectorAll('#autoMatrixOthers input[data-auto-other]:checked')].map(x=>x.value));
 const others=profiles.filter(x=>x!==owner&&selected.has(x));
 if(!owner||!others.length)throw Error('Seleziona almeno una identità da confrontare nel riquadro «Identità da confrontare», poi conferma la policy.');
 const values=autoMatrixIds();
 if(!Object.keys(values).length)throw Error('Inserisci almeno un ID di risorsa temporanea nel campo sopra.');
 const rows=[],skipped=[];
 const existing=new Set();
 for(const item of matrixGetOps){
  const op=`${item.method} ${item.path}`;
  const keys=[...new Set([...item.path.matchAll(/\{([^{}]+)\}/g)].map(x=>x[1]))];
  if(!keys.length)continue;
  if(keys.some(x=>values[x]===undefined)){
   skipped.push(op+' (ID richiesti: '+keys.filter(x=>values[x]===undefined).join(', ')+')');continue;
  }
  for(const other of others){
   const key=op+'|'+other;if(existing.has(key))continue;existing.add(key);
   rows.push({id:'auto-'+(rows.length+1),operation:op,owner,other,
    expected_owner:'allow',expected_other:'deny',path_values:Object.fromEntries(keys.map(k=>[k,values[k]]))});
  }
 }
 if(rows.length>50){
  // Do not quietly skip beyond the access-matrix backend's known safety cap.
  $('autoMatrixStatus').textContent=rows.length+' regole candidate, ma il limite è 50 per campagna. Riduci le identità oppure usa più campagna autorizzate.';
  return;
 }
 if(!rows.length)throw Error('Nessuna GET con ID completi. Controlla i nomi dei parametri nella tabella «Copertura automatica».');
 matrixRules=validateMatrixPayload({rules:rows});invalidateGeneratedMatrix();renderMatrixRules();
 await generateMatrix(false);
 $('autoMatrixStatus').textContent=`${rows.length} regole BOLA candidate generate e salvate. ${skipped.length} GET non incluse per ID mancanti: ${skipped.slice(0,3).join(' · ')||'nessuna'}. Tutti gli accessi sono ancora da verificare.`;
 $('suiteMatrixHelp').textContent='Matrice BOLA generata per tutte le GET con ID forniti. La suite riutilizzerà automaticamente tutte le '+rows.length+' regole.';
}
$('autoMatrixGenerate')?.addEventListener('click',()=>autoGenerateMatrix().catch(e=>show(e.message,true,'autoMatrixStatus')));
$('matrixOperation')?.addEventListener('change',renderMatrixPathFields);
$('matrixAdd')?.addEventListener('click',()=>{try{addMatrixRule()}catch(e){show(e.message,true,'matrixStatus')}});
$('matrixClear')?.addEventListener('click',()=>{matrixRules=[];invalidateGeneratedMatrix();renderMatrixRules()});
$('matrixGenerate')?.addEventListener('click',()=>generateMatrix().catch(e=>show(e.message,true,'matrixStatus')));
$('matrixImportFile')?.addEventListener('change',async(event)=>{
 try{await importMatrixJSON(event.target.files?.[0])}catch(e){show(e.message,true,'matrixStatus')}
 finally{event.target.value='';}
});
$('matrixExport')?.addEventListener('click',()=>{try{downloadMatrixJSON()}catch(e){show(e.message,true,'matrixStatus')}});
$('profiles')?.addEventListener('change',renderMatrixOptions);

$('guidedProbeId')?.addEventListener('click',()=>guideProbeIdentifier().catch(e=>{ $('guidedProbeResult').textContent=e.message }));

// RC16 offline helper: sends *only* the OpenAPI upload ID, never target credentials.
$('manifestRC16Discover')?.addEventListener('click', async()=>{
 try{
  if(!specId)throw Error('Importa prima lo Swagger nel passaggio 1.');
  const profiles=($('profiles')?.value||'').split(',').map(s=>s.trim()).filter(Boolean);
  const data=await request('/api/control/rc16/discover',{
   method:'POST',headers:{'content-type':'application/json'},
   body:JSON.stringify({action:'rc16-workflows',specification_id:specId,profiles:profiles.slice(0,1)})});
  $('manifestEditor').value=JSON.stringify(data.draft,null,2);
  $('configUsage').value='multi-resource';
  $('manifestCandidatesState').textContent=`${data.discovery.total_candidates} workflow candidati rilevati; ${data.draft.resources.length} bozze con POST/GET/DELETE. Nessuna richiesta inviata.`;
  $('manifestState').textContent='Bozza multi-risorsa creata. Compila REVIEW_, verifica i JSON Pointer degli ID e approva il cleanup prima di validarla.';
  $('manifestEditor').focus();
 }catch(e){show(e.message,true,'manifestState')}
});
