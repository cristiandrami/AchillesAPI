'use strict';
// Single-source-of-truth wizard: no hidden shared state between separate panels.
const $=id=>document.getElementById(id);
let csrf='',specId='',authId='',configId='',selectedJob='',evidenceJob='',catalog=[],authTemplate='',manifestCandidates=[];
let savedWorkflows=[];let previousJobs=[]; // Each workflow is isolated by its uploaded configuration ID.
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
 'scope-audit':'Verifica che URL e host siano coerenti con il perimetro autorizzato.'
};
function show(text,isError=false,at='globalMessage'){const target=$(at);if(!target)return;target.textContent=text;target.classList.toggle('error',isError)}
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
async function upload(input,path){const f=input.files?.[0];if(!f)return null;const form=new FormData();form.append('file',f);return request(path,{method:'POST',body:form})}
async function importText(kind,id){const content=$(id).value.trim();if(!content)throw Error('Incolla prima il contenuto YAML/JSON');return request('/api/import-text',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({kind,content,name:'contenuto-incollato.yaml'})})}
async function useSpec(data){specId=data.id;selectedJob='';evidenceJob='';configId='';savedWorkflows=[];renderSavedWorkflows();$('workflowSavedStatus').textContent='Nuovo Swagger: prepara uno o più workflow relativi a questa API.';$('specState').textContent=`✓ ${data.title} · ${data.operations} operazioni riconosciute`;manifestCandidates=[];$('manifestCandidatesState').textContent='Swagger importato: puoi cercare workflow CRUD.';const details=await request('/api/summary/'+specId);const box=$('operationsList');box.replaceChildren();for(const op of details.endpoints){const row=document.createElement('div');row.className='operation';const method=document.createElement('b');method.textContent=op.method;row.append(method,document.createTextNode(op.path));box.append(row)}show('Swagger importato correttamente. Ora configura l’indirizzo del target.')}
async function useAuth(data){authId=data.id;const descriptions=data.descriptions||data.profiles||[];let envs=[];let names=[];for(const item of descriptions){if(typeof item==='string'){names.push(item);continue}names.push(item.name);envs.push(...(item.environment_variables||[]))}envs=[...new Set(envs)];$('authState').textContent='✓ Profili configurati: '+names.join(', ')+(envs.length?' · segreti richiesti: '+envs.join(', '):'');$('profiles').value=names.join(', ');for(const id of ['manifestOwner','manifestOther']){const select=$(id);select.replaceChildren();if(id==='manifestOther'){const none=document.createElement('option');none.value='';none.textContent='Nessuna';select.append(none)}for(const name of names){const opt=document.createElement('option');opt.value=name;opt.textContent=name;select.append(opt)}}const box=$('secretFields');box.replaceChildren();for(const name of envs){const label=document.createElement('label');label.textContent=name;const field=document.createElement('input');field.type='password';field.dataset.secret=name;field.placeholder='Inserisci il valore, non viene salvato sul server';field.autocomplete='off';label.append(field);box.append(label)}show('File auth.yaml valido. Compila i token/password necessari per il test attivo.')}
function toolDetails(){const obj=catalog.find(x=>x.name===$('toolSelect').value);if(!obj)return;
 // Offline tools never inherit active-network state from the previous tool.
 const offline=!obj.active;
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
$('toolName').textContent=obj.name;$('toolInfo').textContent=explanations[obj.name]||`Strumento ${obj.category}: consulta l’output per controlli e risultati.`;
 const prior=$('previousJob')?.closest('.toolinfo');
 if(prior)prior.hidden=!['both','report','report-config','config-report'].includes(obj.requirements);
 const aiMandatory=['ai-correlate','ai-analyze'].includes(obj.name);
 if(aiMandatory){$('modeExplanation').textContent='Questo strumento usa SEMPRE Ollama locale; controlla Stato Ollama e Modello. Non invia richieste alla API target.';}
 $('requirements').textContent=(reqText[obj.requirements]||obj.requirements)+(obj.active?' · Può inviare richieste con conferma':' · Analisi offline')+(obj.writes?' · Modifica risorse di test e richiede cleanup':'');$('toolWrites').disabled=!(obj.writes||obj.name==='auto-assess');if($('toolWrites').disabled)$('toolWrites').checked=false;$('toolAI').disabled=!obj.ai;if(!obj.ai)$('toolAI').checked=false}
function filterTools(){const category=$('categorySelect').value;const current=$('toolSelect').value;const select=$('toolSelect');select.replaceChildren();for(const tool of catalog.filter(t=>!category||t.category===category)){const opt=document.createElement('option');opt.value=tool.name;opt.textContent=tool.name;select.append(opt)}if([...select.options].some(x=>x.value===current))select.value=current;toolDetails()}
function secrets(){const entries={};for(const input of document.querySelectorAll('[data-secret]'))if(input.value)entries[input.dataset.secret]=input.value;return entries}
function currentConfig(execute){return {action:$('toolSelect').value,specification_id:specId||null,assessment_id:evidenceJob||null,config_id:configId||null,auth_config_id:authId||null,base_url:$('baseUrl').value.trim(),allow_host:$('allowHost').value.trim(),execute,acknowledgment:$('toolAck').checked,approve_writes:$('toolWrites').checked,max_requests:clampNumeric('maxRequests'),rate:clampNumeric('rate'),budget:clampNumeric('agentBudget'),profiles:$('profiles').value.split(',').map(x=>x.trim()).filter(Boolean),path_values:$('pathValues').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean),ai:$('toolAI').checked,model:$('ollamaModel').value.trim(),allow_insecure_http:$('insecure').checked,config_usage:$('configUsage').value,secrets:secrets()}}
async function run(execute){const obj=catalog.find(t=>t.name===$('toolSelect').value);if(!obj)throw Error('Seleziona uno strumento');execute=Boolean(execute&&obj.active);const params=currentConfig(execute);if(!execute)params.approve_writes=false;if(['spec','both','spec-config'].includes(obj.requirements)&&!specId)throw Error('Passaggio 1: importa prima lo Swagger/OpenAPI');if(['spec-config','report-config','config:json','config-report'].includes(obj.requirements)&&!configId)throw Error('Passaggio 4: importa il manifesto YAML/JSON richiesto');if(['report','both','report-config','config-report'].includes(obj.requirements)&&!evidenceJob)throw Error('Questo controllo analizza un risultato esistente. 1) Esegui auto-assess (attivo per correlazioni HTTP). 2) In “Analisi precedente”, seleziona il risultato completato. 3) Avvia questo controllo.');
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
const result=await request('/api/control/jobs',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(params)});show('Avviato '+params.action+' · ID '+result.id.slice(0,10)+' · controlla Risultati.');$('toolMessage').textContent='Job avviato: '+result.id;await refresh()}
async function runSuite(){
 if(!specId)throw Error('Carica prima lo Swagger al passaggio 1.');
 const include_active=$('suiteActive').checked;
 const include_writes=$('suiteWrites').checked;
 const params=currentConfig(include_active);
 params.action='auto-assess';
 params.approve_writes=include_writes;
 if(include_active&&(!params.acknowledgment||!params.base_url||!params.allow_host))throw Error('Per i test HTTP inserisci URL, allowlist e spunta la conferma di autorizzazione nel passaggio 4.');
 if(include_writes&&(!include_active||!configId||!authId||!$('toolWrites').checked))throw Error('Per i test di scrittura servono modalità HTTP, auth.yaml, manifest e spunta Approvo le scritture nel passaggio 4.');
 const payload={config:params,include_active,include_writes,include_ai:$('suiteAI').checked,include_optional:$('suiteOptional').checked,max_total_requests:Math.max(1,Math.min(600,parseInt($('suiteBudget').value,10)||300))};
 const result=await request('/api/control/suite',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
 $('suiteStatus').textContent='Suite avviata · '+result.id.slice(0,10)+' · '+result.total+' funzionalità considerate. Consulta i risultati per lo stato dei singoli test.';
 await refresh();
}
function explainJobError(raw){
 const e=String(raw||'');const lower=e.toLowerCase();
 if(lower.includes('environment variable')||lower.includes('required by profile'))return 'Credenziale mancante: controlla auth.yaml e compila tutti i token/password richiesti nel Passaggio 3. Dettaglio: '+e.slice(-280);
 if(lower.includes('scope')||lower.includes('allow-host')||lower.includes('outside approved'))return 'Target fuori scope: verifica Base URL e Host autorizzato al Passaggio 2. '+e.slice(-180);
 if(lower.includes('budget')||lower.includes('max-requests'))return 'Budget richieste insufficiente: aumenta Max Requests entro il limite, oppure riduci i controlli. '+e.slice(-180);
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
  const parents=jobs.filter(j=>j.action==='full-suite');const bySuite=new Map();for(const j of jobs){if(j.suite_id){if(!bySuite.has(j.suite_id))bySuite.set(j.suite_id,[]);bySuite.get(j.suite_id).push(j)}}
  function addJob(job,into){const row=document.createElement('div');row.className='job';const title=document.createElement('div');const b=document.createElement('b');b.textContent=job.action||job.mode;const status=document.createElement('div');status.textContent=job.action==='full-suite'?`${job.status} · ${job.completed_steps||0}/${job.total||0} funzioni · ${job.current_step||'conclusa'}`:`${job.status} · ${job.id.slice(0,8)}`;status.className='helper';title.append(b,status);if(job.error){const error=document.createElement('small');error.textContent=explainJobError(job.error);title.append(error)}row.append(title);if(job.action==='full-suite'||job.status==='complete'){const btn=document.createElement('button');btn.textContent=job.action==='full-suite'?'Apri suite interattiva in nuova scheda':'Esplora in nuova scheda';btn.onclick=()=>window.open('/job/'+encodeURIComponent(job.id),'_blank','noopener,noreferrer');row.append(btn)}if(job.status==='complete'&&job.action!=='full-suite'){const select=document.createElement('button');select.textContent='Seleziona per export';select.onclick=()=>viewJob(job.id);row.append(select)}into.append(row)}
  for(const parent of [...parents].reverse()){
   const group=document.createElement('details');group.className='suite-job-group';const summary=document.createElement('summary');summary.textContent='Suite '+parent.id.slice(0,9)+' · '+parent.status+' · '+(parent.completed_steps||0)+'/'+(parent.total||0)+' task';group.append(summary);
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
   opt.textContent=(job.action||job.mode)+' · '+job.id.slice(0,8)+(job.http_observations>0?' · '+job.http_observations+' risposte HTTP':job.active?' · nessuna osservazione HTTP':' · offline');select.append(opt);
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
async function statusAI(){try{const state=await request('/api/control/services');$('ollamaStatus').textContent=state.ollama;$('modelList').textContent=(state.ollama_models||[]).join(', ')||'Nessun modello disponibile'}catch(e){show(e.message,true)}}
async function prepare(){try{csrf=(await request('/api/bootstrap')).csrf_token;catalog=await request('/api/control/tools');const cats=[...new Set(catalog.map(t=>t.category))].sort();for(const name of cats){const opt=document.createElement('option');opt.value=name;opt.textContent=name;$('categorySelect').append(opt)}filterTools();$('toolSelect').value='auto-assess';toolDetails();await refresh();await statusAI()}catch(e){show('Errore inizializzazione: '+e.message,true)}}
async function discoverManifest(){
 if(!specId)throw Error('Passaggio 1: carica prima uno Swagger/OpenAPI.');
 const data=await request('/api/control/manifest/candidates/'+specId);
 manifestCandidates=data.candidates||[];
 const select=$('manifestCandidate');select.replaceChildren();
 manifestCandidates.forEach((x,i)=>{const option=document.createElement('option');option.value=String(i);option.textContent=x.create+' → '+x.read+' → '+x.delete;select.append(option)});
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
 $('manifestState').textContent='Controlla i campi obbligatori del payload: '+(c.required.join(', ')||'nessuno dichiarato')+'. I valori proposti non sono automaticamente validi per il target.';
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
let guidedStep=1, guidedCandidate=null, guidedApprovedYaml='';
const guideError=(message)=>{const e=$('guidedError');e.hidden=false;e.textContent='Cosa devi correggere: '+message;e.scrollIntoView({behavior:'smooth',block:'nearest'});};
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
 manifestCandidates=response.candidates||[];
 const choices=$('guidedCandidate');choices.replaceChildren();
 for(let index=0;index<manifestCandidates.length;index++){
  const c=manifestCandidates[index];const opt=document.createElement('option');opt.value=String(index);
  opt.textContent=c.create+' → '+c.read+' → '+c.delete;choices.append(opt);
 }
 if(!manifestCandidates.length){
   $('guidedCandidateHelp').textContent='Lo Swagger non descrive un ciclo completo di creazione, lettura e cancellazione. Puoi eseguire comunque tutti i test di lettura (GET). Per scritture serve una procedura di cleanup approvata e una configurazione avanzata.';
   choices.disabled=true;$('guidedNext1').disabled=true;return;
 }
 choices.disabled=false;$('guidedNext1').disabled=false;
 guideUpdateCandidate();
}
function guideUpdateCandidate(){
 guidedCandidate=manifestCandidates[Number($('guidedCandidate').value)]||null;
 if(!guidedCandidate)return;
 const c=guidedCandidate;
 $('guidedCandidateHelp').textContent='Verrà creata UNA risorsa tramite '+c.create+', verificata tramite '+c.read+' e cancellata tramite '+c.delete+'. Non inizierà nessuna richiesta senza la tua approvazione finale.';
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
function guidePrepareBody(){
 const c=guidedCandidate;if(!c)throw Error('Scegli prima una risorsa da testare.');
 const fieldBox=$('guidedPayloadFields');fieldBox.replaceChildren();
 const fields=new Set([...c.required,...c.marker_candidates]);
 // Optional properties are deliberately not sent: minimize side effects.
 for(const name of fields){if(!c.field_specs[name])continue;
  fieldBox.append(guideCreateField(name,c.field_specs[name],c.body_example[name],c.required.includes(name)||c.marker_candidates.includes(name)));
 }
 guideSelect($('guidedMarker'),c.marker_candidates);
 $('guidedPayloadHelp').textContent='Sono mostrati soltanto i campi obbligatori e i campi di marcatura. Gli altri campi non vengono modificati. Il testo di marcatura serve a dimostrare che l’oggetto è stato creato dal test.';
 $('guidedId').value=(c.id_candidates.length===1?c.id_candidates[0]:'');
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
 $('guidedReview').textContent='Il test creerà una risorsa con '+c.create+', la leggerà con '+c.read+' e proverà a cancellarla con '+c.delete+'. Prima di DELETE, AchillesAPI controllerà ID e marcatore. Se la verifica fallisce, non cancellerà un oggetto incerto.';
}
function guideResponseId(){
 const raw=$('guidedResponseExample').value.trim();if(!raw)throw Error('Incolla prima un esempio di risposta JSON della POST, oppure compila il nome del campo ID direttamente.');
 let parsed;try{parsed=JSON.parse(raw)}catch{throw Error('La risposta incollata non è JSON valido. Esempio: {"id":"abc123"}.')}
 if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw Error('Incolla un oggetto JSON con proprietà come id, project_ref o uuid.');
 const names=Object.keys(parsed).filter(x=>/^(id|uuid|.*_id|.*Id|.*ref)$/i.test(x)&&typeof parsed[x]==='string'||/^(id|uuid|.*_id|.*Id|.*ref)$/i.test(x)&&typeof parsed[x]==='number');
 if(names.length===1){$('guidedId').value=names[0];$('guidedReview').textContent='Campo ID individuato: '+names[0]+'. Verifica che la GET restituisca lo stesso campo.';return}
 if(names.length>1)throw Error('Ci sono più possibili campi ID ('+names.join(', ')+'). Scegli quello che identifica la risorsa appena creata.');
 throw Error('Non trovo un campo ID evidente. Controlla la risposta della POST e inserisci il nome esatto della proprietà.');
}
async function guideFinish(){
 guideClear();guideInvalidate();
 if(!$('guidedConfirm').checked)throw Error('Per procedere devi confermare che l’API consente la creazione e la cancellazione di queste risorse temporanee.');
 const owner=$('guidedOwner').value,other=$('guidedOther').value;
 if(!owner)throw Error('Seleziona il profilo che deve creare la risorsa.');
 if(other&&other===owner&&$('guidedDeny').checked)throw Error('Scegli un secondo utente diverso dal proprietario, oppure disattiva il controllo sull’accesso.');
 const ident=$('guidedId').value.trim();if(!ident)throw Error('Indica il nome del campo ID nella risposta POST: per esempio id. La specifica OpenAPI non lo dichiara sempre.');
 const body=guideBody();const c=guidedCandidate;const mark=$('guidedMarker').value;
 if(!body[mark])throw Error('Compila il campo «'+mark+'»: serve a riconoscere la risorsa temporanea.');
 const payload={specification_id:specId,auth_config_id:authId,candidate_index:Number($('guidedCandidate').value),identity:owner,other_identity:other,deny_other:$('guidedDeny').checked,marker:mark,identifier:ident,body};
 const result=await request('/api/control/manifest/guided',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
 const upload=await request('/api/import-text',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({kind:'config',content:result.yaml,name:'resources.yaml'})});
 configId=upload.id;guidedApprovedYaml=result.yaml;
 const label=(c.create+' → '+c.read).slice(0,160);
 savedWorkflows.push({label,configId:upload.id,yaml:result.yaml,specId,requiredRequests:result.required_requests});
 renderSavedWorkflows();$('workflowSaved').value=String(savedWorkflows.length-1);
 $('workflowSavedStatus').textContent='✓ Salvato «'+label+'». Puoi aprire la procedura per aggiungere altri workflow; questo non verrà perso.';

 $('configUsage').value='multi-resource';$('configPaste').value=result.yaml;
 $('manifestEditor').value=result.yaml;
 $('configState').textContent='✓ Manifest di risorsa temporanea pronto · creato dalla procedura guidata';
 $('manifestState').textContent='✓ Manifest generato senza segnaposto e verificato offline';
 $('categorySelect').value='';filterTools();$('toolSelect').value='multi-resource-assess';toolDetails();
 const block=$('guidedResult');block.hidden=false;block.replaceChildren();
 const title=document.createElement('strong');title.textContent='✓ Configurazione pronta. Non è stata inviata alcuna richiesta HTTP.';block.append(title);
 const details=document.createElement('p');details.textContent='Per la prova servono almeno '+result.required_requests+' richieste. Il manifest è già caricato: non devi copiare o modificare YAML.';block.append(details);
 const download=document.createElement('button');download.type='button';download.className='secondary';download.textContent='Scarica il file tecnico (facoltativo)';download.onclick=()=>{const url=URL.createObjectURL(new Blob([guidedApprovedYaml],{type:'text/yaml'}));const a=document.createElement('a');a.href=url;a.download='resources.yaml';a.click();URL.revokeObjectURL(url)};block.append(download);
 const next=document.createElement('button');next.type='button';next.className='primary';next.textContent='Vai a eseguire il test';next.style.marginLeft='8px';next.onclick=()=>{ $('toolMessage').textContent='Configurazione pronta. Imposta un budget sufficiente, abilita le richieste e conferma l’autorizzazione; poi premi Avvia strumento selezionato.'; $('guidedDrawer').open=false;$('workflowLibraryPanel').scrollIntoView({behavior:'smooth',block:'center'});$('toolSelect').scrollIntoView({behavior:'smooth',block:'center'})};block.append(next);
}

// A Swagger can expose many independent CRUD cycles. Keep every validated manifest
// separately, since merging them would require a verified dependency/cleanup graph.
function renderSavedWorkflows(){
 const select=$('workflowSaved');if(!select)return;
 select.replaceChildren();
 if(!savedWorkflows.length){const opt=document.createElement('option');opt.value='';opt.textContent='Non hai ancora preparato un workflow';select.append(opt);return;}
 savedWorkflows.forEach((item,i)=>{const opt=document.createElement('option');opt.value=String(i);opt.textContent=(i+1)+'. '+item.label;select.append(opt)});
}
async function chooseSavedWorkflow(){
 const i=Number($('workflowSaved').value),item=savedWorkflows[i];
 if(!item||item.specId!==specId)throw Error('Scegli un workflow configurato per lo Swagger attuale.');
 configId=item.configId;guidedApprovedYaml=item.yaml;
 $('configUsage').value='multi-resource';$('manifestEditor').value=item.yaml;$('configPaste').value=item.yaml;
 $('categorySelect').value='';filterTools();$('toolSelect').value='multi-resource-assess';toolDetails();
 $('workflowSavedStatus').textContent='✓ Selezionato «'+item.label+'» ('+item.requiredRequests+' richieste minime). Per eseguirlo autorizza scope e scritture nella sezione test.';
 $('toolMessage').textContent='Workflow pronto: '+item.label+'. Inizia con il piano offline, quindi abilita l’esecuzione autorizzata.';
}
function removeSavedWorkflow(){
 const i=Number($('workflowSaved').value);if(!Number.isInteger(i)||!savedWorkflows[i])return;
 const removed=savedWorkflows.splice(i,1)[0];
 if(configId===removed.configId)configId='';
 renderSavedWorkflows();$('workflowSavedStatus').textContent='Workflow rimosso dalla lista. Nessuna richiesta HTTP inviata.';
}

window.addEventListener('DOMContentLoaded',()=>{
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
 $('suiteRun').onclick=()=>runSuite().catch(e=>show(e.message,true,'suiteStatus'));
 $('runTool').onclick=()=>run($('execute').checked).catch(e=>show(e.message,true,'toolMessage'));
 $('toolDry').onclick=()=>run(false).catch(e=>show(e.message,true,'toolMessage'));
 $('refreshBtn').onclick=refresh;
 $('previousJob').onchange=()=>{evidenceJob=$('previousJob').value;if(evidenceJob)viewJob(evidenceJob)};
 $('triageBtn').onclick=async()=>{if(!selectedJob)return show('Seleziona prima un risultato',true);try{$('reportPreview').textContent=JSON.stringify(await request('/api/triage/'+selectedJob),null,2)}catch(e){show(e.message,true)}};
 for(const [kind,id] of [['html','htmlBtn'],['pdf','pdfBtn'],['json','jsonBtn'],['md','mdBtn']])$(id).onclick=()=>openExport(kind);
 $('rawBtn').onclick=()=>{if(!selectedJob)return show('Seleziona prima un job completato',true);window.open('/api/control/download/'+encodeURIComponent(selectedJob),'_blank','noopener,noreferrer')};
 $('serviceRefresh').onclick=statusAI;
 $('ollamaPrepare').onclick=async()=>{if(!confirm('Scaricare llama3.2:3b e preparare achilles-local? Il download del modello usa Internet, i dati del target non vengono inviati.'))return;try{const j=await request('/api/control/ollama/prepare',{method:'POST'});show('Installazione Ollama avviata: '+j.id.slice(0,10));await refresh()}catch(e){show(e.message,true)}};
 $('ollamaStart').onclick=async()=>{try{const s=await request('/api/control/services/ollama/start',{method:'POST'});show('Ollama: '+s.state);await statusAI()}catch(e){show(e.message,true)}};
 prepare();setInterval(refresh,4500);
});
