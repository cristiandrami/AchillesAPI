'use strict';
/* Dashboard actions use an explicit server-side catalog. No command strings or shell. */
let controlToken='',extraId='',toolCatalog=[];
const el=id=>document.getElementById(id);
function controlMessage(t){el('toolMessage').textContent=t}
async function controlApi(path,options={}){
  const headers=options.headers||{};
  if(options.method==='POST')headers['x-achilles-token']=controlToken;
  const response=await fetch(path,{...options,headers});
  const data=await response.json();
  if(!response.ok)throw Error(data.detail||'Request failed');
  return data;
}
async function statusServices(){
  try{
    const state=await controlApi('/api/control/services');
    el('ollamaStatus').textContent=state.ollama.toUpperCase();
    el('modelList').textContent=(state.ollama_models||[]).join(', ')||'Ollama offline o senza modelli installati';
  }catch(e){controlMessage(e.message)}
}
function toolDetail(){
  const item=toolCatalog.find(x=>x.name===el('toolSelect').value);
  if(!item)return;
  const mode=item.active?(item.writes?'Scritture con manifest':'GET autorizzate / piano'):'Solo offline';
  el('toolDetail').textContent=`${item.category} · ${mode} · richiede: ${item.requirements}`;
  el('toolWrites').disabled=!item.writes;
  if(!item.writes)el('toolWrites').checked=false;
  el('toolAI').disabled=!item.ai;
  if(!item.ai)el('toolAI').checked=false;
}
function requestedTool(execute){
  const action=el('toolSelect').value;
  const paths=el('pathValues').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
  return {action,specification_id:specId||null,assessment_id:selectedJob||null,config_id:extraId||null,
    auth_config_id:authId||null,base_url:el('baseUrl').value.trim(),allow_host:el('allowHost').value.trim(),
    execute,approve_writes:el('toolWrites').checked,acknowledgment:el('toolAck').checked,
    max_requests:Number(el('maxRequests').value),rate:Number(el('rate').value),budget:Number(el('agentBudget').value),
    profiles:el('profiles').value.split(',').map(x=>x.trim()).filter(Boolean),path_values:paths,
    ai:el('toolAI').checked,model:el('ollamaModel').value.trim(),allow_insecure_http:el('insecure').checked,
    config_usage:el('configUsage').value};
}
async function runTool(execute){
  try{
    const job=await controlApi('/api/control/jobs',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify(requestedTool(execute))});
    controlMessage(`Avviato ${job.action} · task ${job.id.slice(0,10)}. Usa Activity per aprire il report.`);
    await refresh();
  }catch(e){controlMessage(e.message)}
}
window.addEventListener('DOMContentLoaded',async()=>{
  try{
    controlToken=(await controlApi('/api/bootstrap')).csrf_token;
    toolCatalog=await controlApi('/api/control/tools');
    const select=el('toolSelect');select.replaceChildren();
    for(const item of toolCatalog){const option=document.createElement('option');option.value=item.name;
      option.textContent=`${item.category} · ${item.name}`;select.append(option)}
    select.value='auto-assess';toolDetail();
  }catch(e){controlMessage(e.message);return}
  el('toolSelect').onchange=toolDetail;
  el('serviceRefresh').onclick=statusServices;
  for(const [verb,id] of [['start','ollamaStart'],['stop','ollamaStop']]){
    el(id).onclick=async()=>{try{const result=await controlApi(`/api/control/services/ollama/${verb}`,
      {method:'POST'});controlMessage(`Ollama: ${result.state}`);await statusServices()}
      catch(e){controlMessage(e.message)}};
  }
  el('ollamaPrepare').onclick=async()=>{
    if(!window.confirm('Scaricare llama3.2:3b tramite Ollama e creare achilles-local? Richiede connessione internet per il download, senza inviare dati delle API.'))return;
    try{const j=await controlApi('/api/control/ollama/prepare',{method:'POST'});
      controlMessage('Preparazione modello avviata, job: '+j.id.slice(0,12));await refresh()}
    catch(e){controlMessage(e.message)}
  };
  el('configFile').onchange=async()=>{
    try{
      const f=el('configFile').files[0];if(!f)return;
      const body=new FormData();body.append('file',f);
      const reply=await controlApi('/api/control/config',{method:'POST',body});
      extraId=reply.id;el('configState').textContent=reply.name+' · configurazione acquisita';
      controlMessage('Manifest caricato. Verifica scope e autorizzazioni prima di eseguire.')
    }catch(e){controlMessage(e.message)}
  };
  el('runTool').onclick=()=>runTool(el('execute').checked);
  el('toolDry').onclick=()=>runTool(false);
  await statusServices();
});
