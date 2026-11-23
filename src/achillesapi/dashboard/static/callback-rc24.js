'use strict';
/* Explicit, local-only callback management. Never changes permissions. */
(() => {
 const $=id=>document.getElementById(id);
 const ref=['rc15ToolCallbackBase','rc15ToolObserver'];
 let state=null;
 function applyLocal(){
  const url=state?.url||'http://127.0.0.1:8788';
  $('rc15CallbackBase').value=url;$('rc15CallbackObserver').value=url;
  if($(ref[0]))$(ref[0]).value=url;
  if($(ref[1]))$(ref[1]).value=url;
  $('callbackStatus').textContent='URL locali compilati. Seleziona il consenso callback prima dei test SSRF/XXE. Nessuna scansione avviata.';
 }
 function display(data){
  state=data;
  const active=Boolean(data.running);
  $('callbackIndicator').textContent=active?'● Collector locale raggiungibile':'○ Collector non raggiungibile';
  $('callbackIndicator').classList.toggle('is-running',active);
  $('callbackManagedHint').textContent=active?(data.managed_here?'Gestito dalla dashboard · '+data.url:'Collector esterno già attivo · '+data.url):'Avvialo su 127.0.0.1:8788';
  $('callbackStop').disabled=!data.managed_here;
  $('callbackStatus').textContent=active
    ?'Collector pronto. Per Asterion su localhost premi «Compila URL locali». Ricorda di autorizzare separatamente le callback.'
    :'Collector inattivo. Clicca «Avvia collector locale»; nessuna credenziale o dato del target viene inviato per verificarlo.';
 }
 async function req(url,method){
  const headers={};
  if(method==='POST')headers['x-achilles-token']=window.AchillesDashboardCSRF?.()||'';
  const response=await fetch(url,{method,headers,cache:'no-store'});
  const result=await response.json();
  if(!response.ok)throw Error(typeof result.detail==='string'?result.detail:'Errore collector HTTP '+response.status);
  return result;
 }
 async function operation(path,method){
  for(const id of ['callbackStart','callbackRefresh','callbackStop'])$(id).disabled=true;
  try{
   const data=await req(path,method);display(data);
   if(path.endsWith('/start')&&data.running&&data.url&&
      (!$('rc15CallbackBase').value.trim()||$('rc15CallbackBase').value==='http://127.0.0.1:8788'))applyLocal();
  }catch(error){$('callbackStatus').textContent='Callback: '+error.message;
   window.AchillesIssueGuide?.report?.('Callback: '+error.message,'callbackStatus');
  }finally{$('callbackStart').disabled=false;$('callbackRefresh').disabled=false;
   $('callbackStop').disabled=!state?.managed_here;}
 }
 function init(){
  $('callbackStart')?.addEventListener('click',()=>operation('/api/control/callback/start','POST'));
  $('callbackRefresh')?.addEventListener('click',()=>operation('/api/control/callback/status','GET'));
  $('callbackStop')?.addEventListener('click',()=>operation('/api/control/callback/stop','POST'));
  $('callbackApply')?.addEventListener('click',applyLocal);
  for(const id of ['rc15CallbackBase','rc15CallbackObserver']){
   $(id)?.addEventListener('change',()=>{
    if(id==='rc15CallbackBase'&&$(ref[0]))$(ref[0]).value=$(id).value;
    if(id==='rc15CallbackObserver'&&$(ref[1]))$(ref[1]).value=$(id).value;
   });
  }
  operation('/api/control/callback/status','GET');
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
})();
