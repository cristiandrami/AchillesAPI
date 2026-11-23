'use strict';
/* Complete offline operation inventory. NEVER grants scope or mutation rights. */
(() => {
 const $=id=>document.getElementById(id);
 const labels={read_scan:'GET / controlli input',bola_candidate:'BOLA (confronto identità)',
   bfla_candidate:'BFLA (policy)',mass_assignment_candidate:'Mass Assignment',
   workflow_write:'POST/PATCH/DELETE su fixture'};
 const blockers={resource_ids:'ID reali di risorsa',required_query:'Parametri query obbligatori',
   approved_fixture:'Fixture con cleanup',write_consent:'Consenso alle scritture',
   get_side_effect_risk:'GET con possibile effetto collaterale',dedicated_method_engine:'Motore HTTP specifico'};
 let currentSpec='',currentData=null;
 function addText(tag,text,parent,cls){const n=document.createElement(tag);n.textContent=String(text);if(cls)n.className=cls;parent.append(n);return n;}
 function render(){
  const target=$('autoconfigRows');if(!target)return;
  target.replaceChildren();
  const word=$('autoconfigSearch').value.trim().toLowerCase(),filter=$('autoconfigFilter').value;
  const operations=currentData?.operations||[];
  const filtered=operations.filter(row=>(filter==='all'||row.status===filter)&&(!word||row.operation.toLowerCase().includes(word)));
  const frag=document.createDocumentFragment();
  for(const op of filtered){
   const tr=document.createElement('tr');
   const name=addText('td',op.operation,tr);name.className='autoconfig-operation';
   addText('td',op.categories.map(x=>labels[x]||x).join(' · ')||'Inventario OpenAPI',tr);
   const missing=op.missing_inputs.map(x=>blockers[x]||x);
   const info=addText('td',missing.length?missing.join(' · '):'Nessun dato specifico per pianificare',tr);
   if(missing.length)info.className='autoconfig-needs';
   frag.append(tr);
  }
  if(!filtered.length){const tr=document.createElement('tr');const td=addText('td','Nessuna operazione corrispondente.',tr);td.colSpan=3;frag.append(tr);}
  target.append(frag);
 }
 function proposeTarget(url){
  if(!url)return;
  try{
    const suggestion=new URL(url);
    if(!['http:','https:'].includes(suggestion.protocol)||suggestion.username||suggestion.password)return;
    // Never overwrite operator-entered target settings. If the operator has
    // already entered Base URL but not its approved hostname, suggest the
    // corresponding hostname rather than a different Swagger server.
    const existing=$('baseUrl').value.trim();
    const selected=existing?new URL(existing):suggestion;
    if(!['http:','https:'].includes(selected.protocol)||selected.username||selected.password)return;
    if(!existing)$('baseUrl').value=url;
    if(!$('allowHost').value.trim())$('allowHost').value=selected.hostname;
    // Auto-filling a hostname never checks any execution/consent checkbox.
  }catch(_){return;}
 }
 async function refresh(spec){
  currentSpec=spec||'';if(!currentSpec){currentData=null;render();return;}
  $('autoconfigStats').textContent='Analisi offline di tutti i path in corso…';
  try{const response=await fetch('/api/control/autoconfig/'+encodeURIComponent(currentSpec),{cache:'no-store'});
   const data=await response.json();if(currentSpec!==spec)return;
   if(!response.ok)throw Error(data.detail||'Autoconfigurazione non disponibile');
   currentData=data;const summary=data.summary;
   $('autoconfigStats').replaceChildren();
   const stats=[['Operazioni Swagger',summary.total_operations],['GET candidati',summary.read_candidates],
     ['Possibili BOLA',summary.object_access_candidates],['Scritture / workflow',summary.write_candidates],
     ['Richiedono dati/consensi',summary.operations_requiring_input]];
   for(const [title,value] of stats){const tile=document.createElement('div');tile.className='autoconfig-stat';addText('strong',value,tile);addText('span',title,tile);$('autoconfigStats').append(tile);}
   $('autoconfigDownload').disabled=false;
   proposeTarget(data.suggested_base_url);
   // Raise initial HTTP limits only when they are still at shipped defaults;
   // never overwrite a budget explicitly set by the operator.
   const recommended=Math.min(150,Math.max(40,summary.read_candidates*5));
   if($('maxRequests').value==='40')$('maxRequests').value=String(recommended);
   if($('suiteRc13Budget').value==='100')$('suiteRc13Budget').value=String(Math.min(300,Math.max(100,summary.read_candidates*7)));
   const draft=data.workflow_draft;
   if(draft?.resources?.length){
    $('autoconfigDraftStatus').textContent=`${draft.resources.length} bozze di risorse con POST/GET/DELETE preparate offline. Completa soltanto REVIEW_, ownership, ID e cleanup nella sezione «Prepara risorse temporanee».`;
    const editor=$('manifestEditor');
    if(editor&&!editor.value.trim())editor.value=JSON.stringify(draft,null,2);
   }else $('autoconfigDraftStatus').textContent='Nessun workflow con POST/GET/DELETE e cleanup deducibile; le verifiche GET restano disponibili.';
   render();
  }catch(err){$('autoconfigStats').textContent='Piano automatico non disponibile: '+String(err.message).slice(0,180);}
 }
 function download(){if(!currentData)return;const blob=new Blob([JSON.stringify(currentData,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='achilles-autoconfig-rc24.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
 }
 function init(){
  $('autoconfigRefresh')?.addEventListener('click',()=>refresh(currentSpec));
  $('autoconfigDownload')?.addEventListener('click',download);
  $('autoconfigSearch')?.addEventListener('input',render);
  $('autoconfigFilter')?.addEventListener('change',render);
  $('autoconfigSuite')?.addEventListener('click',()=>{$('fullSuite').scrollIntoView({behavior:'smooth'});});
 }
 window.AchillesAutoConfigure={refresh,get current(){return currentData;}};
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
})();
