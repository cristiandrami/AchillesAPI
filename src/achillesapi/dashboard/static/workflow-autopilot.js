'use strict';
/* RC19 UX: OpenAPI-derived workflow discovery and independent per-test selection.
 * UI only. Does not send test traffic or grant security approvals. */
(() => {
 let candidates=[],saved=[];
 const $=id=>document.getElementById(id);
 const scopes=[['accessWorkflowSelect','access'],['massWorkflowSelect','mass'],['bflaWorkflowSelect','bfla'],['rc13WorkflowSelectAuto','rc13'],['suiteWorkflowSelectAuto','suite']];
 const labels={access:'Accessi tra utenti',mass:'Mass Assignment',bfla:'Funzioni riservate',rc13:'Analisi approfondita',suite:'Suite completa'};
 const acceptable=(candidate,scope)=>scope==='access'?Boolean(candidate.read):scope==='mass'?Boolean(candidate.mutation):scope==='bfla'?Boolean(candidate.write_action_candidates?.length):true;
 function el(tag,className,text){const node=document.createElement(tag);if(className)node.className=className;if(text!==undefined)node.textContent=text;return node;}
 function statusText(candidate){
  if(!candidate)return 'Nessuna risorsa riconosciuta.';
  const missing=[];
  if(!candidate.create)missing.push('POST di creazione');
  if(!candidate.read)missing.push('GET per ID');
  if(!candidate.delete)missing.push('DELETE di cleanup');
  if(candidate.read_get_risk)missing.push('verifica sicurezza della GET');
  if(candidate.required_path_params?.length)missing.push('ID parent: '+candidate.required_path_params.join(', '));
  return candidate.ready?'Ciclo POST → GET → DELETE individuato: nessuna richiesta inviata. '+(missing.length?'Da confermare: '+missing.join('; '):'Restano i dati e i permessi di test.'):
    'Solo discovery: per eseguire scritture è necessario completare '+(missing.join('; ')||'il ciclo di risorsa temporanea e cleanup')+'.';
 }
 function operationChips(target,candidate){
  const list=el('div','workflow-operations');
  for(const [name,value] of [['POST',candidate.create],['GET',candidate.read],['PATCH/PUT',candidate.mutation],['DELETE',candidate.delete]]){
   const chip=el('span','workflow-method'+(value?'':' workflow-unavailable'),value||name+' non documentato');
   chip.title=name;list.append(chip);
  }
  target.append(list);
 }
 function candidateTitle(candidate){return candidate.read||candidate.create||candidate.mutation||'Risorsa senza operazioni compatibili';}
 function summaryNode(candidate,context,withAction=false){
  const fragment=el('div','workflow-preview-content');
  const heading=el('strong','',candidateTitle(candidate));fragment.append(heading);
  operationChips(fragment,candidate);
  const description=el('p','workflow-guidance',statusText(candidate));fragment.append(description);
  if(context==='mass'){
   fragment.append(el('p','workflow-guidance',(candidate.mutation_field_count||Object.keys(candidate.mutation_field_specs||{}).length)+' campi PATCH/PUT disponibili. Seleziona soltanto quelli pertinenti alla policy che intendi verificare.'));
  }
  if(context==='bfla')fragment.append(el('p','workflow-guidance','Azioni da esaminare: '+(candidate.write_action_candidates||[]).join(', ')+'. La policy resta a carico di chi autorizza il test.'));
  if(withAction){
   const b=el('button','secondary','Prepara i dati di test per questo workflow');b.type='button';b.disabled=!candidate.ready;
   b.addEventListener('click',()=>prepareCandidate(candidates.indexOf(candidate)));fragment.append(b);
  }
  return fragment;
 }
 function prepareCandidate(index){
  const candidate=candidates[index];if(!candidate||!candidate.ready)return;
  const guided=$('guidedCandidate'),drawer=$('guidedDrawer');
  if(!guided||!drawer)return;
  drawer.open=true;guided.value=String(index);
  if(typeof guideUpdateCandidate==='function')guideUpdateCandidate();
  if(typeof guideGo==='function')guideGo(1);
  drawer.scrollIntoView({behavior:'smooth',block:'start'});
 }
 function overview(){
  const count=$('workflowDetectedCount'),list=$('workflowDetectedList'),prep=$('workflowCreatePreview');if(!list)return;
  list.replaceChildren();count.textContent=candidates.length+' workflow candidati · '+candidates.filter(c=>c.ready).length+' con ciclo completo';
  if(!candidates.length){list.append(el('p','helper','Nessun ciclo CRUD riconosciuto. I test GET e le altre verifiche compatibili restano disponibili.'));
   prep.textContent='Nessun ciclo POST → GET → DELETE individuato: per test di scrittura servirà un manifest di cleanup esplicitamente approvato.';return;}
  for(const [index,c] of candidates.entries()){
   const card=el('article','workflow-preview-card');
   const title=el('strong','',candidateTitle(c));card.append(title);operationChips(card,c);
   card.append(el('small','workflow-status-label',c.ready?'Ciclo con cleanup rilevato':'Ciclo incompleto · solo discovery'));
   const action=el('button','secondary','Esamina questo workflow');action.type='button';
   action.addEventListener('click',()=>{
    let selectId=c.mutation?'massWorkflowSelect':c.write_action_candidates?.length?'bflaWorkflowSelect':'accessWorkflowSelect';
    const select=$(selectId);if(select&&[...select.options].some(o=>o.value===String(index))){select.value=String(index);select.dispatchEvent(new Event('change',{bubbles:true}));select.scrollIntoView({behavior:'smooth',block:'center'});}
    else if(c.ready)prepareCandidate(index);
   });card.append(action);list.append(card);
  }
  prep.replaceChildren();prep.append(el('p','',candidates.filter(c=>c.ready).length+' workflow configurabili da Swagger. Non devi avviare una ricerca manuale.'));
  const first=candidates.find(c=>c.ready);if(first)prep.append(summaryNode(first,'prepare',true));
 }
 function fillSelect(id,scope){
  const select=$(id);if(!select)return;
  const old=select.value;select.replaceChildren();
  for(const [index,c] of candidates.entries()){
   if(!acceptable(c,scope))continue;
   const option=new Option(candidateTitle(c)+(c.ready?'':' · cleanup da configurare'),String(index));select.add(option);
  }
  if([...select.options].some(o=>o.value===old))select.value=old;
  if(!select.options.length){select.add(new Option('Nessun workflow pertinente in questo Swagger',''));select.disabled=true;}
  else select.disabled=false;
 }
 function chosen(id){const value=$(id)?.value;if(value===undefined||value==='')return null;return candidates[Number(value)]||null;}
 function drawPreview(scope,fromChoice=false){
  const selectId=scope==='access'?'accessWorkflowSelect':scope==='mass'?'massWorkflowSelect':scope==='bfla'?'bflaWorkflowSelect':scope==='rc13'?'rc13WorkflowSelectAuto':'suiteWorkflowSelectAuto';
  const target=$(scope==='access'?'accessWorkflowPreview':scope==='mass'?'massWorkflowPreview':scope==='bfla'?'bflaWorkflowPreview':scope==='rc13'?'rc13WorkflowSelectPreview':'suiteWorkflowSelectPreview');
  if(!target)return;target.replaceChildren();const c=chosen(selectId);
  if(!c){target.append(el('p','helper','Questa sezione non ha workflow pertinenti. Lo Swagger può comunque essere analizzato senza test di scrittura.'));return;}
  target.append(summaryNode(c,scope,scope==='mass'||scope==='bfla'));
  if(scope==='mass'&&$('massConfigureSelected'))$('massConfigureSelected').disabled=!c.ready;
  if(scope==='bfla'&&$('bflaConfigureSelected'))$('bflaConfigureSelected').disabled=!c.ready;
  if(scope==='rc13'||scope==='suite'){
   const existing=saved.findIndex(w=>w.candidateIndex===candidates.indexOf(c)&&w.specId===specId);
   const linked=$(scope==='rc13'?'rc13WorkflowSelect':'suiteWorkflowSelect');
   if(linked){
    if(fromChoice){linked.value=existing>=0?String(existing):'';}
    else if(linked.value!==''&&linked.value!=='__all__'&&saved[Number(linked.value)]?.candidateIndex!==candidates.indexOf(c))linked.value=existing>=0?String(existing):'';
   }
   target.append(el('p','workflow-guidance',linked?.value==='__all__'?'✓ Tutti i '+saved.filter(w=>w.specId===specId).length+' workflow preparati saranno inclusi; il tool gestisce automaticamente il manifesto combinato.':existing>=0?'✓ Risorsa preparata: il manifest con cleanup è selezionato automaticamente per questa analisi.':'Questa risorsa è stata scoperta, ma non ha ancora dati di test approvati. I controlli GET offline sono disponibili; per le scritture prepara una fixture.'));
  }
  if(scope==='access'&&c.read&&$('matrixOperation')){
   const get=$('matrixOperation');if([...get.options].some(o=>o.value===c.read)){
    get.value=c.read;
    if(typeof renderMatrixPathFields==='function')renderMatrixPathFields();
   }
  }
 }
 function massFields(){
  const target=$('massAutoFields');if(!target)return;target.replaceChildren();
  const candidate=chosen('massWorkflowSelect');
  if(!candidate?.mutation){target.append(el('p','helper','Nessun PATCH/PUT su questa risorsa.'));return;}
  const fields=candidate.mutation_field_specs||{};
  if(!Object.keys(fields).length){target.append(el('p','helper','Lo Swagger non dichiara proprietà JSON per questa operazione. Puoi scrivere il body manualmente.'));return;}
  let current={};try{current=$('guidedMutationBody').value.trim()?JSON.parse($('guidedMutationBody').value):{}}catch{current={}};
  for(const [name,schema] of Object.entries(fields)){
   const label=el('label','workflow-field-choice');const check=document.createElement('input');check.type='checkbox';check.value=name;
   check.checked=Object.prototype.hasOwnProperty.call(current||{},name);
   check.addEventListener('change',()=>{
    const editor=$('guidedMutationBody');let json;
    try{json=editor.value.trim()?JSON.parse(editor.value):{};if(!json||typeof json!=='object'||Array.isArray(json))throw Error('oggetto JSON richiesto');}
    catch{check.checked=!check.checked;$('massWorkflowStatus').textContent='Correggi il JSON PATCH: deve essere un oggetto JSON valido prima di selezionare altri campi.';window.AchillesIssueGuide?.report('Body JSON PATCH non valido','massWorkflowStatus');return;}
    if(check.checked){if(!Object.prototype.hasOwnProperty.call(json,name))json[name]=typeof rc19MutationExample==='function'?rc19MutationExample(schema):'REVIEW_VALORE_PATCH';}
    else delete json[name];
    editor.value=JSON.stringify(json,null,2);$('guidedMutation').value=candidate.mutation;
    if(typeof saveLocalPanel==='function')saveLocalPanel('mass');
    if(typeof guideInvalidate==='function')guideInvalidate();
    $('massWorkflowStatus').textContent=Object.keys(json).length+' campi nel body per '+candidate.mutation+'. Rivedi i valori e conferma la policy: non è stata inviata alcuna richiesta.';
   });
   label.append(check,document.createTextNode(' '+name));label.append(el('small','',schema?.type||'string'));target.append(label);
  }
 }
 function refresh(newCandidates,newSaved){
  candidates=Array.isArray(newCandidates)?newCandidates:[];saved=Array.isArray(newSaved)?newSaved:[];
  overview();
  for(const [id,scope] of scopes){
   if(scope==='mass'||scope==='bfla')continue; // Their original renderers update their own selects and settings.
   fillSelect(id,scope);
  }
  for(const scope of ['access','mass','bfla','rc13','suite'])drawPreview(scope);
  massFields();
 }
 function onSaved(newSaved){saved=Array.isArray(newSaved)?newSaved:[];
  for(const scope of ['rc13','suite'])drawPreview(scope);
 }
 function init(){
  for(const [id,scope] of scopes){
   $(id)?.addEventListener('change',()=>{
    queueMicrotask(()=>{drawPreview(scope,true);if(scope==='mass')massFields();});
   });
  }
  for(const [sourceId,discoveryId] of [['rc13WorkflowSelect','rc13WorkflowSelectAuto'],['suiteWorkflowSelect','suiteWorkflowSelectAuto']]){
   $(sourceId)?.addEventListener('change',()=>{
    const val=$(sourceId).value;if(!val||val==='__all__')return;const item=saved[Number(val)];
    if(!item||item.candidateIndex===undefined)return;
    if($(discoveryId)&&[...$(discoveryId).options].some(o=>o.value===String(item.candidateIndex))){
      $(discoveryId).value=String(item.candidateIndex);drawPreview(sourceId==='rc13WorkflowSelect'?'rc13':'suite');
    }
   });
  }
  $('guidedMutationInsert')?.addEventListener('click',()=>queueMicrotask(massFields));
  $('guidedMutationBody')?.addEventListener('input',()=>{massFields()});
  for(const name of ['mass','bfla']){
   $(name==='mass'?'massConfigureSelected':'bflaConfigureSelected')?.addEventListener('click',()=>{
    const value=$(name==='mass'?'massWorkflowSelect':'bflaWorkflowSelect')?.value;
    if(value!==undefined&&value!=='')prepareCandidate(Number(value));
   });
  }
  $('accessConfigure')?.addEventListener('click',()=>{const drawer=$('matrixDrawer');if(drawer){drawer.open=true;drawer.scrollIntoView({behavior:'smooth',block:'start'});}});
  $('bodyProbeWorkflowSelect')?.addEventListener('change',()=>{
   if(!$('bodyProbeWorkflowSelect').value)return;
   if(typeof detectBodyProbeFields==='function')detectBodyProbeFields().catch(e=>{
    if($('bodyProbeHint')){ $('bodyProbeHint').textContent='I campi non possono ancora essere rilevati: '+e.message;window.AchillesIssueGuide?.report(e.message,'bodyProbeHint');}
   });
  });
 }
 function selectWorkflow(scope,operation){
  // Called by the read-only overview. Match by actual operation, never by an
  // index from another discovery engine (which may sort workflows differently).
  if(!['access','mass','bfla','rc13','suite'].includes(scope)||typeof operation!=='string')return false;
  const id=scope==='access'?'accessWorkflowSelect':scope==='mass'?'massWorkflowSelect':scope==='bfla'?'bflaWorkflowSelect':scope==='rc13'?'rc13WorkflowSelectAuto':'suiteWorkflowSelectAuto';
  const index=candidates.findIndex(c=>scope==='access'?c.read===operation:
    scope==='mass'?c.mutation===operation:
    scope==='bfla'?(c.write_action_candidates||[]).includes(operation):
    [c.read,c.create,c.mutation].includes(operation));
  const select=$(id);
  if(index<0||!select||![...select.options].some(o=>o.value===String(index)))return false;
  select.value=String(index);
  select.dispatchEvent(new Event('change',{bubbles:true}));
  return true;
 }
 window.AchillesWorkflowUX={refresh,onSaved,selectWorkflow};
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
})();
