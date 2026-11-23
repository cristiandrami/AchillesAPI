'use strict';
/* Actionable, local-only error guidance. No credentials, requests or approvals are changed. */
(() => {
 const $ = id => document.getElementById(id);
 const sections = {
  step1: ['Passaggio 1 · Importa OpenAPI', 'specFile'],
  step2: ['Passaggio 2 · URL e perimetro autorizzato', 'baseUrl'],
  step3: ['Passaggio 3 · Utenti e credenziali', 'authFile'],
  workflowCreateSection: ['Prepara risorse temporanee · Workflow e cleanup', 'guidedCandidate'],
  autoconfigPanel: ['Copertura automatica · Tutti gli endpoint', 'autoconfigRows'],
  workflowManageSection: ['Workflow configurati · Selezione', 'workflowSaved'],
  authMatrixSection: ['Controlla accessi · Regole per utenti', 'matrixOperation'],
  massAssignmentPanel: ['Mass Assignment · PATCH e campi JSON', 'bodyProbeWorkflowSelect'],
  bflaPanel: ['BFLA · Operazioni riservate', 'bflaWorkflowSelect'],
  fullSuite: ['Suite completa · Autorizzazioni e impostazioni', 'suiteActive'],
  rc13Panel: ['Analisi approfondita · Verifiche selezionate', 'rc13WorkflowSelect'],
  agentOptionsSection: ['Agente locale · Ollama', 'ollamaModel'],
  loginConfigPanel: ['Configurazione accesso e login · OAuth2/OIDC', 'rc18Issuer'],
  loginKeysPanel: ['Chiavi pubbliche · JWKS', 'rc18JWKS'],
  securityScannerOptionsSection: ['Scanner attivi · Callback e fixture', 'rc15CallbackBase'],
  advancedToolsGroup: ['Altri strumenti e opzioni', 'toolSelect'],
  step5: ['Risultati e report · Seleziona un job', 'jobsList']
 };
 const defaults = {
  suiteStatus:'fullSuite', suitePreviewResult:'fullSuite', rc13Status:'rc13Panel',
  bodyProbeHint:'massAssignmentPanel', massWorkflowStatus:'massAssignmentPanel',
  bflaWorkflowStatus:'bflaPanel', workflowSavedStatus:'workflowManageSection',
  workflowRunStatus:'workflowManageSection', guidedError:'workflowCreateSection', guidedProbeResult:'workflowCreateSection', manifestState:'workflowCreateSection',
  manifestCandidatesState:'workflowCreateSection', matrixStatus:'authMatrixSection',
  guidedStatus:'workflowCreateSection', toolMessage:'advancedToolsGroup',
  authState:'step3', specState:'step1', configState:'workflowCreateSection',
  rc18OidcResult:'loginConfigPanel', rc18KeysResult:'loginKeysPanel',
  rc19QualityResult:'step5', rc19BenchmarkResult:'step5',
  globalMessage:'fullSuite'
 };
 function issue(section, detail, focus, secondary){
  return {section, detail, focus:focus||sections[section]?.[1], secondary};
 }
 function diagnose(message, context='globalMessage'){
  const m=String(message||'').toLowerCase(), fallback=defaults[context]||'fullSuite';
  if(m.includes('dashboard non raggiungibile')||m.includes('risposta inattesa dal server')||m.includes('http 500')||m.includes('errore interno della dashboard'))
    return issue('fullSuite','Il server locale della dashboard non risponde correttamente: controlla il terminale in cui hai avviato «uv run achillesapi dashboard --port 8766» e ricarica la pagina. Non dipende dalle autorizzazioni dell’API target.');
  if((m.includes('sond')||m.includes('body probe')) &&
     (m.includes('patch')||m.includes('json')||m.includes('campo')))
    return issue('massAssignmentPanel',
      'Apri Mass Assignment → «Verifica campi JSON con sonde PATCH» → seleziona un workflow già preparato → scegli i campi rilevati. Se il workflow non è presente, prepara prima una risorsa temporanea e il suo DELETE di cleanup nella sezione «Prepara risorse temporanee». Poi torna in Suite completa. La suite può comunque avviare gli altri controlli senza sonde PATCH.',
      'bodyProbeWorkflowSelect','workflowCreateSection');
  if(m.includes('json patch')||m.includes('body patch')||m.includes('body json')||m.includes('campo patch')||m.includes('mass assignment')||(context==='massWorkflowStatus'&&m.includes('json')))
    return issue('massAssignmentPanel',
      'Seleziona la risorsa in «Mass Assignment», verifica il PATCH/PUT riconosciuto e scegli i campi. Completa il JSON soltanto con dati di test; la policy di autorizzazione va confermata da te. Per eseguire scritture serve un workflow temporaneo con cleanup.',
      'massWorkflowSelect','workflowCreateSection');
  if(m.includes('login')||m.includes('issuer')||m.includes('discovery'))
    return issue('loginConfigPanel','Apri «Configurazione accesso e login» e controlla issuer e discovery JSON. Sono dati del provider, non del workflow.', 'rc18Issuer');
  if(m.includes('jwks')||m.includes('jwk')||m.includes('firma jwt'))
    return issue('loginKeysPanel','Apri «Chiavi pubbliche» e verifica il JWKS pubblico, l’algoritmo e le chiavi previste.', 'rc18JWKS');
  if(m.includes('swagger')||m.includes('openapi')||m.includes('specification_id')||m.includes('file troppo grande'))
    return issue('step1','Importa un file OpenAPI YAML/JSON o ZIP valido nel Passaggio 1, quindi attendi «Operazioni riconosciute». Il file principale di un bundle ZIP va indicato solo se ambiguo.', 'specFile');
  if(m.includes('ollama')||m.includes('modello')||m.includes('agent')||m.includes('ai locale'))
    return issue('agentOptionsSection','Mostra gli strumenti specialistici, verifica che Ollama sia avviato e scegli un modello disponibile. Oppure disattiva l’agente AI nella Suite completa: non è indispensabile per gli altri test.', 'ollamaModel','fullSuite');
  if(m.includes('base url')||m.includes('hostname')||m.includes('allow-host')||m.includes('scope')||m.includes('fuori scope')||m.includes('connessione')||m.includes('api non raggiungibile')||m.includes('http in chiaro')||m.includes('target'))
    return issue('step2','Al Passaggio 2 inserisci il Base URL raggiungibile e l’hostname esatto autorizzato. Verifica che il target sia avviato. L’HTTP non cifrato verso host remoti non è consentito. Per inviare test attivi conferma separatamente lo scope nella Suite completa.', 'baseUrl','fullSuite');
  if(m.includes('auth.yaml')||m.includes('credenzial')||m.includes('token')||m.includes('environment variable')||m.includes('profili'))
    return issue('step3','Al Passaggio 3 importa o incolla auth.yaml con i profili di test realmente autorizzati. Per confronti tra utenti occorrono almeno due identità distinte e credenziali utilizzabili.', 'authFile');
  if(m.includes('policy')||m.includes('matrice')||m.includes('regola')||m.includes('bola')||m.includes('idor'))
    return issue('authMatrixSection','In «Controlla accessi» scegli l’endpoint, i due utenti, gli ID reali e l’accesso atteso, poi salva la matrice. Le regole non possono essere dedotte in modo affidabile dal solo Swagger.', 'matrixOperation','step3');
  if(m.includes('bfla')||m.includes('operazione riservata'))
    return issue('bflaPanel','In «BFLA» seleziona il workflow e l’operazione riservata, quindi indica l’identità che non deve poterla eseguire.', 'bflaWorkflowSelect','workflowCreateSection');
  if(m.includes('fixture')||m.includes('cleanup')||m.includes('manifest')||m.includes('resources.yaml')||m.includes('risorsa temporanea')||m.includes('workflow')||m.includes('config_id'))
    return issue('workflowCreateSection','Apri «Prepara risorse temporanee»: scegli uno dei workflow scoperti dallo Swagger, completa soltanto ID/body non deducibili, verifica la DELETE di cleanup e salva il workflow. Ritorna alla sezione Suite completa e scegli la risorsa. Le analisi senza scritture restano disponibili.', 'guidedCandidate','workflowManageSection');
  if(m.includes('sonde')||m.includes('ssrf')||m.includes('xxe')||m.includes('callback')||m.includes('traversal'))
    return issue('securityScannerOptionsSection','Mostra gli strumenti specialistici, imposta una callback/fixture controllata e approva esplicitamente la specifica sonda prima di eseguirla.', 'rc15CallbackBase');
  if(m.includes('budget')||m.includes('rate')||m.includes('max_requests')||m.includes('richieste')||m.includes('durata'))
    return issue('fullSuite','Nella Suite completa riduci i controlli selezionati o modifica il budget e la durata massima. Il limite per singolo job è configurato nel Passaggio 2.', 'suiteBudget','step2');
  if(m.includes('approvazion')||m.includes('autorizzazion')||m.includes('consenso')||m.includes('scritture')||m.includes('post/patch/delete'))
    return issue('fullSuite','Nella Suite completa abilita prima «Verifiche HTTP attive» e conferma lo scope. Per POST/PATCH/DELETE è necessaria una seconda autorizzazione dopo aver verificato il cleanup. Non spuntare consensi senza effettiva autorizzazione.', 'suiteActive','workflowCreateSection');
  if(m.includes('assessment')||m.includes('report')||m.includes('evidenze')||m.includes('job precedente'))
    return issue('step5','Nel Passaggio 5 seleziona un job completato. Per la correlazione HTTP è necessario un assessment attivo con risposte raccolte, non soltanto un piano offline.', 'jobsList');
  return issue(fallback,'Il messaggio non identifica un campo preciso. Apri «Controlla prerequisiti» nella Suite completa e individua il controllo bloccato. Usa il pulsante qui sotto per raggiungere la sezione. Se il blocco persiste, consulta il dettaglio del job prima di modificare le autorizzazioni.');
 }
 function reveal(section){
  const target=$(section);if(!target)return null;
  if(target.matches('details'))target.open=true;
  for(let parent=target.parentElement;parent;parent=parent.parentElement){
   if(parent.matches('details'))parent.open=true;
  }
  if(target.classList.contains('simple-advanced-hidden')||target.closest('.simple-advanced-hidden')){
   const toggle=$('simpleAdvancedToggle');
   if(toggle&&toggle.getAttribute('aria-expanded')!=='true')toggle.click();
   target.classList.remove('simple-advanced-hidden');
  }
  return target;
 }
 function navigate(section,focus){
  const target=reveal(section);if(!target)return;
  window.location.hash=section;
  target.scrollIntoView({behavior:'smooth',block:'start'});
  target.classList.add('issue-guide-focus');
  // Remove a previous focus after navigation; no execution/security state is changed.
  const input=$(focus)||target.querySelector('input,select,textarea,button');
  if(input){for(let parent=input.parentElement;parent;parent=parent.parentElement){if(parent.matches('details'))parent.open=true;}}
  if(input && typeof input.focus==='function')input.focus({preventScroll:true});
 }
 function button(text,section,focus){
  const control=document.createElement('button');control.type='button';control.className='secondary issue-go';
  control.textContent=text;control.setAttribute('data-issue-go',section);
  control.addEventListener('click',()=>navigate(section,focus));return control;
 }
 function detailsSteps(value){
  // Presentation only. Never infer permissions or modify the task configuration.
  return String(value||'').split(/(?<=[.!?])\s+(?=[A-ZÀ-Ú«])/u).map(s=>s.trim()).filter(Boolean);
 }
 function addText(parent,tag,className,content){
  const node=document.createElement(tag);node.className=className;node.textContent=content;parent.append(node);return node;
 }
 function guidanceContent(panel,data){
  const heading=document.createElement('div');heading.className='issue-guide__heading';
  const symbol=addText(heading,'span','issue-guide__symbol','!');symbol.setAttribute('aria-hidden','true');
  const label=document.createElement('div');label.className='issue-guide__heading-copy';
  addText(label,'span','issue-guide__eyebrow','AZIONE RICHIESTA');
  addText(label,'strong','issue-guide__title','Dove correggere');
  heading.append(label);panel.append(heading);
  const route=document.createElement('div');route.className='issue-guide__route';
  const parts=(sections[data.section]?.[0]||data.section).split(' · ');
  parts.forEach((part,i)=>{
   if(i)addText(route,'span','issue-guide__separator','›').setAttribute('aria-hidden','true');
   addText(route,'span',i===0?'issue-guide__route-main':'issue-guide__route-detail',part);
  });
  panel.append(route);
  addText(panel,'div','issue-guide__instruction-label','Come risolvere');
  const steps=detailsSteps(data.detail);
  if(steps.length>1){
   const list=document.createElement('ol');list.className='issue-guide__steps';
   for(const sentence of steps)addText(list,'li','issue-guide__step',sentence);
   panel.append(list);
  }else addText(panel,'p','issue-guide__description',data.detail||'Apri la sezione indicata e verifica i prerequisiti del controllo.');
  const actions=document.createElement('div');actions.className='issue-actions';
  const primary=button('Apri la sezione da correggere',data.section,data.focus);
  primary.classList.add('issue-go--primary');actions.append(primary);
  if(data.secondary){
   const secondary=button('Altro passaggio: '+(sections[data.secondary]?.[0]||data.secondary),data.secondary);
   secondary.classList.add('issue-go--secondary');actions.append(secondary);
  }
  panel.append(actions);
 }
 function card(message,context='globalMessage',options={}){
  const data=options.section ? issue(options.section,options.detail||'',options.focus,options.secondary):diagnose(message,context);
  const panel=document.createElement('section');panel.className='issue-guide';
  panel.setAttribute('role','group');panel.setAttribute('aria-label','Come risolvere il problema');
  guidanceContent(panel,data);return panel;
 }
 function clear(context){const host=$(context);if(!host)return;const panel=$(context+'__guidance');if(panel)panel.remove();}
 function report(message,context='globalMessage',options={}){
  const host=$(context);if(!host)return;
  clear(context);
  const panel=card(message,context,options);panel.id=context+'__guidance';
  host.insertAdjacentElement('afterend',panel);
 }
 function renderList(messages,context='suiteStatus'){
  const host=$(context);if(!host)return;
  clear(context);
  if(!messages.length)return;
  const group=document.createElement('section');group.id=context+'__guidance';group.className='issue-guide-list';
  group.setAttribute('aria-label','Copertura e prerequisiti dei test');
  const summary=document.createElement('div');summary.className='issue-guide-list__summary';
  addText(summary,'strong','issue-guide-list__title','Copertura della scansione · Controlli da completare');
  addText(summary,'p','issue-guide-list__subtitle',messages.length+' note: le operazioni senza dati, policy o cleanup approvati non vengono eseguite. La suite procede con tutti i controlli consentiti.');
  group.append(summary);
  for(const entry of messages){
   const data=entry.section&&sections[entry.section] ? issue(entry.section,'',entry.focus):diagnose(entry.message,context);
   const line=document.createElement('article');line.className='issue-list-entry';
   addText(line,'strong','issue-list-entry__title',window.AchillesPublicNames?.text(entry.label)||entry.label||'Test non eseguito');
   addText(line,'p','issue-list-entry__reason',window.AchillesPublicNames?.text(entry.message)||entry.message);
   const route=document.createElement('div');route.className='issue-list-entry__route';
   addText(route,'span','issue-list-entry__route-label',entry.kind==='information'?'LIMITAZIONE DEL TEST':'DOVE INTERVENIRE');
   addText(route,'span','issue-list-entry__route-value',sections[data.section]?.[0]||data.section);
   line.append(route);
   const actions=document.createElement('div');actions.className='issue-actions';
   actions.append(button(entry.kind==='information'?'Vedi copertura':'Vai alla configurazione',data.section,data.focus));
   if(data.secondary&&entry.kind!=='information')actions.append(button('Passaggio collegato',data.secondary));
   line.append(actions);group.append(line);
  }
  host.insertAdjacentElement('afterend',group);
 }
 window.AchillesIssueGuide={diagnose,reveal,navigate,card,report,clear,renderList};
})();
