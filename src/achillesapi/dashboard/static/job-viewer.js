'use strict';
// No innerHTML with job data: all evidence is rendered as text, never executable markup.
const node=id=>document.getElementById(id);
const jobId=decodeURIComponent(location.pathname.split('/').pop()||'');
let data=null,active='summary',search='',severity='all';
const isSuite=()=>Boolean(data&&Array.isArray(data.suite_steps));
const displayTaskName=name=>window.AchillesPublicNames?.action(name)||String(name||'');
function element(tag,text,cls){const el=document.createElement(tag);if(text!==undefined&&text!==null)el.textContent=String(text);if(cls)el.className=cls;return el}
function add(parent,...children){for(const child of children)parent.append(child);return parent}
function status(msg,err=false){node('notice').textContent=window.AchillesPublicNames?.text(msg)||msg;node('notice').classList.toggle('error',err)}
function card(title,subtitle){const c=element('article',null,'row-card');add(c,element('h3',title));if(subtitle)add(c,element('p',subtitle,'minor'));return c}
function metric(parent,value,title){const c=element('div',null,'metric');add(c,element('div',value,'value'),element('div',title,'caption'));parent.append(c)}
function scalar(value){if(value===null)return 'null';if(typeof value==='object')return Array.isArray(value)?`${value.length} elementi`:`${Object.keys(value).length} campi`;return String(value)}
function tree(value,key=''){const wrap=element('div',null,'tree');function branch(parent,obj,label,depth){if(obj&&typeof obj==='object'&&depth<9){const d=element('details');if(depth<1)d.open=true;const name=label?`${label} · ${scalar(obj)}`:scalar(obj);d.append(element('summary',name));const content=element('div');for(const [k,v] of Object.entries(obj).slice(0,260))branch(content,v,k,depth+1);d.append(content);parent.append(d)}else{const l=element('div',null,'leaf');if(label)l.append(element('b',label+': '));l.append(element('span',scalar(obj)));parent.append(l)}}branch(wrap,value,key,0);return wrap}
function filterBar(parent,withSeverity){const bar=element('div',null,'filter-row');const input=element('input');input.placeholder='Cerca endpoint, categoria, evidenza, testo…';input.type='search';input.value=search;input.setAttribute('aria-label','Cerca nei risultati');input.oninput=()=>{const position=input.selectionStart;search=input.value;renderPanel();const next=node('panel').querySelector('input[type=search]');if(next){next.focus();next.setSelectionRange(position,position)}};bar.append(input);if(withSeverity){const sel=element('select');sel.setAttribute('aria-label','Filtra per severità');for(const k of ['all','critical','high','medium','low','informational','info']){const o=element('option',k==='all'?'Tutte le severità':k);o.value=k;sel.append(o)}sel.value=severity;sel.onchange=()=>{severity=sel.value;renderPanel()};bar.append(sel)}parent.append(bar)}
function matches(value){return !search||JSON.stringify(value).toLowerCase().includes(search.toLowerCase())}
function findingExplanation(cardNode,f){
 if(f.source_type==='ai_hypothesis'){
  cardNode.append(element('p','Origine: Ollama · ipotesi non verificata; nessuna vulnerabilità confermata.','minor'));
  cardNode.append(element('p','Priorità suggerita: '+(f.ai_label||'AI - Info'),'minor'));
 }else if(f.source_type==='static_openapi'){
  cardNode.append(element('p','Origine: analisi statica dello Swagger · nessun test HTTP.','minor'));
 }else if(f.source_action){
  cardNode.append(element('p','Origine: '+displayTaskName(f.source_action)+' · vedere il job origine per i dettagli.','minor'));
 }
 if(Array.isArray(f.access_comparison)&&f.access_comparison.length){
  const block=element('div',null,'access-identity-comparison');
  block.append(element('h4','Identità utilizzate · profili auth.yaml'));
  const table=element('table',null,'identity-table');const head=element('tr');
  for(const h of ['Profilo utilizzato','Accesso atteso','Risposta HTTP'])head.append(element('th',h));
  table.append(head);
  for(const entry of f.access_comparison){const tr=element('tr');
   for(const v of [entry.profile||'Non disponibile',entry.expected||'Non specificato',entry.status_code?'HTTP '+entry.status_code:'Non registrata'])tr.append(element('td',v));
   table.append(tr);
  }
  block.append(table,element('p','Sono mostrati solo gli alias dei profili e i codici di risposta, mai Bearer token, cookie o contenuti HTTP.','minor'));
  cardNode.append(block);
 }
 if(f.discovery_method)cardNode.append(element('p','Come è stato rilevato: '+f.discovery_method,'minor'));
 if(f.test_request)cardNode.append(element('p','Richiesta esaminata: '+f.test_request,'minor'));
 if(f.what_found)cardNode.append(element('p','Cosa è stato trovato: '+f.what_found));
 if(f.cvss_base_score!==undefined)cardNode.append(element('p','CVSS v3.1: '+f.cvss_base_score+' · '+f.cvss_vector+' (vettore fornito dall’analista, non calcolato automaticamente dal tool)','minor'));
 cardNode.append(element('p','Perché è un finding: '+(f.reason||'Segnale da verificare, non vulnerabilità confermata.')));
 if(f.verification_guidance)cardNode.append(element('p','Verifica necessaria: '+f.verification_guidance,'minor'));
 if(Array.isArray(f.test_payloads)&&f.test_payloads.length){
  const info=element('details');info.open=true;
  info.append(element('summary','Payload realmente inviati · '+f.test_payloads.length));
  const input=f.test_input||{};
  info.append(element('p','Parametro: '+(input.parameter||'non disponibile')+' · posizione: '+(input.location||'non disponibile')+' · baseline: '+(input.baseline||'non disponibile'),'minor'));
  const code=element('pre',f.test_payloads.map((x,i)=>`${i+1}. ${x}`).join('\n'),'payload-evidence');
  info.append(code);cardNode.append(info);
 }else{
  cardNode.append(element('p',f.source_type==='ai_hypothesis'?'Payload: nessuno. L’AI ha generato un’ipotesi ma non ha eseguito richieste sul target.':(f.test_request?'Payload applicativo: non previsto/registrato per questo controllo. Per i test di autorizzazione si confrontano richieste, identità e risposte HTTP; nessun token viene mostrato.':'Payload HTTP: non applicabile a questo finding statico o non registrato in questa versione.'),'minor'));
 }
 if(f.evidence&&typeof f.evidence==='object'&&Object.keys(f.evidence).length){const d=element('details');d.append(element('summary','Metadati di confronto HTTP'),tree(f.evidence));cardNode.append(d)}
}
// The same taxonomy drives standalone reports and the complete-suite view.
// Categories are presentation only: severity and confidence come from the engine.
const FINDING_SECTIONS = [
 ['authorization','Autorizzazione · possibili BOLA/BFLA','Confronti tra profili, policy attesa e status HTTP osservati; una risposta 2xx non dimostra da sola accesso ai dati.'],
 ['injection','Injection e input applicativi','Indicatori ottenuti da sonde effettivamente inviate; occorre controllare le evidenze ed escludere falsi positivi.'],
 ['ai','Ipotesi prodotte dall’AI','Proposte del modello, non verificate automaticamente con richieste HTTP.'],
 ['static','Avvisi statici OpenAPI','Indicazioni dedotte dal contratto Swagger; nessuna violazione runtime è dimostrata.'],
 ['other','Altre osservazioni','Risultati di analisi e altri controlli che richiedono una valutazione contestuale.']
];
function findingSection(f){
 const category=String(f.category||'').toLowerCase();
 if(f.source_type==='ai_hypothesis')return 'ai';
 if(f.source_type==='static_openapi')return 'static';
 if(category.includes('authorization')||category.includes('mass_assignment')||category.startsWith('authz')||category.startsWith('bola')||category.startsWith('bfla'))return 'authorization';
 if(category.includes('injection')||category.includes('sqli')||category.includes('ssti')||category.includes('crlf'))return 'injection';
 return 'other';
}
function vulnerabilityName(f){
 const c=String(f.category||'').toLowerCase();
 if(f.source_type==='ai_hypothesis')return 'Ipotesi AI · '+(c.replace('ai_','')||'rischio generico');
 if(c==='auth-002')return 'Documentazione autenticazione mancante';
 if(c==='authz-001')return 'Endpoint candidato a BOLA (non verificato)';
 if(c.includes('mass_assignment'))return 'Possibile Mass Assignment: modifica persistente di campi vietati dalla policy';
 if(c.includes('bfla'))return 'Possibile Broken Function Level Authorization (BFLA)';
 if(c.includes('authorization'))return 'Possibile controllo di autorizzazione inefficace (BOLA/BFLA da classificare)';
 if(c.includes('sql_error')||c.includes('sql_boolean')||c.includes('sql_time'))return 'Possibile SQL Injection';
 if(c.includes('nosql'))return 'Possibile NoSQL Injection';
 if(c.includes('ssti'))return 'Possibile Server-Side Template Injection';
 if(c.includes('command'))return 'Possibile Command Injection (marcatore non conclusivo)';
 if(c.includes('xpath'))return 'Possibile XPath Injection';
 if(c.includes('ldap'))return 'Possibile LDAP Injection';
 if(c.includes('crlf'))return 'Possibile CRLF/Header Injection';
 return 'Osservazione da esaminare';
}
// Macro severity is the highest severity actually reported within that group.
// This is a presentation roll-up, NOT an increase in confidence or an exploit proof.
const SEVERITY_ORDER=Object.freeze({critical:5,high:4,medium:3,low:2,informational:1,info:1});
const severityRank=value=>SEVERITY_ORDER[String(value||'informational').toLowerCase()]||1;
function highestSeverity(rows){
 const strongest=(rows||[]).reduce((current,item)=>severityRank(item.severity)>severityRank(current)?item.severity:current,'informational');
 return strongest==='info'?'informational':strongest;
}
function groupedFindings(target,findings,opts={}){
 target.replaceChildren();const groups=new Map();
 FINDING_SECTIONS.forEach(([key,label,description],ordinal)=>groups.set(key,{key,label,description,ordinal,subtypes:new Map(),count:0,findings:[]}));
 for(const f of findings){
  const group=groups.get(findingSection(f));const category=String(f.category||f.title||'Altra osservazione');
  if(!group.subtypes.has(category))group.subtypes.set(category,[]);
  group.subtypes.get(category).push(f);group.findings.push(f);group.count++;
 }
 const ordered=[...groups.values()].filter(group=>group.count).sort((a,b)=>
  severityRank(highestSeverity(b.findings))-severityRank(highestSeverity(a.findings))||a.ordinal-b.ordinal);
 for(const group of ordered){
  const macroSeverity=highestSeverity(group.findings);
  const section=element('details',null,'finding-section');section.open=true;
  section.dataset.severity=macroSeverity;
  const heading=element('summary');
  heading.append(element('span',group.label+' · '+group.count+' osservazioni'));
  heading.append(element('span','Severità massima: '+macroSeverity,'tag severity-rollup '+macroSeverity));
  section.append(heading,element('p',group.description,'minor'));
  const clusters=[...group.subtypes.entries()].sort((a,b)=>
    severityRank(highestSeverity(b[1]))-severityRank(highestSeverity(a[1]))||a[0].localeCompare(b[0]));
  for(const [category,entries] of clusters){
   const sortedEntries=[...entries].sort((a,b)=>severityRank(b.severity)-severityRank(a.severity));
   const cluster=element('details',null,'finding-category');cluster.open=entries.length<=3;
   const clusterTitle=element('summary');
   clusterTitle.append(element('span',category+' · '+entries.length+' '+(entries.length===1?'risultato':'risultati')));
   clusterTitle.append(element('span',highestSeverity(entries),'tag '+highestSeverity(entries)));
   cluster.append(clusterTitle,element('p','Tipo: '+vulnerabilityName(entries[0]),'minor'));
   for(const f of sortedEntries){
    const record=element('details',null,'finding-record');
    const title=element('summary');
    const participants=(f.access_comparison||[]).map(x=>x.profile).filter(Boolean).join(' vs ');
    title.append(element('strong',f.operation||f.endpoint||f.title||category));
    if(participants)title.append(element('span',' · '+participants,'minor'));
    title.append(element('span',f.severity||'informational','tag '+String(f.severity||'informational').toLowerCase()));
    record.append(title,element('p','Tipologia: '+vulnerabilityName(f),'minor'));
    if(f.rule_id)record.append(element('p','Regola della matrice: '+f.rule_id,'minor'));
    findingExplanation(record,f);
    if(f.source_job_id){const link=element('a','Apri il job origine (nuova scheda)');link.href='/job/'+encodeURIComponent(f.source_job_id);link.target='_blank';link.rel='noopener noreferrer';record.append(link)}
    cluster.append(record);
   }
   section.append(cluster);
  }
  target.append(section);
 }
 if(!ordered.length)target.append(element('div','Nessuna osservazione per i filtri selezionati. Un test non eseguito non equivale a risultato negativo.','empty'));
}
function renderFindings(panel){
 filterBar(panel,true);
 const selected=(isSuite()?(data.suite_findings||[]):(data.findings||[])).filter(f=>(severity==='all'||f.severity===severity)&&matches(f));
 const list=element('div');groupedFindings(list,selected);panel.append(list);
}

function renderSections(panel){filterBar(panel,false);const groups=(data.sections||[]).filter(s=>matches(s));if(!groups.length)panel.append(element('div','Questo comando non ha prodotto elenchi strutturati. Usa “Dettagli” per esplorare gli altri campi.','empty'));for(const group of groups){const c=element('section',null,'group');const head=element('div',null,'group-head');add(head,element('h3',group.title),element('span',group.count+' elementi','minor'));c.append(head,element('div',group.key,'minor'));const visible=(group.items||[]).filter(item=>matches(item));for(const item of visible.slice(0,120)){const entry=card(typeof item==='string'?item:(item.operation||item.endpoint||item.path||item.action||item.name||item.method||'Elemento'));if(item&&typeof item==='object'){if(group.key==='steps'&&/^[a-f0-9]{32}$/.test(item.job_id||'')){const link=element('a','Apri risultato · '+item.status);link.href='/job/'+encodeURIComponent(item.job_id);link.target='_blank';link.rel='noopener noreferrer';entry.append(link)}entry.append(tree(item))}c.append(entry)}if(visible.length>120)c.append(element('p','Mostrati i primi 120 elementi filtrati.','minor'));panel.append(c)}}
function renderAI(panel){filterBar(panel,false);const sections=(data.ai||[]);if(!sections.length){panel.append(element('div','Nessuna analisi AI strutturata in questo job. Se è una funzione offline, non implica un errore.','empty'));return}for(const item of sections){if(!matches(item))continue;const c=card(item.title);const obj=item.data||{};if(obj.executive_summary)c.append(element('p',obj.executive_summary));for(const [key,val] of Object.entries(obj)){if(key==='executive_summary')continue;const d=element('details');d.append(element('summary',key.replaceAll('_',' ')+' · '+scalar(val)),tree(val));c.append(d)}panel.append(c)}}
function renderSummary(panel){const s=data.summary||{};const c=element('div',null,'section-list');const left=card('Informazioni sull’esecuzione');for(const [k,v] of Object.entries(s)){if(v&&typeof v==='object')continue;const r=element('div',null,'fact');add(r,element('span',k.replaceAll('_',' ')),element('strong',scalar(v)));left.append(r)}c.append(left);const right=card('Significato del risultato');right.append(element('p',data.notice||''));if((data.highlights||[]).length)for(const t of data.highlights)right.append(element('div',t,'minor'));if(data.limitations?.length){const d=element('details');d.open=true;d.append(element('summary','Limitazioni del report'),tree(data.limitations));right.append(d)}c.append(right);panel.append(c);if(data.findings?.length){const shortcut=card(`${data.findings.length} osservazioni da esaminare`,'Apri la scheda Osservazioni per filtrare categoria, severità ed endpoint.');const btn=element('button','Esamina osservazioni','details-button');btn.onclick=()=>switchTab('findings');shortcut.append(btn);panel.append(shortcut)}}
function optionSelect(options,selected){const box=element('select');for(const [value,label] of options){const opt=element('option',label);opt.value=value;box.append(opt)}box.value=selected||options[0][0];return box}
function field(label,type='text',value=''){const wrap=element('label',label,'retry-field');const inp=element('input');inp.type=type;if(type==='checkbox'){inp.checked=Boolean(value)}else{inp.value=String(value||'')}wrap.append(inp);return [wrap,inp]}
function rowCheck(text,checked=false){const [label,box]=field(text,'checkbox',checked);return [label,box]}
function suiteReason(reason){return window.AchillesPublicNames?.text(reason||'Il controllo richiede input aggiuntivi o una verifica della configurazione.')||reason}
function fixFromDashboard(message){
 const explicit=arguments.length>1?arguments[1]:null;
 const guide=explicit?.section && explicit?.instructions ?
  {section:explicit.section,detail:explicit.instructions}:
  window.AchillesIssueGuide?.diagnose(message,'suiteStatus');
 if(!guide)return null;
 const labels={step1:'Importa API',step2:'URL e scope',step3:'Utenti e credenziali',
  workflowCreateSection:'Prepara workflow e cleanup',workflowManageSection:'Workflow salvati',
  massAssignmentPanel:'Mass Assignment · PATCH',bflaPanel:'BFLA',fullSuite:'Suite completa',
  authMatrixSection:'Matrice degli accessi',rc13Panel:'Analisi approfondita',
  agentOptionsSection:'Agente AI',step5:'Risultati e report'};
 const wrap=element('div',null,'suite-remediation');
 wrap.append(element('p','Come risolvere: '+guide.detail,'minor'));
 const link=element('a','Apri nella dashboard: '+(labels[guide.section]||guide.section));
 link.href='/#'+encodeURIComponent(guide.section);link.target='_blank';link.rel='noopener noreferrer';
 wrap.append(link);return wrap;
}
function reviewTitle(f){return f.source_type==='ai_hypothesis' ? (f.title||'AI · ipotesi da verificare') : (f.category||f.title||'Osservazione da verificare')}
function renderSuite(panel){
 const summary=data.suite_summary||{},steps=data.suite_steps||[],findings=data.suite_findings||[];
 const activeActions=new Set(steps.filter(s=>Number(s.http_requests_sent||s.http_observations||0)>0).map(s=>s.action));
 const isActiveFinding=f=>f.source_type!=='ai_hypothesis'&&f.source_type!=='static_openapi'&&activeActions.has(f.source_action);
 const activeFindings=findings.filter(isActiveFinding).length;
 const aiFindings=findings.filter(f=>f.source_type==='ai_hypothesis').length;
 const staticFindings=findings.filter(f=>f.source_type==='static_openapi').length;
 const head=card('Campagna di test · risultati riuniti','I risultati dei task sono consultabili qui. Gli indicatori HTTP derivano da risposte reali; gli avvisi statici derivano da analisi del contratto OpenAPI. Nessuno dei due equivale da solo a una vulnerabilità confermata.');
 head.classList.add('suite-hero');
 if(data.ai_readiness){
  const ai=data.ai_readiness;
  head.append(element('p','Ollama · '+(ai.status||'sconosciuto')+' · modello '+(ai.model||'non selezionato')+' · '+(ai.message||''),'minor'));
 }

 const stats=element('div',null,'suite-stats');for(const [key,label] of [['completed','Completati'],['failed','Falliti'],['skipped','Saltati']])metric(stats,summary[key]||0,label);metric(stats,activeFindings,'Indicatori HTTP');metric(stats,aiFindings,'Ipotesi AI da verificare');metric(stats,staticFindings,'Avvisi statici');head.append(stats);
 if(data.quality_gate?.state){head.append(element('p','Verifica qualità: '+data.quality_gate.state+' · copertura e task non eseguiti nella scheda Qualità esecuzione.','minor'));}
 panel.append(head);
 const writeCoverage=data.write_operation_coverage;
 if(writeCoverage&&Array.isArray(writeCoverage.operations)){
  const covered=card('Copertura delle operazioni di scrittura',
   writeCoverage.documented_write_operations+' operazioni POST/PATCH/PUT/DELETE nello Swagger · '+
   writeCoverage.with_approved_fixture+' con fixture autorizzata · '+
   writeCoverage.executed_write_operations+' incluse in campagne concluse. Una campagna completata non conferma il successo di ogni richiesta.');
  const unresolved=writeCoverage.operations.filter(op=>op.state==='not_tested_no_approved_fixture');
  if(unresolved.length){const details=element('details');details.append(element('summary',unresolved.length+' operazioni senza fixture/cleanup approvati'));
   for(const op of unresolved)details.append(element('p',op.operation,'minor'));
   covered.append(details)}
  panel.append(covered);
 }
 const dossier=card('Dossier AI completo','Apri in una scheda separata tutte le analisi AI disponibili dai task della campagna: sintesi, osservazioni, test raccomandati, limitazioni e consigli. Nessuna richiesta HTTP viene inviata.');
 const dossierLink=element('a','Apri il dossier delle analisi AI in nuova scheda');dossierLink.href='/job/'+encodeURIComponent(jobId)+'/ai';dossierLink.target='_blank';dossierLink.rel='noopener noreferrer';dossierLink.className='dossier-link';dossier.append(dossierLink);panel.append(dossier);
 const alerts=card('Osservazioni e vulnerabilità potenziali',`${activeFindings} indicatori da test HTTP · ${aiFindings} ipotesi AI · ${staticFindings} avvisi statici. Gli avvisi OpenAPI (es. security non dichiarata) non sono violazioni automaticamente confermate.`);
 const kindFilter=optionSelect([['all','Tutte le osservazioni'],['http','Solo indicatori HTTP'],['ai','Solo ipotesi AI'],['static','Solo avvisi statici']], 'all');kindFilter.setAttribute('aria-label','Filtra per provenienza del finding');alerts.append(kindFilter);
 const findingFilter=element('input');findingFilter.type='search';findingFilter.placeholder='Cerca categoria, endpoint, severità…';findingFilter.setAttribute('aria-label','Cerca osservazioni della suite');alerts.append(findingFilter);
 const findingsList=element('div');alerts.append(findingsList);
 function fillFindings(){
  const q=findingFilter.value.toLowerCase();
  const selected=findings.filter(f=>{
   const fromHTTP=isActiveFinding(f);
   if(kindFilter.value==='http'&&!fromHTTP)return false;
   if(kindFilter.value==='ai'&&f.source_type!=='ai_hypothesis')return false;
   if(kindFilter.value==='static'&&f.source_type!=='static_openapi')return false;
   return !q||JSON.stringify(f).toLowerCase().includes(q);
  });
  groupedFindings(findingsList,selected);
 }
 findingFilter.oninput=fillFindings;kindFilter.onchange=fillFindings;fillFindings();panel.append(alerts);
 const gaps=data.coverage_gaps||[];
 if(gaps.length){
  const missing=card('Cosa non è stato verificato · '+gaps.length+' controlli','Queste classi non risultano coperte dai task saltati o falliti. Un controllo non eseguito non equivale a un risultato negativo.');
  for(const gap of gaps){const d=element('details');d.append(element('summary',(gap.capability||gap.task)+' · '+gap.status),
    element('p','Motivo: '+gap.reason),element('p','Come sbloccarlo: '+gap.next_step,'minor'));const fix=fixFromDashboard(gap.reason+' '+gap.next_step);if(fix)d.append(fix);missing.append(d)}
  panel.append(missing);
 }
 const tasks=card('Task della suite','Espandi un task per visualizzare i suoi risultati qui oppure aprirli in una scheda separata. I task saltati o falliti possono essere rilanciati singolarmente.');
 const filter=element('input');filter.type='search';filter.placeholder='Filtra task per nome, stato, prerequisito…';filter.setAttribute('aria-label','Filtra task della suite');tasks.append(filter);
 const taskContainer=element('div');tasks.append(taskContainer);
 function drawTasks(){taskContainer.replaceChildren();steps.forEach((step,index)=>{if(filter.value&&!JSON.stringify(step).toLowerCase().includes(filter.value.toLowerCase()))return;
 const d=element('details',null,'suite-task '+(step.status||''));const sum=element('summary');add(sum,element('strong',displayTaskName(step.action||'Task')+(step.workflow_label?' · '+step.workflow_label:'')),element('span',step.status||'unknown','tag '+step.status));if(step.candidate_indicators>0)sum.append(element('span',step.candidate_indicators+' indicatori da verificare','tag'));if(step.http_requests_sent>0)sum.append(element('span',step.http_requests_sent+' richieste HTTP','tag'));if(step.ai_status)sum.append(element('span','Ollama: '+step.ai_status,'tag'));d.append(sum);
 const help=data.task_help_map?.[step.action];
 if(help){const info=element('div',null,'task-help');
  info.append(element('h4','Cosa fa questo task'),element('p',help.purpose),
   element('h4','Cosa serve per funzionare'),element('p',help.requires),
   element('p',help.interpretation,'minor'));
  d.append(info);}
 if(step.reason)d.append(element('p',suiteReason(step.reason),'suite-reason'));if(['failed','skipped','blocked'].includes(step.status)){const remediation=fixFromDashboard(step.error||step.reason||'',step.remediation);if(remediation)d.append(remediation);}if(step.ai_note)d.append(element('p',step.ai_note,'minor'));
 const linkRow=element('div',null,'suite-actions');
 if(step.job_id){const link=element('a','Apri questo job in nuova scheda');link.href='/job/'+encodeURIComponent(step.job_id);link.target='_blank';link.rel='noopener noreferrer';linkRow.append(link);
 const inline=element('button','Esplora qui');inline.type='button';const preview=element('div',null,'suite-inline');inline.onclick=async()=>{preview.replaceChildren(element('p','Caricamento…'));try{const res=await fetch('/api/job-view/'+encodeURIComponent(step.job_id),{cache:'no-store'});const sub=await res.json();if(!res.ok)throw Error(sub.detail||'Risultato non disponibile');preview.replaceChildren();const fl=sub.findings||[];preview.append(element('h4',fl.length+' osservazioni da verificare'));if(fl.length){for(const f of fl.slice(0,80)){const c=card(reviewTitle(f));c.append(element('span',f.severity||'info','tag '+String(f.severity).toLowerCase()),element('p',f.operation||f.endpoint||'','minor'));findingExplanation(c,f);preview.append(c)}}else preview.append(element('p','Nessuna osservazione rilevata da questo task.','minor'));for(const section of (sub.ai||[])){const info=element('details');info.append(element('summary','AI · '+section.title),tree(section.data));preview.append(info)}for(const sec of (sub.sections||[]).slice(0,12)){const info=element('details');info.append(element('summary',sec.title+' · '+sec.count+' elementi'),tree(sec.items));preview.append(info)}}catch(e){preview.replaceChildren(element('p','Errore: '+e.message,'suite-reason'))}};linkRow.append(inline);d.append(linkRow,preview)}
 if(['failed','skipped'].includes(step.status))addRetryEditor(d,step,index);
 if(step.attempts?.length){const history=element('details');history.append(element('summary','Storico tentativi · '+step.attempts.length),tree(step.attempts));d.append(history)}taskContainer.append(d)})}
 filter.oninput=drawTasks;drawTasks();panel.append(tasks);
}
function addRetryEditor(container,step,index){
 const section=element('details',null,'retry-editor');
 section.append(element('summary','Correggi e riprova · '+displayTaskName(step.action)+(step.workflow_label?' · '+step.workflow_label:'')));
 const form=element('div',null,'retry-form');section.append(form);
 const loading=element('p','Caricamento dei prerequisiti per '+displayTaskName(step.action)+'…','minor');form.append(loading);
 section.addEventListener('toggle',()=>{if(section.open&&!section.dataset.loaded){section.dataset.loaded='yes';prepareRetry().catch(e=>{loading.textContent='Impossibile caricare i prerequisiti: '+e.message})}});
 async function prepareRetry(){
  const response=await fetch(`/api/control/suite/${encodeURIComponent(jobId)}/prerequisites/${index}`,{cache:'no-store'});
  const options=await response.json();if(!response.ok)throw Error(options.detail||'Prerequisiti non disponibili');
  const r=options.retry_requirements||{};form.replaceChildren();
  form.append(element('p',suiteReason(step.reason||step.error),'suite-reason'));
  form.append(element('p','I dati già presenti nella suite sono riutilizzati automaticamente. Qui compaiono soltanto i dati necessari a questo task. Nessuna richiesta viene eseguita durante la compilazione.','minor'));
  let authFile=null,configFile=null,usage=null,generatedAuth=null,generatedConfig=null,builderDetails=null;
  let retryProfileSelectors=[];
  const makeFile=(caption,accept)=>{const item=field(caption,'file');item[1].accept=accept;form.append(item[0]);return item[1]};
  const note=msg=>form.append(element('p',msg,'minor'));
  if(r.needs_auth){
    if(r.has_auth)note('✓ auth.yaml già configurato: verrà riutilizzato.');
    else{
      note('Manca auth.yaml: importa soltanto questo file oppure genera qui profili Bearer.');
      const authQuick=element('details',null,'guided-prerequisites');authQuick.append(element('summary','Crea auth.yaml con nomi e token senza scrivere YAML'));form.append(authQuick);
      const profiles=[],list=element('div');authQuick.append(list);
      const addProfile=()=>{if(profiles.length>=12)return;const name=field('Nome profilo (es. owner)');const token=field('Token Bearer','password');name[1].placeholder='owner';token[1].autocomplete='off';list.append(name[0],token[0]);profiles.push([name[1],token[1]])};
      addProfile();const addButton=element('button','Aggiungi utente','secondary');addButton.type='button';addButton.onclick=addProfile;authQuick.append(addButton);
      const create=element('button','Genera e valida auth.yaml','retry-submit');create.type='button';authQuick.append(create);
      create.onclick=async()=>{create.disabled=true;try{const entries=profiles.map(([name,token])=>({name:name.value.trim(),type:'bearer',token:token.value}));
       const csrf=(await(await fetch('/api/bootstrap')).json()).csrf_token;
       const resp=await fetch('/api/import-text',{method:'POST',headers:{'content-type':'application/json','x-achilles-token':csrf},body:JSON.stringify({kind:'auth',name:'retry-auth.yaml',content:JSON.stringify({profiles:entries})})});
       const obj=await resp.json();if(!resp.ok)throw Error(obj.detail||'auth.yaml non valido');generatedAuth=obj.id;
       for(const [,token] of profiles)token.value='';authQuick.open=false;feedback.textContent='✓ auth.yaml creato e validato sul server locale.';await refreshRetryProfiles(generatedAuth);
      }catch(e){feedback.textContent='Credenziali non valide: '+e.message}finally{create.disabled=false}};
      authFile=makeFile('Oppure carica auth.yaml esistente','.yaml,.yml');
    }
  }
  // Changing auth.yaml must immediately refresh the user selectors for a
  // retry, not leave them bound to the original (possibly empty) suite auth.
  async function refreshRetryProfiles(authId){
   if(!authId||!retryProfileSelectors.length)return;
   const response=await fetch(`/api/control/suite/${encodeURIComponent(jobId)}/prerequisites/${index}?auth_config_id=${encodeURIComponent(authId)}`,{cache:'no-store'});
   const details=await response.json();if(!response.ok)throw Error(details.detail||'Impossibile leggere i profili');
   const names=details.auth_profiles||[];
   if(names.length<2){feedback.textContent='auth.yaml caricato, ma servono almeno due identità differenti.';return}
   retryProfileSelectors.forEach((selector,i)=>{
    const previous=selector.value;selector.replaceChildren();
    for(const name of names)selector.append(new Option(name,name));
    selector.value=names.includes(previous)?previous:names[Math.min(i,names.length-1)];
   });
   feedback.textContent='✓ '+names.length+' identità disponibili nel retry. Seleziona la coppia e completa gli ID.';
  }
  const secrets={};
  const addSecret=(variable)=>{if(secrets[variable])return;const item=field('Credenziale '+variable+' (necessaria al profilo)','password');item[1].autocomplete='off';form.append(item[0]);secrets[variable]=item[1];};
  for(const variable of r.required_secret_variables||[]){
   addSecret(variable);
  }
  if(authFile){authFile.onchange=async()=>{if(!authFile.files?.length)return;
    try{const csrf=(await(await fetch('/api/bootstrap')).json()).csrf_token;
     const fd=new FormData();fd.append('file',authFile.files[0]);
     const res=await fetch('/api/auth-config',{method:'POST',headers:{'x-achilles-token':csrf},body:fd});
     const info=await res.json();if(!res.ok)throw Error(info.detail||'auth.yaml non valido');
     generatedAuth=info.id;await refreshRetryProfiles(generatedAuth);for(const entry of info.descriptions||info.profiles||[]){for(const name of entry.environment_variables||[])addSecret(name)}
     if(builderDetails){builderDetails.replaceChildren(element('summary','Crea il file richiesto con il modulo guidato'));
      await mountPrerequisiteBuilder(builderDetails,jobId,index,step.action,result=>{generatedConfig=result;feedback.textContent='✓ Configurazione generata e validata.'},()=>generatedAuth)}
     feedback.textContent='✓ auth.yaml valido. Inserisci soltanto le eventuali variabili mostrate.';
    }catch(e){feedback.textContent='auth.yaml non importato: '+e.message}
   }}
  if(r.needs_config){
   if(r.has_config)note('✓ Configurazione «'+r.current_usage+'» già disponibile: verrà riutilizzata.');
   else{
    note('Manca soltanto la configurazione '+(r.config_usages||[]).join(' / ')+' per '+step.action+'.');
    if(options.builder && step.action!=='access-probe' && step.action!=='auth-profiles'){
      const guided=element('details',null,'guided-prerequisites');guided.open=true;builderDetails=guided;
      guided.append(element('summary','Crea il file richiesto con il modulo guidato'));form.append(guided);
      await mountPrerequisiteBuilder(guided,jobId,index,step.action,result=>{
       if(result.auth_config_id)generatedAuth=result.auth_config_id;
       else generatedConfig=result;
       feedback.textContent='✓ Configurazione generata e validata per '+step.action+'.';
      },()=>generatedAuth);
    }else{
      // Fallback for a task without a specialized generator: typed JSON rows
      // rather than requiring a raw JSON document to be written by hand.
      const guided=element('details',null,'guided-prerequisites');guided.append(element('summary','Costruisci un file JSON semplice dal modulo'));form.append(guided);
      const rows=[],list=element('div');guided.append(list);
      function addRow(){if(rows.length>=30)return;const key=field('Nome proprietà JSON');const value=field('Valore');const type=optionSelect([['string','Testo'],['number','Numero'],['boolean','Booleano'],['json','Oggetto/array JSON']],'string');const typeLabel=element('label','Tipo valore','retry-field');typeLabel.append(type);list.append(key[0],typeLabel,value[0]);rows.push([key[1],type,value[1]])}
      addRow();const plus=element('button','Aggiungi proprietà','secondary');plus.type='button';plus.onclick=addRow;guided.append(plus);
      const create=element('button','Crea JSON','retry-submit');create.type='button';guided.append(create);
      create.onclick=async()=>{create.disabled=true;try{const obj={};for(const [k,t,v] of rows){const name=k.value.trim();if(!name||name==='__proto__'||name==='constructor')throw Error('Nome proprietà non valido');
       let value=v.value;if(t.value==='number'){value=Number(value);if(!Number.isFinite(value))throw Error('Numero non valido: '+name)}
       if(t.value==='boolean'){if(!['true','false'].includes(value))throw Error('Usa true/false: '+name);value=value==='true'}
       if(t.value==='json'){value=JSON.parse(value)}obj[name]=value}
       const csrf=(await(await fetch('/api/bootstrap')).json()).csrf_token;
       const resp=await fetch('/api/import-text',{method:'POST',headers:{'content-type':'application/json','x-achilles-token':csrf},body:JSON.stringify({kind:'config',name:'retry-input.json',content:JSON.stringify(obj)})});
       const result=await resp.json();if(!resp.ok)throw Error(result.detail||'JSON non valido');generatedConfig={id:result.id,config_usage:r.config_usages?.[0]||'context'};
       feedback.textContent='✓ JSON formato correttamente. La struttura specifica sarà verificata durante il retry.';
      }catch(e){feedback.textContent='JSON non creato: '+e.message}finally{create.disabled=false}};
    }
    configFile=makeFile('Oppure carica il file di configurazione richiesto','.yaml,.yml,.json');
    usage=optionSelect((r.config_usages||['multi-resource']).map(x=>[x,x]),r.config_usages?.[0]||'multi-resource');
    const label=element('label','Tipo configurazione caricata','retry-field');label.append(usage);form.append(label);
   }
  }
  const probe={profiles:[],values:[],operation:null,expected:null};
  if(step.action==='access-probe'||step.action==='rc16-access-auto'){
    const heading=element('h4',step.action==='rc16-access-auto'?'Confronto automatico tra identità · Lettura risorse':'GET da confrontare con due identità');form.append(heading);
    const names=options.auth_profiles||[];
    if(names.length){for(const i of [0,1]){const fieldLabel=element('label',i?'Secondo utente':'Utente proprietario','retry-field');const select=optionSelect(names.map(n=>[n,n]),names[Math.min(i,names.length-1)]);fieldLabel.append(select);form.append(fieldLabel);probe.profiles.push(select)}}
    else{for(const caption of ['Utente proprietario','Secondo utente']){const f=field(caption);form.append(f[0]);probe.profiles.push(f[1])}}
    retryProfileSelectors=probe.profiles;
    const getOps=(options.operations||[]).filter(x=>x.method==='GET'&&!(x.parameters||[]).some(p=>p.location==='query'&&p.required));
    probe.operation=optionSelect(getOps.map(x=>[x.operation,x.operation]),getOps[0]?.operation);
    const opLabel=element('label','Endpoint GET','retry-field');opLabel.append(probe.operation);if(step.action==='access-probe')form.append(opLabel);
    probe.expected=optionSelect([['deny','Accesso vietato'],['allow','Accesso consentito'],['unknown','Policy non nota']],'unknown');
    const policy=element('label','Risultato atteso da policy','retry-field');policy.append(probe.expected);form.append(policy);
    const parameters=element('div');form.append(parameters);
    function renderParams(){parameters.replaceChildren();probe.values=[];
     const inputs=step.action==='rc16-access-auto'
       ? [...new Map(getOps.flatMap(op=>(op.parameters||[]).filter(p=>p.location==='path').map(p=>[p.name,p]))).values()].slice(0,15)
       : (getOps.find(x=>x.operation===probe.operation.value)?.parameters||[]).filter(p=>p.location==='path');
     if(step.action==='rc16-access-auto')parameters.append(element('p','Inserisci gli ID di prova approvati per tutte le categorie di risorsa (massimo 15). I test senza ID saranno indicati separatamente.','minor'));
     for(const p of inputs){
      const f=field('ID di test per '+p.name);f[1].placeholder='ID approvato per '+p.name;parameters.append(f[0]);probe.values.push([p.name,f[1]])}}
    probe.operation.onchange=renderParams;renderParams();
  }
  let workflowIdentitySelectors=[],workflowExpectedPolicy=null;
  if(step.action==='rc16-assess'){
    form.append(element('h4','Identità e policy per tutti i controlli di questa risorsa'));
    const names=options.auth_profiles||[];
    for(let i=0;i<2;i++){
      const wrap=element('label',i===0?'Profilo proprietario':'Profilo da confrontare','retry-field');
      const selector=names.length ? optionSelect(names.map(n=>[n,n]),names[Math.min(i,names.length-1)]) : element('select');
      if(!names.length)selector.append(new Option('Carica auth.yaml per scegliere i profili',''));
      wrap.append(selector);form.append(wrap);workflowIdentitySelectors.push(selector);
    }
    retryProfileSelectors=workflowIdentitySelectors;
    const policy=element('p','La policy del secondo utente deve essere dichiarata da chi conosce i permessi applicativi. Le scritture richiedono un manifest con cleanup verificato.','minor');form.append(policy);
    workflowExpectedPolicy=optionSelect([['unknown','Seleziona la policy attesa (obbligatoria)'],['deny','Secondo profilo NON autorizzato (deny)'],['allow','Secondo profilo autorizzato (allow)']],'unknown');
    const policyLabel=element('label','Policy attesa per il secondo profilo','retry-field');policyLabel.append(workflowExpectedPolicy);form.append(policyLabel);
  }
  let injection=[];
  if(step.action==='injection-assess'){
   const controls=element('details',null,'guided-prerequisites');controls.append(element('summary','Categorie injection'));form.append(controls);
   for(const [id,label,defaultOn] of [['sql_error','SQLi error',true],['sql_boolean','SQLi boolean',true],['sql_time','SQLi time-based',false],['nosql','NoSQL',true],['ssti','SSTI',true],['command','Command marker',true],['xpath','XPath',true],['ldap','LDAP',true],['crlf','CRLF',true]]){
    const control=rowCheck(label,defaultOn);controls.append(control[0]);injection.push([id,control[1]])}
  }
  let activeCheck=null,approval=null,writes=null,scopeUrl=null,scopeHost=null,plain=null;
  if(r.active_capable){
    const box=rowCheck('Esegui richieste HTTP per questo task',r.active_selected);activeCheck=box[1];
    if(r.active_selected){activeCheck.disabled=true;note('Questa suite era già in modalità HTTP; il retry mantiene tale modalità.');}
    else form.append(box[0]);
    const network=element('div');form.append(network);
    const displayActive=()=>{network.replaceChildren();if(!activeCheck.checked)return;
      if(!r.has_scope){const u=field('Base URL autorizzato','text',r.base_url||'');const h=field('Hostname autorizzato','text',r.allow_host||'');scopeUrl=u[1];scopeHost=h[1];network.append(u[0],h[0])}
      const check=rowCheck('Confermo l’autorizzazione per questo task HTTP',false);approval=check[1];network.append(check[0]);
      if(r.requires_writes){const check=rowCheck('Approvo POST/PATCH/DELETE sulle fixture selezionate',false);writes=check[1];network.append(check[0])}
      const url=scopeUrl?.value||r.base_url||'';
      if(url.startsWith('http://')&&!/https?:\/\/(?:127\.0\.0\.1|localhost)(?::|\/|$)/.test(url))note('HTTP in chiaro fuori da localhost è bloccato.');
      if(url.startsWith('http://')&&/https?:\/\/(?:127\.0\.0\.1|localhost)(?::|\/|$)/.test(url)){
        const check=rowCheck('Permetto HTTP locale con credenziali',false);plain=check[1];network.append(check[0]);
      }
    };
    if(!r.active_selected)activeCheck.onchange=displayActive;displayActive();
  }
  if(r.active_capable && !r.active_selected && /^http:\/\/(127\.0\.0\.1|localhost)(?=[:/]|$)/.test(r.base_url||'')){
    const local=rowCheck('Consenti l’URL HTTP del laboratorio localhost per il retry (nessun traffico se offline)',false);
    form.append(local[0]);
    if(!plain)plain=local[1];
  }
  let ai=null,model=null;
  if(r.ai_capable){
    const item=rowCheck('Abilita AI locale per questo task',r.ai_selected);ai=item[1];if(r.ai_selected)ai.disabled=true;else form.append(item[0]);
    if(!r.ai_selected){const m=field('Modello Ollama (solo se abiliti AI)','text','achilles-local');model=m[1];m[0].hidden=true;form.append(m[0]);ai.onchange=()=>m[0].hidden=!ai.checked}
  }
  if(r.needs_source_assessment&&!r.has_source_assessment){
   const message=element('p','Mancano osservazioni HTTP reali. Prima esegui auto-assess attivo; non caricare o generare un JSON che simuli risposte.','suite-reason');form.append(message);
   const link=element('a','Apri lo workspace per eseguire auto-assess');link.href='/#step4';form.append(link);
  }
  let budget=null;
  // The campaign ledger counts actually attempted requests, not estimated reservations.
  if(r.active_capable && (r.actual_remaining_requests??r.max_total_requests)<(r.requires_writes?r.per_task_requests:1)){
    const remaining=Number(r.actual_remaining_requests)||0;
    const required=Math.max(1,Number(r.per_task_requests)||1);
    const suggested=Number(r.max_total_requests)+Math.max(0,required-remaining);
    if(suggested<=600){
      const item=field('Nuovo limite TOTALE di richieste HTTP per questo retry (approvazione esplicita)','number',String(suggested));budget=item[1];budget.min=String(r.max_total_requests);budget.max='600';form.append(item[0]);
      form.append(element('p','I tentativi già effettuati restano conteggiati: il budget non viene azzerato.','suite-reason'));
    }else{
      form.append(element('p','Budget globale esaurito: hai raggiunto il massimo di 600. Per continuare avvia una nuova suite con uno scope ridotto e solo i controlli mancanti.','suite-reason'));
    }
  }
  const advanced=element('details',null,'guided-prerequisites');advanced.append(element('summary','Sostituisci file già configurati (facoltativo)'));form.append(advanced);
  let alternateAuth=null,alternateConfig=null,alternateUsage=null;
  if(r.has_auth&&r.needs_auth){const f=field('Sostituisci auth.yaml','file');f[1].accept='.yaml,.yml';advanced.append(f[0]);alternateAuth=f[1]}
  if(r.has_config&&r.needs_config){const f=field('Sostituisci configurazione','file');f[1].accept='.yaml,.yml,.json';advanced.append(f[0]);alternateConfig=f[1];alternateUsage=optionSelect((r.config_usages||[]).map(x=>[x,x]),r.current_usage);const l=element('label','Tipo file','retry-field');l.append(alternateUsage);advanced.append(l)}
  if(alternateAuth)alternateAuth.onchange=async()=>{
    if(!alternateAuth.files?.length)return;
    try{
      const csrf=(await(await fetch('/api/bootstrap')).json()).csrf_token;
      const fd=new FormData();fd.append('file',alternateAuth.files[0]);
      const response=await fetch('/api/auth-config',{method:'POST',headers:{'x-achilles-token':csrf},body:fd});
      const info=await response.json();if(!response.ok)throw Error(info.detail||'auth.yaml non valido');
      generatedAuth=info.id;await refreshRetryProfiles(generatedAuth);
      for(const entry of info.descriptions||info.profiles||[])for(const name of entry.environment_variables||[])addSecret(name);
    }catch(error){feedback.textContent='Impossibile aggiornare i profili: '+error.message}
  };
  if(!alternateAuth&&!alternateConfig)advanced.remove();
  const button=element('button','Riprova soltanto '+step.action,'retry-submit');button.type='button';form.append(button);
  const feedback=element('p','','minor');feedback.setAttribute('role','status');form.append(feedback);
  if(r.needs_source_assessment&&!r.has_source_assessment){button.disabled=true;button.title='Esegui prima un auto-assess attivo';}
  button.onclick=async()=>{button.disabled=true;feedback.textContent='Controllo dei prerequisiti…';try{
    const csrf=(await(await fetch('/api/bootstrap')).json()).csrf_token;
    async function uploadFile(input,path){if(!input?.files?.length)return null;const fd=new FormData();fd.append('file',input.files[0]);const resp=await fetch(path,{method:'POST',headers:{'x-achilles-token':csrf},body:fd});const data=await resp.json();if(!resp.ok)throw Error(data.detail||'Caricamento fallito');return data.id}
    const a=generatedAuth||(await uploadFile(authFile||alternateAuth,'/api/auth-config'));
    const c=await uploadFile(configFile||alternateConfig,'/api/control/config');
    const isActive=!!(activeCheck&&activeCheck.checked);
    if(isActive&&!approval?.checked)throw Error('Conferma l’autorizzazione al test HTTP.');
    if(isActive&&r.requires_writes&&!writes?.checked)throw Error('Approva esplicitamente le scritture.');
    const secretValues={};for(const [name,input] of Object.entries(secrets)){if(input.value)secretValues[name]=input.value}
    const payload={step_index:index,enable_active:isActive,enable_ai:!!(ai?.checked||r.ai_selected),
     acknowledgment:isActive,approve_writes:!!(isActive&&writes?.checked),allow_insecure_http:!!plain?.checked,
     secrets:secretValues};
    if(a||generatedAuth)payload.auth_config_id=a||generatedAuth;
    if(c||generatedConfig){payload.config_id=c||generatedConfig.id;payload.config_usage=c?(usage||alternateUsage)?.value:generatedConfig.config_usage}
    if(scopeUrl?.value.trim())payload.base_url=scopeUrl.value.trim();
    if(scopeHost?.value.trim())payload.allow_host=scopeHost.value.trim();
    if(ai?.checked&&model?.value.trim())payload.model=model.value.trim();
    if(budget)payload.max_total_requests=Math.max(1,Math.min(600,Number(budget.value)||600));
    if(injection.length)payload.injection_families=injection.filter(([k,i])=>i.checked).map(([k])=>k);
    if(step.action==='access-probe'||step.action==='rc16-access-auto'){
     const names=probe.profiles.map(x=>x.value.trim());if(names.length!==2||!names[0]||!names[1]||names[0]===names[1])throw Error('Seleziona due profili distinti.');
     if(!probe.operation.value)throw Error('Seleziona una GET.');
     payload.profiles=names;
     if(step.action==='access-probe')payload.operation=probe.operation.value;
     payload.expected_other=probe.expected.value;
     payload.path_values=probe.values.filter(([name,input])=>step.action==='access-probe'||input.value.trim()).map(([name,input])=>{if(!input.value.trim())throw Error('Inserisci ID '+name);return name+'='+input.value.trim()});
     if(step.action==='rc16-access-auto'&&!payload.path_values.length)throw Error('Inserisci almeno un ID per uno degli endpoint GET riconosciuti.');
    }
    if(step.action==='rc16-assess'){
      const names=workflowIdentitySelectors.map(x=>x.value.trim());
      if(names.length!==2||!names[0]||!names[1]||names[0]===names[1])throw Error('Seleziona due identità differenti dal file auth.yaml.');
      payload.profiles=names;
      if(!['deny','allow'].includes(workflowExpectedPolicy?.value))throw Error('Indica esplicitamente se il secondo profilo deve avere accesso (allow) o no (deny).');
      payload.expected_other=workflowExpectedPolicy.value;
    }
    const resp=await fetch('/api/control/suite/'+encodeURIComponent(jobId)+'/retry',{method:'POST',headers:{'content-type':'application/json','x-achilles-token':csrf},body:JSON.stringify(payload)});
    const result=await resp.json();if(!resp.ok)throw Error(typeof result.detail==='string'?result.detail:JSON.stringify(result.detail));
    for(const input of Object.values(secrets))input.value='';feedback.textContent='✓ Retry avviato. Gli altri task non saranno rieseguiti.';
    status('Retry di '+step.action+' avviato');setTimeout(load,1200);
   }catch(e){feedback.textContent='Non avviato: '+e.message;button.disabled=false}
  };
 }
 container.append(section);
}

// Mostra separatamente quality gate e finding: una campagna offline non è "sicura".
function renderQualityPanel(panel){
 const q=data.quality_gate||{};
 if(!q.metrics){panel.append(element('div','La verifica qualità non è ancora disponibile.','empty'));return}
 const stats=element('div',null,'metrics');
 for(const [key,label] of [['total_steps','Task pianificati'],['failed','Errori'],['skipped','Non eseguiti'],['reported_http_observations','Osservazioni HTTP']])metric(stats,q.metrics[key]??0,label);
 panel.append(stats);
 const note=card('Qualità della campagna · '+q.state,
  'Questo è un controllo di completezza, non una conferma che l’API sia priva di vulnerabilità.');
 for(const check of q.checks||[]){const row=element('div',null,'fact');
  add(row,element('strong',check.id+' · '+check.status),element('span',check.detail));note.append(row)}
 panel.append(note);
 if(data.release_readiness?.checks){const review=element('details');review.append(element('summary','Controlli di readiness · RC2'),tree(data.release_readiness));panel.append(review)}
 const traffic=data.http_telemetry||{};
 if(traffic.scope==='campaign_all_processes'){
  const aggregate=element('div',null,'metrics');
  for(const [value,label] of [[traffic.attempted??0,'Tentativi HTTP globali'],
   [traffic.responses_received??0,'Risposte HTTP'],[traffic.network_errors??0,'Errori rete'],
   [traffic.remaining??0,'Budget residuo']])metric(aggregate,value,label);
  panel.append(aggregate);
  const detail=element('details');detail.append(element('summary','Contabilità per status e limiti'),tree(traffic));panel.append(detail);
 }
 panel.append(card('Contabilità del traffico',data.http_accounting_note||
 'Non confondere osservazioni registrate con tutte le richieste inviate.'));
 if(q.limitations?.length){const d=element('details');d.append(element('summary','Limiti della valutazione'),tree(q.limitations));panel.append(d)}
}

// Le categorie OWASP indicano ipotesi da testare, non vulnerabilità trovate.
function renderRiskPanel(panel){
 const capabilities=data.security_capabilities||{};
 if(Array.isArray(capabilities.candidates)&&capabilities.candidates.length){
  panel.append(card('Superfici di verifica individuate nello Swagger',capabilities.candidates.length+' candidati: non sono test HTTP né finding confermati.'));
  for(const item of capabilities.candidates.slice(0,100)){
   const row=element('details',null,'coverage-operation');
   row.append(element('summary',item.title+' · '+item.operation));
   row.append(element('p','Campo o parametro: '+(item.field||'non specificato'),'minor'));
   row.append(element('p','Per eseguire la verifica: '+item.prerequisite,'minor'));
   row.append(element('p','Stato: candidato · non eseguito.','minor'));
   panel.append(row);
  }
  return;
 }
 const risks=data.risk_matrix||{};const cases=risks.candidates||[];
 if(!cases.length){panel.append(element('div','Nessuna superficie candidata deducibile dai path. Non significa assenza di vulnerabilità.','empty'));return}
 const intro=card('Matrice OWASP API Security',cases.length+' test candidati generati senza inviare HTTP. Nessuna vulnerabilità viene dichiarata confermata.');panel.append(intro);
 const toolbar=element('div',null,'filter-row');const searchBox=element('input');searchBox.type='search';searchBox.placeholder='Cerca endpoint o tipologia…';
 const categories=['all',...[...new Set(cases.map(x=>x.owasp_category))].sort()];
 const select=optionSelect(categories.map(x=>[x,x==='all'?'Tutte le categorie':x]),'all');toolbar.append(searchBox,select);panel.append(toolbar);
 const list=element('div');panel.append(list);
 function redraw(){list.replaceChildren();let shown=0;
  for(const item of cases){if(select.value!=='all'&&item.owasp_category!==select.value)continue;
   if(searchBox.value&&!JSON.stringify(item).toLowerCase().includes(searchBox.value.toLowerCase()))continue;
   const row=card(item.hypothesis,item.operation);const tag=element('span',item.owasp_category,'tag');
   row.append(tag,element('p',item.preconditions,'minor'),element('p','Da verificare · nessuna prova di vulnerabilità','minor'));list.append(row);shown++;if(shown>=250)break}
  if(!shown)list.append(element('div','Nessun elemento con questi filtri.','empty'));
 }
 searchBox.oninput=redraw;select.onchange=redraw;redraw();
}

function renderCoverageTab(panel){
 if(data.rc13_coverage&&data.rc13_coverage.coverage_not_a_security_score){
  const cov=data.rc13_coverage;
  const metrics=element('div',null,'metrics');
  for(const [val,label] of [[cov.operations_documented??0,'Operazioni documentate'],
    [cov.operations_with_http_attempts??0,'Operazioni con tentativi HTTP'],
    [cov.operations_with_evaluable_http_results??0,'Operazioni con risposte valutabili'],
    [(cov.operations_not_verified||[]).length,'Operazioni non verificate']])metric(metrics,val,label);
  if(data.verification&&data.verification.unique_review_items!==undefined){
   const review=element('details',null,'group');review.append(element('summary','Verifica evidenze e deduplicazione · '+data.verification.unique_review_items+' gruppi da revisionare'),tree(data.verification.observations||[]));panel.append(review);
  }
  panel.append(metrics,card('Copertura dei test · misurazione effettiva',
   'La copertura indica richieste eseguite, non una percentuale di sicurezza. Le operazioni non verificate restano esplicitamente elencate.'));
  const states=element('details',null,'group');states.open=true;
  states.append(element('summary','Esiti dell’analisi approfondita'),tree(cov.stages||{}));panel.append(states);
  const missing=element('details',null,'group');missing.append(element('summary',
   'Operazioni non verificate · '+(cov.operations_not_verified||[]).length));
  missing.append(tree(cov.operations_not_verified||[]));panel.append(missing);
  return;
 }
 const coverage=data.compatibility||((data.details||{}).engine==='achilles-compatibility-v080'?data.details:{});
 if(!coverage?.summary){panel.append(element('div','Questo job non contiene una matrice OpenAPI.', 'empty'));return}
 const sum=coverage.summary,stats=element('div',null,'metrics');
 for(const [value,label] of [[sum.operations,'Operazioni Swagger'],[sum.observed_operations,'Endpoint osservati'],[sum.http_coverage_percent+'%','Copertura HTTP'],[sum.not_observed_operations,'Senza evidenze HTTP']])metric(stats,value,label);
 panel.append(stats);
 const notice=card('Come leggere la matrice','Una proposta di test non è un finding. Un endpoint senza osservazioni non è stato verificato. La copertura HTTP non misura quante vulnerabilità siano state scoperte.');panel.append(notice);
 const section=card('Matrice endpoint · filtri interattivi');const filter=element('input');filter.type='search';filter.placeholder='Cerca metodo, path, prerequisito…';filter.setAttribute('aria-label','Cerca nella matrice');section.append(filter);
 const select=element('select');for(const [val,label] of [['all','Tutte le operazioni'],['not_observed','Senza evidenze HTTP'],['needs_configuration','Configurazione mancante'],['requires_approval','Autorizzazione richiesta'],['candidate','Candidate ai test']]){const option=element('option',label);option.value=val;select.append(option)}section.append(select);
 const entries=element('div');section.append(entries);function redraw(){entries.replaceChildren();let shown=0;for(const op of coverage.operations||[]){if(filter.value&&!JSON.stringify(op).toLowerCase().includes(filter.value.toLowerCase()))continue;if(select.value!=='all'&&(select.value==='not_observed'?op.coverage!=='not_observed':op.applicability!==select.value))continue;
 const d=element('details',null,'coverage-operation');d.append(element('summary',op.operation+' · '+op.applicability+' · '+op.http_observations+' risposte HTTP'));
 if(op.missing_inputs?.length)d.append(element('p','Manca: '+op.missing_inputs.join(' · '),'minor'));
 d.append(tree({security_schemes:op.security_schemes,required_parameters:op.required_parameters,suggested_checks:op.suggested_checks}));entries.append(d);shown++;if(shown>=450)break}
 if(!shown)entries.append(element('p','Nessun endpoint corrispondente.','minor'))};filter.oninput=redraw;select.onchange=redraw;redraw();panel.append(section);
 for(const [title,key] of [['Gate di rilascio v0.99 (revisione umana necessaria)','release_readiness'],['Verifica indicatori (non automaticamente confermati)','verification'],['Audit qualità della campagna','quality_gate'],['Preflight task','task_preflight'],['Matrice OWASP API Security','risk_matrix'],['Workflow inferiti dallo Swagger','workflow_proposals'],['Preparazione profili autenticazione','auth_readiness'],['Superfici di sicurezza da verificare','security_surfaces'],['Piano adattivo senza esecuzione automatica','adaptive_plan']]){const obj=data[key];if(!obj||Object.keys(obj).length===0)continue;const details=element('details',null,'group');details.append(element('summary',title),tree(obj));panel.append(details)}
}

function renderPanel(){const panel=node('panel');panel.replaceChildren();if(!data)return;
 if(!isSuite()&&data.task_help){const h=data.task_help;const info=card('Cosa fa questo task',h.purpose);
  info.append(element('h4','Cosa serve per funzionare'),element('p',h.requires),element('p',h.interpretation,'minor'));panel.append(info);}
if(active==='suite')renderSuite(panel);else if(active==='coverage')renderCoverageTab(panel);else if(active==='risk')renderRiskPanel(panel);else if(active==='quality')renderQualityPanel(panel);else if(active==='summary')renderSummary(panel);else if(active==='findings')renderFindings(panel);else if(active==='sections')renderSections(panel);else if(active==='ai')renderAI(panel);else{filterBar(panel,false);const detail=data.details||{};const visible=Object.fromEntries(Object.entries(detail).filter(([k,v])=>matches({[k]:v})));panel.append(tree(visible))}}
function switchTab(tab){active=tab;search='';severity='all';for(const b of node('tabs').children)b.setAttribute('aria-selected',String(b.dataset.tab===tab));renderPanel()}
function setupTabs(){const tabs=node('tabs');tabs.replaceChildren();for(const [id,label,count] of [...(isSuite()?[['suite','Risultati suite',data.suite_steps.length]]:[]),...(isSuite()||data.rc13_coverage?.coverage_not_a_security_score||data.details?.engine==='achilles-compatibility-v080'?[['coverage','Copertura e preflight','']]:[]),...(isSuite()?[['risk','Ipotesi OWASP',data.risk_matrix?.candidates?.length||0],['quality','Qualità esecuzione','']]:[]),['summary','Panoramica',''],['findings','Osservazioni',isSuite()?(data.suite_findings?.length||0):(data.findings?.length||0)],['sections','Elementi e azioni',data.sections?.length||0],['ai','Analisi AI',data.ai?.length||0],['details','Dettagli esplorabili','']]){const btn=element('button',label+(count!==''?' · '+count:''));btn.dataset.tab=id;btn.setAttribute('aria-selected',String(id===active));btn.onclick=()=>switchTab(id);tabs.append(btn)}}
async function load(){try{if(!/^[a-f0-9]{32}$/.test(jobId))throw Error('Identificativo del job non valido');const resp=await fetch('/api/job-view/'+encodeURIComponent(jobId),{cache:'no-store'});const body=await resp.json();if(!resp.ok)throw Error(body.detail||'Job non disponibile');if(body.status!=='complete'&&!(body.action==='full-suite'&&Array.isArray(body.suite_steps))){status('Job '+(body.status||'in corso')+(body.completed_steps!==undefined?' · '+body.completed_steps+'/'+(body.total||'?')+' funzionalità · '+(body.current_step||'preparazione'):'')+(body.error?': '+body.error:''),body.status==='failed');if(body.status==='orchestrating'||body.status==='running')setTimeout(load,2500);return}data=body;if(isSuite()&&active==='summary')active='suite';node('jobTitle').textContent=isSuite()?(data.display_name||'Suite · '+jobId.slice(0,12)):displayTaskName(data.action||'Risultato');node('jobSubtitle').textContent=data.source_kind+' · '+jobId.slice(0,12)+' · risultato completato';for(const [id,url] of [['aiDossier',`/job/${jobId}/ai`],['htmlExport',`/api/export/${jobId}/html`],['pdfExport',`/api/export/${jobId}/pdf`],['jsonExport',`/api/export/${jobId}/json`],['rawExport',`/api/control/download/${jobId}`]])node(id).href=url;const metrics=node('metrics');metrics.replaceChildren();metric(metrics,isSuite()?(data.suite_findings||[]).filter(f=>f.source_type!=='ai_hypothesis'&&f.source_type!=='static_openapi'&&new Set((data.suite_steps||[]).filter(s=>Number(s.http_requests_sent||s.http_observations||0)>0).map(s=>s.action)).has(f.source_action)).length:(data.findings?.length||0),isSuite()?'Indicatori HTTP da verificare':'Osservazioni da verificare');if(isSuite())metric(metrics,(data.suite_findings||[]).filter(f=>f.source_type==='ai_hypothesis').length,'Ipotesi AI (non verificate)');metric(metrics,isSuite()?data.summary?.campaign_http_attempted??0:data.summary?.target_requests_reported??0,isSuite()?'Tentativi HTTP globali':'Richieste HTTP riportate');metric(metrics,data.summary?.operations_in_spec??'—','Operazioni nello Swagger');metric(metrics,data.sections?.length||0,'Sezioni esplorabili');setupTabs();renderPanel();status(data.status==='orchestrating'?'Suite in esecuzione · risultati parziali aggiornati automaticamente.':'Risultato completo · consultazione sanitizzata; i retry richiedono conferma esplicita.');if(data.status==='orchestrating')setTimeout(()=>{if(document.querySelector('.retry-editor:focus-within'))setTimeout(load,3000);else load()},2500)}catch(e){status('Impossibile aprire il job: '+e.message,true)}}
node('refresh').onclick=load;load();
