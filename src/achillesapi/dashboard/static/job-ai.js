'use strict';
// Read-only dossier. Never interpret AI content as markup or executable code.
const jobId=decodeURIComponent(location.pathname.split('/').slice(-2)[0]||'');
const get=id=>document.getElementById(id);
const displayTaskName=name=>name==='rc13-assess'?'Analisi approfondita API':name;
function el(tag,text,cls){const out=document.createElement(tag);if(text!==undefined&&text!==null)out.textContent=String(text);if(cls)out.className=cls;return out}
function safeTree(data,depth=0){const wrap=el('div',null,'tree');if(depth>7){wrap.append(el('p','[limite profondità]'));return wrap}
 if(data&&typeof data==='object'){
  for(const [key,value] of Object.entries(data).slice(0,260)){
   const row=el('details');row.open=depth===0;
   const count=value&&typeof value==='object'?(Array.isArray(value)?value.length+' elementi':Object.keys(value).length+' campi'):'';
   row.append(el('summary',Array.isArray(data)?'Elemento '+(Number(key)+1):key.replaceAll('_',' ')+(count?' · '+count:'')));
   if(value&&typeof value==='object')row.append(safeTree(value,depth+1));
   else row.append(el('p',value===null?'null':String(value),'dossier-text'));
   wrap.append(row);
  }
 }else wrap.append(el('p',String(data),'dossier-text'));
 return wrap;
}
function renderField(parent,key,value){
 const readable={'executive_summary':'Sintesi esecutiva','risk_observations':'Rischi e ipotesi',
   'recommended_tests':'Test consigliati','recommended_actions':'Azioni consigliate',
   'recommendations':'Raccomandazioni','next_steps':'Prossimi passi',
   'limitations':'Limiti dell’analisi','cross_correlations':'Correlazioni',
   'false_positive_checks':'Verifiche contro i falsi positivi'};
 const title=readable[key]||key.replaceAll('_',' ');
 const box=el('details',null,'finding-category');box.open=['executive_summary','risk_observations','recommended_tests','recommendations','next_steps'].includes(key);
 box.append(el('summary',title));
 if(typeof value==='string')box.append(el('p',value,'dossier-text'));
 else if(Array.isArray(value)){
  if(!value.length)box.append(el('p','Nessun elemento','minor'));
  for(const [i,item] of value.slice(0,250).entries()){
   const line=el('div',null,'dossier-entry');
   line.append(el('strong',String(i+1)+'. '));
   if(typeof item==='string')line.append(el('span',item));
   else line.append(safeTree(item));
   box.append(line);
  }
 }else box.append(safeTree(value));
 parent.append(box);
}
// Executive digest uses *only* the already-sanitized dossier supplied by the backend.
// No AI call, target request or HTML interpretation is performed.
function digestColumn(title, rows, kind, emptyMessage){
 const section=el('section',null,'digest-column digest-'+kind);
 const head=el('div',null,'digest-title');head.append(el('h3',title),el('span',String(rows.length),'digest-count'));section.append(head);
 if(!rows.length){section.append(el('p',emptyMessage,'minor'));return section}
 const list=el('ol',null,'digest-list');
 for(const item of rows){
  if(!item||typeof item.text!=='string')continue;
  const line=el('li');line.append(el('p',item.text,'digest-text'));
  const source=el('span','Fonte: '+displayTaskName(item.action||'job AI'),'digest-source');
  if(/^[a-f0-9]{32}$/.test(item.job_id||'')){
   const link=el('a','Apri analisi');link.href='/job/'+encodeURIComponent(item.job_id)+'/ai';link.target='_blank';link.rel='noopener noreferrer';source.append(' · ',link);
  }
  line.append(source);list.append(line);
 }
 section.append(list);return section;
}
function renderDigest(dossier){
 const container=get('digestBody');container.replaceChildren();
 const summary=dossier.executive_digest||{};
 const briefs=Array.isArray(summary.executive_summaries)?summary.executive_summaries:[];
 const risks=Array.isArray(summary.risks)?summary.risks:[];
 const actions=Array.isArray(summary.actions)?summary.actions:[];
 const limits=Array.isArray(summary.limitations)?summary.limitations:[];
 if(!briefs.length&&!risks.length&&!actions.length){
  container.append(el('div','Nessun riepilogo AI disponibile. Consulta i task e verifica se Ollama ha prodotto un output strutturato.','empty'));
  return;
 }
 if(briefs.length){const lead=el('div',null,'digest-lead');lead.append(el('h3','Quadro generale'));
  for(const brief of briefs)lead.append(el('p',brief.text,'dossier-text'));container.append(lead);
 }
 const columns=el('div',null,'digest-columns');
 columns.append(digestColumn('Cosa è stato segnalato',risks,'risks','Nessuna osservazione di rischio esplicita registrata.'));
 columns.append(digestColumn('Cosa è consigliato fare',actions,'actions','Nessuna azione consigliata esplicita registrata.'));
 container.append(columns);
 if(limits.length){const details=el('details',null,'digest-limitations');details.append(el('summary','Limiti e cautele dell’analisi · '+limits.length));
  const list=el('ul');for(const item of limits)list.append(el('li',item.text));details.append(list);container.append(details)
 }
}
function build(dossier){
 get('aiItems').replaceChildren();get('notExecuted').replaceChildren();get('metrics').replaceChildren();
 renderDigest(dossier);
 get('dossierSuiteName').textContent=dossier.display_name?'Suite · '+dossier.display_name:'';
 for(const [value,label] of [[dossier.total_ai_outputs||0,'Output AI disponibili'],[(dossier.tasks_without_ai_output||[]).length,'Task AI senza output registrato']]){
  const metric=el('div',null,'metric');metric.append(el('div',value,'value'),el('div',label,'caption'));get('metrics').append(metric);
 }
 const items=dossier.entries||[];
 if(!items.length)get('aiItems').append(el('div','Nessuna analisi AI strutturata è stata registrata in questo job. Controlla i task saltati, il modello selezionato e lo stato Ollama.','empty'));
 for(const item of items){
  const article=el('section',null,'row-card');
  const heading=el('div',null,'group-head');heading.append(el('h3',item.action));
  heading.append(el('span',item.provenance==='ollama_eseguito'?'Ollama utilizzato':item.provenance==='analisi_deterministica'?'Analisi deterministica':'Output AI presente · inferenza non verificata','tag'));
  article.append(heading,el('p','Stato: '+item.ai_status+' · '+item.note,'minor'));
  const link=el('a','Apri il job di origine in nuova scheda');link.href='/job/'+encodeURIComponent(item.job_id);link.target='_blank';link.rel='noopener noreferrer';article.append(link);
  for(const section of item.sections||[]){
   const group=el('details',null,'dossier-section');group.open=true;group.append(el('summary',section.name.replaceAll('_',' ')));
   if(section.data&&typeof section.data==='object'&&!Array.isArray(section.data)){
    for(const [key,value] of Object.entries(section.data))renderField(group,key,value);
   }else renderField(group,'Contenuto',section.data);
   article.append(group);
  }
  get('aiItems').append(article);
 }
 if((dossier.tasks_without_ai_output||[]).length){const skipped=el('section',null,'row-card');skipped.append(el('h3','Task senza output AI registrato'));
  for(const item of dossier.tasks_without_ai_output)skipped.append(el('p',item.action+' · '+item.reason,'minor'));
  get('notExecuted').append(skipped);
 }
}
async function load(){try{
 if(!/^[a-f0-9]{32}$/.test(jobId))throw Error('Identificativo job non valido');
 const response=await fetch('/api/job-ai/'+encodeURIComponent(jobId),{cache:'no-store'});
 const result=await response.json();if(!response.ok)throw Error(result.detail||'Dossier AI non disponibile');
 build(result);get('notice').textContent='Output sanitizzato · '+(result.entries||[]).length+' analisi disponibili · nessuna richiesta HTTP al target.';
}catch(error){get('notice').textContent='Errore apertura dossier AI: '+error.message;get('notice').classList.add('error')}}
get('backToJob').href='/job/'+encodeURIComponent(jobId);
get('refresh').onclick=load;
load();
