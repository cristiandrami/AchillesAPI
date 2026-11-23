'use strict';
// Forms contain only operator choices. The backend constructs and validates typed YAML/JSON.
async function mountPrerequisiteBuilder(parent, suite, stepIndex, action, onDone, getAuthId=()=>null) {
 const panel = document.createElement('section'); panel.className='prereq-builder';parent.append(panel);
 const el=(tag,txt,klass)=>{const n=document.createElement(tag);if(txt!==undefined)n.textContent=txt;if(klass)n.className=klass;return n};
 const field=(caption,val='',kind='text')=>{const l=el('label',caption,'retry-field');const i=el('input');i.type=kind;if(kind!=='file')i.value=val;l.append(i);panel.append(l);return i};
 const select=(caption,items)=>{const l=el('label',caption,'retry-field');const x=el('select');for(const [value,title] of items){const opt=el('option',title);opt.value=value;x.append(opt)}l.append(x);panel.append(l);return x};
 const button=(title,cb)=>{const b=el('button',title,'retry-submit');b.type='button';b.onclick=cb;panel.append(b);return b};
 const note=(msg)=>panel.append(el('p',msg,'minor'));
 note('Generazione guidata: il file verrà costruito e verificato sul server senza inviare richieste al target. I dati di ownership e le policy sono scelte dell’operatore, non deduzioni dello scanner.');
 const feedback=el('p','','minor');
 try{
 const authOverride=getAuthId();const params=authOverride?'?auth_config_id='+encodeURIComponent(authOverride):'';
 const res=await fetch(`/api/control/suite/${encodeURIComponent(suite)}/prerequisites/${stepIndex}`+params,{cache:'no-store'});
 const options=await res.json();if(!res.ok)throw Error(options.detail||'Impossibile caricare le opzioni');
 if(!options.builder){note('Per questo task puoi usare il caricamento file nel modulo sottostante.');return}
 const gets=(options.operations||[]).filter(o=>o.method==='GET');let build;
 if(action==='auth-profiles'){
  note('Inserisci il token direttamente nel file auth.yaml generato. Il token rimane sul server locale: non condividere il file.');
  const profiles=[],area=el('div');panel.append(area);
  function addProfile(){const block=el('fieldset',null,'builder-step');block.append(el('legend','Profilo '+(profiles.length+1)));const name=el('input');name.placeholder='Nome: owner, other, admin';block.append(name);const token=el('input');token.type='password';token.placeholder='Token Bearer (salvato in auth.yaml locale)';token.autocomplete='off';block.append(token);area.append(block);profiles.push({name,token});}
  addProfile();button('Aggiungi profilo Bearer',addProfile);
  build=()=>({profiles:profiles.map(p=>({name:p.name.value.trim(),type:'bearer',token:p.token.value}))});
 } else if(action==='ai-plan-guard'){
  note('Il piano AI è solo una proposta: nessuna azione verrà avviata. Seleziona controlli consentiti e un eventuale endpoint Swagger.');
  const operations=options.operations||[];
  const actions=[], area=el('div');panel.append(area);
  function addAction(){if(actions.length>=20)return;
   const group=el('fieldset',null,'builder-step');group.append(el('legend','Proposta '+(actions.length+1)));
   const a=el('select');for(const name of options.allowed_actions||[]){const opt=el('option',name);opt.value=name;a.append(opt)}group.append(a);
   const op=el('select');const none=el('option','Tutta l’API (nessun endpoint specifico)');none.value='';op.append(none);
   for(const item of operations){const option=el('option',item.operation);option.value=item.operation;op.append(option)}group.append(op);
   area.append(group);actions.push({a,op});
  }
  addAction();button('Aggiungi altra proposta',addAction);
  build=()=>({actions:actions.map(({a,op})=>({action:a.value,...(op.value?{operation:op.value}:{})}))});
 } else if(action==='analyze-evidence'){
  if(options.assessment_available){note('Sono disponibili evidenze HTTP dal job auto-assess della suite. Non è necessario cercare o creare manualmente un file.');build=()=>({});}
  else{note('Non ci sono risposte HTTP precedenti: esegui auto-assess attivo, poi riprova. Non è corretto generare risposte HTTP fittizie.');return}
 } else if(action==='access-matrix'){
  note('Prepara regole GET tra due profili, senza scrivere JSON. La policy va verificata con il proprietario dell’API.');
  const available=options.auth_profiles||[];
  if(available.length<2){note('Serve auth.yaml con almeno due profili: caricalo nel modulo di retry.');return}
  if(!gets.length){note('Lo Swagger non contiene operazioni GET applicabili.');return}
  const rules=[],wrap=el('div');panel.append(wrap);
  function addRule(){if(rules.length>=20)return;
   const group=el('fieldset',null,'builder-step');group.append(el('legend','Regola '+(rules.length+1)));
   const operation=el('select');for(const o of gets){const opt=el('option',o.operation);opt.value=o.operation;operation.append(opt)}group.append(operation);
   const owner=el('select');const other=el('select');for(const name of available){for(const ctrl of [owner,other]){const option=el('option',name);option.value=name;ctrl.append(option)}}
   if(available.length>1)other.selectedIndex=1;
   const ownerLabel=el('label','Profilo proprietario','retry-field');ownerLabel.append(owner);group.append(ownerLabel);
   const otherLabel=el('label','Secondo profilo','retry-field');otherLabel.append(other);group.append(otherLabel);
   const expectedOwner=el('select');for(const [value,label] of [['allow','Primo utente autorizzato'],['deny','Primo utente NON autorizzato']]){const item=el('option',label);item.value=value;expectedOwner.append(item)}
   const expectedOwnerLabel=el('label','Accesso atteso del primo utente','retry-field');expectedOwnerLabel.append(expectedOwner);group.append(expectedOwnerLabel);
   const expected=el('select');for(const [value,label] of [['deny','La lettura è vietata'],['allow','La lettura è consentita']]){const option=el('option',label);option.value=value;expected.append(option)}
   const expectedLabel=el('label','Comportamento atteso secondo la policy','retry-field');expectedLabel.append(expected);group.append(expectedLabel);
   const fields=el('div');group.append(fields);
   function update(){fields.replaceChildren();group._values=[];const info=gets.find(o=>o.operation===operation.value);
    for(const p of info?.parameters||[]){if(p.location!=='path')continue;const input=el('input');input.placeholder='ID autorizzato';
     const label=el('label',p.name+' (path)','retry-field');label.append(input);fields.append(label);group._values.push([p.name,input]);}}
   operation.onchange=update;update();wrap.append(group);rules.push({operation,owner,other,expected,expectedOwner,group});}
  addRule();button('Aggiungi regola GET',addRule);
  build=()=>({rules:rules.map((rule,i)=>{if(rule.owner.value===rule.other.value)throw Error('Le due identità devono essere diverse');
   const values={};for(const [name,input] of rule.group._values){if(!input.value.trim())throw Error('Inserisci '+name);values[name]=input.value.trim()}
   return {id:'retry-'+(i+1),operation:rule.operation.value,owner:rule.owner.value,
    other:rule.other.value,expected_owner:rule.expectedOwner.value,expected_other:rule.expected.value,path_values:values};})});
 } else if(action==='verify-access-policy'){
  note('Definisci una regola di accesso *attesa* e confermata dal responsabile dell’API. Il codice HTTP da solo non dimostra una BOLA.');
  const ops=select('Operazione GET soggetta alla regola',gets.map(o=>[o.operation,o.operation]));
  const identity=field('Identità del profilo (come in auth.yaml)','owner');
  const expected=select('Comportamento autorizzativo previsto',[['deny','L’identità NON deve accedere'],['allow','L’identità deve poter accedere']]);
  build=()=>({rules:[{operation:ops.value,identity:identity.value.trim(),expected:expected.value}]});
  if(options.observation_pairs?.length)note('Osservazioni disponibili per '+options.observation_pairs.length+' combinazioni operazione/identità. Scegli quelle per cui conosci davvero la policy.');
 } else if(action==='journey-assess'){
  note('Crea un percorso di lettura GET con valori autorizzati. Aggiungi più passaggi se vuoi attraversare più endpoint; non vengono fatte scritture.');
  const steps=[],wrap=el('div');panel.append(wrap);
  function addStep(){if(steps.length>=12)return;
   const group=el('fieldset',null,'builder-step');const legend=el('legend','Passaggio GET '+(steps.length+1));group.append(legend);
   const op=document.createElement('select');for(const o of gets){const item=el('option',o.operation);item.value=o.operation;op.append(item)}group.append(op);
   const params=el('div');group.append(params);
   const identity=el('input');identity.placeholder='Profilo (facoltativo)';group.append(identity);
   function update(){params.replaceChildren();const chosen=gets.find(o=>o.operation===op.value);const fields=[];
    for(const p of (chosen?.parameters||[])){const l=el('label',`${p.name} (${p.location}${p.required?', obbligatorio':''})`,'retry-field');const inp=el('input');inp.placeholder='Valore autorizzato';l.append(inp);params.append(l);fields.push([p.name,inp,p.required])}group._fields=fields}
   op.onchange=update;update();wrap.append(group);steps.push({op,group,identity});}
  addStep();button('Aggiungi passaggio GET',addStep);
  build=()=>({steps:steps.map(s=>{const values={};for(const [name,i,required] of s.group._fields){if(i.value.trim())values[name]=i.value.trim();else if(required)throw Error('Compila il parametro obbligatorio: '+name)}return {operation:s.op.value,values,...(s.identity.value.trim()?{identity:s.identity.value.trim()}:{})}})});
 } else if(action==='workflow-assess'||action==='multi-resource-assess'||action==='workflow-graph'){
  if(!options.candidates?.length){note('Lo Swagger non presenta un ciclo POST → GET → DELETE con un marker riconoscibile. Non posso generare un workflow sicuro; usa un file progettato e approvato manualmente.');return}
  note('Scegli un ciclo CRUD e conferma i dati della risorsa temporanea. Il server verificherà schema, ID e cleanup. Le scritture richiedono approvazione separata.');
  const candidates=options.candidates;
  const chosen=select('Ciclo di risorsa temporanea',candidates.map((c,i)=>[String(i),`${c.create} → ${c.read} → ${c.delete}`]));
  const owner=field('Profilo proprietario','owner'),other=field('Profilo secondo utente (facoltativo)','other');
  const marker=select('Campo marker della risorsa',[['label','label']]);const pointer=field('Campo ID nella risposta POST (es. id o /data/id)','id');
  const riskBox=el('label','Confermo di aver verificato questa GET sospetta e che il test usa solo fixture temporanee','retry-field');
  const riskCheck=el('input');riskCheck.type='checkbox';riskBox.prepend(riskCheck);panel.append(riskBox);
  const riskHelp=el('p','','minor');panel.append(riskHelp);
  const parentFields=el('div');panel.append(parentFields);
  const properties=el('div');panel.append(properties);
  function update(){const candidate=candidates[Number(chosen.value)];riskBox.hidden=!candidate.read_get_risk;
   riskCheck.checked=false;riskHelp.textContent=candidate.read_get_risk||'';
   parentFields.replaceChildren();parentFields._fields=[];
   for(const name of candidate.required_path_params||[]){const f=field('ID parent '+name);parentFields._fields.push([name,f]);parentFields.append(f.parentElement)}
   const oldMarker=marker.value;marker.replaceChildren();for(const name of candidate.marker_candidates){const opt=el('option',name);opt.value=name;marker.append(opt)}if(candidate.marker_candidates.includes(oldMarker))marker.value=oldMarker;pointer.value=(candidate.id_candidates||[])[0]||'id';properties.replaceChildren();const rows=[];
   for(const name of [...new Set([...(candidate.required||[]),marker.value])]){if(!candidate.fields.includes(name))continue;const spec=candidate.field_specs?.[name]||{};const l=el('label',name+' ('+(spec.type||'string')+')','retry-field');const inp=el('input');inp.value=String(candidate.body_example?.[name]??(name===marker.value?'temporary-test-resource':''));l.append(inp);properties.append(l);rows.push([name,inp,spec.type||'string'])}properties._rows=rows;}
  chosen.onchange=update;marker.onchange=update;update();
  build=()=>{const candidate=candidates[Number(chosen.value)];const body={};for(const [name,i,type] of properties._rows){const v=i.value.trim();if(!v||v==='REVIEW_VALUE')throw Error('Inserisci un valore reale e temporaneo per '+name);if(type==='integer'||type==='number'){const n=Number(v);if(!Number.isFinite(n))throw Error('Numero non valido: '+name);body[name]=n}else if(type==='boolean'){if(!['true','false'].includes(v.toLowerCase()))throw Error('Scrivi true o false: '+name);body[name]=v.toLowerCase()==='true'}else body[name]=v}
   if(!body[marker.value])throw Error('Compila il campo marker');
   if(candidate.read_get_risk&&!riskCheck.checked)throw Error('Conferma la GET sospetta soltanto dopo una verifica manuale');
   const path_values={};for(const [name,inp] of parentFields._fields){if(!inp.value.trim())throw Error('Inserisci ID parent '+name);path_values[name]=inp.value.trim()}
   return {candidate_index:Number(chosen.value),owner:owner.value.trim(),other:other.value.trim(),marker_field:marker.value,marker_value:String(body[marker.value]),id_pointer:pointer.value.trim(),body,path_values,acknowledge_get_side_effect_risk:riskCheck.checked};};
 } else if(action==='benchmark-evaluate'){
  note('Il benchmark NON è uno scanner: confronta due insiemi di ID etichettati da persone. Non è possibile inventare una ground truth a partire dallo Swagger o dai finding.');
  const positives=field('ID di vulnerabilità realmente presenti (separati da virgola)');
  const verified=field('ID di vulnerabilità verificate (separati da virgola)');
  const check=el('input');check.type='checkbox';const l=el('label','Confermo di avere validato indipendentemente gli ID','retry-field');l.prepend(check);panel.append(l);
  const ids=s=>s.split(',').map(x=>x.trim()).filter(Boolean);
  build=()=>({positive_ids:ids(positives.value),verified_positive_ids:ids(verified.value),human_verified:check.checked});
 } else {note('Usa il caricamento di un file già validato nel modulo sottostante.');return}
 const b=button('Genera e valida file per questo task',async()=>{b.disabled=true;feedback.textContent='Validazione in corso…';try{
  const payload=build();const newlyConfiguredAuth=getAuthId();if(newlyConfiguredAuth)payload.auth_config_id=newlyConfiguredAuth;const bootstrap=await(await fetch('/api/bootstrap')).json();const res=await fetch(`/api/control/suite/${encodeURIComponent(suite)}/prerequisites/${stepIndex}/generate`,{method:'POST',headers:{'content-type':'application/json','x-achilles-token':bootstrap.csrf_token},body:JSON.stringify(payload)});const generated=await res.json();if(!res.ok)throw Error(typeof generated.detail==='string'?generated.detail:JSON.stringify(generated.detail));onDone(generated);feedback.textContent='File creato e validato. Puoi ora cliccare “Riprova il task”.';
  }catch(e){feedback.textContent='File non generato: '+e.message}finally{b.disabled=false}});
 panel.append(feedback);
 }catch(e){panel.append(el('p','Errore nel builder: '+e.message,'suite-reason'))}
}
