// Runs the actual dashboard matrix editor functions in a minimal DOM simulation.
// No browser, target server or HTTP access is required.
'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

const root=path.resolve(__dirname,'..');
const full=fs.readFileSync(path.join(root,'src/achillesapi/dashboard/static/app.js'),'utf8');
const begin=full.indexOf('function invalidateGeneratedMatrix(){');
const end=full.indexOf("$('matrixOperation')?.addEventListener('change',renderMatrixPathFields);",begin);
assert(begin>=0&&end>begin,'actual matrix editor functions not found');
const source=full.slice(begin,end);
class Node {
 constructor(tag='div'){this.tag=tag;this.children=[];this.textContent='';this.className='';this.value='';this.disabled=false;this.attrs={};this.listeners={};this.dataset={};}
 append(...children){this.children.push(...children)}
 replaceChildren(){this.children=[]}
 addEventListener(kind,fn){this.listeners[kind]=fn}
 setAttribute(name,value){this.attrs[name]=value}
 click(){this.wasClicked=true}
 remove(){this.wasRemoved=true}
}
const els={};
const $=id=>els[id]||(els[id]=new Node());
for(const id of ['matrixRulesList','matrixStatus','matrixExport','matrixOperation','matrixOwner','matrixOther','matrixExpected','matrixOwnerExpected','configState'])$(id);
$('matrixOperation').value='GET /tenants/{tenant}/items/{id}';
$('matrixOwner').value='owner';$('matrixOther').value='other';
$('matrixExpected').value='deny';$('matrixOwnerExpected').value='allow';
const pathInputs=[new Node('input'),new Node('input')];
pathInputs[0].dataset.matrixPath='tenant';pathInputs[0].value='acme';
pathInputs[1].dataset.matrixPath='id';pathInputs[1].value='t100';
const downloads=[];
const context={$,document:{createElement:tag=>new Node(tag),querySelectorAll:()=>pathInputs,body:{append(el){downloads.push(el)}}},
  Blob,URL:{createObjectURL(blob){assert(blob.size>0);return 'blob:matrix-json'},revokeObjectURL(){}},console,setTimeout:(fn)=>fn(), specId:'spec',authId:'auth',matrixRules:[],
  matrixGetOps:[{method:'GET',path:'/tenants/{tenant}/items/{id}'},{method:'GET',path:'/health'}],
  matrixAuthProfiles:['owner','other','colleague'],matrixGeneratedConfigId:'',configId:'',
  show(){},request(){return Promise.resolve({id:'new-config'})},filterTools(){},toolDetails(){},
};
vm.createContext(context);vm.runInContext(source,context);
const json=rules=>JSON.stringify({rules});
const file=content=>({size:Buffer.byteLength(content),text:async()=>content});
const r1={id:'custom-1',operation:'GET /tenants/{tenant}/items/{id}',path_values:{tenant:'acme',id:'t100'},owner:'owner',other:'other',expected_owner:'allow',expected_other:'deny'};
const r2={id:'custom-2',operation:'GET /health',path_values:{},owner:'owner',other:'colleague',expected_owner:'deny',expected_other:'deny'};
const run=async()=>{
 await context.importMatrixJSON(file(json([r1,r2])));
 assert.equal(context.matrixGeneratedConfigId,'new-config', 'valid JSON must be persisted for the suite automatically');
 assert.equal(context.configId,'', 'matrix import must not overwrite an unrelated workflow manifest');
 assert.equal(context.matrixRules.length,2);
 assert.equal($('matrixRulesList').children.length,2);
 assert.equal($('matrixRulesList').children[0].children[1].textContent,'×');
 assert.match($('matrixRulesList').children[0].children[1].attrs['aria-label'],/Elimina regola 1/);
 assert.equal($('matrixExport').disabled,false);
 context.downloadMatrixJSON();
 assert.equal(downloads[0].download,'access-matrix.rules.json');
 assert.equal(downloads[0].wasClicked,true);
 context.matrixGeneratedConfigId='old-config'; context.configId='old-config';
 // One-click delete, no confirmation and no accidental re-use of the old configuration.
 $('matrixRulesList').children[0].children[1].listeners.click();
 assert.equal(context.matrixRules.length,1);
 assert.equal(context.matrixRules[0].id,'custom-2');
 assert.equal(context.configId,'');
 assert.match($('configState').textContent,/Matrice modificata/);
 // Invalid imports must NOT overwrite the remaining rules.
 await assert.rejects(()=>context.importMatrixJSON(file('bad-json')),/JSON valido/);
 await assert.rejects(()=>context.importMatrixJSON(file(json([r1,r1]))),/duplicato/);
 await assert.rejects(()=>context.importMatrixJSON(file(json([{...r1,other:'unknown'}]))),/auth.yaml/);
 await assert.rejects(()=>context.importMatrixJSON(file(json([{...r1,operation:'GET /unknown'}]))),/Swagger/);
 await assert.rejects(()=>context.importMatrixJSON(file(json([{...r1,path_values:{tenant:'acme'}}]))),/path_values/);
 await assert.rejects(()=>context.importMatrixJSON(file(json([{...r1,path_values:{tenant:'../acme',id:'a'}}]))),/non consentito/);
 assert.equal(context.matrixRules.length,1);
 context.addMatrixRule();
 assert.equal(context.matrixRules.length,2);
 assert.equal(context.matrixRules[1].id,'rule-1');
 assert.equal(context.matrixRules[0].id,'custom-2');
 context.matrixRules=[];
 context.addMatrixRule();context.addMatrixRule();
 assert.deepEqual(Array.from(context.matrixRules, r=>r.id),['rule-1','rule-2']);
 context.matrixRules.splice(0,1);context.addMatrixRule();
 assert.deepEqual(Array.from(context.matrixRules,r=>r.id),['rule-2','rule-1']);
 // Full import of the sample must work for the independent OpenAPI and auth profiles.
 const sample=JSON.parse(fs.readFileSync(path.join(root,'examples/northstar-access-matrix.rules.json'),'utf8'));
 const uniqueOps=[...new Set(sample.rules.map(r=>r.operation))];
 context.matrixGetOps=uniqueOps.map(o=>({method:'GET',path:o.slice(4)}));
 context.matrixAuthProfiles=['owner','other','colleague','manager','finance','other_manager'];
 await context.importMatrixJSON(file(JSON.stringify(sample)));
 assert.equal(context.matrixRules.length,14);
 await context.generateMatrix();
 assert.equal(context.configId,'new-config');
 assert.equal(context.matrixGeneratedConfigId,'new-config');
 // Further deletion invalidates exactly the generated matrix snapshot.
 $('matrixRulesList').children[13].children[1].listeners.click();
 assert.equal(context.configId,'');
 assert.equal(context.matrixRules.length,13);
 console.log('matrix editor DOM scenarios passed');
};
run().catch(error=>{console.error(error.stack||String(error));process.exitCode=1});
