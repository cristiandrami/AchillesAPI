'use strict';
/* AchillesAPI UI localization. Presentation-only: never translates payloads, evidence,
   JSON/YAML, technical identifiers or values submitted to the server. */
(() => {
  const LANGUAGES = Object.freeze({it:'Italiano',en:'English',es:'Español',fr:'Français'});
  const STORAGE_KEY = 'achillesapi.ui.language.v1';
  const dictionary = window.AchillesUILocales || {};
  const sourceNodes = new WeakMap();
  const sourceAttributes = new WeakMap();
  const noTranslate = 'script,style,code,pre,kbd,samp,textarea,[contenteditable="true"],[data-no-translate],.payload-evidence,.dossier-text,#reportPreview';
  let language = 'it';
  let scheduled = false;
  let observer;
  function savedLanguage(){try{return localStorage.getItem(STORAGE_KEY)||'it'}catch{return 'it'}}
  function remember(value){try{localStorage.setItem(STORAGE_KEY,value)}catch{/* private browser */}}
  function translate(text, target=language){
    if(!text) return text;
    const leading = text.match(/^\s*/)?.[0]||'';
    const trailing = text.match(/\s*$/)?.[0]||'';
    const inner = text.trim();
    const catalog = dictionary[target]||{};
    if(Object.prototype.hasOwnProperty.call(catalog,inner))return leading+catalog[inner]+trailing;
    // Translate known UI label prefixes while leaving runtime values and findings intact.
    const divider = inner.match(/^([^:]{2,65})(:\s*)(.+)$/s);
    if(divider && catalog[divider[1]])return leading+catalog[divider[1]]+divider[2]+divider[3]+trailing;
    // Preserve variables such as counts, endpoint names and model identifiers.
    const fragments = inner.split(/(\s+·\s+)/);
    if(fragments.length>1){
      let modified=false;
      const result=fragments.map(fragment=>{const clean=fragment.trim();if(catalog[clean]){modified=true;return fragment.replace(clean,catalog[clean])}return fragment});
      if(modified)return leading+result.join('')+trailing;
    }
    return text; // fallback to the original Italian string, never guess a translation
  }
  function excluded(node){
    const element=node.nodeType===3?node.parentElement:node;
    return !element || Boolean(element.closest(noTranslate));
  }
  function paintText(node){
    if(!node || node.nodeType!==3 || excluded(node))return;
    const raw=node.nodeValue;
    if(!raw || !raw.trim())return;
    let state=sourceNodes.get(node);
    if(!state || (raw!==state.last && raw!==state.source)){
      state={source:raw,last:raw};sourceNodes.set(node,state);
    }
    const next=translate(state.source);
    if(node.nodeValue!==next)node.nodeValue=next;
    state.last=next;
  }
  const LOCALIZED_ATTRIBUTES=['placeholder','title','aria-label','alt'];
  function paintAttributes(el){
    if(el.closest(noTranslate))return;
    let record=sourceAttributes.get(el);
    if(!record){record={};sourceAttributes.set(el,record)}
    for(const attr of LOCALIZED_ATTRIBUTES){
      if(!el.hasAttribute(attr))continue;
      const raw=el.getAttribute(attr);
      if(!record[attr] || (raw!==record[attr].last && raw!==record[attr].source))record[attr]={source:raw,last:raw};
      const state=record[attr];const next=translate(state.source);
      if(raw!==next)el.setAttribute(attr,next);
      state.last=next;
    }
  }
  function paint(root=document.body){
    if(!root)return;
    if(root.nodeType===3){paintText(root);return}
    if(root.nodeType!==1 || excluded(root))return;
    if(root.tagName==='TITLE')return;
    paintAttributes(root);
    const walker=document.createTreeWalker(root,NodeFilter.SHOW_ELEMENT|NodeFilter.SHOW_TEXT);
    let child;
    while((child=walker.nextNode())){
      if(child.nodeType===3)paintText(child);
      else if(!excluded(child))paintAttributes(child);
    }
  }
  function schedule(){if(scheduled)return;scheduled=true;queueMicrotask(()=>{scheduled=false;paint()})}
  function refreshControls(){
    document.documentElement.lang=language;
    document.querySelectorAll('[data-achilles-language]').forEach(select=>{
      if(select.value!==language)select.value=language;
    });
    const rootTitle=document.querySelector('title');
    if(rootTitle){
      const stored=rootTitle.dataset.italianTitle||rootTitle.textContent;
      rootTitle.dataset.italianTitle=stored;
      rootTitle.textContent=translate(stored);
    }
  }
  function setLanguage(target){
    if(!LANGUAGES[target])return false;
    language=target;remember(target);refreshControls();paint();
    window.dispatchEvent(new CustomEvent('achilles:language-change',{detail:{language:target}}));
    return true;
  }
  function mountSelector(){
    if(document.querySelector('[data-achilles-language]'))return;
    const header=document.querySelector('header.top .top-right,header.viewer-top .top-actions');
    if(!header)return;
    const box=document.createElement('label');box.className='language-control';
    const caption=document.createElement('span');caption.className='language-label';caption.textContent='Lingua';
    const select=document.createElement('select');select.id='uiLanguage';select.setAttribute('data-achilles-language','');select.setAttribute('aria-label','Lingua dell’interfaccia');
    for(const [key,name] of Object.entries(LANGUAGES)){
      const option=document.createElement('option');option.value=key;option.textContent=name;select.append(option);
    }
    select.value=language;
    select.addEventListener('change',()=>setLanguage(select.value));
    box.append(caption,select);
    header.append(box);
  }
  function init(){
    language=LANGUAGES[savedLanguage()]?savedLanguage():'it';
    mountSelector();refreshControls();paint();
    observer=new MutationObserver(mutations=>{
      for(const m of mutations){if(m.type==='childList' && m.addedNodes.length){schedule();return}
        if(m.type==='characterData'){schedule();return}}
    });
    observer.observe(document.body,{subtree:true,childList:true,characterData:true});
  }
  window.AchillesI18n=Object.freeze({setLanguage,getLanguage:()=>language,translate,getSupportedLanguages:()=>({...LANGUAGES}),refresh:()=>paint()});
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
})();
