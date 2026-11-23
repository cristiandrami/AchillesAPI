'use strict';
/* Presentation/navigation only. No scanner, approval, request or payload changes. */
(() => {
 function init(){
  const nav=document.querySelector('.sidebar');
  if(!nav)return;
  const anchors=[...nav.querySelectorAll('a[href^="#"]')];
  const targets=anchors.map(a=>({a,target:document.getElementById(a.getAttribute('href').slice(1))})).filter(x=>x.target);
  function markActive(target){
   for(const row of targets){
    const active=row.target===target;
    row.a.classList.toggle('active',active);
    if(active)row.a.setAttribute('aria-current','location');else row.a.removeAttribute('aria-current');
   }
  }
  // Deep-linking to an accordion must open it; otherwise the user lands on a hidden wizard.
  for(const {a,target} of targets){
   a.addEventListener('click',()=>{
    if(target.matches('details'))target.open=true;
    for(const ancestor of target.closest('details')?[target.closest('details')]:[]){ancestor.open=true;}
    markActive(target);
   });
  }
  if(location.hash){
   const initial=document.getElementById(decodeURIComponent(location.hash.slice(1)));
   if(initial){if(initial.matches('details'))initial.open=true;
    for(const parent of initial.closest('details')?[initial.closest('details')]:[])parent.open=true;}
  }
  if('IntersectionObserver' in window){
   const observer=new IntersectionObserver(entries=>{
    const current=entries.filter(e=>e.isIntersecting).sort((a,b)=>a.boundingClientRect.top-b.boundingClientRect.top)[0];
    if(current)markActive(current.target);
   },{rootMargin:'-120px 0px -65% 0px',threshold:0});
   for(const {target} of targets)observer.observe(target);
  }
  // The page is long; keep an accessible back-to-top action available after scrolling.
  const goTop=document.createElement('button');
  goTop.type='button';goTop.className='workspace-back-top';
  goTop.textContent='↑';goTop.title='Torna all’inizio';goTop.setAttribute('aria-label','Torna all’inizio');
  goTop.hidden=true;
  goTop.addEventListener('click',()=>window.scrollTo({top:0,behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'}));
  document.body.append(goTop);
  let scheduled=false;
  function syncBackTop(){scheduled=false;goTop.hidden=window.scrollY<700;}
  window.addEventListener('scroll',()=>{if(!scheduled){scheduled=true;requestAnimationFrame(syncBackTop)}},{passive:true});
  syncBackTop();
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
})();
