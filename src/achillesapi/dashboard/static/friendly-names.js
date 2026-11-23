/* Only user-facing copy. Actual CLI action IDs, API payloads and evidence are unchanged. */
'use strict';
(() => {
 const names = Object.freeze({
 'auto-assess':'Analisi automatica degli endpoint',
 'rc13-assess':'Analisi approfondita API',
 'rc15-scan':'Scanner di vulnerabilità HTTP',
 'rc16-assess':'Test dei workflow e autorizzazioni',
 'rc16-access-auto':'Confronto accessi tra identità',
 'access-probe':'Confronto dei permessi su una risorsa',
 'access-matrix':'Matrice delle autorizzazioni',
 'verify-access-policy':'Verifica delle policy di accesso',
 'workflow-assess':'Test del flusso di lavoro',
 'multi-resource-assess':'Test di risorse collegate',
 'injection-assess':'Test di injection',
 'advanced-vuln-assess':'Analisi avanzata delle vulnerabilità',
 'rc17-verify':'Verifica delle evidenze',
 'rc17-agent':'Agente AI locale',
 'ai-correlate':'Correlazione AI delle evidenze',
 'ai-analyze':'Analisi locale AI',
 'ai-prioritize':'Priorità dei controlli',
 'full-suite':'Suite completa',
 'rc18-oidc':'Controllo OAuth2 e OIDC',
 'rc18-jwks':'Verifica delle chiavi pubbliche',
 'coverage-report':'Misurazione della copertura',
 'workflow-graph':'Grafo dei workflow'
 });
 const replacements = [
  [/\bRC13\s*(?:JSON|PATCH)?\b/gi,'Analisi approfondita dei campi JSON'],
  [/\bRC15\b/gi,'Scanner avanzati'],
  [/\bRC16\s*GET\b/gi,'Confronto accessi tra identità'],
  [/\bRC16\b/gi,'Test dei workflow'],
  [/\bRC17\b/gi,'Agente AI e verifica'],
  [/\bRC18\b/gi,'Controlli OAuth2 e OIDC'],
  [/\bRC19\b/gi,'Controlli qualità'],
  [/\bRC20\b/gi,'Diagnostica'],
  [/\bRC21\b/gi,'Test multi-risorsa'],
  [/\bRC22\b/gi,'Verifica approfondita'],
  [/\bRC23\b/gi,'Analisi della copertura'],
  [/\bRC24\b/gi,'Configurazione automatica'],
  [/\bRC25\b/gi,'Controllo multi-workflow']
 ];
 const text = value => replacements.reduce((str,[regex,replacement])=>str.replace(regex,replacement),String(value??''));
 const action = value => names[String(value||'')]||text(String(value||'').replaceAll('-',' '));
 window.AchillesPublicNames = Object.freeze({action,text,names});
})();
