"""Schede di aiuto dei task, indipendenti dalla dashboard e dal laboratorio.

Appunti: un task non è una vulnerabilità. La descrizione spiega cosa
analizza, quali dati richiede e come leggere l'esito in modo prudente.
"""
from __future__ import annotations

from achillesapi.core.registry_v090 import TOOLS

# Ogni elemento ha una descrizione specifica. Le spiegazioni sono pensate
# per chi usa la dashboard, non per il parser o il modello AI.
PURPOSES = {
 'rc18-oidc-audit':'Analizza offline gli schemi OAuth2/OIDC nello Swagger, i grant e gli scope dichiarati; non tratta indizi di configurazione come exploit.',
 'rc16-workflows':'Analizza tutti i cicli CRUD del documento OpenAPI, inclusi endpoint annidati e suggerisce un manifest multi-risorsa offline; non invia richieste.',
 'rc16-access-auto':'Genera e confronta GET con ID approvati tra proprietario e altri profili, su più endpoint. Policy esplicite, nessuna scrittura.',
 'rc16-assess':'Crea risorse temporanee approvate, risolve dipendenze tra workflow, confronta i ruoli (BOLA/BFLA/BOPLA) e verifica DELETE in ordine inverso.',
 'rc15-scan':'Verifica input GET e, con fixture approvate, input JSON/form/XML/upload, SSRF, XXE, XSS, traversal e redirect. Ogni finding richiede revisione.',
 'rc13-assess':'Esegue il motore coordinato RC13 (copertura, input GET, matrice, workflow temporanei e Ollama) usando le configurazioni già presenti nella dashboard.',
 'access-matrix':'Confronta più endpoint GET tra identità diverse e verifica le regole di accesso dichiarate.',
 'access-probe':'Confronta una GET documentata nello Swagger con due utenti diversi, sulla stessa risorsa.',
 'auth-session-audit':'Analizza offline la configurazione delle sessioni e le opzioni di rinnovo dei token.',
 'proof-gate':'Valuta se le prove salvate bastano per attribuire un livello di conferma ai finding.',
 'ai-followup-safe':'Filtra possibili follow-up del modello locale usando solo operazioni ammesse.',
 'campaign-audit':'Controlla se la campagna è completa e se sono tracciati task falliti o saltati.',
 'evidence-integrity':'Calcola la firma SHA-256 del report per verificarne successivamente l’integrità.',
 'analyze-openapi':'Legge lo Swagger e produce un inventario della struttura dell’API.',
 'compatibility-report':'Calcola l’applicabilità e la copertura dei controlli per ogni operazione OpenAPI.',
 'workflow-infer':'Propone sequenze tra operazioni correlate; non esegue richieste HTTP.',
 'adaptive-plan':'Suggerisce controlli successivi sulla base di copertura e prerequisiti.',
 'verify-findings':'Riesamina offline i finding disponibili senza confermarli automaticamente.',
 'auth-preflight':'Verifica i requisiti di autenticazione dichiarati dallo Swagger.',
 'security-surfaces':'Individua superfici sensibili e controlli da pianificare.',
 'risk-matrix':'Associa le operazioni a ipotesi OWASP API Security da verificare.',
 'workflow-safety':'Valuta offline le precondizioni e il cleanup possibile dei workflow.',
 'access-evidence-review':'Confronta risposte già raccolte da identità differenti.',
 'mutation-review':'Confronta istantanee prima/dopo per possibili modifiche a campi protetti.',
 'evidence-package':'Crea un indice delle evidenze privo di credenziali e corpi HTTP.',
 'campaign-diagnostics':'Elenca blocchi, errori e punti non testati della campagna.',
 'release-readiness':'Controlla condizioni e limitazioni che impediscono un risultato di rilascio affidabile.',
 'benchmark-review':'Confronta le segnalazioni con una ground truth indipendente.',
 'ai-plan-guard':'Valida proposte di task AI senza eseguirle né autorizzare nuovo traffico.',
 'campaign-preflight':'Mostra le precondizioni dei task prima di avviare la campagna.',
 'workflow-dependencies':'Ricostruisce legami strutturali fra operazioni dello Swagger.',
 'auth-audit':'Esamina schemi di autenticazione e opportunità di test, senza inviare credenziali.',
 'verification-review':'Analizza il grado di verifica delle osservazioni contenute nel report.',
 'campaign-quality':'Misura copertura e completezza di una suite precedente.',
 'generate-tests':'Genera proposte di controlli dalla specifica OpenAPI.',
 'map-api':'Organizza in una mappa le operazioni e le loro relazioni.',
 'assess':'Genera un assessment strutturale senza richieste attive.',
 'intelligent-plan':'Costruisce un piano di verifica deterministico dallo Swagger.',
 'workflow-discover':'Individua operazioni che potrebbero formare un processo applicativo.',
 'workflow-map':'Rappresenta le dipendenze individuate fra risorse.',
 'journey-discover':'Identifica possibili percorsi di lettura fra endpoint.',
 'security-inventory':'Riepiloga autenticazione, dati e superfici di rischio documentate.',
 'auth-draft':'Propone una configurazione di autenticazione da completare e revisionare.',
 'ai-analyze':'Chiede al modello Ollama locale un’analisi consultiva dello Swagger.',
 'ai-correlate':'Correla con Ollama risposte HTTP effettivamente raccolte.',
 'scan':'Combina analisi dello Swagger e suggerimenti AI locali.',
 'scope-audit':'Verifica che URL e host appartengano allo scope indicato.',
 'auth-profiles':'Controlla i profili auth.yaml e le modalità di autenticazione disponibili.',
 'benchmark-evaluate':'Calcola metriche rispetto a etichette verificate indipendentemente.',
 'vulnerability-triage':'Classifica le osservazioni già raccolte per la revisione manuale.',
 'differential-review':'Analizza differenze fra risposte già presenti in un assessment.',
 'adaptive-review':'Combina struttura OpenAPI ed evidenze per proporre i prossimi controlli.',
 'analyze-evidence':'Analizza un file di risposte HTTP reali nel formato responses.',
 'coverage-report':'Calcola quali endpoint hanno evidenze e quali non sono stati osservati.',
 'next-actions':'Propone i controlli prioritari senza eseguirli.',
 'agent-review':'Esamina le proposte di azione dell’agente locale.',
 'ai-prioritize':'Ordina consultivamente gli elementi da verificare tramite Ollama.',
 'workflow-graph':'Costruisce un grafo delle operazioni da un manifest workflow.',
 'verify-access-policy':'Confronta evidenze raccolte con regole allow/deny esplicite.',
 'auto-assess':'Esegue i controlli automatici applicabili, opzionalmente con GET autorizzate.',
 'advanced-vuln-assess':'Esegue ulteriori controlli di sicurezza autorizzati con evidenze HTTP.',
 'journey-assess':'Segue una sequenza di GET con parametri e identità definite nel manifest.',
 'workflow-assess':'Esegue un workflow autorizzato con scritture e cleanup documentato.',
 'multi-resource-assess':'Verifica accessi su più risorse temporanee create con consenso esplicito.',
 'autonomous-agent':'Pianifica e controlla follow-up entro budget e scope.',
 'agent-loop-v2':'Esegue cicli di assessment limitati dal budget e dai permessi.',
 'injection-assess':'Esegue sonde HTTP limitate su GET (query, path e header personalizzati); inventaria offline input JSON/form/XML e operazioni POST/PATCH/PUT/DELETE per verifiche successive. Gli indizi non sono conferme.',
}

SPECIAL = {
 'rc18-oidc-audit':'Swagger/OpenAPI; metadati OIDC e JWKS opzionali dalla CLI o dal pannello OIDC. Per verificare un JWT usare token-env, issuer e audience; la suite resta offline.',
 'rc16-workflows':'Solo file OpenAPI; bozza manifest opzionale dalla CLI. Non deduce la proprietà reale delle risorse.',
 'rc16-access-auto':'OpenAPI, auth.yaml con owner e altri profili, ID di test per i parametri dei path, policy allow/deny, scope e consenso per GET.',
 'rc16-assess':'OpenAPI, resources.yaml con POST/GET/DELETE e marcatori temporanei, auth.yaml, profili da confrontare, budget sufficiente, autorizzazione HTTP e approvazione scritture. Cleanup inverso.',
 'rc15-scan':'Swagger, Base URL, allow-host e consenso. Per POST/PATCH/XML/upload carica un manifesto rc15-security con cleanup e abilita le scritture; per SSRF/XXE configura callback e collector locali. I test non sono conferme automatiche.',
 'rc13-assess':'Swagger; Base URL, host e consenso per GET; auth.yaml e manifest generato dal wizard se usi scritture; per sonde JSON seleziona nel wizard i campi PATCH già approvati e conferma il consenso aggiuntivo. Ollama locale soltanto se richiesto.',
 'access-probe': 'Swagger; Base URL e host autorizzato; auth.yaml con due profili; operazione GET; ID path se presenti; policy attesa; consenso per richieste attive.',
 'access-matrix': 'Swagger; auth.yaml con almeno due profili; regole allow/deny; valori path; Base URL, host e consenso.',
 'ai-plan-guard': 'Swagger e file proposte con lista actions. Puoi creare proposte guidate dalla pagina del retry, senza scrivere JSON.',
 'injection-assess': 'Swagger con input GET query/path/header personalizzati; Base URL, host autorizzato, budget e consenso HTTP. Per i path servono ID fixture autorizzati. Un profilo auth.yaml alla volta. POST/PATCH/JSON/XML sono soltanto nel piano offline.',
 'analyze-evidence': 'Risposte HTTP reali in un file con array responses. Se disponibili, genera il file da auto-assess attivo.',
 'verify-access-policy': 'Assessment con evidenze e policy con regole allow/deny compilate dall’operatore.',
 'workflow-assess': 'Swagger, manifest workflow, auth.yaml, host autorizzato e approvazione scritture. I dati di fixture devono essere validi.',
 'multi-resource-assess': 'Swagger, manifest multi-risorsa, due identità, creazione fixture e cleanup approvati.',
 'journey-assess': 'Swagger, manifest journey con operazioni GET e ID, host e consenso HTTP.',
 'benchmark-evaluate': 'Assessment e ground truth verificata da un operatore: non si può dedurre dai finding.',
 'benchmark-review': 'Report e ground truth indipendente per classificare falsi positivi e falsi negativi.',
 'auth-profiles': 'File auth.yaml con i profili necessari e credenziali di test.',
 'ai-correlate': 'Ollama locale attivo, modello disponibile e assessment con vere osservazioni HTTP.',
}


def task_help(action: str) -> dict[str, str]:
    """Spiega un singolo task senza dipendere dallo stato del browser."""
    item = TOOLS[action]
    kind = item['requirements']
    parts = []
    if kind in {'spec', 'both', 'spec-config'}:
        parts.append('file OpenAPI')
    if kind in {'report', 'both', 'report-config', 'config-report'}:
        parts.append('risultato precedente')
    if kind in {'spec-config', 'report-config', 'config:json', 'config-report'}:
        parts.append('file di configurazione coerente con il comando')
    if kind == 'scope':
        parts.append('URL e host autorizzato')
    if kind == 'auth-only':
        parts.append('auth.yaml')
    if item.get('active'):
        parts.append('target autorizzato e consenso HTTP per eseguire richieste')
    if item.get('writes'):
        parts.append('approvazione delle scritture e cleanup')
    if item.get('ai'):
        parts.append('Ollama locale e modello installato')
    return {
        'purpose': PURPOSES[action],
        'requires': SPECIAL.get(action, '; '.join(parts) or 'Nessun file specifico oltre agli input del comando.'),
        'interpretation': ('I risultati sono indizi da verificare: senza policy e prove riproducibili non sono vulnerabilità confermate.'
                           if item['category'] in {'Security', 'Assessment', 'AI locale'} else
                           'Un task completato indica esecuzione conclusa, non assenza di vulnerabilità.'),
    }


assert set(PURPOSES) == set(TOOLS), 'Manca una scheda esplicativa per uno o più task'
