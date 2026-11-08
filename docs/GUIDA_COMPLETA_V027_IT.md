# AchillesAPI v0.27.0 — Guida operativa completa (Windows, Kali e laboratorio)

> **Scopo**: audit autorizzato di API descritte da OpenAPI. La guida descrive ciò che il programma fa realmente, inclusi i limiti. **Non** eseguire test su sistemi senza permesso scritto. Usare preferibilmente staging, account di test e dati disposable.
>
> **Importante**: v0.27.0 è una release *development/pre-production*. I finding del motore sono osservazioni da verificare, non prove automatiche di vulnerabilità. La componente AI non può inviare traffico al target né autorizzare nuovi target o operazioni di scrittura.

## Indice

1. Requisiti e installazione
2. Struttura dell'archivio e scelta del laboratorio
3. Avvio rapido da PowerShell
4. Comandi per il percorso professionale (offline, GET, workflow)
5. Autenticazione e gestione delle credenziali
6. Dati di test, ID e policy di autorizzazione
7. Workflow di lettura con cattura di ID
8. Workflow di scrittura disposable e cleanup
9. Nuovi comandi della v0.24–0.27
10. Ollama locale e AI consultiva
11. Reporting PDF/HTML/Markdown/JSON
12. Tutti i comandi CLI, per categoria
13. Interpretazione dei risultati e verifica dei falsi positivi
14. Errori comuni e relative soluzioni
15. Requisiti per l'utilizzo in un pentest aziendale
16. Limiti tecnici e prossimi sviluppi

## 1. Installazione

### Windows 11 (PowerShell)

Estrai il file ZIP. Entra nella cartella `achillesapi`, cioè quella che contiene `pyproject.toml`.

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dev --extra pdf
uv run achillesapi version
uv run achillesapi --help
uv run pytest -q
```

`uv` può essere installato consultando la documentazione ufficiale di Astral. In un ambiente aziendale, usa la procedura software approvata dall'IT. Il flag `--extra pdf` installa ReportLab per i PDF. **Non sono necessari modelli cloud, chiavi API a pagamento o servizi esterni per la scansione.**

**PowerShell**: per andare a capo in un comando usa un backtick `` ` `` alla fine della riga, senza spazi dopo il backtick.

### Kali / Debian / Linux

```bash
uv python install 3.12
uv sync --python 3.12 --extra dev --extra pdf
uv run achillesapi version
uv run pytest -q
```

Usa `\` per la continuazione delle righe della shell, non il backtick di PowerShell.

**Compatibilità:** Python 3.11+; test condotti in ambiente Python 3.13. È consigliata Python 3.12 per coerenza con gli script di esempio e le dipendenze.

## 2. Struttura del pacchetto

- `src/achillesapi/cli.py`: punto di ingresso dei comandi.
- `src/achillesapi/core/`: parsing, HTTP, scope, autenticazione, test, workflow, agent e triage.
- `src/achillesapi/ai/`: integrazione Ollama locale e sanitizzazione.
- `src/achillesapi/reporting/professional.py`: esportazione dei report offline.
- `labs/independent_api/`: API FastAPI con problemi di autorizzazione e mutazione intenzionali.
- `labs/v020_service/`: laboratorio autenticazione OAuth2/login JSON e workflow GET.
- `examples/`: file OpenAPI ed esempi di configurazione.
- `tests/`: unit test e test d'integrazione.
- `docs/`: guide, spiegazione delle funzioni e architettura.

**Non modificare i moduli `src/achillesapi` per adattarli a un laboratorio**: per ogni cliente fornisci una specifica OpenAPI, un file di autenticazione e, solo se necessario, un contesto e workflow approvati.

## 3. Prima prova sul laboratorio locale

Apri **PowerShell A**:

```powershell
powershell -ExecutionPolicy Bypass -File .\labs\independent_api\start.ps1
```

Swagger UI: `http://127.0.0.1:8765/docs`. Lo Swagger JSON incluso è `labs/independent_api/openapi.json`.

Apri **PowerShell B**, nella stessa cartella `achillesapi`:

```powershell
$env:ACHILLES_DEMO_ALICE = 'demo-alice'
$env:ACHILLES_DEMO_BOB = 'demo-bob'
$env:ACHILLES_DEMO_ADMIN = 'demo-admin'

uv run achillesapi analyze-openapi .\labs\independent_api\openapi.json
uv run achillesapi workflow-map .\labs\independent_api\openapi.json `
  --output .\reports\lab-map.json

uv run achillesapi auto-assess .\labs\independent_api\openapi.json `
  --base-url http://127.0.0.1:8765 `
  --auth-config .\labs\independent_api\auth.yaml `
  --profile alice --profile bob `
  --allow-host 127.0.0.1 --allow-insecure-http `
  --max-requests 50 --rate 2 --agent-budget 2 `
  --execute --output .\reports\lab-assessment.json
```

**Perché `--allow-insecure-http`?** Solo perché questo laboratorio usa HTTP in loopback. Su un'applicazione reale usa HTTPS e non attivare il flag senza una ragione documentata. I token dimostrativi non devono essere utilizzati fuori dal lab.

La scansione attiva effettua soltanto i GET consentiti dal piano. Per il workflow con POST/PATCH/DELETE vedi §8.

## 4. Percorso consigliato per un target aziendale

### Passo A: definisci il perimetro

Conserva l'autorizzazione del cliente, gli host consentiti, l'ambiente, gli account di test, le operazioni permesse e i limiti di carico. Le restrizioni di engagement non vengono dedotte dallo Swagger.

Esempio fittizio: `https://staging.example.com/api`, host `staging.example.com`.

### Passo B: esegui discovery *senza rete*

```powershell
uv run achillesapi analyze-openapi .\swagger.yaml
uv run achillesapi intelligent-plan .\swagger.yaml --output .\reports\intelligent.json
uv run achillesapi security-inventory .\swagger.yaml --output .\reports\inventory.json
uv run achillesapi workflow-map .\swagger.yaml --output .\reports\dependencies.json
uv run achillesapi journey-discover .\swagger.yaml --draft-config .\journey.draft.yaml
uv run achillesapi workflow-discover .\swagger.yaml --draft-config .\workflows.draft.yaml
uv run achillesapi auth-draft .\swagger.yaml --output .\auth.draft.yaml
```

`workflow-map` produce soltanto **corrispondenze ipotetiche** tra campi di risposta e parametri di path. Non raccoglie veri ID, non autorizza POST e non crea fixture.

### Passo C: genera il piano iniziale

```powershell
uv run achillesapi auto-assess .\swagger.yaml `
  --base-url https://staging.example.com/api `
  --output .\reports\plan.json
```

Questa modalità non invia richieste all'API. Leggi `plan.summary`, `plan.operations`, `workflow_dependency_map` e `security_inventory`: gli endpoint con input mancanti vengono bloccati. Non forzare valori fittizi su dati di produzione.

### Passo D: configura le identità

Crea un file YAML con account *di test*. I segreti devono stare in variabili d'ambiente (vedi §5).

### Passo E: GET assessment con budget

```powershell
uv run achillesapi auto-assess .\swagger.yaml `
  --base-url https://staging.example.com/api `
  --allow-host staging.example.com `
  --auth-config .\auth-profiles.yaml `
  --profile tester --profile admin `
  --context .\engagement-context.yaml `
  --max-requests 80 --rate 1 --timeout 8 `
  --agent-budget 3 --execute `
  --output .\reports\assessment.json
```

`--max-requests` governa il budget del motore target e delle componenti riservate; le richieste di autenticazione dinamica sono riportate separatamente. Controlla entrambi i conteggi nel JSON. Le operazioni di scrittura non vengono abilitate da questo comando.

### Passo F: analizza e genera il report

```powershell
uv run achillesapi vulnerability-triage .\reports\assessment.json `
  --output .\reports\triage.json
uv run achillesapi ai-prioritize .\swagger.yaml .\reports\assessment.json `
  --budget 3 --output .\reports\priorities.json
uv run achillesapi report .\reports\assessment.json `
  --output-dir .\reports\professional `
  --format json --format md --format html --format pdf
```

`ai-prioritize` è **offline** per impostazione predefinita. Il parametro `--ai` consulta solo Ollama locale. **Non** esegue ulteriori richieste al target; il motore `auto-assess --agent-budget` è quello che può ripetere un GET già previsto da OpenAPI.

## 5. Autenticazione, OAuth2, login JSON e token

### Profilo statico Bearer

`auth-profiles.yaml`:

```yaml
profiles:
  - name: tester
    type: bearer
    token_env: TESTER_API_TOKEN
  - name: admin
    type: bearer
    token_env: ADMIN_API_TOKEN
```

PowerShell (solo ambiente di test):

```powershell
$env:TESTER_API_TOKEN = 'IL_TOKEN_DEL_TESTER'
$env:ADMIN_API_TOKEN = 'IL_TOKEN_ADMIN_DI_TEST'
uv run achillesapi auth-profiles --config .\auth-profiles.yaml
```

Per gli altri tipi di auth, usa `auth-draft` e leggi `labs/v020_service/auth.yaml`, che include `oauth2_client_credentials` e `login_json`. OAuth2 autorizza solo il flusso Client Credentials implementato; **OIDC/SSO interattivo, MFA e refresh generico non sono completi**. Non salvare password nel repository o nello Swagger.

## 6. Parametri dinamici e policy dell'engagement

OpenAPI non può indicare chi possiede un customer o una fattura. Il file di contesto fornisce ID di test e regole attese senza usare i valori di un laboratorio precostituito.

`engagement-context.yaml`:

```yaml
path_values:
  customerId: "CUSTOMER_ID_DI_TEST"
expected_access:
  "GET /customers/{customerId}":
    tester: allow
    admin: allow
```

Usa `--context .\engagement-context.yaml`, oppure ripeti `--path-value customerId=...` da riga di comando. La policy deve essere corretta per quell'ID e quegli account. Se invece l'utente deve essere negato, usa `deny`; in assenza della policy AchillesAPI non dichiara automaticamente un BOLA confermato.

## 7. Journey GET con cattura dinamica degli ID

`journey-discover` produce un esempio da rivedere. Nel laboratorio v0.20, `labs/v020_service/journey.yaml` contiene già i JSON Pointer e i riferimenti tra step.

```powershell
powershell -ExecutionPolicy Bypass -File .\labs\v020_service\start.ps1
```

In un altro PowerShell:

```powershell
$env:ACHILLES_V020_CLIENT_ID = 'demo-client'
$env:ACHILLES_V020_CLIENT_SECRET = 'demo-secret'
$env:ACHILLES_V020_USER = 'demo-user'
$env:ACHILLES_V020_PASSWORD = 'demo-password'

uv run achillesapi journey-assess .\labs\v020_service\openapi.json `
  --journey-config .\labs\v020_service\journey.yaml `
  --base-url http://127.0.0.1:8780 `
  --auth-config .\labs\v020_service\auth.yaml `
  --allow-host 127.0.0.1 --allow-insecure-http --execute
```

Il motore legge gli identificativi temporaneamente in memoria e li usa nei passi successivi. Non li esporta come testo nel report. **I journey generici restano limitati ai GET supportati.**

## 8. Workflow POST→GET→PATCH→DELETE su risorsa disposable

**Attenzione: questo comando modifica dati.** Deve essere utilizzato su fixture create appositamente, con rollback/cleanup dichiarato e autorizzazione esplicita.

Il workflow verifica l'ID e un marcatore univoco, prova accessi tra due identità e può eseguire fino a cinque modifiche PATCH/PUT approvate. In caso di verifica non conclusiva, si interrompe e segnala una richiesta di cleanup manuale.

Con il laboratorio `independent_api` avviato e le variabili di §3 impostate:

```powershell
uv run achillesapi workflow-assess .\labs\independent_api\openapi.json `
  --workflow-config .\labs\independent_api\workflow_v023.yaml `
  --base-url http://127.0.0.1:8765 `
  --auth-config .\labs\independent_api\auth.yaml `
  --allow-host 127.0.0.1 --allow-insecure-http `
  --max-requests 20 --rate 2 `
  --execute --approve-writes `
  --output .\reports\workflow.json
```

Un workflow scritto per un cliente deve specificare create/read/mutations/cleanup per l'API del cliente. **Il workflow engine non orchestra ancora transazioni arbitrariamente complesse su più risorse diverse**: la mappa offline v0.26 è un primo supporto, non un sostituto della configurazione verificata.

## 9. Nuove funzionalità v0.24–v0.27

### v0.24 `report` — Professional Reporting

Input: file JSON generato da `auto-assess`. Output: report JSON sanitizzato, Markdown, HTML e PDF opzionale. Il processo non contatta la rete. Il campo `evidence` include solo metadati consentiti, **non** richieste, body, token o cookie. I contenuti HTML vengono escapati.

```powershell
uv run achillesapi report .\reports\assessment.json `
  --output-dir .\reports\professional `
  --format html --format pdf --format md --format json
```

Il PDF richiede `uv sync --extra pdf`. Se hai usato `uv sync --extra dev --extra pdf`, è già presente. Il report **non inventa CWE/CVSS** quando non disponibili; l'attribuzione professionale di CWE, CVSS e impatto deve essere revisionata.

### v0.25 `vulnerability-triage` — Raccolta e revisione delle evidenze

```powershell
uv run achillesapi vulnerability-triage .\reports\assessment.json `
  --output .\reports\triage.json
```

Conta gli indicatori, restituisce una coda di verifiche da effettuare manualmente e non trasforma errori 5xx o HTTP 200 in exploit provati. Il motore già contiene check limitati per CORS, auth contrast, schemi risposta e input validation; **non** dispone di scanner evoluti e completi per SQLi/NoSQLi/SSRF/SSTI.

### v0.26 `workflow-map` — Mappa delle dipendenze

```powershell
uv run achillesapi workflow-map .\swagger.yaml `
  --output .\reports\workflow-map.json
```

Legge i nomi dei campi dichiarati nelle risposte OpenAPI e li confronta con i parametri di path. Un match produce solo una proposta con `executable: false`: la dipendenza dev'essere validata con una fixture approvata. Nessuna rete.

### v0.27 `ai-prioritize` — Decisioni limitate dal motore deterministico

```powershell
uv run achillesapi ai-prioritize .\swagger.yaml .\reports\assessment.json `
  --budget 3 --output .\reports\priorities.json
```

Aggiungi `--ai --model achilles-local` se vuoi anche le raccomandazioni del modello locale. L'AI opera su evidenze sanitizzate e **non può** scegliere URL, endpoint non dichiarati, POST/PATCH/DELETE, modificare scope o confermare vulnerabilità. Il motore restituisce una coda di verifiche GET *proposte* ma non le esegue.

## 10. Installare e utilizzare Ollama in locale

Su Windows installa Ollama seguendo le procedure aziendali approvate, quindi in PowerShell:

```powershell
ollama --version
ollama pull llama3.2:3b
ollama create achilles-local -f .\deployment\Modelfile
ollama list
```

Se Ollama non è già in esecuzione, avvialo in una finestra separata con `ollama serve` (può esserci già un servizio attivo; non lanciarne una seconda copia sulla stessa porta).

Esempio AI consultiva offline:

```powershell
uv run achillesapi ai-prioritize .\swagger.yaml .\reports\assessment.json `
  --budget 3 --ai --model achilles-local `
  --output .\reports\ai-advice.json
```

Il modello Ollama deve essere servito su loopback (`127.0.0.1:11434`). Il programma non invia i dati ad API LLM cloud. Una risposta dell'LLM è **consiglio da verificare**, non un ordine di rete. Se una specifica API contiene dati riservati, verifica le regole aziendali anche per l'elaborazione locale.

## 11. Interpretare il report

Il risultato di `auto-assess` è un file JSON con campi quali:

- `plan`: operazioni e motivazioni di esecuzione/esclusione;
- `execution_report`: osservazioni e finding prodotti da test attivi GET;
- `workflow_execution`: risultati del workflow disposable, se autorizzato;
- `vulnerability_triage`: indicatori e conferme ancora necessarie;
- `security_inventory`: aree di sicurezza potenzialmente applicabili;
- `workflow_dependency_map`: possibili dipendenze, tutte non eseguibili automaticamente;
- `agent_plan`/`agent_execution`: verifiche GET adattive, se abilitate;
- `ai_advisory`: analisi consultiva locale, se richiesta.

**Livelli di evidenza:** *candidate/indicator* non è una vulnerabilità confermata. Per BOLA serve una ownership policy attendibile e un confronto con account non autorizzati; per injection serve una dimostrazione affidabile che l'input controlli un'interprete, non soltanto un 500.

**Se `manual_cleanup_required` è true**, tratta la risorsa di test come ancora esistente e verifica il cleanup manualmente. Un HTTP DELETE 2xx senza successiva prova di assenza non equivale necessariamente a cleanup garantito.

## 12. Catalogo dei comandi CLI (33 comandi)

| Comando | Modalità | A cosa serve |
|---|---|---|
| `version` | offline | Versione installata |
| `analyze-openapi` | offline | Parsing e riepilogo API |
| `generate-tests` | offline | Test candidati |
| `map-api` | offline | Grafo API |
| `assess` | offline | Ipotesi passive |
| `scan` | offline/Ollama | Assessment passivo con AI opzionale |
| `auth-profiles` | offline | Configurazione delle identità |
| `auth-draft` | offline | Bozza profili |
| `intelligent-plan` | offline | Esempi schema-aware e priorità |
| `security-inventory` | offline | Categorie OWASP API |
| `workflow-discover` | offline | Bozza CRUD |
| `workflow-map` | offline | Possibili dipendenze |
| `journey-discover` | offline | Bozza GET→GET |
| `adaptive-review` | offline | Follow-up suggeriti |
| `agent-review` | offline | Piano di ripetizioni GET |
| `vulnerability-triage` | offline | Evidenze da revisionare |
| `ai-prioritize` | offline/Ollama | Prioritizzazione limitata da policy |
| `analyze-evidence` | offline | Verifica evidenze preesistenti |
| `jwt-inspect` | offline | Parsing JWT; firma non verificata |
| `ai-analyze` | Ollama | Commento AI sulla specifica |
| `ai-correlate` | Ollama | Correlazione AI delle evidenze |
| `report` | offline | Esporta HTML/PDF/Markdown/JSON |
| `http-get` | GET autorizzata | Client singola richiesta |
| `auto-assess` | offline/GET/workflow approvato | Assessment principale |
| `journey-assess` | GET autorizzata | Catena letture con capture |
| `workflow-assess` | scritture autorizzate | CRUD disposable con cleanup |
| `bola-check` | loopback | Controllo BOLA mirato legacy |
| `bola-sweep` | loopback | Confronti BOLA legacy |
| `bfla-sweep` | loopback | Controlli privilegi legacy |
| `role-matrix` | loopback | Confronto identità legacy |
| `sqli-check` | loopback | Indicatore limitato di SQL error disclosure |
| `fuzz-parameter` | loopback | Fuzz limitato query |
| `mass-assignment-check` | loopback | PATCH mirata legacy |

Per le opzioni valide per la versione installata, esegui `uv run achillesapi NOME-COMANDO --help`. Non assumere che tutti i comandi accettino `--execute`, `--ai` o le stesse opzioni.

## 13. Errori comuni

**`Blocked: host not allowed`**: l'host di `--base-url` deve comparire esattamente in `--allow-host`. Non usare wildcard o domini impliciti.

**`Missing environment variable`**: imposta la variabile richiesta dal profilo **nella stessa sessione PowerShell** da cui lanci AchillesAPI.

**`--approve-writes required`**: il workflow modifica dati; è richiesta autorizzazione esplicita e un YAML valido con cleanup. Verifica prima il piano offline.

**`REPLACE_ME placeholders`**: la bozza generata non contiene informazioni reali dell'API. Completa gli ID/payload/role/cleanup con dati di test verificabili.

**`Ollama connection refused`**: verifica `ollama list`, che il modello esista e che il servizio sia raggiungibile su `127.0.0.1:11434`.

**`--allow-insecure-http`**: non abilitare credenziali in chiaro su target aziendali; preferisci HTTPS. Sul laboratorio locale serve perché è intenzionalmente HTTP.

**`No eligible GET / missing inputs`**: la specifica richiede parametri o identità non disponibili. Controlla `--context`, `--path-value`, `--auth-config` e i campi `plan.operations`.

**`PDF export requires uv sync --extra pdf`**: installa la dipendenza opzionale ReportLab nell'ambiente del progetto.

**`Port already in use`**: interrompi il server locale precedente o verifica quale processo occupa la porta 8765/8780 prima di riavviare il lab.

**`test not found` o errore import `labs`**: lancia i comandi dalla radice `achillesapi`, non da `src/` o dalla cartella `labs/`.

## 14. Sicurezza operativa per incarichi professionali

Checklist prima di `--execute`:

1. Possiedo il permesso scritto e il target autorizzato è esatto.
2. Uso staging o account e risorse di test appositamente creati.
3. Ho controllato il piano offline e gli endpoint GET potenzialmente mutativi.
4. Ho fissato `--max-requests`, `--rate`, `--timeout` e host allowlist.
5. Conosco le regole di ownership e di autorizzazione per i dati impiegati.
6. Se attivo scritture, ho configurato cleanup e verificato la fixture disposable.
7. Evito di archiviare token, cookie e dati personali in report o log.
8. Riesamino i finding e non considero sicura un'API solo perché non sono emersi indicatori.

## 15. Limiti effettivi della v0.27.0

- I journey generici sono GET-only; le scritture multi-risorsa autonome non sono implementate.
- OAuth2 Client Credentials e login JSON sono supportati, ma SSO/OIDC interattivo e sessioni complesse no.
- La scansione non è un motore completo di SQLi/NoSQLi/SSTI/SSRF/business logic testing.
- La nuova mappa dei workflow è un indice di ipotesi basato sui nomi, non un orchestratore transazionale.
- L'AI locale è consultiva: nessun prompt può imporre nuovi URL o aumentare lo scope.
- Il report non calcola automaticamente un CVSS affidabile e non produce finding confermati soltanto dal modello.
- Il client HTTP richiede hardening aggiuntivo su DNS rebinding, perimetro IP, proxy e ambienti aziendali complessi.
- Non esiste ancora un benchmark indipendente per misurare detection rate e falsi positivi su API sconosciute.

**Decisione consigliata**: usare AchillesAPI v0.27.0 come framework assistivo/pre-production, sempre con supervisione tecnica di un penetration tester. Prima della produzione servono test indipendenti, hardening e validazione del cliente.
