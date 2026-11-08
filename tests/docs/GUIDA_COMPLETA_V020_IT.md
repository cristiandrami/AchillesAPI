# AchillesAPI v0.20.0 — Guida operativa professionale

> Scopo: test di sicurezza **autorizzati** su API descrivibili con OpenAPI 3.x. La v0.20 è una release di sviluppo, non uno scanner certificato né un sostituto del pentester. Il laboratorio è una verifica di regressione, non la base della logica di produzione.

## Indice

1. [Installazione](#1-installazione)
2. [Cosa esegue automaticamente](#2-cosa-esegue-automaticamente)
3. [Avviare il laboratorio v0.20](#3-avviare-il-laboratorio-v020)
4. [Autenticazione OAuth2 / login JSON](#4-autenticazione-oauth2--login-json)
5. [Discovery dei workflow e acquisizione ID](#5-discovery-dei-workflow-e-acquisizione-id)
6. [Assessment completo con un unico comando](#6-assessment-completo-con-un-unico-comando)
7. [Test su un'API aziendale](#7-test-su-unapi-aziendale)
8. [Workflow di scrittura disposable](#8-workflow-di-scrittura-disposable)
9. [Ollama e AI locale](#9-ollama-e-ai-locale)
10. [Tutti i comandi CLI](#10-tutti-i-comandi-cli)
11. [Report, segreti e limiti](#11-report-segreti-e-limiti)
12. [Troubleshooting](#12-troubleshooting)

## 1. Installazione

Requisiti: Python 3.11+ (consigliato 3.12), `uv`; per i laboratori, dipendenze `dev` (FastAPI/Uvicorn); Ollama è facoltativo e funziona in locale.

**Windows PowerShell**, dentro la directory `achillesapi`:

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dev
uv run achillesapi version
uv run pytest -q
uv run achillesapi --help
```

**Kali/Linux**:

```bash
uv python install 3.12
uv sync --python 3.12 --extra dev
uv run achillesapi version
uv run pytest -q
```

Usa *sempre* il comando `uv run` dalla directory che contiene `pyproject.toml`. Non serve copiare file nella cartella globale di Python. In caso di conflitti con Python 3.15 usa `uv sync --python 3.12`.

## 2. Cosa esegue automaticamente

- Offline: valida Swagger, identifica endpoint, schemi, controlli candidati, catene CRUD, relazioni GET→GET e produce bozze di profili.
- Attivo e autorizzato: GET con più identità, test di autenticazione, CORS, query validation, errori interni, metadata/response schema, correlazione con regole di accesso fornite dall'operatore.
- OAuth2: grant **client_credentials** e login JSON con credenziali da variabili d'ambiente, cache breve del token e riacquisizione alla scadenza.
- Dynamic data: nelle journey GET il valore letto con JSON Pointer viene usato in una richiesta successiva, senza salvarlo nel report.
- Adaptive follow-up: ripete fino a tre GET che hanno prodotto 5xx in baseline; un 5xx ripetibile **non prova da solo una vulnerabilità**.
- AI: con `--ai` interpreta evidenze **sanitizzate** tramite Ollama in loopback; l'LLM non crea richieste arbitrarie, non autorizza target e non sceglie metodi di scrittura.
- Scrittura: i precedenti workflow `POST → GET → PATCH → DELETE` rimangono separati, **solo** su risorse disposable, con configurazione esplicita e `--approve-writes`.

**Non supportati integralmente:** OAuth2 authorization-code interattivo, SSO/MFA complessi, refresh-token grant dedicato, Swagger 2.0, `$ref` remoto, dipendenze arbitrarie tra endpoint di scrittura, AI autonoma capace di lanciare exploit, rollback garantito, pentest di logica business senza policy, rilevamento esaustivo di SQLi/NoSQLi/SSRF e report PDF finale. Non inferire dal nome "v0.20" che tutte queste funzioni siano implementate.

## 3. Avviare il laboratorio v0.20

Apri **due finestre** PowerShell, entrambe nella directory `achillesapi`.

**Finestra 1 — Server:**

```powershell
powershell -ExecutionPolicy Bypass -File .\labs\v020_service\start.ps1
```

API: http://127.0.0.1:8780; Swagger: http://127.0.0.1:8780/docs. Si avvia su loopback; **non** usare `0.0.0.0` né esporlo su Internet.

Per Linux:

```bash
bash labs/v020_service/start.sh
```

**Finestra 2 — scanner:**

```powershell
$env:ACHILLES_V020_CLIENT_ID = "demo-client"
$env:ACHILLES_V020_CLIENT_SECRET = "demo-secret"
$env:ACHILLES_V020_USER = "demo-user"
$env:ACHILLES_V020_PASSWORD = "demo-password"

uv run achillesapi version
uv run achillesapi analyze-openapi .\labs\v020_service\openapi.json
```

C'è anche `labs/independent_api`, il laboratorio precedente con BOLA, BOPLA e mass assignment intenzionali. La nuova API verifica **auth dinamica, JSON Pointer, GET multi-step e follow-up adattivo**. Sono servizi separati dal motore AchillesAPI.

Per rigenerare lo Swagger dopo una modifica al laboratorio:

```powershell
uv run --extra dev python -m labs.v020_service.export_openapi
```

In questa release lo script `export_openapi.py` può essere eseguito in alternativa direttamente dal path usando il comando:

```powershell
uv run --extra dev python .\labs\v020_service\export_openapi.py
```

## 4. Autenticazione OAuth2 / login JSON

Il file `labs/v020_service/auth.yaml` contiene **solo** nomi delle variabili ambiente. I token e le password non vanno salvati nel repository.

### OAuth2 client credentials

```yaml
profiles:
  - name: workload
    type: oauth2_client_credentials
    token_url: http://127.0.0.1:8780/oauth/token
    client_id_env: ACHILLES_V020_CLIENT_ID
    client_secret_env: ACHILLES_V020_CLIENT_SECRET
    scopes: [read:organizations]
```

Il motore invia un form `grant_type=client_credentials` con autenticazione HTTP Basic al token endpoint, usa `access_token` nella forma `Authorization: Bearer ...`, e riacquisisce il token dopo la durata comunicata (con anticipo). La chiamata al token endpoint deve avere un hostname approvato con `--allow-host`. In ambienti HTTPS **non** usare `--allow-insecure-http`.

### Login JSON con token annidato

```yaml
profiles:
  - name: user
    type: login_json
    login_url: http://127.0.0.1:8780/session
    username_env: ACHILLES_V020_USER
    password_env: ACHILLES_V020_PASSWORD
    username_field: username
    password_field: password
    token_pointer: /session/access_token
```

In questo caso la POST di autenticazione invia JSON e legge il JWT/token dal JSON Pointer configurato. Non gestisce automaticamente cookie di sessione o CSRF per login via browser.

### Comandi utili per i profili

```powershell
uv run achillesapi auth-profiles --config .\labs\v020_service\auth.yaml
uv run achillesapi auth-draft .\labs\v020_service\openapi.json --output .\auth-profiles.draft.yaml
```

`auth-draft` crea un profilo in base ai **meccanismi pubblicati da OpenAPI**, ma non può dedurre la password o il processo di login di ogni app. Controlla sempre il file prodotto e sostituiscilo/arricchiscilo con i dati autorizzati. La prima autenticazione attiva contatta il servizio e non è inclusa nel solo budget delle GET target: ha un limite separato di 10 tentativi per AuthenticationManager; il report indica il numero di richieste di autenticazione.

## 5. Discovery dei workflow e acquisizione ID

La parte **offline** trova possibili legami tra le proprietà JSON nelle risposte e i parametri dei path di altre GET. Supporta campi annidati e array: `/organizations/0/organization_ref` diventa la variabile `organization_id`.

```powershell
uv run achillesapi journey-discover .\labs\v020_service\openapi.json `
  --output .\reports\journey-candidates.json `
  --draft-config .\journey.draft.yaml
```

**ATTENZIONE:** la bozza contiene `REPLACE_WITH_AUTH_PROFILE`: **non è pronta da eseguire**. Devi verificare proprietà e scope e specificare identità e valori iniziali. Il laboratorio contiene una configurazione già revisionata in `labs/v020_service/journey.yaml`.

Esempio di journey:

```yaml
steps:
  - operation: GET /api/organizations
    identity: workload
    capture:
      organization_id: /organizations/0/organization_ref
  - operation: GET /api/organizations/{organization_ref}
    identity: user
    values:
      organization_ref: $organization_id
```

La seconda richiesta usa l'ID catturato dalla prima. L'ID compare solo nella richiesta **in memoria**, non nel file `reports/journey.json`.

**Dry-run (0 richieste):**

```powershell
uv run achillesapi journey-assess .\labs\v020_service\openapi.json `
  --journey-config .\labs\v020_service\journey.yaml `
  --base-url http://127.0.0.1:8780 `
  --output .\reports\journey-plan.json
```

**Esecuzione (GET autorizzate):**

```powershell
uv run achillesapi journey-assess .\labs\v020_service\openapi.json `
  --journey-config .\labs\v020_service\journey.yaml `
  --base-url http://127.0.0.1:8780 `
  --auth-config .\labs\v020_service\auth.yaml `
  --allow-host 127.0.0.1 `
  --allow-insecure-http --execute `
  --max-requests 10 --rate 2 `
  --output .\reports\journey.json
```

## 6. Assessment completo con un unico comando

Il laboratorio ha un ID di test noto `org-317`, che non viene hardcodato in AchillesAPI.

**Prima analisi offline:**

```powershell
uv run achillesapi auto-assess .\labs\v020_service\openapi.json `
  --base-url http://127.0.0.1:8780 `
  --output .\reports\preflight.json
```

**Esecuzione completa delle funzioni non distruttive v0.20:**

```powershell
uv run achillesapi auto-assess .\labs\v020_service\openapi.json `
  --base-url http://127.0.0.1:8780 `
  --auth-config .\labs\v020_service\auth.yaml `
  --profile workload --profile user `
  --journey-config .\labs\v020_service\journey.yaml `
  --path-value organization_ref=org-317 `
  --allow-host 127.0.0.1 `
  --allow-insecure-http `
  --max-requests 40 --rate 2 `
  --adaptive-verify --execute `
  --output .\reports\assessment-v020.json
```

Produce i blocchi `execution_report`, `adaptive_verification`, `journey_execution`, `intelligent_plan`, `suggested_security_tests` e `passive_assessment`. Le osservazioni contengono status code, etichette e nomi dei campi, **non** corpi HTTP o token. Per la verifica di vulnerabilità consulta `requires_review`: una risposta HTTP 200 non basta per classificare BOLA.

`--adaptive-verify` riserva 3 richieste del budget totale per una seconda GET dopo errori 5xx nella baseline. `--journey-config` riserva una richiesta per ogni step GET. I workflow `POST/PATCH/DELETE` hanno una riserva distinta per cleanup.

## 7. Test su un'API aziendale

Sostituisci file, target e profili con quelli **autorizzati** dal cliente:

```powershell
uv run achillesapi analyze-openapi .\customer-api.yaml --output .\reports\surface.json
uv run achillesapi generate-tests .\customer-api.yaml --output .\reports\testplan.json
uv run achillesapi auth-draft .\customer-api.yaml --output .\auth-profiles.draft.yaml
uv run achillesapi journey-discover .\customer-api.yaml --output .\reports\journey-candidates.json
```

Definisci le credenziali da variabili ambiente, prepara `auth-profiles.yaml` e una policy per le identità di test (vedi `docs/PROFESSIONAL_ASSESSMENT.md` e gli esempi `context.yaml`). Poi:

```powershell
uv run achillesapi auto-assess .\customer-api.yaml `
  --base-url https://staging.customer.example `
  --auth-config .\auth-profiles.yaml `
  --allow-host staging.customer.example `
  --context .\context.yaml `
  --max-requests 80 --rate 1 --execute `
  --output .\reports\assessment.json
```

**Prima di ogni incarico:** conferma autorizzazione scritta, host esatti, account, tenant, intervallo temporale, limiti di traffico, PII, ambiente, procedure di reset. Per un ambiente reale non usare `--allow-insecure-http` e non condividere gli output contenenti identificativi o metadata sensibili. Alcune GET possono produrre effetti collaterali se l'API è progettata male: escludi quelle note e verifica l'impatto col cliente.

## 8. Workflow di scrittura disposable

La funzione delle release precedenti è ancora disponibile:

```powershell
uv run achillesapi workflow-discover .\customer-api.yaml --output .\reports\crud-candidates.json
```

Crea un `workflows.yaml` con fixture disposable, due account, policy di ownership, payload di creazione e cleanup **verificabile**; il modello deve restituire ID e marcatore della risorsa creata. Per capire il formato, consulta `docs/WORKFLOWS_PROFESSIONAL_IT.md`.

```powershell
uv run achillesapi workflow-assess .\customer-api.yaml `
  --workflow-config .\workflows.yaml `
  --base-url https://staging.customer.example `
  --auth-config .\auth-profiles.yaml `
  --allow-host staging.customer.example `
  --execute --approve-writes `
  --output .\reports\workflow-assessment.json
```

Nessun POST/PATCH/DELETE viene inviato senza la configurazione revisionata e il flag `--approve-writes`. **Cleanup non equivale a rollback garantito:** il tool potrebbe dover segnalare `manual_cleanup_required`.

## 9. Ollama e AI locale

Il motore principale funziona **senza AI**. Per interpretazioni aggiuntive con un modello già installato localmente:

```powershell
ollama pull llama3.2:3b
ollama serve
```

Se `ollama serve` segnala che la porta è occupata, il servizio potrebbe essere già avviato. Il modello non deve essere chiamato tramite una URL pubblica. In una seconda finestra:

```powershell
uv run achillesapi ai-analyze .\customer-api.yaml --model llama3.2:3b
uv run achillesapi auto-assess .\customer-api.yaml `
  --base-url https://staging.customer.example `
  --allow-host staging.customer.example `
  --auth-config .\auth-profiles.yaml `
  --execute --ai --model llama3.2:3b `
  --output .\reports\assessment-with-ai.json
```

L'AI è *advisory*: non può scegliere endpoint fuori scope, concedere operazioni di scrittura o creare automaticamente token. Il progetto comunica con Ollama solo su `127.0.0.1`/loopback. Installazione di modelli tramite `ollama pull` richiede Internet **una sola volta**; le inferenze locali successive non ne hanno bisogno.

## 10. Tutti i comandi CLI

| Comando | Modalità | Funzione |
|---|---|---|
| `version` | offline | Versione corrente |
| `analyze-openapi` | offline | Elenca e normalizza operazioni e sicurezza OpenAPI |
| `generate-tests` | offline | Test candidati, nessuna richiesta |
| `map-api` | offline | Grafo endpoint-risorse-schemi |
| `assess` | offline | Ipotesi di problemi dalla specifica |
| `scan` | offline / Ollama | Analisi passiva, AI facoltativa |
| `intelligent-plan` | offline | Payload d'esempio, dipendenze candidate, check |
| `auth-draft` | offline | Template di auth da schemi OpenAPI |
| `auth-profiles` | offline | Verifica profili senza rivelare segreti |
| `journey-discover` | offline | Relazioni GET→GET e bozza YAML |
| `journey-assess` | GET | Esegue una catena GET con variabili acquisite |
| `workflow-discover` | offline | Identifica pattern CRUD |
| `workflow-assess` | POST/GET/PATCH/DELETE | Lifecycle disposable esplicitamente approvato |
| `auto-assess` | offline / GET / workflow | Orchestratore principale e follow-up adattivo |
| `adaptive-review` | offline | Suggerisce verifiche da osservazioni già raccolte |
| `analyze-evidence` | offline | Cerca indicatori in evidenze HTTP |
| `http-get` | GET | Una richiesta GET controllata |
| `bola-check` | GET locale | Confronto owner/non-owner, legacy |
| `bola-sweep` | GET locale | BOLA su più endpoint, legacy |
| `bfla-sweep` | GET locale | Privilegi per endpoint, legacy |
| `role-matrix` | GET locale | Matrice di visibilità/account, legacy |
| `mass-assignment-check` | PATCH locale | Test con payload fornito, legacy |
| `sqli-check` | GET locale | Segnale d'errore con apostrofo, legacy |
| `fuzz-parameter` | GET locale | Nove valori limite, legacy |
| `jwt-inspect` | offline | Decodifica JWT senza verificare la firma |
| `ai-analyze` | Ollama locale | Analisi AI dei metadati OpenAPI |
| `ai-correlate` | Ollama locale | Correlazione AI di evidenze sanificate |

Il comando `version` è registrato tramite `@app.command()` e gli altri con nomi espliciti: **27 comandi** complessivi. Per qualsiasi opzione ufficiale: `uv run achillesapi <comando> --help`.

## 11. Report, segreti e limiti

- Gli output JSON contengono inferenze, risultati e metadati; non contengono token del laboratorio né body delle risposte nelle nuove funzioni.
- Le evidenze sono **indicatori** e non automaticamente vulnerabilità confermate. Segui la policy di autorizzazione del cliente e verifica manualmente i risultati importanti.
- `max_requests` limita le richieste contro il target; le chiamate di acquisizione token sono **contate separatamente** (`authentication_requests`) e limitate a 10 per istanza del manager.
- L'allowlist attuale limita per **hostname**; non è una garanzia completa contro DNS rebinding o qualunque forma di SSRF. Non passare YAML non fidati senza revisione.
- Il tool impedisce redirect HTTP automatici e ignora proxy d'ambiente per le richieste effettuate dal proprio client.
- L'interpretazione di una risposta `403`, `404`, `200` o `503` dipende da ownership e requisiti. Nessun singolo status code basta a provare BOLA/SQLi/SSRF.
- Non generare payload o ID sintetici per risorse reali se non sono autorizzate e isolate.
- `pytest` e il laboratorio verificano la regressione. Non sostituiscono benchmark su un corpus di API indipendenti né una review del codice e dell'operatività.

## 12. Troubleshooting

**`ModuleNotFoundError`**: `uv sync --python 3.12 --extra dev` dalla directory del progetto.

**`Blocked: Environment variable ...`**: imposta il valore nello *stesso* terminale in cui lanci `uv run`. Per PowerShell `$env:VARIABLE = 'valore'`; per Bash `export VARIABLE=valore`.

**`Authentication URL outside approved scope`**: conferma `token_url`, `--allow-host` e HTTPS. Solo in laboratorio locale aggiungi `--allow-insecure-http`.

**`Unknown previous capture ...`**: la variabile `$nome` deve essere dichiarata in un precedente `capture` e deve corrispondere al JSON Pointer realmente restituito.

**`Required OpenAPI parameter not supplied`**: aggiungi `values:` nella journey, o `--path-value NAME=VALUE` in `auto-assess`.

**`Increase --max-requests`**: il budget deve coprire GET, gli step della journey, le eventuali verifiche adattive e l'intero lifecycle di scrittura (inclusa la pulizia).

**`Unable to connect`**: verifica che l'API sia avviata in un'altra finestra e risponda sulla stessa porta definita dal config (8780 per il laboratorio v0.20).

**`Ollama unavailable`**: avvia Ollama, verifica `ollama list` e passa `--model` con il nome installato. Il modello AI non è necessario per gli altri comandi.

**Cleanup non verificato**: non riprovare DELETE a caso; consulta il report e segui la procedura manuale concordata con il cliente.
