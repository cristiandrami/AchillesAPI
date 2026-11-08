# AchillesAPI 0.16 — Guida operativa dettagliata (Windows PowerShell / Kali)

> **Scopo**: assessment di API di cui hai autorizzazione scritta. Il laboratorio incluso è vulnerabile intenzionalmente, e deve ascoltare soltanto su `127.0.0.1`. Questa guida distingue ciò che il framework **esegue** da ciò che **suggerisce**.

## 1. Preparazione su Windows

Installa Python 3.12, `uv` e (solo se vuoi usare l'AI) Ollama. Apri PowerShell nella directory `achillesapi` estratta dallo ZIP.

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dev
uv run achillesapi version
uv run pytest -q
uv run achillesapi --help
```

Per Linux/Kali gli stessi comandi `uv` funzionano senza la sintassi PowerShell per andare a capo. Se `uv` non è nel PATH, installalo prima tramite la procedura ufficiale.

## 2. Avviare il laboratorio indipendente

**Finestra PowerShell A** (lascia aperta):

```powershell
powershell -ExecutionPolicy Bypass -File .\labs\independent_api\start.ps1
```

Swagger UI: `http://127.0.0.1:8765/docs` ; specifica: `labs/independent_api/openapi.json`. La specifica è inclusa e puoi rigenerarla con:

```powershell
powershell -ExecutionPolicy Bypass -File .\labs\independent_api\export-openapi.ps1
```

**Finestra PowerShell B**, nella directory `achillesapi`:

```powershell
$env:ACHILLES_DEMO_ALICE = 'demo-alice'
$env:ACHILLES_DEMO_BOB = 'demo-bob'
$env:ACHILLES_DEMO_ADMIN = 'demo-admin'
uv run achillesapi auth-profiles --config .\labs\independent_api\auth.yaml
```

Questi token sono **finti e pubblici**: non usarli mai fuori dal laboratorio.

## 3. Esplorare la specifica senza inviare richieste

```powershell
uv run achillesapi analyze-openapi .\labs\independent_api\openapi.json --output .\reports\api.json
uv run achillesapi intelligent-plan .\labs\independent_api\openapi.json --output .\reports\intelligence.json
uv run achillesapi generate-tests .\labs\independent_api\openapi.json --output .\reports\candidates.json
uv run achillesapi map-api .\labs\independent_api\openapi.json --output .\reports\graph.json
uv run achillesapi workflow-discover .\labs\independent_api\openapi.json --draft-config .\reports\workflow-draft.yaml --output .\reports\workflow-discovery.json
```

`intelligent-plan` produce esempi *sintetici* di body e parametri, ipotesi di dipendenze e una lista di check candidati. Non interpreta valori fittizi come ID reali. Il draft di workflow è **non eseguibile** finché non viene completato e approvato.

## 4. Assessment automatico delle GET

**Dry-run**: nessuna richiesta HTTP.

```powershell
uv run achillesapi auto-assess .\labs\independent_api\openapi.json `
  --base-url http://127.0.0.1:8765 `
  --context .\labs\independent_api\context.yaml `
  --output .\reports\dryrun.json
```

**Esecuzione**: autorizza espressamente l'host e la trasmissione di credenziali su HTTP, *solo per il laboratorio loopback*.

```powershell
uv run achillesapi auto-assess .\labs\independent_api\openapi.json `
  --base-url http://127.0.0.1:8765 `
  --context .\labs\independent_api\context.yaml `
  --auth-config .\labs\independent_api\auth.yaml `
  --profile alice --profile bob --profile admin `
  --allow-host 127.0.0.1 `
  --allow-insecure-http `
  --max-requests 60 --rate 3 --execute `
  --output .\reports\get-assessment.json
```

`auto-assess` esegue GET selezionate dallo schema: baseline, controllo auth assente, confronto tra identità, CORS, validazione input limitata, disclosure di errori e confronto proprietà di risposta. La presenza di un HTTP 200 **non è da sola una vulnerabilità**. L'output registra metadati e fingerprint, non il contenuto completo delle risposte.

## 5. Workflow di scrittura: POST → GET → PATCH → DELETE

Il file `labs/independent_api/workflow.yaml` è una configurazione approvata **solo per il laboratorio**: contiene il payload disposable, i profili, i JSON Pointer per l'ID, i campi non modificabili e la DELETE di cleanup.

Prima controlla il piano senza contattare l'API:

```powershell
uv run achillesapi workflow-assess .\labs\independent_api\openapi.json `
  --workflow-config .\labs\independent_api\workflow.yaml `
  --auth-config .\labs\independent_api\auth.yaml `
  --base-url http://127.0.0.1:8765 `
  --output .\reports\workflow-plan.json
```

Poi esegui **esclusivamente sul laboratorio locale**:

```powershell
uv run achillesapi workflow-assess .\labs\independent_api\openapi.json `
  --workflow-config .\labs\independent_api\workflow.yaml `
  --auth-config .\labs\independent_api\auth.yaml `
  --base-url http://127.0.0.1:8765 `
  --allow-host 127.0.0.1 --allow-insecure-http `
  --execute --approve-writes --max-requests 30 --rate 2 `
  --output .\reports\workflow-result.json
```

Risultati attesi: BOLA (Bob legge la risorsa di Alice), BOPLA (campo `internal_note` visibile), mass assignment (campo `is_approved` modificato) e `cleanup_verified: true`. Se `manual_cleanup_required: true`, fermati e verifica la risorsa: non dare per scontato che DELETE sia riuscita.

## 6. Unire GET e workflow nel comando principale

```powershell
uv run achillesapi auto-assess .\labs\independent_api\openapi.json `
  --base-url http://127.0.0.1:8765 `
  --auth-config .\labs\independent_api\auth.yaml `
  --context .\labs\independent_api\context.yaml `
  --workflow-config .\labs\independent_api\workflow.yaml `
  --allow-host 127.0.0.1 --allow-insecure-http `
  --max-requests 80 --rate 2 --execute --approve-writes `
  --output .\reports\combined.json
```

Il budget totale viene suddiviso tra i check GET e il workflow; non aggiungere `--approve-writes` se non vuoi modifiche. I test sul laboratorio non sono una prova di copertura su una API reale.

## 7. Usare l'AI locale

Installa Ollama, scarica il modello locale, poi avvia il servizio. La prima installazione richiede Internet; l'inferenza è locale.

```powershell
ollama pull llama3.2:3b
ollama create achilles-local -f .\deployment\Modelfile
ollama list
```

Se `ollama create` fallisce, verifica che `deployment/Modelfile` faccia riferimento a un modello effettivamente installato (`FROM ...`). Puoi anche usare direttamente `--model llama3.2:3b`.

```powershell
uv run achillesapi ai-analyze .\labs\independent_api\openapi.json --model achilles-local --output .\reports\ai.json
uv run achillesapi auto-assess .\labs\independent_api\openapi.json --base-url http://127.0.0.1:8765 --ai --model achilles-local --output .\reports\ai-plan.json
```

**Attenzione**: l'AI è un consulente; non può autorizzare nuove destinazioni, aumentare il budget o dichiarare una vulnerabilità confermata. Il comando `--ai` può inviare al servizio Ollama locale soltanto i metadati sanitizzati selezionati dal framework.

## 8. Passare a una API aziendale

1. Ottieni scope scritto (host, metodi consentiti, limiti, finestra, account e dati test).
2. Acquisisci lo Swagger reale (`swagger.yaml` o `openapi.json`).
3. Esegui `analyze-openapi`, `intelligent-plan`, `generate-tests`, `workflow-discover` **offline**.
4. Prepara `auth-profiles.yaml`: le credenziali vanno in variabili d'ambiente, non nel repository.
5. Prepara `engagement-context.yaml` con ID test approvati e policy di accesso note.
6. Avvia `auto-assess` in dry-run e controlla la lista dei test proposti.
7. Esegui soltanto i check GET con `--allow-host`, budget e rate concordati.
8. Per scritture, usa staging e un workflow **disposable** con creazione/lettura/cancellazione verificabili. Non usare i dati di clienti reali.
9. Controlla manualmente le evidenze e la policy prima di dichiarare una vulnerabilità.

Esempio per un target HTTPS autorizzato:

```powershell
uv run achillesapi auto-assess .\swagger.yaml `
  --base-url https://staging.example.com `
  --allow-host staging.example.com `
  --auth-config .\auth-profiles.yaml `
  --context .\engagement-context.yaml `
  --max-requests 80 --rate 1 --timeout 8 --execute `
  --output .\reports\assessment.json
```

**Non** utilizzare `--allow-insecure-http` su reti aziendali con credenziali reali, salvo autorizzazione specifica e comprensione del rischio.

## 9. Comandi disponibili — riferimento sintetico

| Comando | Scopo | Rete |
|---|---|---|
| `version` | Versione installata | No |
| `analyze-openapi` | Parsing e validazione Swagger | No |
| `intelligent-plan` | Esempi di parametri/body, dipendenze, check applicabili | No |
| `adaptive-review` | Suggerimenti di follow-up da osservazioni | No |
| `generate-tests` | Proposte di test security | No |
| `map-api` | Grafo delle risorse | No |
| `assess` | Analisi passiva OpenAPI | No |
| `scan` | Analisi passiva + AI opzionale | Solo Ollama se attivato |
| `auto-assess` | Pianificazione e GET automatiche; workflow opzionale | Con `--execute` |
| `workflow-discover` | Individua CRUD e draft YAML | No |
| `workflow-assess` | Test su risorsa temporanea e cleanup | Con `--execute --approve-writes` |
| `auth-profiles` | Descrizione profili auth | No |
| `http-get` | GET controllata | Con `--execute` |
| `bola-check` | Controllo BOLA mirato legacy | GET localhost |
| `bola-sweep` | BOLA su GET multiple legacy | GET localhost |
| `bfla-sweep` | Confronto ruoli legacy | GET localhost |
| `role-matrix` | Accesso e differenze JSON per profilo | GET localhost |
| `mass-assignment-check` | PATCH legacy su localhost | Con `--execute` |
| `sqli-check` | Segnali di errori SQL (non SQLi confermata) | GET localhost |
| `fuzz-parameter` | Input anomali limitati | GET localhost |
| `jwt-inspect` | Decodifica JWT senza verifica firma | No |
| `analyze-evidence` | Analisi offline evidenze | No |
| `ai-analyze` | Advisory AI sullo Swagger | Ollama locale |
| `ai-correlate` | Advisory AI su evidenze | Ollama locale |

`adaptive-review` richiede un JSON di osservazioni, per esempio:

```json
[{"operation":"GET /v2/search", "status":500}]
```

```powershell
uv run achillesapi adaptive-review .\labs\independent_api\openapi.json .\observations.json --output .\reports\next-steps.json
```

Per conoscere tutte le opzioni reali di un comando: `uv run achillesapi NOME-COMANDO --help`.

## 10. Limiti reali della v0.16

- `intelligent-plan` **non esegue** le dipendenze ipotizzate: suggerisce possibili collegamenti tra output e input, non li usa automaticamente per cambiare risorse.
- Il workflow supporta una sequenza disposable approvata; non è un orchestratore generale di login OAuth2, paginazione, code asincrone o transazioni distribuite.
- OAuth2 authorization-code, client-credentials e refresh token **non sono ancora automatizzati** dal motore auth. Sono supportati profili con token forniti tramite variabili d'ambiente.
- SQLi, SSRF, race conditions, business logic avanzata e rate limiting generalizzato **non sono coperti in modo affidabile** dal nuovo motore.
- Il rollback dipende dal comportamento del server. `cleanup_verified` va controllato, e un guasto può lasciare una risorsa da eliminare manualmente.
- Nessun modello AI può dedurre con certezza le regole di proprietà/ruolo dalla sola specifica OpenAPI.
- Il report è JSON tecnico: la produzione automatica di un report professionale PDF/HTML è ancora da sviluppare.
- La suite e il laboratorio verificano funzionalità specifiche, **non** equivalgono a una certificazione per produzione o a un benchmark di detection su API aziendali.

## 11. Diagnostica rapida

- `Blocked: ... --allow-host`: devi specificare esplicitamente l'host del target autorizzato.
- `Blocked: ... insecure HTTP`: con credenziali e HTTP serve l'opt-in, solo per il laboratorio locale.
- `Missing environment variable`: imposta le variabili dei profili nella stessa sessione PowerShell.
- `--workflow-config` senza `--approve-writes`: esecuzione di scrittura bloccata intenzionalmente.
- `cleanup_verified: false`: verifica manualmente lo stato del target; non ripetere automaticamente il test.
- `Connection refused`: assicurati che la finestra A del laboratorio sia ancora aperta.
- `uv run pytest`: esegui dalla root del repository, dopo `uv sync --extra dev`.
