# AchillesAPI v0.10.2 — guida completa al laboratorio (Windows 11 / PowerShell)

Questa guida riguarda **solo un laboratorio locale**. Usa dati falsi, credenziali
pubbliche e alcune vulnerabilità volutamente introdotte. **Non aprire la porta
8000 su Internet e non avviare questa API con `--host 0.0.0.0`.**

## 1. Cosa contiene il laboratorio

Il codice si trova in `src/achillesapi/lab/full_app.py`. La specifica è
`examples/full_lab_openapi.json` (generata direttamente dalle route FastAPI).

| Area | Endpoint volutamente vulnerabile | Endpoint di confronto protetto |
|---|---|---|
| BOLA / IDOR | `GET /api/orders/{order_id}` | `GET /api/secure/orders/{order_id}` |
| BFLA | `GET /api/admin/audit` | `GET /api/admin/metrics` |
| BOPLA / data exposure | `GET /api/profiles/{username}` | `GET /api/secure/profiles/{username}` |
| Mass assignment | `PATCH /api/profiles/{username}` | `PATCH /api/secure/profiles/{username}` |
| SQL error leakage (simulata) | `GET /api/search?q=...` | `GET /api/secure/search?q=...` |

Sono inoltre presenti:

- `GET /health`: endpoint pubblico per verificare che la API sia online.
- `GET /api/inventory`: vincoli su numeri e categorie.
- `GET /api/catalog/{sku}`: identificativo non convenzionale (`sku`).
- `POST /api/reports` e `GET /api/reports/{report_ref}`: workflow create→read;
  **solo la POST manuale** crea dati in memoria, perché `auto-assess` resta GET-only.
- `GET /api/basic/account`: autenticazione HTTP Basic.
- `GET /api/partner/summary`: API key nell'header `X-API-Key`.
- `GET /api/session/me`: autenticazione tramite cookie `sessionid`.

**Attenzione a SQLi:** l'errore `sqlite error` è soltanto simulato con un
messaggio di training. Non c'è alcun database SQL né una SQL injection reale.
Il test può segnalare l'errore, non confermare automaticamente una vulnerabilità.

## 2. Requisiti

- Windows 11 e PowerShell.
- Python 3.12 gestito da `uv` (installare `uv`, poi `uv python install 3.12`).
- Ollama per Windows, **solo** per i comandi `--ai`.
- Modello locale `llama3.2:3b`, creato come `achilles-local` dal Modelfile.

L'installazione iniziale delle dipendenze e il primo download del modello
richiedono una connessione Internet. Le chiamate al modello durante i test
sono locali su `127.0.0.1:11434`.

## 3. Avvio automatico: un comando

Apri PowerShell **nella cartella di AchillesAPI** estratta dal file ZIP.

### Solo laboratorio + controlli automatici

```powershell
powershell -ExecutionPolicy Bypass -File .\deployment\windows\start-all.ps1 -IncludeLegacyChecks
```

Lo script apre una **seconda finestra PowerShell** per l'API, attende la
risposta di `/health`, imposta le credenziali dimostrative in variabili
d'ambiente, esegue l'analisi Swagger, genera piani e grafo, esegue le GET
consentite e prova i controlli legacy selezionati.

Puoi accedere a:

- Swagger UI: http://127.0.0.1:8000/docs
- Swagger JSON: http://127.0.0.1:8000/openapi.json
- Health: http://127.0.0.1:8000/health

### Anche con l'AI locale

**Prima esecuzione (scarica il modello, se manca):**

```powershell
powershell -ExecutionPolicy Bypass -File .\deployment\windows\start-all.ps1 -WithAI -DownloadModel -IncludeLegacyChecks
```

**Avvii successivi (modello già installato):**

```powershell
powershell -ExecutionPolicy Bypass -File .\deployment\windows\start-all.ps1 -WithAI -IncludeLegacyChecks
```

**Opzione aggiuntiva SOLO per il laboratorio**: `-RunWriteDemo` invia due
richieste PATCH esplicite agli endpoint di mass assignment. La prima modifica
l'utente fittizio Alice; riavvia il server per ripristinare lo stato.

## 4. Avvio manuale in tre terminali (se vuoi capire ogni pezzo)

**Terminale 1 — API**

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dev
uv run python -m achillesapi.lab.export_spec
uv run uvicorn achillesapi.lab.full_app:app --host 127.0.0.1 --port 8000
```

Non chiudere questo terminale mentre testi il laboratorio.

**Terminale 2 — AI locale**

Con Ollama installato, dalla cartella di AchillesAPI:

```powershell
powershell -ExecutionPolicy Bypass -File .\deployment\windows\start-ai.ps1 -DownloadModel
```

Se il modello è già presente, ometti `-DownloadModel`. Puoi verificare:

```powershell
ollama list
```

Devi vedere `achilles-local` nell'elenco. In alternativa puoi eseguire
manualmente `ollama pull llama3.2:3b` e poi
`ollama create achilles-local -f .\deployment\Modelfile`.

**Terminale 3 — AchillesAPI**

```powershell
powershell -ExecutionPolicy Bypass -File .\deployment\windows\run-lab-demo.ps1 -WithAI -IncludeLegacyChecks
```

I risultati vengono salvati in `reports/full-lab/`.

## 5. Esempio minimo senza script

Prima un controllo puramente offline:

```powershell
uv run achillesapi auto-assess .\examples\full_lab_openapi.json `
  --base-url http://127.0.0.1:8000 `
  --output .\reports\lab-plan.json
```

Poi autorizza le richieste GET verso il laboratorio:

```powershell
$env:ACHILLES_LAB_ALICE_TOKEN = 'alice-token'
$env:ACHILLES_LAB_BOB_TOKEN = 'bob-token'
uv run achillesapi auto-assess .\examples\full_lab_openapi.json `
  --base-url http://127.0.0.1:8000 `
  --allow-host 127.0.0.1 `
  --auth-config .\examples\full-lab-auth.yaml `
  --profile alice --profile bob `
  --path-value order_id=order-bob `
  --path-value username=bob `
  --path-value sku=SKU-1001 `
  --path-value report_ref=not-created `
  --allow-insecure-http `
  --max-requests 60 --rate 3 --execute `
  --output .\reports\lab-requests.json
```

`--allow-insecure-http` si usa **solo perché questa API dimostrativa è in HTTP
sul loopback**. Non trasmettere token reali su HTTP.

`auto-assess` riconosce dagli schemi OpenAPI se una route richiede Bearer,
Basic, API key oppure cookie, e utilizza solo profili compatibili. Altrimenti
registra la route come saltata. Le informazioni di autenticazione **non sono
scritte nel JSON**.

## 6. Test specifici da interpretare

### BOLA / IDOR

```powershell
uv run achillesapi bola-check http://127.0.0.1:8000/api/orders/order-bob `
  --owner-token bob-token --other-token alice-token --execute

uv run achillesapi bola-check http://127.0.0.1:8000/api/secure/orders/order-bob `
  --owner-token bob-token --other-token alice-token --execute
```

**Atteso:** nel primo caso Alice riceve HTTP 200 per l'ordine di Bob (BOLA
riprodotta in laboratorio). Nel secondo caso Alice riceve HTTP 403.

### BFLA

```powershell
$headers = @{ Authorization = 'Bearer alice-token' }
Invoke-RestMethod http://127.0.0.1:8000/api/admin/audit -Headers $headers
```

**Atteso:** l'endpoint `audit` restituisce il dato admin anche a una utenza
normale. L'endpoint `/api/admin/metrics` invece rifiuta l'accesso con HTTP 403.
Con `-IncludeLegacyChecks` viene eseguito anche `bfla-sweep` per confrontare
le identità Alice e Admin su più endpoint. Il risultato è un *indicatore*:
le policy amministrative vanno comunque dichiarate e verificate.

### SQL error disclosure (solo simulazione)

```powershell
uv run achillesapi sqli-check http://127.0.0.1:8000/api/search `
  --parameter q --token alice-token
```

**Atteso:** baseline HTTP 200, canary con apostrofo HTTP 500 e marker
`sqlite error`. La presenza dell'errore non prova una SQL injection.

### Fuzzing leggero

```powershell
uv run achillesapi fuzz-parameter http://127.0.0.1:8000/api/secure/search `
  --parameter q --token alice-token
```

### Mass assignment

Prima soltanto l'anteprima (nessuna PATCH):

```powershell
uv run achillesapi mass-assignment-check http://127.0.0.1:8000/api/profiles/alice `
  --body-file .\examples\full-lab-profile-patch.json --token alice-token
```

Poi, **solo dopo aver compreso l'effetto** sulla utenza fittizia:

```powershell
uv run achillesapi mass-assignment-check http://127.0.0.1:8000/api/profiles/alice `
  --body-file .\examples\full-lab-profile-patch.json --token alice-token --execute
```

**Atteso:** `is_admin` passa a `true` per Alice sul percorso vulnerabile.
L'endpoint PATCH `/api/secure/profiles/alice` risponde 422 a questa richiesta.
Riavviare il lab elimina tutte le modifiche in memoria.

### Analisi con AI locale

```powershell
uv run achillesapi scan .\examples\full_lab_openapi.json `
  --ai --model achilles-local `
  --output .\reports\lab-ai.json
```

Questo comando consulta il modello sul **computer locale** e non invia
richieste all'API: è una analisi passiva della specifica, non una validazione
delle vulnerabilità riprodotte nei test HTTP.

## 7. File generati e come leggerli

- `openapi.json`: elenco normalizzato di metodi, percorsi e parametri.
- `test-plan.json`: test di sicurezza **proposti**, con prerequisiti.
- `graph.json`: possibili relazioni tra risorse, endpoint e schemi.
- `dry-run.json`: ciò che `auto-assess` farebbe senza inviare richieste.
- `active-get.json`: esito delle GET autorizzate, per identità, con status e tempi.
- `bfla-sweep.json`: confronti legacy tra due ruoli (se richiesti).
- `ollama-passive.json`: interpretazione consultiva dell'AI locale (se richiesta).

Per capire cosa modificare, leggi anche `docs/FUNCTION_GUIDE.md`, in
particolare la parte su `core/generic.py` e `lab/full_app.py`.

## 8. Cosa AchillesAPI NON automatizza ancora

- Non esegue automaticamente POST, PATCH e DELETE dal generatore OpenAPI.
- Non ricava policy di ruoli e ownership dal solo Swagger.
- Non conferma BOLA/BFLA semplicemente confrontando HTTP 200 e HTTP 403.
- Non acquisisce sessioni tramite OAuth e non gestisce workflow complessi.
- Non collega ancora l'evidenza runtime al modello AI come unico comando.
- I vecchi motori avanzati restano **limitati a loopback**.

Il laboratorio mette a disposizione tutte queste aree per sviluppo e test,
ma la copertura automatica attuale non equivale ancora a uno scanner autonomo
completo per il mondo reale.
