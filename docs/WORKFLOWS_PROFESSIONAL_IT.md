# AchillesAPI v0.12.0 — Workflow di test su API reali

La v0.12.0 è sviluppata per **API diverse tra loro**. Il laboratorio incluso nello ZIP è
solo una fixture di verifica; il motore non contiene `alice`, `bob`, `order_id`,
endpoint o token del laboratorio.

## Che cosa può fare automaticamente

1. Leggere e normalizzare OpenAPI 3.x, senza contattare il server.
2. Proporre le sequenze `POST collection → GET item → PATCH/PUT item → DELETE item` basandosi
   soltanto sui metodi e sui path del file OpenAPI.
3. Individuare i campi richiesti dal `requestBody`, senza inventare dati aziendali.
4. Eseguire controlli GET automatici (autenticazione, CORS, validazione dei parametri,
   error disclosure, BOPLA e confronti tra identità) usando `auto-assess`.
5. **Solo se l'operatore autorizza esplicitamente i write**, creare una nuova risorsa
   di prova, verificarne l'identificativo, eseguire controlli BOLA/BFLA e mass assignment,
   quindi tentare DELETE e verificare che la risorsa non esista più.
6. Produrre risultati JSON senza corpi HTTP, token, cookie o identificativi concreti.

La versione **non può dedurre da Swagger** chi possiede una risorsa, se una proprietà è
amministrativa, come acquisire sessioni complesse e come recuperare un oggetto orfano
se un server fallisce senza restituire l'ID. Per questo serve una piccola configurazione
operatore per ogni workflow di scrittura. Gli indicatori richiedono revisione umana.

## 1. Installazione (PowerShell)

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dev
uv run achillesapi version
uv run pytest -q
```

## 2. Prima passata: solo Swagger, senza traffico

```powershell
uv run achillesapi analyze-openapi .\swagger.yaml
uv run achillesapi generate-tests .\swagger.yaml --output .\reports\test-plan.json
uv run achillesapi workflow-discover .\swagger.yaml `
  --output .\reports\workflow-candidates.json `
  --draft-config .\my-disposable-workflows.yaml
uv run achillesapi auto-assess .\swagger.yaml --output .\reports\dryrun.json
```

`workflow-discover` cerca pattern CRUD e genera una bozza YAML **non eseguibile**;
le etichette `REPLACE_ME` devono essere sostituite. Non riempire la bozza con
credenziali o dati di produzione: usare account e risorse di test.

## 3. Configurare autenticazione senza scrivere segreti nel repository

`auth-profiles.yaml` (nome a tua scelta):

```yaml
profiles:
  - name: owner
    type: bearer
    token_env: APPROVED_OWNER_TOKEN
  - name: outsider
    type: bearer
    token_env: APPROVED_OTHER_TOKEN
```

PowerShell:

```powershell
$env:APPROVED_OWNER_TOKEN = "TOKEN_TEST_OWNER"
$env:APPROVED_OTHER_TOKEN = "TOKEN_TEST_OTHER"
```

Le password eventualmente richieste **nel JSON di creazione** possono essere
lette dall'ambiente con `{$env: VARIABLE_NAME}`, senza inserirle nel YAML.

## 4. Esempio di workflow indipendente dal laboratorio

La configurazione qui sotto è illustrativa e NON funzionerà finché non sostituisci
nomi di endpoint, parametri, JSON Pointer e payload con quelli del tuo Swagger.

```yaml
workflows:
  - name: test_fixtures
    create:
      operation: "POST /v2/assets"
      identity: owner
      body:
        label: "achilles-disposable-fixture"
      id_pointer: "/asset_ref"
      marker_field: label
    read:
      operation: "GET /v2/assets/{asset_ref}"
      identity: owner
      id_parameter: "asset_ref"
      id_pointer: "/asset_ref"
      marker_pointer: "/label"
    access:
      - identity: outsider
        expected: deny
        category: BOLA
      # Per BFLA, puoi indicare un'altra funzione GET e la policy attesa:
      # - identity: outsider
      #   expected: deny
      #   category: BFLA
      #   operation: "GET /v2/privileged/status"
    restricted_response_fields:
      - internal_only
    # Facoltativo. Eseguire solo quando la risorsa è creata dal workflow
    # e hai approvazione esplicita per un campo dichiarato non scrivibile:
    mutation:
      operation: "PATCH /v2/assets/{asset_ref}"
      identity: owner
      body:
        internal_only: true
      restricted_fields:
        - internal_only
    cleanup:
      operation: "DELETE /v2/assets/{asset_ref}"
      identity: owner
```

La configurazione non usa ID predefiniti: il valore `asset_ref` viene estratto
dal JSON restituito dalla `POST` mediante `/asset_ref` (JSON Pointer). Se
il server usa `/data/id`, scrivi `/data/id`. L'ID rimane in memoria, non nel report.

**Protezione aggiuntiva:** `marker_field` indica un campo stringa scrivibile,
che AchillesAPI riempie con un valore temporaneo casuale. La GET deve restituire
esattamente quel valore in `marker_pointer`. Solo allora il tool effettua
PATCH/PUT e DELETE. Questo evita di cancellare un oggetto preesistente su cui
la POST si sia comportata come un upsert. Se il marker non coincide, il tool
richiede pulizia manuale invece di cancellare una risorsa incerta. La POST deve
restituire **201 Created**, non semplicemente 200.

Se un endpoint richiede altri parametri path/query/header specificati nello
Swagger, aggiungi nel workflow il dizionario `path_values`:

```yaml
    path_values:
      tenant_ref: "APPROVED_TEST_TENANT"
      locale: "it"
```

La configurazione è *dati*, non codice eseguibile: nessun comando shell,
JavaScript o Python viene caricato da YAML.

## 5. Prima simulazione (zero richieste)

```powershell
uv run achillesapi workflow-assess .\swagger.yaml `
  --base-url https://staging.example.com `
  --workflow-config .\my-disposable-workflows.yaml `
  --auth-config .\auth-profiles.yaml `
  --output .\reports\workflow-plan.json
```

Se manca un parametro, se l'operazione non esiste in OpenAPI o se la catena
non contiene DELETE della stessa risorsa, il motore blocca il workflow.

## 6. Esecuzione con autorizzazione esplicita

**Solo in uno scope autorizzato e preferibilmente in staging/test.**

```powershell
uv run achillesapi workflow-assess .\swagger.yaml `
  --base-url https://staging.example.com `
  --workflow-config .\my-disposable-workflows.yaml `
  --auth-config .\auth-profiles.yaml `
  --allow-host staging.example.com `
  --max-requests 30 --rate 1 --timeout 8 `
  --execute --approve-writes `
  --output .\reports\workflow-results.json
```

`--approve-writes` **non è implicito** in `--execute`. Sono richieste entrambe.
Un unico budget copre creazione, letture, prove e cleanup; alcune richieste
sono riservate alla cancellazione e alla verifica finale.

### Un comando per GET intelligenti + workflow

```powershell
uv run achillesapi auto-assess .\swagger.yaml `
  --base-url https://staging.example.com `
  --auth-config .\auth-profiles.yaml `
  --workflow-config .\my-disposable-workflows.yaml `
  --allow-host staging.example.com `
  --max-requests 80 --rate 1 `
  --execute --approve-writes `
  --output .\reports\full-assessment.json
```

`auto-assess` riserva prima il budget previsto per i workflow di scrittura e
usa il resto per i controlli GET adattivi. Niente test di scrittura se manca
uno dei flag di approvazione. Puoi aggiungere `--ai` per un'interpretazione
**consultiva locale**; l'AI non decide scope, metodo o autorizzazione.

### Interpretazione degli esiti

- **BOLA:** una seconda identità ottiene la risorsa creata, contro una policy
  `deny` inserita dall'operatore. Il tool verifica anche l'ID nel JSON.
- **BFLA:** un account accede a una funzione GET per cui l'operatore dichiara
  `deny`. Non basta la parola `admin` nel path per confermare un problema.
- **Mass assignment:** una PATCH/PUT di prova viene accettata e la GET successiva
  mostra il campo vietato cambiato verso il valore inviato. Senza lettura prima/dopo,
  il risultato resta inconcludente.
- **BOPLA:** un campo esplicitamente vietato dalla policy appare nel JSON.
- **Cleanup:** DELETE è sempre tentata in `finally` quando l'ID di una risorsa
  creata è noto. GET successiva deve rispondere 404/410 per confermare la pulizia.

## 7. Attenzione: rollback non è una garanzia assoluta

Un'API può applicare POST ma rispondere 500, può non restituire l'ID o può
rifiutare DELETE. In questi casi AchillesAPI **non può garantire il ripristino**.
Il JSON conterrà `manual_cleanup_required: true`, e il comando termina con
**codice 2** se il cleanup non è verificato. Controlla il target e ripristina
manualmente con il referente applicativo. Gli ID effettivi non vengono salvati
nel report per proteggere i dati.

Non usare questi workflow su oggetti reali. Non lanciare prove di scrittura su
asset permanenti o sistemi senza procedure approvate di pulizia. Nemmeno
OpenAPI garantisce che una GET sia priva di effetti collaterali.

## 8. Limiti attuali

- Swagger/OpenAPI 3.x; solo riferimenti locali e JSON per i workflow di scrittura.
- I workflow CRUD auto-individuati sono *candidati*, non una comprensione completa
  delle regole di business o dei flussi OAuth2.
- I test di scrittura sono autorizzati solo su **nuove risorse disposable** create
  nello stesso run; non esegue PATCH/DELETE su oggetti preesistenti.
- Identificativi restituiti dalla POST devono essere stringhe/numeri semplici e
  usabili in sicurezza come singolo segmento URL.
- `restricted_fields` e `restricted_response_fields` sono proprietà **top-level**.
- Non effettua automaticamente test di race condition, SSRF, RCE, upload, pagamenti,
  multistep con conferme esterne o mutation Fuzzing aggressivo.
- I report contengono **osservazioni**, non vulnerabilità automaticamente confermate.
- Nessun provider AI cloud; il modello Ollama locale è opzionale.
- Richieste con redirect disabilitati, certificati TLS verificati, proxy ereditati
  dall'ambiente disabilitati, budget/timeout/rate limit applicati.

## 9. Dove modificare il codice (commenti leggibili)

| Vuoi cambiare... | File/funzione |
|---|---|
| Discovery delle relazioni CRUD | `core/workflows.py` → `discover_workflows()` |
| Bozza di configurazione | `core/workflows.py` → `draft_workflow_config()` |
| Vincoli del file YAML | `core/workflows.py` → `read_workflows()` |
| Controlli preflight su endpoint | `core/workflows.py` → `_validate_workflows()` |
| Esecuzione e ripristino | `core/workflows.py` → `run_workflows()` |
| Recupero ID dal JSON | `core/workflows.py` → `_json_pointer()` |
| Redazione e osservazioni | `core/workflows.py` → `_safe_response()` |
| Limiti e client HTTP | `core/http.py` → `SafeHTTPClient` |
| Autenticazione | `core/auth.py` → `AuthenticationManager` |
| Test GET autonomi | `core/smart.py` → `run_smart_assessment()` |
| Comandi PowerShell/CLI | `cli.py` → `workflow_assess_command()` e `auto_assess_command()` |

Tutte le nuove funzioni hanno docstring che spiegano in termini semplici lo
scopo, e i passaggi più delicati sono commentati nel codice.
