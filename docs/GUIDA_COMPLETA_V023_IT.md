# AchillesAPI v0.23.0 — Guida operativa italiana

Questa guida riguarda **il codice realmente implementato nella v0.23.0**. Il motore di produzione non conosce percorsi, utenti o identificativi dei laboratori. Gli esempi in `labs/` esistono soltanto per esercitare e verificare il framework.

> **Ambito**: test autorizzati, preferibilmente su staging. Lo Swagger descrive un'interfaccia, non dimostra che un account possieda un oggetto né autorizza modifiche. La v0.23 non è ancora un pentester senza supervisione né uno scanner production-ready certificato.

## 1. Preparazione Windows PowerShell

Estrai lo ZIP ed entra nella cartella contenente `pyproject.toml`:

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dev
uv run achillesapi version
uv run pytest -q
uv run achillesapi --help
```

Su Kali/Linux gli stessi comandi, senza i caratteri PowerShell di continuazione `` ` ``. Per vedere tutte le opzioni di un comando:

```powershell
uv run achillesapi auto-assess --help
uv run achillesapi workflow-assess --help
uv run achillesapi security-inventory --help
```

## 2. Il percorso professionale consigliato

**Analisi offline senza contattare il target**:

```powershell
uv run achillesapi analyze-openapi .\swagger.yaml
uv run achillesapi intelligent-plan .\swagger.yaml --output .\reports\intelligent.json
uv run achillesapi security-inventory .\swagger.yaml --output .\reports\inventory.json
uv run achillesapi workflow-discover .\swagger.yaml --draft-config .\workflows.draft.yaml
uv run achillesapi journey-discover .\swagger.yaml --draft-config .\journey.draft.yaml
uv run achillesapi auth-draft .\swagger.yaml --output .\auth.draft.yaml
uv run achillesapi auto-assess .\swagger.yaml --base-url https://staging.example.com --output .\reports\plan.json
```

Leggi il piano. Se ci sono path con `{id}` e mancano valori, fornisci **identificativi di risorse autorizzate** tramite `--path-value id=...` oppure il file `--context`; non usare ID casuali altrui. Le bozze YAML generate non sono pronte da eseguire: devono contenere valori reali e autorizzati.

**Esecuzione di soli controlli GET**, con budget limitato e decisioni adattive sulle osservazioni:

```powershell
uv run achillesapi auto-assess .\swagger.yaml `
  --base-url https://staging.example.com `
  --allow-host staging.example.com `
  --auth-config .\auth-profiles.yaml `
  --profile tester --profile admin `
  --max-requests 80 --rate 1 `
  --agent-budget 4 `
  --execute `
  --output .\reports\assessment.json
```

`--agent-budget 4` riserva al massimo quattro GET per verifiche aggiuntive. Prima esegue il motore GET; poi, solo se ha osservato un 5xx in baseline o un 2xx anonimo su un endpoint dichiarato protetto, ripete **la stessa GET ricostruita dallo Swagger**. Nessun payload di Ollama o body remoto può diventare un'istruzione di rete. Il controllo serve alla **riproducibilità**, non alla conferma automatica di una vulnerabilità.

`--ai --model achilles-local` aggiunge un **parere locale di Ollama** sulle evidenze sanitizzate; occorre che Ollama e il modello siano già disponibili. L'AI non sceglie né autorizza richieste HTTP. `--adaptive-verify` è il precedente controllo limitato ai 5xx; puoi scegliere quello oppure il nuovo agent per evitare verifiche ridondanti.

## 3. Authentication Engine

I token vanno dichiarati in variabili d'ambiente, **mai** inseriti in `swagger.yaml` né in file versionati. Il file di esempio `labs/v020_service/auth.yaml` illustra OAuth2 Client Credentials e login JSON; `labs/independent_api/auth.yaml` illustra Bearer statici.

```powershell
$env:COMPANY_TEST_TOKEN = 'token-for-staging-test-user'
uv run achillesapi auth-profiles --config .\auth-profiles.yaml
```

Esempio di profilo statico:

```yaml
profiles:
  - name: tester
    type: bearer
    token_env: COMPANY_TEST_TOKEN
```

Il file di autenticazione può essere usato da `auto-assess`, `journey-assess` e `workflow-assess`. Per HTTP non cifrato, il framework blocca l'invio di credenziali salvo `--allow-insecure-http`, da usare solo su lab locali autorizzati. `--allow-host` deve corrispondere all'host esatto.

## 4. Workflow GET con ID acquisiti dalle risposte

Per una catena di lettura, `journey-discover` propone un file YAML. Il comando `journey-assess` lo esegue solo dopo aver verificato le operazioni OpenAPI. Un esempio funzionante è `labs/v020_service/journey.yaml`. I JSON Pointer estraggono identificativi in memoria, mai nel report:

```yaml
steps:
  - operation: GET /api/organizations
    identity: workload
    capture:
      org_id: /organizations/0/organization_ref
  - operation: GET /api/organizations/{organization_ref}
    identity: user
    values:
      organization_ref: $org_id
```

Esecuzione (dopo aver avviato il laboratorio v0.20 e impostato le sue variabili d'ambiente):

```powershell
uv run achillesapi journey-assess .\labs\v020_service\openapi.json `
  --journey-config .\labs\v020_service\journey.yaml `
  --base-url http://127.0.0.1:8780 `
  --auth-config .\labs\v020_service\auth.yaml `
  --allow-host 127.0.0.1 --allow-insecure-http --execute
```

## 5. v0.21 — Più mutazioni su una risorsa temporanea

Un workflow di scrittura non può essere dedotto automaticamente con sicurezza da Swagger. Usa `workflow-discover` per ottenere una **bozza**, poi fornisci un JSON di creazione disposable, un campo `marker_field` stringa, il JSON Pointer dell'ID, identità, policy di accesso e DELETE finale.

La v0.21 supporta `mutations` (fino a 5 PATCH/PUT ordinate) oltre alla precedente chiave singola `mutation`. Non puoi specificare entrambe. Ogni mutazione è seguita da GET e controllo **ID + marcatore immutabile**; se non coincidono, il framework ferma ulteriori mutazioni e non elimina automaticamente l'oggetto. In caso di incertezza la pulizia va verificata manualmente.

Esempio completo e pronto per il laboratorio: `labs/independent_api/workflow_v023.yaml`.

```powershell
uv run achillesapi workflow-assess .\labs\independent_api\openapi.json `
  --workflow-config .\labs\independent_api\workflow_v023.yaml `
  --base-url http://127.0.0.1:8765 `
  --auth-config .\labs\independent_api\auth.yaml `
  --allow-host 127.0.0.1 --allow-insecure-http `
  --max-requests 20 --rate 2 `
  --execute --approve-writes `
  --output .\reports\workflow-v023.json
```

L'esecuzione di GET e scritture in un unico assessment è disponibile anche tramite `auto-assess --workflow-config ... --approve-writes`. Questo flag **non** deve essere usato su produzione senza dati disposable e un cleanup validato.

## 6. v0.22 — Inventario di copertura e controlli aggiuntivi

```powershell
uv run achillesapi security-inventory .\swagger.yaml --output .\reports\inventory.json
```

Classifica possibili controlli con etichette **OWASP API Security Top 10 2023**: BOLA, autenticazione, autorizzazione di funzioni/proprietà, misconfiguration e consumo risorse. Ogni voce è una **opportunità di test**, non un finding. I requisiti mancanti (ownership, credenziali, fixture e policy) sono esplicitati. I controlli GET già presenti effettuano anche verifiche di proprietà JSON, CORS, contratto di risposta e input validation. Nella v0.22 la generazione di valori volutamente invalidi copre anche `minLength` e alcuni `format` OpenAPI, con payload piccoli.

**Non sono implementati motori generali di SQLi/NoSQLi/SSRF/SSTI, injection out-of-band, rate-limit stress o test business logic arbitrari**. Non considerare l'inventario come una scansione di queste categorie.

## 7. v0.23 — Adaptive Agent, Offline Review e Ollama

La modalità offline legge un precedente report e propone le prossime verifiche, **senza rete**:

```powershell
uv run achillesapi agent-review .\swagger.yaml .\reports\assessment.json `
  --budget 3 --output .\reports\agent-plan.json
```

L'agent applica regole deterministiche e un limite massimo di 20 GET di follow-up per invocazione. `agent-review` usa il proprio parser OpenAPI, quindi non accetta percorsi arbitrari dal file JSON. Per i follow-up reali, usa `auto-assess --agent-budget N --execute` con scope/budget autorizzati.

Con `--ai` l'interpretazione con Ollama è **consultiva**. Non è una procedura automatica di sfruttamento di vulnerabilità, né può approvare risorse di scrittura. Questa separazione evita che risposte malevole dell'API o testo generato dall'LLM siano interpretati come comandi da eseguire.

## 8. Avviare i laboratori locali

Per i test v0.21–v0.23, apri una prima PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\labs\independent_api\start.ps1
```

Swagger: http://127.0.0.1:8765/docs. In una seconda finestra:

```powershell
$env:ACHILLES_DEMO_ALICE = 'demo-alice'
$env:ACHILLES_DEMO_BOB = 'demo-bob'
$env:ACHILLES_DEMO_ADMIN = 'demo-admin'
uv run achillesapi security-inventory .\labs\independent_api\openapi.json
uv run achillesapi workflow-assess .\labs\independent_api\openapi.json `
  --workflow-config .\labs\independent_api\workflow_v023.yaml `
  --base-url http://127.0.0.1:8765 `
  --auth-config .\labs\independent_api\auth.yaml `
  --allow-host 127.0.0.1 --allow-insecure-http `
  --max-requests 20 --rate 2 --execute --approve-writes
```

Risultati attesi sul laboratorio: due mutazioni, BOLA, esposizione di una proprietà ristretta e cleanup verificato. Nella prova di sviluppo sono state eseguite **9 richieste** sul workflow (POST, GET, GET, PATCH, GET, PATCH, GET, DELETE, GET).

Per il laboratorio di autenticazione/GET adattive: `powershell -ExecutionPolicy Bypass -File .\labs\v020_service\start.ps1` (porta 8780); consulta la guida v0.20 per i quattro nomi delle variabili d'ambiente e l'esecuzione di `auto-assess`.

## 9. Cosa leggere nei JSON

- `plan`: operazioni GET eleggibili, input mancanti e budget.
- `execution_report.observations`: solo stato, identità, nome del controllo, durata, digest HMAC per-run.
- `execution_report.findings`: **indicatori** da verificare, non vulnerabilità automaticamente confermate.
- `security_inventory`: test applicabili e dati di contesto richiesti.
- `agent_plan`: GET candidate per ripetizione e ragione della scelta.
- `agent_execution`: risultati delle verifiche, senza corpi HTTP né valori di credenziali.
- `workflow_plan` / `workflow_execution`: ciclo disposable, possibili mismatch di policy e cleanup.
- `journey_execution`: step GET e nomi dei valori catturati in memoria.
- `ai_advisory`: interpretazione di Ollama, se richiesto.

Se `manual_cleanup_required` è vero, **interrompi** e verifica lo stato del sistema: un rollback remoto non è garantito.

## 10. Comandi disponibili

`version`, `analyze-openapi`, `generate-tests`, `map-api`, `assess`, `scan`, `auto-assess`, `auth-profiles`, `auth-draft`, `http-get`, `bola-check`, `bola-sweep`, `bfla-sweep`, `role-matrix`, `mass-assignment-check`, `sqli-check`, `fuzz-parameter`, `jwt-inspect`, `analyze-evidence`, `ai-analyze`, `ai-correlate`, `workflow-discover`, `workflow-assess`, `intelligent-plan`, `adaptive-review`, `journey-discover`, `journey-assess`, `security-inventory`, `agent-review`.

I comandi legacy specifici (`bola-check`, `sqli-check`, `fuzz-parameter` e altri) sono ancora limitati a target locali o a operazioni singole. Per API aziendali utilizza `auto-assess` e workflow esplicitamente approvati.

## 11. Limiti e criteri per la produzione

- Il tool non deduce con certezza la business logic o la ownership dal nome degli endpoint.
- I workflow multi-write supportano più modifiche **sullo stesso oggetto**; non eseguono ancora dipendenze arbitrarie POST→POST→PATCH tra risorse diverse.
- Il meccanismo di cleanup è best-effort, non transazionale; restituzioni ambigue devono essere esaminate manualmente.
- Il modello locale è consultivo; la logica di follow-up è deterministica e copre soltanto due categorie di anomalie GET.
- L'autenticazione SSO browser, OAuth authorization-code interattivo, API incomplete e riferimenti OpenAPI esterni sono ancora limiti.
- Persistono attività di hardening rete (IP/DNS, rebinding, verifiche TLS/proxy), benchmark su target indipendenti e reporting HTML/PDF.
- I test automatici certificano le **funzionalità del software**, non il detection rate su vulnerabilità ignote. Misura falsi positivi e copertura prima di usarlo come unico controllo di sicurezza.

Per investigare un problema: `uv run achillesapi <comando> --help`, poi `uv run pytest -q` e leggi `docs/FUNCTION_GUIDE.md` insieme a `src/achillesapi/core/`.
