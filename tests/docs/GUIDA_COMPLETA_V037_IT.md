# AchillesAPI v0.37.0 — Guida completa (Windows, Kali, browser)

## 0. Cosa offre questa release

La v0.37 parte dalla v0.34 e introduce **tre estensioni** più una **dashboard locale**:

1. **Advanced Workflow & State Engine (v0.35)**: ogni risorsa disposable può avere fino a quattro PATCH/PUT esplicitamente approvate, con GET di verifica prima e dopo ogni modifica. Il motore conserva gli ID solo in memoria e ripristina le risorse create nell'ordine inverso, se può riconoscerle con ID e marcatore.
2. **Advanced Verification Engine (v0.36)**: verifica offline una matrice di regole allow/deny fornite dall'operatore, distinguendo *policy mismatch* da test inconcludenti. I controlli GET già presenti (autenticazione, CORS, validazione limitata, schema e informazioni esposte) restano disponibili. Non è un exploit engine SQLi/SSRF completo.
3. **Agent v2 (v0.37)**: fino a due turni di verifica adattiva per GET dichiarate in OpenAPI, con budget globale e motivazione dei follow-up. Ollama è facoltativo, strettamente locale e solo consultivo: non scrive comandi eseguibili, URL o payload al posto dell'operatore.
4. **Dashboard FastAPI**: importa file OpenAPI e profili YAML, mostra gli endpoint, avvia piani offline o GET automatiche sul target autorizzato, mostra i report JSON, esegue triage offline ed esporta HTML/PDF. Ascolta solo su 127.0.0.1.

**Non è la v1.0**: i workflow complessi non possono essere dedotti/eseguiti per ogni API senza dati disposable e una policy esplicita; non vengono lanciati payload di exploitation avanzati senza un motore specializzato; la dashboard non può fare scritture (per scelta di sicurezza). Un risultato HTTP 200/500 non conferma da solo una vulnerabilità.

## 1. Prerequisiti

- Windows 10/11 PowerShell oppure Kali Linux, Python 3.12 e `uv` installati.
- Per la dashboard: dipendenze `fastapi`, `uvicorn` e `python-multipart` (extra `dashboard`).
- Per esportare PDF: extra `pdf` (`reportlab`).
- Facoltativo: Ollama in esecuzione **sullo stesso PC**, senza servizi cloud.
- Devi essere autorizzato a testare gli host e conoscere limiti di richieste, account, dati e finestre operative.

### Installazione Windows

Apri PowerShell nella cartella `achillesapi` estratta dallo ZIP:

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dev --extra pdf --extra dashboard
uv run achillesapi version
uv run pytest -q
```

In caso di problemi con i Python più recenti, forza `uv run --python 3.12 achillesapi ...`.

### Installazione Kali

```bash
uv python install 3.12
uv sync --python 3.12 --extra dev --extra pdf --extra dashboard
uv run achillesapi version
uv run pytest -q
```

## 2. Dashboard grafica locale

### Avvio

```powershell
uv run achillesapi dashboard --port 8766 --workspace .\dashboard-data
```

Kali:

```bash
uv run achillesapi dashboard --port 8766 --workspace ./dashboard-data
```

Apri nel browser **http://127.0.0.1:8766**. Per terminare premi `Ctrl+C` nella console che ospita la dashboard.

### Utilizzo, passo per passo

1. **OpenAPI specification**: seleziona un file `.yaml`, `.yml` o `.json` OpenAPI 3.x. Il server verifica il file e mostra titolo, numero di operazioni e lista degli endpoint. Il file rimane nel tuo workspace locale.
2. **Base URL**: indica l'indirizzo dell'ambiente target. Per esempio `https://staging.example.com`. **Approved hostname** deve essere esattamente `staging.example.com` (niente `https://`, porte o path).
3. **Max requests / rate**: configura un budget piccolo per iniziare: 40 richieste, 1 al secondo. La dashboard limita max 100 e rate max 5.
4. **Auth configuration** (facoltativo): seleziona un file YAML di profili. I profili NON contengono password/token, ma i nomi delle variabili di ambiente che il processo risolverà. Inserisci i nomi nel campo `Profile names`, separati da virgola.
5. **Active assessment** disattivato: `Start assessment` produce un piano offline, senza traffico al target.
6. **Active assessment** attivato: invia GET e verifiche limitate verso il solo host approvato. Richiede URL e hostname esatto.
7. **Assessment activity**: controlla lo stato `running`, `complete`, `failed`. Seleziona `View report`, `Analyze findings`, `Export HTML` o `Export PDF`.

**Sicurezza**: la dashboard ascolta solo su loopback, usa token anti-CSRF, blocca richieste cross-origin e non permette l'esecuzione di comandi shell arbitrari. Non espone endpoint per POST/PATCH/DELETE di prova: per queste operazioni usa la CLI e il manifesto approvato.

Le credenziali devono essere disponibili come **variabili d'ambiente del processo prima dell'avvio della dashboard**; dopo averle cambiate, riavvia la dashboard. Non inserirle nel file YAML.

Esempio PowerShell:

```powershell
$env:ACHILLES_TESTER_TOKEN = "<TOKEN_DI_TEST>"
uv run achillesapi dashboard
```

Nel workspace `dashboard-data/uploads` vengono conservate le specifiche e i file YAML importati; in `dashboard-data/reports` trovi le uscite. Proteggi la directory e non sincronizzarla su cloud se le specifiche sono riservate.

**Limiti dashboard:** i job sono tracciati in memoria: dopo il riavvio le vecchie esecuzioni non vengono mostrate nella lista, ma i report sul disco restano disponibili. Non è un servizio multiutente, non è previsto l'accesso dalla rete aziendale ed è necessaria supervisione umana.

## 3. Avvio laboratorio locale completo

Il laboratorio `labs/multi_resource_demo` espone risorse parent/child, BOLA volutamente introdotte e PATCH non distruttive sui campi `note`. NON esporlo su rete esterna.

### Terminale 1 — server

```powershell
powershell -ExecutionPolicy Bypass -File .\labs\multi_resource_demo\start.ps1
```

Su Kali:

```bash
bash ./labs/multi_resource_demo/start.sh
```

Documentazione del laboratorio: `http://127.0.0.1:8790/docs`. File OpenAPI locale: `labs/multi_resource_demo/openapi.json`.

### Terminale 2 — credenziali dimostrative

```powershell
$env:ACHILLES_DEMO_OWNER = "lab-alice"
$env:ACHILLES_DEMO_OTHER = "lab-bob"
```

Su Kali:

```bash
export ACHILLES_DEMO_OWNER=lab-alice
export ACHILLES_DEMO_OTHER=lab-bob
```

### Prova offline (0 richieste)

```powershell
uv run achillesapi multi-resource-assess .\labs\multi_resource_demo\openapi.json `
  --config .\labs\multi_resource_demo\resources_v037.yaml `
  --auth-config .\labs\multi_resource_demo\auth.yaml `
  --base-url http://127.0.0.1:8790 `
  --allow-host 127.0.0.1 `
  --output .\reports\dry-multi.json
```

### Prova HTTP reale con risorse disposable

```powershell
uv run achillesapi multi-resource-assess .\labs\multi_resource_demo\openapi.json `
  --config .\labs\multi_resource_demo\resources_v037.yaml `
  --auth-config .\labs\multi_resource_demo\auth.yaml `
  --base-url http://127.0.0.1:8790 `
  --allow-host 127.0.0.1 `
  --allow-insecure-http `
  --max-requests 30 --rate 2 `
  --execute --approve-writes `
  --output .\reports\multi-v037.json
```

Cosa fa: crea una collection temporanea, verifica ID/marker, modifica `note`, verifica di nuovo, controlla accesso con una seconda identità; crea e modifica un document figlio e infine cancella document prima della collection, verificando che entrambi siano assenti. Un eventuale cleanup non sicuro compare come `manual_cleanup_required: true`.

`--allow-insecure-http` è **solo per il laboratorio locale**. In un assessment aziendale utilizza HTTPS.

### Come adattare un manifesto YAML a una vera API

Nel file `resources_v037.yaml`, ogni elemento sotto `resources` è una risorsa dichiarata nello Swagger:

- `name`: identificativo interno unico della risorsa;
- `create`, `read`, `delete`: operazioni `METHOD /path` **esattamente** presenti nello Swagger;
- `identity`: profilo di autenticazione da usare;
- `body`: JSON di creazione approvato, non valori inventati;
- `id_pointer` e `read_id_pointer`: posizioni JSON dell'identificativo nelle risposte;
- `marker_field` e `marker_pointer`: campo stringa scrivibile, verificabile dalla GET;
- `path_values`: valori per i path, inclusi `${collection.id}` ottenuti dai precedenti passaggi;
- `mutations`: facoltativo, da 0 a 4 operazioni PATCH/PUT sulla stessa risorsa con `body` statici approvati;
- `access`: eventuali identità con atteso `allow`/`deny` secondo policy reale.

**Preflight obbligatorio**: manifest approvato, schema POST JSON, marker stringa, GET/DELETE dello stesso oggetto, parametri risolti, ruoli compatibili, budget sufficiente. Il motore non elimina una risorsa se non può dimostrare che è stata creata durante il test. Nessun cleanup può essere garantito su ogni API: verifica prima il processo di rollback del target.

## 4. Assessment di un'API aziendale

### 4.1 Piano offline

```powershell
uv run achillesapi analyze-openapi .\swagger.yaml
uv run achillesapi intelligent-plan .\swagger.yaml --output .\reports\intelligent-plan.json
uv run achillesapi workflow-map .\swagger.yaml --output .\reports\workflow-map.json
uv run achillesapi auto-assess .\swagger.yaml `
  --base-url https://staging.example.com `
  --output .\reports\plan.json
```

Controlla se il pianificatore ha identificato correttamente endpoint, autenticazione, parametri e possibili dipendenze.

### 4.2 Profili di autenticazione

Esempio `auth.yaml`:

```yaml
profiles:
  - name: tester
    type: bearer
    token_env: ACHILLES_TESTER_TOKEN
  - name: admin
    type: bearer
    token_env: ACHILLES_ADMIN_TOKEN
```

Nel terminale imposta le variabili d'ambiente corrispondenti. Per API che usano OAuth2 Client Credentials o login JSON, consulta gli esempi inclusi nelle guide v0.20; non inserire segreti nello Swagger o nello YAML.

### 4.3 Verifica attiva autorizzata

```powershell
uv run achillesapi auto-assess .\swagger.yaml `
  --base-url https://staging.example.com `
  --allow-host staging.example.com `
  --auth-config .\auth.yaml `
  --profile tester --profile admin `
  --max-requests 60 --rate 1 `
  --execute `
  --output .\reports\assessment.json
```

I parametri obbligatori non deducibili devono essere forniti tramite `--path-value NAME=VALUE` oppure contesto approvato. Gli endpoint con operazioni non sicure non vengono scritti senza manifesto ed approvazione. Per sapere cosa è stato davvero raggiunto usa:

```powershell
uv run achillesapi coverage-report .\swagger.yaml .\reports\assessment.json `
  --output .\reports\coverage.json
```

## 5. Verifica delle policy di autorizzazione

Crea un file `access-rules.yaml`:

```yaml
rules:
  - operation: GET /customers/{customerId}
    identity: tester
    expected: deny
  - operation: GET /public/catalog
    identity: tester
    expected: allow
```

Poi esegui:

```powershell
uv run achillesapi verify-access-policy .\reports\assessment.json .\access-rules.yaml `
  --output .\reports\access-verification.json
```

Questo controllo non invia traffico. Restituisce `policy_mismatch_requires_review`, `consistent_with_policy_not_proven` o `inconclusive_*`, a seconda delle osservazioni disponibili. Una singola 200 non dimostra che la risorsa appartenga a un utente diverso: verifica body e negative control in un ambiente autorizzato.

## 6. Autonomous Agent 2.0 e Ollama

### 6.1 Prima revisione offline

```powershell
uv run achillesapi agent-loop-v2 .\swagger.yaml .\reports\assessment.json `
  --budget 5 `
  --output .\reports\agent-plan.json
```

### 6.2 Esecuzione di follow-up GET autorizzati

```powershell
uv run achillesapi agent-loop-v2 .\swagger.yaml .\reports\assessment.json `
  --base-url https://staging.example.com `
  --allow-host staging.example.com `
  --auth-config .\auth.yaml `
  --profile tester `
  --budget 5 --rate 1 --execute `
  --output .\reports\agent-v2.json
```

L'agente ricostruisce gli URL dalla specifica, non dal testo AI. Verifica in massimo due cicli gli errori 5xx o altri segnali supportati; se non sono più riproducibili si ferma. Il budget è globale, l'AI non lo può aumentare.

### 6.3 Utilizzo facoltativo del modello locale

Avvia Ollama in locale (se necessario `ollama serve`) e verifica il modello disponibile con `ollama list`. Per una prima installazione scegli un modello coerente con l'hardware, per esempio `ollama pull llama3.2:3b` e usa `--model llama3.2:3b`. Non viene contattato nessun provider cloud.

```powershell
uv run achillesapi agent-loop-v2 .\swagger.yaml .\reports\assessment.json `
  --budget 3 --ai --model llama3.2:3b `
  --output .\reports\agent-with-local-ai.json
```

La parte `--ai` invia a Ollama locale soltanto metadati sanitizzati dei controlli. LLM non autorizza chiamate al target né convalida vulnerabilità.

## 7. Advanced vulnerability review e reporting

```powershell
uv run achillesapi advanced-vuln-assess .\swagger.yaml `
  --assessment .\reports\assessment.json `
  --output .\reports\vulnerability-review.json

uv run achillesapi report .\reports\assessment.json `
  --output-dir .\reports\professional `
  --format html --format pdf --format md --format json
```

Per un report completo di finding verificati serve revisione manuale e prova riproducibile dell'impatto: queste esportazioni trattano gli indicatori in modo conservativo.

## 8. Catalogo dei principali comandi

- **Entrata principale**: `auto-assess`.
- **Discovery**: `analyze-openapi`, `generate-tests`, `map-api`, `intelligent-plan`, `workflow-map`, `workflow-graph`, `security-inventory`, `journey-discover`, `workflow-discover`.
- **Autenticazione e sessioni**: `auth-profiles`, `auth-draft`, `jwt-inspect`.
- **Controlli GET**: `http-get`, `bola-check`, `bola-sweep`, `bfla-sweep`, `role-matrix`, `sqli-check`, `fuzz-parameter`, `advanced-vuln-assess` (alcuni legacy rimangono loopback-only).
- **Workflow e stato**: `workflow-assess`, `multi-resource-assess`, `journey-assess`, `mass-assignment-check`.
- **Analisi evidenze**: `analyze-evidence`, `vulnerability-triage`, `verify-access-policy`, `differential-review`, `coverage-report`, `benchmark-evaluate`.
- **AI**: `ai-analyze`, `ai-correlate`, `ai-prioritize`, `adaptive-review`, `agent-review`, `autonomous-agent`, `agent-loop-v2`, `next-actions`, `scan`.
- **Report**: `report`.
- **Dashboard**: `dashboard`.
- **Ambiente**: `version`, `scope-audit`.

Visualizza le opzioni esatte di ogni comando con `uv run achillesapi <comando> --help`.

## 9. Troubleshooting

| Errore | Cosa verificare |
|---|---|
| `No module named fastapi` o `python-multipart` | Esegui `uv sync --extra dashboard --extra dev` |
| Dashboard non raggiungibile | Apri `http://127.0.0.1:8766`; verifica porta libera e console attiva |
| Upload OpenAPI non valido | Solo OpenAPI 3.x YAML/JSON; riferimenti `$ref` locali e file sotto 2 MB |
| `ScopeError` / blocked | `--base-url` e `--allow-host` devono corrispondere; nessun redirect fuori scope |
| `ACHILLES_* required` | Imposta la variabile d'ambiente corretta prima di avviare CLI/dashboard |
| Report non trovato | Verifica `dashboard-data/reports` e lo stato del job |
| PDF non disponibile | Esegui `uv sync --extra pdf` |
| `Ollama returned error` | `ollama serve`, `ollama list` e nome del modello scelto |
| `manual_cleanup_required` | NON ripetere le scritture alla cieca; verifica la risorsa temporanea e segui il rollback approvato |
| Nessun finding | Non significa API sicura; controlla `coverage-report` e i test bloccati |

## 10. Limiti dichiarati / prossima roadmap

- Mancano supporto OAuth2/OIDC completo e SSO interattivo generico.
- Mancano payload di exploitation generalizzati e controlli OAST affidabili per SQLi, NoSQLi, SSRF, SSTI e command injection. Il motore attuale non deve essere descritto come un exploit framework generale.
- Lo State Engine richiede manifesti di fixture. Non inventa richieste con effetti permanenti; PUT che sostituisce il marker può interrompere e richiedere cleanup manuale.
- La dashboard non consente di lanciare POST/PATCH/DELETE. Non sostituisce la CLI e il processo di autorizzazione alle scritture.
- L'agente v2 può eseguire solo follow-up GET previsti e ricostruiti da OpenAPI. Ollama è consultivo.
- Il client effettua un controllo hostname esplicito e può verificare CIDR su alcune funzioni, ma l'enforcement dell'IP di connessione resta da rafforzare; per ambienti enterprise usa anche firewall/proxy di egress che impongano lo scope.
- I risultati devono essere validati con benchmark indipendenti e controlli di falsi positivi prima di usare AchillesAPI in autonomia senza supervisione.

La dashboard e il laboratorio sono creati esclusivamente come parte locale del pacchetto; non richiedono login cloud né raccolta remota di telemetria.
