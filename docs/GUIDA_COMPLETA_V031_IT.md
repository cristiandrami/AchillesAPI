# AchillesAPI v0.31 — Guida completa (Windows PowerShell e Kali)

> **Destinazione:** assessment **autorizzati** di API proprie o di clienti che hanno esplicitamente incluso gli host, gli endpoint e i test nello scope. La v0.31 è una release di sviluppo: non promette un penetration test esaustivo né una classificazione automatica di tutte le vulnerabilità.

## 1. Qual è il comando principale?

`auto-assess` è il punto d'ingresso. Dato un OpenAPI 3.x valido, prepara un piano; con `--execute` può effettuare GET autorizzate, controlli non distruttivi su autenticazione/header/CORS/validazione e, **solo** con workflow approvato e `--approve-writes`, operazioni di scrittura su fixture disposable. Rilevamenti e anomalie sono candidati da verificare, non vulnerabilità confermate.

## 2. Installazione Windows

1. Installare Python 3.12 tramite `uv python install 3.12` (installare `uv` se mancante).
2. Estrarre lo ZIP; entrare nella cartella `achillesapi`.
3. In PowerShell:

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dev --extra pdf
uv run achillesapi version
uv run pytest -q
uv run achillesapi --help
```

Usare `uv run achillesapi <COMANDO> --help` per la sintassi esatta di ciascuna funzione. `--extra pdf` abilita ReportLab; ometterlo se non servono PDF.

## 3. Installazione Kali Linux

```bash
cd achillesapi
uv python install 3.12
uv sync --python 3.12 --extra dev --extra pdf
uv run achillesapi version
uv run pytest -q
```

Se `uv` non è disponibile, installarlo secondo la procedura ufficiale del progetto Astral. È possibile usare un venv Python 3.11+ con `pip install -e '.[dev,pdf]'`.

## 4. Usare una API aziendale

### 4.1 Materiale necessario

- Swagger/OpenAPI 3.x esportato localmente (`swagger.yaml`, `openapi.json`).
- Base URL del servizio nello scope (`https://staging.example.com/api`).
- Allowlists esplicite e autorizzazione scritta all'assessment.
- Facoltativi: `auth.yaml` con profili, test ID `--path-value`, `context.yaml` con aspettative di accesso, workflow YAML disposable.
- Credenziali in variabili d'ambiente, mai hardcoded nei file condivisi.

### 4.2 Controlla scope prima di avviare

```powershell
uv run achillesapi scope-audit "https://staging.example.com/api" `
  --allow-host staging.example.com `
  --output .\reports\scope.json
```

È un controllo **offline** e non valida DNS/reticolo IP. Il controllo CIDR `--allow-cidr 10.10.0.0/16` è utile per IP letterali, ma per hostnames la vera verifica deve essere al momento dell'esecuzione. Il client HTTP supporta CIDR opzionali tramite API Python `SafeHTTPClient(allowed_cidrs={"10.10.0.0/16"}, ...)`. Tale preflight DNS **non impedisce da solo il DNS rebinding**: usare anche firewall/proxy con egress limitato.

### 4.3 Piano offline

```powershell
uv run achillesapi auto-assess .\swagger.yaml `
  --base-url https://staging.example.com/api `
  --output .\reports\plan.json
```

Nessuna richiesta HTTP al target. Controllare `operations`, blocchi per parametri mancanti, controlli proposti e operations marcate `manual_only_non_get`.

### 4.4 Assessment GET attivo

```powershell
uv run achillesapi auto-assess .\swagger.yaml `
  --base-url https://staging.example.com/api `
  --allow-host staging.example.com `
  --auth-config .\auth.yaml `
  --profile tester --profile admin `
  --max-requests 80 --rate 1 --timeout 8 `
  --agent-budget 3 `
  --execute `
  --output .\reports\assessment.json
```

Le opzioni `--auth-config` e `--profile` si usano solo quando disponibili profili validi. Per HTTP locale con credenziali bisogna aggiungere `--allow-insecure-http`; **non** farlo per target aziendali.

`--agent-budget` abilita soltanto ripetizioni controllate di GET già presenti nel piano. Non autorizza endpoint extra e non esegue POST/PATCH/DELETE autonomamente.

### 4.5 Come aumentare la copertura

```powershell
uv run achillesapi coverage-report .\swagger.yaml .\reports\assessment.json `
  --output .\reports\coverage.json

uv run achillesapi next-actions .\swagger.yaml .\reports\assessment.json `
  --budget 10 --output .\reports\next-actions.json

uv run achillesapi differential-review .\reports\assessment.json `
  --output .\reports\review.json
```

`coverage-report` considera **osservato** un endpoint solo se esiste un record HTTP associato a quell'operazione. Non misura la percentuale di vulnerabilità rilevate. `next-actions` non invia traffico: suggerisce GET ancora testabili, dati mancanti o revisioni di workflow. `differential-review` mostra variazioni di classi HTTP che richiedono controllo umano.

### 4.6 Report professionali

```powershell
uv run achillesapi report .\reports\assessment.json `
  --output-dir .\reports\professional `
  --format json --format html --format md --format pdf
```

Prima di consegnare un report al cliente, controllare manualmente finding, severità, confidenza, evidenze, impatto e remediation. I report eliminano i dettagli più sensibili, ma possono includere nomi di endpoint e identificativi: applicare le policy di data handling aziendali.

## 5. Workflow e operazioni di scrittura

### 5.1 Scoprire relazioni

```powershell
uv run achillesapi workflow-map .\swagger.yaml --output .\reports\dependencies.json
uv run achillesapi workflow-discover .\swagger.yaml --draft-config .\workflows.yaml
```

Sono ipotesi ricavate dagli schemi; non sono autorizzazioni a creare dati.

### 5.2 Validare una sequenza multi-risorsa

Creare un YAML ispirandosi a `examples/v031/multi-resource-dag.example.yaml`, sostituendo ogni metodo/path con una operazione **effettivamente presente nel proprio Swagger**.

```powershell
uv run achillesapi workflow-graph .\swagger.yaml `
  --config .\multi-resource-dag.yaml `
  --output .\reports\workflow-graph.json
```

Verifica: metodo dichiarato, dipendenze esistenti, assenza di cicli, cleanup dichiarato per ogni POST di creazione. **Non genera payload e non esegue richieste.**

### 5.3 Workflow disposable già supportato dalla v0.27

Dopo aver compilato un `workflows.yaml` idoneo, usare il comando esistente:

```powershell
uv run achillesapi workflow-assess .\swagger.yaml `
  --workflow-config .\workflows.yaml `
  --base-url https://staging.example.com/api `
  --allow-host staging.example.com `
  --auth-config .\auth.yaml `
  --max-requests 30 --rate 1 `
  --execute --approve-writes `
  --output .\reports\workflow-result.json
```

Il workflow legacy è progettato per **singole risorse temporanee** con ID e marcatore verificabili; il cleanup può fallire e richiedere intervento manuale. Non collegare la nuova mappa DAG alle scritture come se fosse un orchestratore automatico multi-risorsa: non lo è.

## 6. AI locale — Ollama

1. Installare Ollama sul proprio computer e avviare il servizio.
2. Scaricare un modello locale compatibile (la dimensione del modello deve essere compatibile con RAM/VRAM).
3. Se il pacchetto contiene `deployment/Modelfile`, da **cartella principale del progetto** eseguire:

```powershell
ollama pull llama3.2:3b
ollama create achilles-local -f .\deployment\Modelfile
ollama list
```

4. Analisi offline con AI:

```powershell
uv run achillesapi ai-analyze .\swagger.yaml --model achilles-local `
  --output .\reports\ai.json
uv run achillesapi ai-prioritize .\swagger.yaml .\reports\assessment.json `
  --ai --model achilles-local --budget 3 `
  --output .\reports\ai-priorities.json
```

L'AI non deve scegliere autonomamente URL, credenziali, metodi o payload eseguibili. Eventuali priorità LLM sono consultive. Controllare che il server Ollama resti **locale** e non usi servizi cloud.

## 7. Benchmark indipendenti

I due file `examples/v031/ground-truth.example.json` e `verified-results.example.json` contengono identificativi dimostrativi, **non risultati di un pentest**.

```powershell
uv run achillesapi benchmark-evaluate `
  .\examples\v031\ground-truth.example.json `
  .\examples\v031\verified-results.example.json `
  --output .\reports\benchmark.json
```

Il risultato calcola TP, FP, FN, precision, recall da ID indipendenti e verificati. Non trasforma le osservazioni dello scanner in vulnerabilità provate.

## 8. Laboratori inclusi

Sono mantenuti i laboratori dei rilasci precedenti, utili per regressioni ma **non utilizzati dal motore di produzione**.

| Laboratorio | Avvio | URL Swagger |
|---|---|---|
| `labs/independent_api` | `powershell -ExecutionPolicy Bypass -File .\labs\independent_api\start.ps1` | `http://127.0.0.1:8765/docs` |
| `labs/v020_service` | `powershell -ExecutionPolicy Bypass -File .\labs\v020_service\start.ps1` | `http://127.0.0.1:8780/docs` |

Per esempi completi di token, GET e workflow locale leggere `docs/GUIDA_COMPLETA_V027_IT.md`. Le API di laboratorio devono restare in ascolto su `127.0.0.1`, non su interfacce pubbliche.

## 9. Catalogo sintetico comandi

- **Principali:** `auto-assess`, `scan`, `assess`, `analyze-openapi`, `generate-tests`, `intelligent-plan`.
- **Sicurezza:** `bola-check`, `bola-sweep`, `bfla-sweep`, `role-matrix`, `sqli-check`, `fuzz-parameter`, `mass-assignment-check`, `jwt-inspect`, `security-inventory`, `vulnerability-triage`.
- **Autenticazione:** `auth-profiles`, `auth-draft`, `http-get`.
- **Relazioni e workflow:** `map-api`, `workflow-discover`, `workflow-map`, `workflow-graph`, `workflow-assess`, `journey-discover`, `journey-assess`.
- **Evidenze:** `analyze-evidence`, `adaptive-review`, `agent-review`, `ai-prioritize`, `ai-analyze`, `ai-correlate`, `differential-review`.
- **Output e qualità:** `report`, `scope-audit`, `coverage-report`, `next-actions`, `benchmark-evaluate`, `version`.

Per i dettagli esatti (comandi legacy inclusi), usare `uv run achillesapi --help` e `uv run achillesapi NOME --help`; la guida storica dei 33 comandi v0.27 è ancora inclusa.

## 10. Troubleshooting

- **Blocked: host outside allowlist:** la parte hostname di `--base-url` deve essere identica a uno dei `--allow-host`; non sono ammessi wildcard implicitamente.
- **401/403:** verificare il profilo, gli schemi di autenticazione OpenAPI, la scadenza dei token e i permessi del test account.
- **Missing required path parameter:** passare `--path-value ID=valore` o un contesto approvato; il tool non inventa identificativi validi.
- **Test POST/PATCH/DELETE non eseguiti:** senza workflow approvato e `--approve-writes` è normale: non sono abilitati automaticamente.
- **PDF non disponibile:** installare `uv sync --extra pdf`.
- **Ollama non raggiungibile:** avviare il servizio e controllare `ollama list`; non inviare mai credenziali reali a servizi cloud esterni.
- **Cleanup manuale:** ispezionare il report dei workflow; non ripetere indiscriminatamente le scritture.
- **Windows PyYAML su Python troppo nuovo:** utilizzare Python 3.12 tramite `uv sync --python 3.12`.

## 11. Limiti residui

La v0.31 ha più controlli operativi, ma **non** implementa interamente: agente AI autonomo generalista, orchestrazione automatica di scritture multi-risorsa, motori generali approfonditi di injection e SSRF, DNS pinning crittograficamente affidabile, benchmark su sistemi reali indipendenti, né gestione di tutte le forme di SSO. Non considerare il numero di test unitari una misura del detection rate.
