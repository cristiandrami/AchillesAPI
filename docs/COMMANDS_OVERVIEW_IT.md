# Tutti i comandi di AchillesAPI v0.12.0

Comandi PowerShell da eseguire nella cartella che contiene `pyproject.toml`.
Per qualsiasi comando: `uv run achillesapi NOME --help`.

| Comando | Cosa fa | Contatta l'API? | Uso consigliato |
|---|---|---|---|
| `version` | Mostra la versione | No | Installazione |
| `analyze-openapi` | Elenca endpoint, metodi, parametri e security schemes | No | Sempre all'inizio |
| `generate-tests` | Pianifica test BOLA/BFLA/BOPLA/mass assignment/schema | No | Valutare copertura |
| `map-api` | Genera grafo di endpoint e risorse | No | Analisi delle dipendenze |
| `assess` | Produzione di ipotesi passive | No | Baseline offline |
| `scan` | Assessment passivo; opzionale Ollama `--ai` | Solo Ollama se `--ai` | Interpretazione metadati |
| `auto-assess` | Test GET intelligenti; workflow di scrittura **solo se configurato** | Con `--execute` | **Comando professionale principale** |
| `workflow-discover` | Deduce possibili catene POST→GET→PATCH/DELETE; genera draft | No | Quando servono test mutativi |
| `workflow-assess` | Crea fixture test, verifica BOLA/BFLA/BOPLA/mass assignment, tenta cleanup | Con `--execute --approve-writes` | Test su risorse disposable |
| `auth-profiles` | Valida e mostra profili senza mostrare segreti | No | Configurazione credenziali |
| `http-get` | Una GET con allowlist, opzionalmente autenticata | Con `--execute` | Diagnostica di rete |
| `bola-check` | Confronta owner/non-owner su un URL locale | Con `--execute`; loopback | Legacy e regressione |
| `bola-sweep` | Confronta due identità su più GET | Sì; loopback | Legacy e regressione |
| `bfla-sweep` | Confronta accesso a funzioni GET di due identità | Sì; loopback | Legacy e regressione |
| `role-matrix` | Matrice GET su più account | Sì; loopback | Legacy e regressione |
| `mass-assignment-check` | PATCH JSON esplicita su URL locale | Con `--execute` | Legacy; può cambiare dati |
| `sqli-check` | Canary SQLi a basso impatto (non conferma SQLi) | Sì; loopback | Legacy |
| `fuzz-parameter` | Prova nove valori innocui in query | Sì; loopback | Legacy |
| `jwt-inspect` | Decodifica JWT senza verificarne la firma | No | Ispezione token |
| `analyze-evidence` | Analizza un JSON di evidenze già raccolte | No | Post-processing |
| `ai-analyze` | Spiega Swagger con Ollama locale | Solo Ollama | Analisi consultiva |
| `ai-correlate` | Correlazione evidenze + Swagger via Ollama | Solo Ollama | Post-processing |

## I cinque comandi principali per lavorare

### 1. Scoprire l'API

```powershell
uv run achillesapi analyze-openapi .\swagger.yaml
```

### 2. Generare automaticamente i controlli

```powershell
uv run achillesapi generate-tests .\swagger.yaml --output .\reports\test-plan.json
```

### 3. Eseguire i controlli di lettura con scope autorizzato

```powershell
uv run achillesapi auto-assess .\swagger.yaml `
  --base-url https://staging.example.com `
  --auth-config .\auth-profiles.yaml `
  --allow-host staging.example.com --max-requests 50 `
  --execute --output .\reports\assessment.json
```

### 4. Scoprire workflow applicabili e creare il file da personalizzare

```powershell
uv run achillesapi workflow-discover .\swagger.yaml `
  --draft-config .\workflows.yaml `
  --output .\reports\workflow-discovery.json
```

### 5. Eseguire prove su nuove risorse disposable (solo se autorizzato)

```powershell
uv run achillesapi auto-assess .\swagger.yaml `
  --base-url https://staging.example.com `
  --auth-config .\auth-profiles.yaml `
  --workflow-config .\workflows.yaml `
  --allow-host staging.example.com --max-requests 80 `
  --execute --approve-writes `
  --output .\reports\complete-assessment.json
```

Prima di utilizzare il punto 5, apri e personalizza `workflows.yaml`:
nessun campo `REPLACE_ME` deve rimanere. Leggi **WORKFLOWS_PROFESSIONAL_IT.md**.

## Opzioni comuni

- `--output`: file JSON di destinazione.
- `--base-url`: endpoint base del server target, non un percorso a caso.
- `--allow-host`: hostname esatto autorizzato, obbligatorio per le esecuzioni.
- `--auth-config`: YAML profili; segreti letti dalle variabili d'ambiente.
- `--profile`: seleziona uno o più account nel comando principale.
- `--context`: path/query value e policy di accesso per le GET autonome.
- `--workflow-config`: lifecycle disposable approvato; non autorizza scritture da solo.
- `--execute`: autorizza il contatto con il target.
- `--approve-writes`: ulteriore approvazione per POST/PATCH/DELETE del workflow.
- `--max-requests`: budget totale di richieste.
- `--rate`: richieste/secondo, limitate.
- `--timeout`: tempo massimo per richiesta.
- `--allow-insecure-http`: consenso esplicito a trasmettere credenziali via HTTP;
  da evitare su target non isolati.
- `--ai`: interpretazione consultiva locale, opzionale.

## Cosa fa davvero il motore professionale

`auto-assess` esamina OpenAPI, sceglie controlli GET per ogni endpoint idoneo,
verifica eventuali policy e produce osservazioni. Se è presente anche un file
di workflow approvato, può creare e testare una **nuova risorsa temporanea**,
confrontarne accessi e campi, poi eliminarla. Non è un sistema di exploit
universale né sostituisce la revisione manuale delle regole di business.

I comandi vecchi limitati a localhost restano per retrocompatibilità; non
sono la strada consigliata per usare AchillesAPI sul lavoro.
