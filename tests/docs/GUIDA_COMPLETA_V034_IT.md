# AchillesAPI v0.34.0 — Guida operativa completa

## 0. Leggere prima di iniziare

AchillesAPI è un framework di **assessment API autorizzato**, non un agente in grado di sfruttare arbitrariamente qualsiasi API. La v0.34 introduce tre percorsi:

- **Multi-resource:** esegue POST/GET/DELETE di risorse di prova espressamente approvate, riutilizzando gli ID catturati tra endpoint e verificando il cleanup. Non esegue automaticamente PATCH/PUT su risorse arbitrarie; per quelle resta `workflow-assess` con configurazione disposable.
- **Advanced vulnerability:** riutilizza il motore GET non distruttivo (autenticazione, CORS, validation, exposure, error review) e classifica le evidenze senza considerare una risposta 2xx/5xx una conferma sufficiente. L'injection approfondita, SSRF/OAST e i test di carico non sono inclusi nel nuovo motore.
- **Agent:** può selezionare e ripetere GET già previste dallo Swagger dopo un assessment. Il modello Ollama è esclusivamente consultivo, non decide URL, header, permessi o scritture.

**Non usare account reali, oggetti aziendali o ambienti di produzione per i workflow di scrittura senza fixture e procedure di ripristino approvate dal responsabile dell'engagement.** Il tool non garantisce il rollback universale.

## 1. Requisiti

- Python 3.12 consigliato (evitare Python 3.15 se alcune librerie non dispongono di wheel).
- `uv` installato e disponibile su `PATH`.
- Windows PowerShell o Kali/Linux.
- Ollama facoltativo, solo locale su `http://127.0.0.1:11434`.

Installazione PowerShell (dalla directory `achillesapi` estratta):

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dev --extra pdf
uv run --python 3.12 achillesapi version
uv run --python 3.12 pytest -q
uv run --python 3.12 achillesapi --help
```

Su Kali:

```bash
uv python install 3.12
uv sync --python 3.12 --extra dev --extra pdf
uv run --python 3.12 achillesapi version
uv run --python 3.12 pytest -q
```

## 2. Avviare il laboratorio multi-risorsa

Il laboratorio è **indipendente dal core**; espone collection e document e una vulnerabilità BOLA intenzionale. Esegue solo su loopback.

PowerShell, finestra 1:

```powershell
powershell -ExecutionPolicy Bypass -File .\labs\multi_resource_demo\start.ps1
```

Kali, terminale 1:

```bash
bash labs/multi_resource_demo/start.sh
```

Documentazione FastAPI: `http://127.0.0.1:8790/docs`. Health check: `http://127.0.0.1:8790/health`. Lo Swagger su disco è `labs/multi_resource_demo/openapi.json`.

PowerShell, finestra 2:

```powershell
$env:ACHILLES_DEMO_OWNER = 'lab-alice'
$env:ACHILLES_DEMO_OTHER = 'lab-bob'
```

Kali:

```bash
export ACHILLES_DEMO_OWNER=lab-alice
export ACHILLES_DEMO_OTHER=lab-bob
```

Le credenziali sono fittizie. Non copiarle in configurazioni aziendali.

## 3. Primo avvio: pianificare senza traffico

```powershell
uv run --python 3.12 achillesapi multi-resource-assess `
  .\labs\multi_resource_demo\openapi.json `
  --config .\labs\multi_resource_demo\resources.yaml `
  --auth-config .\labs\multi_resource_demo\auth.yaml `
  --base-url http://127.0.0.1:8790 `
  --output .\reports\multi-plan.json
```

Non viene inviato **nessun** pacchetto al target (neppure per autenticarsi). Il piano contiene `request_budget_required`, ordine delle risorse, dipendenze, operazioni e controlli. Non include i valori dei body o credenziali.

## 4. Esecuzione reale del workflow disposable

```powershell
uv run --python 3.12 achillesapi multi-resource-assess `
  .\labs\multi_resource_demo\openapi.json `
  --config .\labs\multi_resource_demo\resources.yaml `
  --auth-config .\labs\multi_resource_demo\auth.yaml `
  --base-url http://127.0.0.1:8790 `
  --allow-host 127.0.0.1 `
  --allow-insecure-http `
  --max-requests 20 `
  --rate 2 `
  --execute --approve-writes `
  --output .\reports\multi-live.json
```

*Perché i flag*: `--allow-host` delimita lo scope, `--execute` permette la rete, `--approve-writes` conferma la creazione e cancellazione di fixture temporanee. `--allow-insecure-http` è solo per il laboratorio locale: su sistemi reali usa HTTPS. `--max-requests` riserva richieste per il cleanup. `--rate` limita il ritmo.

Risultato atteso: vengono create collection e document; gli ID sono catturati e usati in seguito; viene rilevato un accesso non conforme alla policy `expected: deny`; le risorse sono eliminate nell'ordine inverso e l'assenza è verificata. La vulnerabilità è volutamente introdotta nel laboratorio.

Nel JSON controlla sempre:

- `requests_sent`
- `resources_results[].created`, `.verified` e `.cleanup_verified`
- `manual_cleanup_required`
- `findings[].confidence`, categorie e operazioni

Se `manual_cleanup_required: true`, non ripetere ciecamente la scansione: controlla lo stato dell'applicazione e procedi secondo il piano di ripristino dell'engagement. I raw ID non vengono inseriti nel report per ridurre il rischio di leakage.

## 5. Capire la configurazione multi-risorsa

Il file `labs/multi_resource_demo/resources.yaml` è un esempio, **non** una configurazione che il framework presume valida per ogni API.

Per ciascuna risorsa servono:

| Campo YAML | Significato |
|---|---|
| `name` | Nome locale della fixture, per esempio `collection` |
| `create` | Operazione POST dichiarata nello Swagger |
| `read` | Operazione GET della risorsa appena creata |
| `delete` | DELETE dello stesso identico path della GET |
| `identity` | Profilo autenticazione con cui creare/leggere/eliminare |
| `body` | JSON di prova **approvato** dall'operatore |
| `marker_field` | Campo stringa scrivibile in cui il framework mette un marker casuale |
| `id_pointer` | JSON Pointer per l'ID restituito dalla POST, ad esempio `/data/id` |
| `read_id_pointer` | Puntatore all'ID restituito dalla GET |
| `marker_pointer` | Puntatore al campo marker restituito dalla GET |
| `path_values` | Valori path espliciti; si può inserire `${collection.id}` |
| `access` | Controlli GET con seconda identità e policy `allow` o `deny` |

Esempio: una POST su `/collections` restituisce `{"id":"col-123"}`; l'ID resta in memoria. La POST su `/collections/{collection_ref}/documents` inserisce l'ID nel path con `${collection.id}`. Per la GET del documento, `${document.id}` usa l'ID restituito dalla seconda POST.

**Prerequisiti di sicurezza**: ogni POST deve ritornare `201`, avere un campo marker persistente e una GET di verifica; nessuna DELETE viene eseguita se non corrispondono ID **e** marker. `202 Accepted`, `200 OK` o timeout in fase di creazione sono ambigui e richiedono controllo manuale. Nessun valore letto da una risposta può cambiare l'host o inventare un metodo HTTP.

**Limiti**: massimo 10 risorse per manifesto, massimo 6 access check per risorsa, body fino a 8 KiB e nessun rollback transazionale universale. I percorsi devono coincidere con operazioni OpenAPI esistenti.

## 6. Esecuzione integrata con auto-assess

`auto-assess` mantiene lo scanner GET, gli agent follow-up e i vecchi workflow. La v0.34 aggiunge `--multi-resource-config` per riservare un budget al motore multi-risorsa:

```powershell
uv run --python 3.12 achillesapi auto-assess `
  .\labs\multi_resource_demo\openapi.json `
  --base-url http://127.0.0.1:8790 `
  --auth-config .\labs\multi_resource_demo\auth.yaml `
  --profile owner --profile other `
  --multi-resource-config .\labs\multi_resource_demo\resources.yaml `
  --allow-host 127.0.0.1 `
  --allow-insecure-http `
  --max-requests 100 --rate 2 `
  --agent-budget 2 `
  --execute --approve-writes `
  --output .\reports\assessment-completo.json
```

Il comando non forza la creazione di ID su endpoint non configurati. Se vuoi includere solo letture, **ometti** `--multi-resource-config` e `--approve-writes`.

## 7. Advanced Vulnerability Engine

Modalità offline:

```powershell
uv run --python 3.12 achillesapi advanced-vuln-assess .\swagger.yaml `
  --output .\reports\advanced-plan.json
```

Triage di un report esistente:

```powershell
uv run --python 3.12 achillesapi advanced-vuln-assess .\swagger.yaml `
  --assessment .\reports\assessment.json `
  --output .\reports\advanced-triage.json
```

Verifiche non distruttive su API aziendale autorizzata:

```powershell
uv run --python 3.12 achillesapi advanced-vuln-assess .\swagger.yaml `
  --base-url https://staging.example.com `
  --allow-host staging.example.com `
  --auth-config .\auth.yaml --profile tester `
  --max-requests 40 --rate 1 `
  --execute `
  --output .\reports\advanced-live.json
```

Il motore determina le opportunità dagli endpoint e riutilizza controlli GET su autenticazione, CORS, parametri, contratti JSON ed esposizione dati, quando applicabili. `evidence_review` contiene `unconfirmed_indicator` oppure `policy_supported_review`, **non finding arbitrariamente confermati**.

Per SQLi/NoSQLi/OS command injection/SSTI/SSRF/OAST e rate limiting ad alta intensità l'attuale motore produce solo classificazioni o prerequisiti. Non inventa risultati. Controlli legacy più limitati sono disponibili a parte per loopback.

## 8. Autonomous Agent e Ollama

L'agente seleziona un insieme limitato di GET di follow-up dalle osservazioni di un assessment precedente. Per esempio, un 503 ricevuto da una GET già consentita può essere ricontrollato per stabilire se è riproducibile.

Solo pianificazione, senza rete:

```powershell
uv run --python 3.12 achillesapi autonomous-agent .\swagger.yaml `
  .\reports\assessment.json --budget 3 `
  --output .\reports\agent-plan.json
```

Follow-up eseguibili, solo sul target autorizzato:

```powershell
uv run --python 3.12 achillesapi autonomous-agent .\swagger.yaml `
  .\reports\assessment.json --budget 3 `
  --base-url https://staging.example.com `
  --allow-host staging.example.com `
  --auth-config .\auth.yaml --profile tester `
  --execute --output .\reports\agent-followups.json
```

L'agente ricostruisce il percorso **dal file Swagger**, non dai link presenti nei dati salvati. Per i percorsi con `{id}` devi fornire un `--path-value id=VALORE_APPROVATO` oppure usare una journey approvata. `--budget` limita le GET ripetute. Usa il report solo con lo stesso ambiente di staging da cui provengono le osservazioni.

AI opzionale, *solo consultiva*:

```powershell
ollama serve
ollama pull llama3.2:3b
ollama create achilles-local -f .\deployment\Modelfile
```

Verifica l'effettivo file `Modelfile` presente nel tuo pacchetto prima di usare l'ultimo comando; in alternativa, passa direttamente `--model llama3.2:3b`. Esempio:

```powershell
uv run --python 3.12 achillesapi autonomous-agent .\swagger.yaml `
  .\reports\assessment.json --budget 3 `
  --ai --model llama3.2:3b `
  --output .\reports\agent-ai.json
```

Ollama rimane locale; la parte AI non può generare richieste di rete al target. Il modello deve essere installato e in esecuzione. Non abbiamo verificato l'inferenza Ollama sulla tua macchina.

## 9. Esempio per una API aziendale

1. Ottieni per iscritto host, ambiente, account, operazioni consentite, limiti e procedure di ripristino.
2. Inizia con `auto-assess swagger.yaml --output plan.json` per il piano offline.
3. Configura `auth.yaml` con nomi di variabili d'ambiente, mai token in chiaro nel repository.
4. Avvia `auto-assess --execute` solo GET con `--allow-host` e limiti.
5. Usa `coverage-report` per identificare gli endpoint non coperti.
6. Per le scritture prepara manualmente `resources.yaml` con fixture create per il test, marker persistente e DELETE verificabile. Fai prima il dry-run.
7. Usa `advanced-vuln-assess` per il triage e `autonomous-agent` per follow-up selezionati.
8. Genera HTML/PDF, rivedi manualmente gli indicatori, assegna severità solo alle vulnerabilità confermate.

Comandi di chiusura:

```powershell
uv run --python 3.12 achillesapi coverage-report .\swagger.yaml .\reports\assessment.json `
  --output .\reports\coverage.json
uv run --python 3.12 achillesapi report .\reports\assessment.json `
  --output-dir .\reports\professional --format json --format html --format md --format pdf
```

## 10. Troubleshooting

- **`Unknown profile` / variabile d'ambiente mancante:** verifica il nome esatto in `auth.yaml` e imposta le variabili nella **stessa** finestra PowerShell che avvia AchillesAPI.
- **`No such command`**: controlla `uv run --python 3.12 achillesapi version`, la cartella estratta e che sia davvero `0.34.0`.
- **`Missing path value`**: indica un valore approvato con `--path-value` oppure predisponi una journey.
- **`Created ID missing`**: la POST non ritorna il JSON Pointer dichiarato; correggi `/id` o `/data/id`, non tentare cancellazioni casuali.
- **`cleanup_suspended_marker_mismatch`**: non fare altri tentativi di DELETE automatici. Controlla la risorsa nel contesto autorizzato.
- **`404` durante cleanup:** verifica il percorso DELETE/GET e le regole di ownership. Non assumere che ogni 404 significhi rollback riuscito.
- **`request budget too small`**: aumenta `--max-requests` per includere le GET di conferma e le DELETE; non disattivare il controllo.
- **`--allow-insecure-http`**: riservalo a `127.0.0.1`. HTTPS su staging e produzione.
- **Ollama non disponibile:** usa l'assessment deterministico senza `--ai`, quindi avvia/installalo separatamente.
- **`uv` e PyYAML su Python recentissimo:** installa 3.12 e usa `uv sync --python 3.12`.

## 11. Limiti e priorità dopo la v0.34

**Già operativo**: multi-risorsa POST/GET/DELETE con ID in memoria e controllo di appartenenza via marker; confronto accessi; budget, scope, limiti di rete; GET dinamiche e differenziali; triage; report; follow-up deterministici con AI consultiva.

**Ancora incompleto**: creazione autonoma e sicura di fixture sconosciute, workflow multi-risorsa con PATCH/PUT arbitrari e rollback transazionale, OIDC interattivo, exploit-aware SQLi/NoSQLi/SSRF/SSTI/command injection, rate-limit testing approfondito, agente AI pienamente decisionale e benchmark indipendenti su sistemi aziendali.

Non interpretare il numero di unit test come detection rate: i controlli provati dal laboratorio non certificano l'efficacia su API ignote.
