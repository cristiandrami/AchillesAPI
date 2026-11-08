# AchillesAPI v0.38 — Guida al Control Center e al laboratorio

## 1. Che cosa trovi nel pacchetto

La v0.38 mantiene il codice e i comandi CLI v0.37 e aggiunge:

- **Control Center Web**: pulsante *Avvia tutto*, stato laboratorio/Ollama, import Swagger, import file di autenticazione, upload manifest, catalogo con 30 azioni predefinite, job asincroni, consultazione risultati, triage, export e download.
- **Control Center Training API**: FastAPI locale, indipendente dal framework, 15 operazioni con progetti e ticket annidati, casi BOLA/BFLA volutamente vulnerabili e alternative protette.
- **Ollama manager**: avvio e arresto solo di processi lanciati dalla dashboard, stato dei modelli, installazione esplicita del modello `llama3.2:3b` e creazione di `achilles-local` con il Modelfile incluso.
- **Runner a comandi consentiti**: nessun input da browser è trattato come comando shell; i job utilizzano la CLI effettiva di AchillesAPI.

La dashboard **non rende autonomi** i controlli che nella CLI sono ancora parziali. Gli exploit avanzati di SQLi/SSRF e il testing di business logic generale restano incompleti. I 30 strumenti esposti sono un sottoinsieme delle azioni CLI, selezionate per una gestione strutturata e controllata. Alcuni comandi legacy a singolo URL rimangono CLI-only.

## 2. Installazione su Windows 11 (PowerShell)

Prerequisiti: `uv` disponibile in PowerShell, Python 3.12, accesso alle porte 8766 e 8795 sul loopback. Ollama è opzionale.

```powershell
# Da una cartella con il pacchetto estratto
cd .\achillesapi
uv python install 3.12
uv sync --python 3.12 --extra dev --extra dashboard --extra pdf
uv run achillesapi version
uv run achillesapi dashboard --port 8766
```

Apri **http://127.0.0.1:8766** nel browser. Mantieni aperta questa finestra: esegue il server dashboard. Se il comando `uv` non è presente, installalo seguendo le istruzioni ufficiali di Astral prima di procedere.

### Avvio alternativo manuale del laboratorio

Puoi avviare l'API senza il browser in una seconda finestra:

```powershell
powershell -ExecutionPolicy Bypass -File .\labs\control_center_api\start.ps1
```

Swagger: **http://127.0.0.1:8795/docs**. OpenAPI JSON: **http://127.0.0.1:8795/openapi.json**.

Non lanciare il laboratorio due volte sulla porta 8795; se un processo occupa la porta, fermalo prima.

## 3. Installazione su Kali Linux

```bash
cd achillesapi
uv python install 3.12
uv sync --python 3.12 --extra dev --extra dashboard --extra pdf
uv run achillesapi dashboard --port 8766
```

Apri `http://127.0.0.1:8766`. In alternativa avvia soltanto il laboratorio con `bash labs/control_center_api/start.sh`.

**Non esporre** la dashboard o il laboratorio su `0.0.0.0`, LAN, VPN, reverse proxy o internet. La dashboard non implementa autenticazione utenti remota e si basa sul binding loopback, Host/Origin guard e token CSRF per le modifiche.

## 4. Procedura guidata nel browser: dalla prima accensione al report

1. **Avvia tutto il laboratorio**: premi il pulsante omonimo. Parte l'API su 8795, vengono caricati automaticamente Swagger, profili e manifesto di risorse temporanee. Se Ollama è installato, viene avviato in locale; non vengono scaricati modelli a tua insaputa.
2. **Verifica lo stato**: attendi che *Training API* mostri `ONLINE`. Apri `http://127.0.0.1:8795/docs` per consultare gli endpoint.
3. **Prima analisi senza traffico**: scegli `auto-assess` nel catalogo. Lascia *Active assessment* spento e premi *Piano offline*. In *Assessment activity* vedrai il job; apri *View report* quando è completo.
4. **Prova le GET**: mantieni `auto-assess`, attiva *Active assessment*, spunta *Confermo scope e autorizzazione*; imposta max requests e rate. Premi *Esegui strumento selezionato*. Il motore effettua soltanto controlli supportati e autorizzati.
5. **Workflow multi-risorsa**: scegli `multi-resource-assess`, assicurati che il manifest della demo sia caricato, seleziona *Active assessment*, spunta sia *Confermo scope e autorizzazione* sia *Approvo POST/PATCH/DELETE*. Imposta, ad esempio, 60 richieste massime e rate 2. Premi *Esegui*. In caso di successo il report indica risorse create, accessi verificati e cleanup.
6. **Leggi i risultati**: scegli il job in *Assessment activity*, fai *View report* e, se adatto, *Analyze findings*, *Export HTML* o *Export PDF*. Il pulsante freccia `↓` scarica il JSON/YAML originale del job.
7. **Approfondisci**: con un report aperto scegli `coverage-report`, `vulnerability-triage`, `differential-review`, `next-actions`, `agent-loop-v2` o `ai-prioritize`. Alcuni strumenti richiedono anche lo Swagger caricato, altri un report precedente.
8. **Ferma il laboratorio** con *Ferma API* al termine. Le risorse dell'API sono in memoria e si azzerano al riavvio del server.

### 4.1 Attenzione ai checkbox

Il flag *Active assessment* vale per l'interfaccia di esecuzione dei tool; il pulsante *Piano offline* lo ignora. L'avvio del laboratorio da solo **non autorizza** alcun penetration test. Scritture richiedono conferma separata e un manifesto specifico per risorse temporanee approvate.

### 4.2 Credenziali dimostrative

La dashboard passa automaticamente, solo ai job rivolti a `http://127.0.0.1:8795`, questi valori in variabili d'ambiente del processo figlio:

- `ACHILLES_LAB_OWNER=demo-owner`
- `ACHILLES_LAB_OTHER=demo-other`
- `ACHILLES_LAB_ADMIN=demo-admin`

I file YAML contengono solo **nomi delle variabili**, non credenziali. Non utilizzare questi profili su API aziendali e non copiarli nei report.

## 5. Usare una API reale autorizzata

1. Carica il file `.yaml` o `.json` in *OpenAPI specification*. Verifica nell'elenco gli endpoint effettivamente scoperti.
2. Inserisci `https://staging.example.com` come *Base URL* e `staging.example.com` come *Approved hostname*, adattando agli host autorizzati dall'incarico.
3. Carica un file di configurazione dei profili con i soli nomi delle variabili d'ambiente. Avvia il dashboard **dopo** aver definito queste variabili sul terminale in cui gira il server.
4. Seleziona i nomi dei profili in *Profile names*. Non digitare segreti nelle caselle della dashboard.
5. Esegui prima un piano offline; verifica i path dinamici, le esclusioni e i limiti dello scope.
6. Esegui le GET soltanto dopo l'approvazione esplicita. Gli strumenti per le scritture richiedono un manifesto predisposto con dati disposable e cleanup affidabile. **Non usare il manifest del laboratorio su un target reale.**
7. Genera report e controlla manualmente i finding: differenze di risposta e status HTTP non dimostrano da soli una vulnerabilità.

### Esempio di configurazione autenticazione

```yaml
profiles:
  - name: tester
    type: bearer
    token_env: API_TESTER_TOKEN
  - name: admin
    type: bearer
    token_env: API_ADMIN_TOKEN
```

PowerShell:

```powershell
$env:API_TESTER_TOKEN = 'TOKEN_DI_TEST'
$env:API_ADMIN_TOKEN = 'TOKEN_ADMIN_DI_TEST'
uv run achillesapi dashboard --port 8766
```

Non utilizzare credenziali di produzione quando puoi usare credenziali dedicate in staging. Il browser non mostra i valori dei token.

## 6. Catalogo degli strumenti disponibili nella dashboard

| Strumento | Funzione | Richiede |
|---|---|---|
| analyze-openapi | Descrizione endpoint | Swagger |
| generate-tests | Test candidati | Swagger |
| map-api | Grafo logico API | Swagger |
| assess | Ipotesi passive | Swagger |
| intelligent-plan | Payload e dipendenze candidate | Swagger |
| workflow-discover | Catene CRUD candidate | Swagger |
| workflow-map | Dipendenze producer/consumer | Swagger |
| journey-discover | Sequenze GET candidate | Swagger |
| security-inventory | Copertura potenziale OWASP | Swagger |
| auth-draft | Bozza profili auth | Swagger |
| ai-analyze | Analisi Ollama offline rispetto al target | Swagger + Ollama |
| scan | Assessment passivo con AI opzionale | Swagger |
| scope-audit | Controlli scope senza rete | Base URL + host |
| vulnerability-triage | Classificazione evidenze salvate | Report |
| differential-review | Anomalie di risposte | Report |
| adaptive-review | Follow-up suggeriti | Swagger + report |
| analyze-evidence | Analisi file evidenze JSON | File evidenze |
| coverage-report | Endpoint osservati realmente | Swagger + report |
| next-actions | Azioni candidate basate sulla copertura | Swagger + report |
| agent-review | Follow-up sicuri pianificati | Swagger + report |
| ai-prioritize | Prioritizzazione con Ollama opzionale | Swagger + report |
| workflow-graph | Validazione grafo di workflow | Swagger + YAML compatibile |
| verify-access-policy | Confronto con policy reale | Report + YAML regole |
| auto-assess | Assessment guidato da OpenAPI, GET attive opzionali | Swagger, scope, auth opzionale |
| advanced-vuln-assess | Controlli GET e triage | Swagger, scope, auth opzionale |
| journey-assess | Workflow GET multi-step | Swagger + manifest journey |
| workflow-assess | Workflow di fixture disposable | Swagger + manifest workflow + auth |
| multi-resource-assess | Risorse dipendenti, mutation e cleanup | Swagger + manifest multi-risorsa + auth |
| autonomous-agent | Follow-up GET limitati | Swagger + report |
| agent-loop-v2 | Due cicli GET di verifica | Swagger + report |

Gli strumenti non condividono tutti la stessa struttura YAML. Un manifesto multi-risorsa non è intercambiabile con un manifesto `workflow-assess` o `journey-assess`. I comandi CLI legacy a singolo endpoint (`sqli-check`, `bola-check`, `fuzz-parameter` e simili) rimangono accessibili da PowerShell/Kali; non sono stati trasformati in strumenti web generalizzati.

## 7. Avvio e installazione del modello Ollama

1. Installa Ollama localmente (non è distribuito nello ZIP).
2. Premi *Avvia Ollama*. Se già attivo esternamente, *Aggiorna* ne mostra lo stato ma la dashboard non tenta di arrestare processi non avviati da lei.
3. Premi *Installa achilles-local* **solo dopo aver letto la conferma**: scarica `llama3.2:3b` con `ollama pull` (richiede internet per ottenere il modello) e costruisce `achilles-local` dal Modelfile incluso.
4. Attendi che il job risulti completo nella sezione *Assessment activity*; seleziona *Aggiorna* per vedere i modelli disponibili.
5. Seleziona uno strumento AI, spunta *Usa Ollama locale* quando applicabile, e imposta `achilles-local`.

Non vengono inviati a servizi cloud Swagger o risultati di test. Il **download iniziale dei pesi da Ollama** usa internet. L'AI non può estendere scope o autorizzare scritture.

### Se l'avvio di Ollama non funziona

Prova in una finestra separata `ollama serve` e poi `ollama list`. Installa il modello manualmente con `ollama pull llama3.2:3b` e `ollama create achilles-local -f deployment/Modelfile` dalla root del repository.

## 8. Esempio CLI equivalente

```powershell
$env:ACHILLES_LAB_OWNER = 'demo-owner'
$env:ACHILLES_LAB_OTHER = 'demo-other'
uv run achillesapi multi-resource-assess `
  .\labs\control_center_api\openapi.json `
  --config .\labs\control_center_api\resources.yaml `
  --auth-config .\labs\control_center_api\auth.yaml `
  --base-url http://127.0.0.1:8795 `
  --allow-host 127.0.0.1 `
  --allow-insecure-http `
  --max-requests 60 `
  --rate 2 `
  --execute --approve-writes `
  --output .\reports\lab-multiresource.json
```

## 9. Troubleshooting

| Problema | Verifica |
|---|---|
| Porta 8766 occupata | `uv run achillesapi dashboard --port 8866`, quindi apri la nuova URL |
| Porta 8795 occupata | Chiudi il laboratorio precedente o ferma il processo che la usa |
| Il laboratorio risulta offline per alcuni secondi | Clicca *Aggiorna* dopo l'avvio; consulta `dashboard-data/lab.log` |
| Job failed | Controlla tipo di file, profili, valori richiesti e preflight scope; riprova prima offline |
| `Missing environment variable` | Imposta le variabili prima di avviare la dashboard; riavviala dopo modifiche |
| Nessun finding | L'assenza di finding non indica che un endpoint sia stato completamente testato; consulta *coverage-report* |
| Cleanup manuale richiesto | Non ripetere la scansione alla cieca: verifica le risorse sul target |
| Ollama non trovato | Installa Ollama o aggiungilo al PATH; riavvia la dashboard |
| PDF non disponibile | `uv sync --extra pdf --extra dashboard` |
| CSRF / Origin bloccato | Apri la pagina esattamente dall'URL mostrata dal programma, non da domini/proxy |

## 10. Limiti e sicurezza

- Dashboard singolo utente, **solo loopback**, senza login remoto, database né persistenza dei job dopo un riavvio.
- I file caricati restano in `dashboard-data/uploads` e i report in `dashboard-data/reports`; sono potenzialmente sensibili. Proteggi la directory localmente.
- Non tutti i 40+ comandi storici sono esposti via UI; la dashboard espone 30 azioni con input tipizzati più i comandi per il servizio locale, il modello, gli export e il monitoraggio.
- Non esistono garanzie assolute di rollback. Un cleanup non confermato richiede intervento manuale e deve essere trattato come incidente operativo.
- Non esporre la demo a una rete, neanche interna. I controlli volutamente vulnerabili sono pensati soltanto per imparare il comportamento del motore, **non sono componenti di una API sicura**.
- L'applicazione non è certificata production-ready. Non sostituisce l'autorizzazione scritta o il controllo umano dei finding.

## 11. Assessment combinato dalla dashboard (GET + workflow)

Se vuoi eseguire i controlli GET e il workflow multi-risorsa nello stesso job, senza cambiare schermata:

1. Premi *Avvia tutto il laboratorio*.
2. Nel catalogo scegli `auto-assess`.
3. Nel campo *Tipo di configurazione per auto-assess* seleziona **Multi-resource fixture**.
4. Assicurati che il manifesto demo sia già caricato (la dashboard mostra *Manifest multi-risorsa caricato*).
5. Abilita *Active assessment*, *Confermo scope e autorizzazione*, e *Approvo POST/PATCH/DELETE*.
6. Imposta `Max requests=70`, `Rate=2` e (se desideri) `Follow-up AI=2`.
7. Premi *Esegui strumento selezionato* e apri il report alla conclusione.

Il risultato contiene i dati GET e `multi_resource_execution`; in caso di impossibilità di verificare il cleanup, non considerare ripristinato il target. Il numero massimo di richieste è condiviso dal motore del comando.

Il campo *Tipo di configurazione* permette anche di selezionare **Single-resource workflow** e **GET journey**, ma occorre caricare un file di configurazione con lo schema corrispondente. Le scritture non possono essere approvate con *GET journey*, che è un flusso di sola lettura.
