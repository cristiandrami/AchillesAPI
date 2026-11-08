# AchillesAPI v0.44 — Guida operativa: PDF, AI e risultati precedenti

## Prima di iniziare: tre concetti semplici

**Swagger/OpenAPI** è la descrizione delle operazioni dell'API, non il report dei test. Il file viene caricato al Passaggio 1.

**Assessment** è un'esecuzione di AchillesAPI. Un *piano offline* individua le verifiche ma non contatta il bersaglio. Un *assessment HTTP attivo* invia effettivamente richieste GET autorizzate e registra metadati delle risposte (status, operazione, identità, errori). Questo è il risultato giusto per la correlazione AI.

**Report precedente** significa il risultato di un job terminato in AchillesAPI: non è `auth.yaml`, non è `resources.yaml` e non è il file Swagger. Lo puoi scegliere dal menu **Analisi precedente** (Passaggio 4), oppure aprirlo da **Attività e report** (Passaggio 5). I job sono conservati nello spazio di lavoro locale della dashboard, non in cloud; non sono necessariamente persistenti tra riavvii.

## 1. Installazione e correzione PDF

### Windows PowerShell

Estrai la nuova release in una cartella nuova, poi dalla cartella `achillesapi`:

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dashboard --extra pdf --extra dev
uv run achillesapi version
uv run achillesapi dashboard --port 8766
```

La versione deve essere `0.44.0`. Apri `http://127.0.0.1:8766`.

**Novità:** `reportlab` è una dipendenza diretta dell'extra `dashboard` e viene installata da `uv sync`; non devi installare manualmente un generatore PDF esterno. Se hai conservato una vecchia directory con una vecchia `.venv`, esegui nuovamente `uv sync --python 3.12 --extra dashboard --extra pdf --extra dev`. Per verificare l'installazione:

```powershell
uv run python -c "import reportlab; print(reportlab.Version)"
```

Per Kali/Linux gli stessi comandi `uv` funzionano dalla directory del progetto, omettendo `uv python install` se Python 3.12 è già disponibile.

### Esportazione report

Dopo un job terminato, premi **Apri PDF in nuova scheda** oppure **Apri HTML in nuova scheda**. La pagina principale resta aperta e mantiene i valori inseriti. Il browser può bloccare popup: autorizza le nuove schede per `127.0.0.1:8766`. JSON e Markdown vengono scaricati in una nuova scheda o tramite download, senza spostare la dashboard.

Se il PDF non si genera, controlla prima che il job sia terminato e poi prova `uv run python -c "import reportlab"`. Il nuovo messaggio d'errore indica la causa effettiva invece del precedente avviso generico.

## 2. API di laboratorio indipendente

Il laboratorio è un progetto **separato** e non viene avviato da AchillesAPI. Estrai `Independent-Vulnerable-API-Lab.zip` e apri un terminale nella cartella `independent-api-lab`:

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

Verifica `http://127.0.0.1:8795/docs`.

Apri un secondo terminale nella cartella AchillesAPI e avvia la dashboard come indicato sopra.

### Compila la dashboard

1. **Passaggio 1:** carica `independent-api-lab/openapi.json`.
2. **Passaggio 2:** Base URL `http://127.0.0.1:8795`, Host autorizzato `127.0.0.1`, massimo richieste `60`, rate `2`. Attiva l'opzione HTTP non cifrato **solo per localhost**.
3. **Passaggio 3:** carica `independent-api-lab/auth.yaml`. Il file definisce i profili; per il laboratorio inserisci nelle caselle dei segreti `ACHILLES_LAB_OWNER = demo-owner`, `ACHILLES_LAB_OTHER = demo-other`, `ACHILLES_LAB_ADMIN = demo-admin`. Identità: `owner,other,admin`.
4. **Passaggio 4:** seleziona `auto-assess`. Prima **Genera piano offline** per esaminare gli endpoint. Poi attiva **Esegui richieste HTTP**, conferma di essere autorizzato e scegli **Avvia strumento selezionato**. Per la sola correlazione AI NON servono manifest né approvazione POST/PATCH/DELETE.
5. **Passaggio 5:** premi **Aggiorna risultati**, apri l'`auto-assess` completato. Verifica nel JSON che `execution_report` abbia `requests_sent` maggiore di zero e un elenco `observations`.
6. **Passaggio 4, AI:** scegli `ai-correlate` e nel menu **Analisi precedente** seleziona quel job `auto-assess` completato. Controlla che Ollama sia avviato e che il modello indicato esista; poi **Avvia strumento selezionato**. Non serve abilitare il traffico verso l'API: la correlazione è offline per il target, ma comunica con Ollama sul PC.
7. **Passaggio 5:** apri il nuovo risultato `ai-correlate`; se vuoi esportarlo, scegli PDF/HTML.

Se `auto-assess` non ha potuto eseguire GET (ad es. mancavano ID obbligatori), il report non contiene osservazioni e non è utilizzabile per `ai-correlate`. Rivedi `skipped` e i valori richiesti oppure scegli un endpoint realmente testabile.

## 3. Quale risultato serve a ciascun comando AI?

| Funzione | Serve un report precedente? | Come ottenerlo | Contatta l'API? | Richiede Ollama? |
|---|---|---|---|---|
| `ai-analyze` | No | Carica solo Swagger (Passaggio 1) | No | **Sì** |
| `scan` | No | Carica solo Swagger | No | Solo se selezioni l'opzione AI |
| `ai-correlate` | **Sì, osservazioni HTTP** | Esegui `auto-assess` **attivo**, poi scegli il job in Analisi precedente | No, usa il report salvato | **Sì** |
| `ai-prioritize` | **Sì** | Esegui `auto-assess`, scegli il risultato precedente | No | Facoltativo |
| `agent-review` | **Sì** | Esegui `auto-assess`, scegli il risultato | No | No |
| `next-actions` | **Sì** | Esegui `auto-assess`, scegli il risultato | No | No |
| `autonomous-agent` | **Sì** | Esegui `auto-assess`, scegli il risultato | Solo con esecuzione e scope autorizzati | Facoltativo |
| `agent-loop-v2` | **Sì** | Esegui `auto-assess`, scegli il risultato | Solo con esecuzione e scope autorizzati | Facoltativo |

**Nota importante:** `agent-review` e `next-actions` sono motori deterministici: sono nella categoria dell'intelligenza del framework, ma **non interrogano Ollama**. I flag `--ai` sulle funzioni che li supportano consentono una valutazione consultiva, mai il controllo diretto della rete da parte del modello.

### Perché prima falliva `ai-correlate`?

Nella v0.43 la dashboard passava erroneamente il **manifest YAML** come secondo argomento di `ai-correlate`, che invece richiede dati HTTP in formato JSON. Questo generava `Expecting value: line 1 column 1`. La v0.44 gli passa il **job di assessment precedente** e converte i soli metadati delle osservazioni nel formato previsto. Non inventa body o header che non sono stati raccolti. Se il file non contiene traffico osservato, il backend lo rifiuta con un messaggio specifico.

### Avvio e modello Ollama

Da un terminale separato puoi avviare `ollama serve` (se non è già attivo come servizio). Per controllare i modelli:

```powershell
ollama list
```

La dashboard ha pulsanti **Avvia Ollama**, **Aggiorna stato** e **Installa modello locale**. Se il modello `achilles-local` non esiste, installalo o seleziona un modello già presente, come `llama3.2:3b` (se installato). Il primo download usa Internet, **ma non vengono inviati dati dell'assessment al cloud**. Le inferenze successive si svolgono in locale.

Se Ollama è spento o il modello non produce JSON, la dashboard ora distingue il problema di connessione da un output del modello vuoto o non valido. Anche con modelli locali buoni, le risposte non sono garantite: un risultato AI rimane un'interpretazione da revisionare e non una vulnerabilità confermata.

## 4. Uso contro una vera API aziendale

1. Ottieni dal cliente una specifica OpenAPI 3.x valida, **URL di staging autorizzato**, scope scritto e credenziali di test.
2. Carica solo Swagger. Imposta Base URL e hostname esattamente autorizzati. Non usare la configurazione e i token del laboratorio.
3. Se l'API richiede identità, crea un `auth.yaml` dalla dashboard usando i tipi supportati (Bearer, API key, Basic, Cookie o flussi dinamici previsti dal motore). Inserisci i segreti nelle caselle della dashboard e non nel YAML.
4. Esegui piano offline, valuta quanti endpoint sono testabili e quali parametri mancano. Se occorrono ID reali, fornisci **identificativi di risorse di prova autorizzate**, non ID arbitrari di produzione.
5. Esegui `auto-assess` attivo con budget ridotto e rate conservativo. Rivedi `execution_report`.
6. Solo dopo scegli `ai-correlate` / `ai-prioritize`, selezionando **l'assessment appena concluso**. Nessuna delle analisi AI crea nuove autorizzazioni.
7. Per scritture, predisponi dati temporanei, manifest guidato, policy e cleanup approvati: non abilitare POST/PATCH/DELETE su dati reali senza un piano di ripristino.
8. Esporta HTML/PDF in una nuova scheda, verifica manualmente i risultati e le limitazioni prima di inserirli in un report professionale.

## 5. Errori comuni e che cosa fare

- **PDF: import reportlab / PDF extra** → esegui `uv sync --python 3.12 --extra dashboard --extra pdf --extra dev`; riavvia la dashboard.
- **ai-correlate: manca un report** → esegui prima `auto-assess` attivo e selezionalo dal menu Analisi precedente.
- **Il report selezionato non contiene osservazioni HTTP** → avevi creato solo il piano offline, oppure nessun endpoint era eseguibile; controlla `execution_report` e i parametri richiesti.
- **Ollama non raggiungibile / nessun modello** → avvia `ollama serve`, controlla `ollama list`, correggi il nome nel campo Modello, premi Aggiorna stato.
- **Ollama restituisce una risposta vuota o un JSON invalido** → verifica il modello, riprova con meno contesto; non significa che l'API sia vulnerabile.
- **Esportazione apre una nuova pagina al posto della dashboard** → assicurati di aver aggiornato alla v0.44, riavviato il server e ricaricato la pagina una volta; autorizza le nuove schede per localhost.
- **L'analisi precedente appartiene a uno Swagger diverso** → carica lo Swagger corretto e crea un assessment sullo stesso target.
- **Credenziali mancanti** → compila i campi nella sezione autenticazione; il nome del profilo non è il nome della variabile segreta.

## Limiti verificati

La v0.44 verifica il flusso con test automatici, export PDF e un finto server Ollama di test su loopback. Non è stata testata un'inferenza reale con il tuo modello specifico né l'interazione visiva sul tuo browser Windows. Le evidenze di AchillesAPI omettono valori sensibili: `ai-correlate` può correlare status e operazioni, ma non ricostruisce corpi di risposta o header mancanti. La dashboard rimane separata dal laboratorio.
