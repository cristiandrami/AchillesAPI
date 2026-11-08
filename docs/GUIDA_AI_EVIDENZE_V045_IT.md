# AchillesAPI v0.45.0 — Guida per far funzionare analisi AI e agent

## 1. Installazione Windows (PowerShell)

Estrai `AchillesAPI-v0.45.0-Corrected-AI-Workflow.zip` e apri PowerShell nella cartella `achillesapi` (quella che contiene `pyproject.toml`).

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dashboard --extra pdf --extra dev
uv run achillesapi version
uv run achillesapi dashboard --port 8766
```

Devi vedere `AchillesAPI 0.45.0` e aprire `http://127.0.0.1:8766`. Se la v0.44 era già aperta, chiudi il relativo processo e ricarica la pagina con Ctrl+F5.

## 2. Laboratorio del tutto indipendente

In un **secondo terminale** apri la cartella estratta di `Independent-Vulnerable-API-Lab.zip`, e avvia:

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

La documentazione del target è su `http://127.0.0.1:8795/docs`. La dashboard non conosce né avvia questo laboratorio: è un target HTTP esterno come un'API aziendale.

## 3. Compila i campi della dashboard

1. **Specifica OpenAPI:** importa `independent-api-lab/openapi.json`.
2. **Base URL:** `http://127.0.0.1:8795`.
3. **Hostname autorizzato:** `127.0.0.1`.
4. **Numero richieste:** 60; **richieste al secondo:** 2.
5. Spunta **Consenti HTTP locale con credenziali**: esclusivamente perché questo laboratorio usa HTTP loopback.
6. Carica `independent-api-lab/auth.yaml` nella sezione autenticazione, poi inserisci nei campi dei segreti `ACHILLES_LAB_OWNER=demo-owner`, `ACHILLES_LAB_OTHER=demo-other`, `ACHILLES_LAB_ADMIN=demo-admin` (la dashboard mostra i nomi; non aggiungere `ACHILLES_LAB_` tra le identità).
7. Campo identità: `owner,other,admin`.

## 4. Sequenza corretta: prima HTTP, poi analisi AI

### A. Prima esecuzione: `auto-assess`

Seleziona `auto-assess`. Puoi iniziare con **Genera piano offline**, per controllare operazioni e campi mancanti. Per avere evidenze da correlare devi poi attivare **Esegui richieste HTTP**, confermare il perimetro autorizzato, ed eseguire le GET. Attendi che il job sia `complete`. Se esegui solo il piano offline, **non hai osservazioni HTTP**.

### B. Seleziona le evidenze

Nella voce **Evidenze da usare per il prossimo strumento**, seleziona il job `auto-assess` completato che riporta un numero positivo di `risposte HTTP`. Puoi aprire altri report nel pannello Risultati senza sostituire la selezione delle evidenze.

### C. `ai-correlate`

Seleziona `ai-correlate`, verifica che Ollama sia installato e che il modello selezionato esista, poi premi **Esegui analisi offline**. Questo comando **non** contatta l'API target ma contatta **Ollama locale**. Non serve spuntare una generica casella `--ai`: è sempre una chiamata al modello. Il report precedente deve contenere osservazioni reali.

### D. `ai-prioritize`

Seleziona `ai-prioritize`, e un report precedente dello stesso Swagger. Può funzionare anche con un piano senza risposte; in quel caso ricostruisce il piano dal file OpenAPI e presenta le verifiche da fare, **senza fingere di avere analizzato risposte HTTP**. La casella AI è **facoltativa**: se la abiliti, Ollama produce raccomandazioni consultive.

### E. `next-actions` e `agent-review`

Sono strumenti **offline**: propongono cosa manca da verificare; non inviano richieste alla API e non richiedono Ollama. Se mostrano POST/DELETE come attività manuali, è perché richiedono fixture e cleanup approvati.

### F. `autonomous-agent` e `agent-loop-v2`

Questi strumenti ripetono **soltanto anomalie GET già supportate da evidenze**, come risposte 5xx o accessi anonimi inattesi. Se il risultato indica `requests_sent: 0`, `no_supported_actions` oppure `no_supported_candidate`, non è necessariamente un malfunzionamento: potrebbe non esserci nessuna anomalia verificabile nei dati precedenti. Non significa che il pentest sia completo e non implica che l'API sia sicura. Se desideri avviare GET mai testate, torna a `auto-assess` attivo.

## 5. Serve sempre un report precedente?

| Strumento | Risultato precedente | Contatta target? | Ollama |
|---|---|---|---|
| `ai-analyze` | No, basta OpenAPI | No | Sì |
| `scan --ai` | No | No | Sì se abilitato |
| `auto-assess` | No | Solo con esecuzione attiva | No |
| `ai-correlate` | **Sì, assessment HTTP con risposte** | No | Sì |
| `ai-prioritize` | Sì, anche report offline dello stesso Swagger | No | Opzionale |
| `next-actions` | Sì | No | No |
| `agent-review` | Sì | No | No |
| `autonomous-agent` | Sì; per ripetere GET servono anomalie HTTP | Solo se autorizzato | Opzionale |
| `agent-loop-v2` | Sì; per ripetere GET servono anomalie HTTP | Solo se autorizzato | Opzionale |

## 6. Installare e avviare Ollama

Installa Ollama sul tuo computer e avvia il servizio. Dal terminale:

```powershell
ollama list
ollama pull llama3.2:3b
```

Se nella dashboard hai scelto `achilles-local`, devi prima crearlo usando la procedura locale prevista dal framework, oppure selezionare un modello **effettivamente presente in `ollama list`** (per esempio `llama3.2:3b`). La dashboard può controllare lo stato del servizio. La prima installazione del modello richiede Internet; le successive analisi rimangono locali.

## 7. Su un'API aziendale

1. Importa uno Swagger/OpenAPI fornito dall'azienda.
2. Inserisci soltanto la Base URL e l'hostname presenti nell'autorizzazione scritta al PT.
3. Configura i profili di identità di test e inserisci le credenziali nel browser, non nel file `auth.yaml`.
4. Avvia un piano offline e controlla i prerequisiti.
5. Esegui l'assessment GET con rate e budget concordati.
6. Seleziona **quel job con osservazioni HTTP**, poi usa correlazione e priorità.
7. Abilita POST/PATCH/DELETE solo su risorse temporanee autorizzate con cleanup validato.
8. Esporta il report e controlla manualmente ogni finding non confermato.

**Limiti reali:** il tool non esegue exploitation generale su qualsiasi API, non può inferire policy business da OpenAPI e non garantisce che gli agent trovino vulnerabilità. Questa release corregge in particolare il flusso dati dashboard → CLI → AI, senza inventare risultati.
