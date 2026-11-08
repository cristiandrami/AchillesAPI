# AchillesAPI v0.49 — Visualizzatore interattivo per tutti i job

## Avvio Windows (PowerShell)

Estrarre lo ZIP in una nuova cartella e aprire PowerShell nella cartella `achillesapi`:

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dashboard --extra pdf --extra dev
uv run achillesapi version
uv run achillesapi dashboard --port 8766
```

Aprire http://127.0.0.1:8766 e, dopo eventuale aggiornamento forzato con Ctrl+F5, caricare lo Swagger, impostare il perimetro autorizzato e avviare un controllo.

## Aprire e usare la nuova scheda

Nella sezione **5 · Risultati e report**, per ogni job `complete` appare il pulsante **Esplora in nuova scheda**. Non sostituisce la dashboard: configurazioni, credenziali non persistite e selezioni restano nella scheda originaria. Per utilizzare l'export rapido della dashboard, il pulsante separato **Seleziona per export** mantiene la vecchia selezione del job.

La nuova scheda offre:

- **Panoramica**: contatori, tipologia del risultato, limitazioni, stato e azioni rapide.
- **Osservazioni**: finding dello scanner, severità, confidenza, endpoint, indicatori sanitizzati. Ricerca e filtro per severità.
- **Elementi e azioni**: elenchi di endpoint, operazioni, richieste, candidati, workflow, round e azioni, se presenti nell'output. Ogni elemento può essere espanso.
- **Analisi AI**: sezioni `ai_analysis`, `ai_correlation`, `ai_advisory` e `local_ai_advice`, con testi, test proposti e limitazioni.
- **Dettagli esplorabili**: esplorazione annidata ad albero del risultato sanitizzato (senza dover leggere il JSON monolitico).

Da questa scheda puoi aprire report HTML e PDF in ulteriori schede oppure scaricare JSON e output originale. Il visualizzatore è **di sola lettura**: filtrare o espandere non genera traffico verso il target e non abilita i test di scrittura.

## Esempi per tipologia

| Job | Dove osservare il risultato |
|---|---|
| `auto-assess`, `advanced-vuln-assess` | Panoramica + Osservazioni + operazioni in Elementi e azioni |
| `ai-analyze` | Analisi AI e dettagli deterministici |
| `ai-correlate` | Osservazioni preservate + Analisi AI + dettagli della correlazione |
| `ai-prioritize`, `agent-review` | Elementi e azioni, Dettagli; eventuale Analisi AI |
| `next-actions`, `autonomous-agent`, `agent-loop-v2` | Elementi e azioni, `stop_reason`, round e richieste effettuate |
| `workflow-assess`, `journey-assess`, `multi-resource-assess` | Workflow, azioni/operazioni e osservazioni disponibili |
| `security-inventory`, `workflow-map`, `map-api`, `generate-tests` | Elementi e azioni; se il formato non contiene liste note, Dettagli esplorabili |
| `auth-draft` | Metadati non sensibili; YAML scaricabile separatamente |
| Altri comandi | Panoramica + Dettagli esplorabili con il loro output sanitizzato |

**Attenzione:** zero finding non significa assenza di vulnerabilità. Gli agenti possono produrre zero richieste per mancanza di anomalie ripetibili. Ollama genera suggerimenti, non conferme.

## Limiti e privacy

Il visualizzatore non mostra header grezzi, token, cookie, corpi HTTP, chiavi o valori che sembrano credenziali. Vengono applicati limiti di profondità e numero di elementi per evitare schermate gigantesche. Per controllare l'output originale, scegli consapevolmente **Output originale**: può contenere dati non presenti nella vista sanitizzata. La sanitizzazione è prudenziale e non sostituisce la gestione dei dati aziendali.

La cronologia dei job è tenuta in memoria dal server dashboard: **se arresti e riavvii la dashboard, gli URL dei vecchi job non sono più consultabili tramite questo visualizzatore**, anche se i file dei report possono rimanere nella cartella di lavoro. Scarica il report prima di terminare la sessione. Questa release non implementa un archivio persistente di job né revisioni manuali dei finding.

Se un browser blocca popup, consenti l'apertura delle schede per `127.0.0.1:8766`. La pagina del job deve essere aperta dalla stessa istanza della dashboard in esecuzione.
