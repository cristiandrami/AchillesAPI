# AchillesAPI v0.46 — guida completa al laboratorio indipendente e all'esportazione

## Perché HTML e PDF fallivano

Il vecchio esportatore assumeva che ogni JSON fosse un `auto-assess` con un oggetto `plan`. Questo è sbagliato: la dashboard esegue anche `security-inventory`, `workflow-map`, `ai-prioritize`, `autonomous-agent` e altri comandi con output diversi.

**Correzione v0.46:** gli output di strumenti supportati sono riconosciuti per tipologia. Un assessment con piano produce il normale rapporto; un inventario, una pianificazione o un risultato AI produce un **documento di analisi** con contatori, metadati sicuri e limiti dichiarati. L'esportazione HTML/PDF non inventa né conferma vulnerabilità inesistenti. Il JSON originale resta disponibile separatamente; dati di risposta e credenziali non vengono copiati nei report sanitizzati.

## 1. Avvia il laboratorio esterno

Scarica **Independent-Vulnerable-API-Lab-v2.zip** (separato dallo ZIP AchillesAPI), estrailo e apri PowerShell nella cartella `independent-api-lab`:

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

Swagger UI: `http://127.0.0.1:8795/docs`. Non avviare il laboratorio dalla dashboard: è una seconda applicazione indipendente.

## 2. Avvia AchillesAPI

Estrai **AchillesAPI-v0.46.0-Reporting-Fix.zip** in un'altra cartella. Apri PowerShell nella cartella `achillesapi`:

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dashboard --extra pdf --extra dev
uv run achillesapi version
uv run achillesapi dashboard --port 8766
```

Apri `http://127.0.0.1:8766`. Se hai ancora la v0.45 sulla stessa porta, chiudi il processo precedente e usa Ctrl+F5.

## 3. Importa Swagger

Nel passaggio 1, scegli **Carica file** e seleziona `independent-api-lab/openapi.json`. In alternativa incolla il contenuto di quel file. Dovresti vedere **30 operazioni**. Sono tutte API del laboratorio, nessun indirizzo hardcoded nel framework.

## 4. Target e scope

Nel passaggio 2 imposta:

| Campo dashboard | Valore laboratorio |
|---|---|
| Base URL | `http://127.0.0.1:8795` |
| Host autorizzato | `127.0.0.1` |
| Rate | `2` (richieste/secondo; massimo dashboard 5) |
| Max requests | `120` (dashboard massimo 150) |
| Credenziali su HTTP locale | Consenti **solo perché è localhost** |

Su una API aziendale usa HTTPS e l'hostname esplicitamente autorizzato dal cliente.

## 5. Autenticazione

Importa il file `independent-api-lab/auth.yaml` dal passaggio 3:

```yaml
profiles:
  - name: owner
    type: bearer
    token_env: ACHILLES_LAB_OWNER
  - name: other
    type: bearer
    token_env: ACHILLES_LAB_OTHER
  - name: admin
    type: bearer
    token_env: ACHILLES_LAB_ADMIN
```

Compila i tre campi della dashboard: `ACHILLES_LAB_OWNER` = `demo-owner`; `ACHILLES_LAB_OTHER` = `demo-other`; `ACHILLES_LAB_ADMIN` = `demo-admin`.

Nel campo **Identità da confrontare** inserisci `owner,other,admin`. `token_env` è il **nome** della variabile, non il token; i valori dei token restano nella memoria del job.

## 6. Assessment e risultati attesi

Apri `auto-assess`, abilita **Esegui HTTP**, conferma di essere autorizzato e avvia. Questo programma esegue GET non distruttive e probe limitati. Se hai caricato un progetto temporaneo di prova, puoi aggiungere `project_ref` tra i parametri per confronti BOLA; altrimenti alcune verifiche sulle risorse singole saranno saltate o inconcludenti.

Nel JSON di output cerca `execution_report.findings`. Per gli endpoint di prova del laboratorio sono previsti:

- `unauthenticated_access_review` su `/misconfigured/auth`;
- `cors_credentialed_origin_reflection` su `/misconfigured/cors`;
- `write_only_property_returned` su `/profile/exposed`;
- `authenticated_public_cache` e `technology_disclosure` su `/misconfigured/cache`;
- `response_contract_mismatch` su `/misconfigured/contract`;
- `error_disclosure` su `/misconfigured/error` (**non** SQL injection);
- `cross_identity_object_review` su una risorsa di prova posseduta da un altro account, se il suo ID è noto.

I risultati possono variare con budget, profili selezionati, valori path/query e ordine degli endpoint. Per verificare il laboratorio stesso usa `TEST_MATRIX.md` nello ZIP standalone.

## 7. Workflow POST/PATCH/DELETE

Importa `independent-api-lab/resources.yaml` come manifest, scegli `multi-resource-assess` e verifica le operazioni. Questo manifest sa creare un progetto e un ticket e ripristinarli. Per la **scrittura** servono autorizzazione, `--execute`, `--approve-writes`, identità e budget; i dati sono esclusivamente sintetici. **Non** copiare il manifest del laboratorio su un cliente: la procedura di cleanup deve essere approvata sul sistema reale.

## 8. AI: quale report precedente scegliere?

- **`ai-analyze`**: basta Swagger e un modello Ollama locale; nessuna evidenza HTTP richiesta.
- **`ai-correlate`**: prima devi completare **`auto-assess` attivo**. Seleziona proprio quel job nella voce **Analisi precedente**. Il modello riceve soltanto i metadati sanitizzati, non token o corpi delle risposte.
- **`ai-prioritize`, `agent-review`, `next-actions`**: seleziona un job precedente di assessment; servono a prioritizzare verifiche, non a dimostrare vulnerabilità.
- **`autonomous-agent`, `agent-loop-v2`**: per follow-up eseguibili servono osservazioni precedenti che supportino una ripetizione GET. Se non ci sono, **zero richieste è un risultato corretto**.

L'agente non esegue exploit SQLi/SSRF generalizzati e non deve riportare finding fittizi per riempire il report.

## 9. Esportare HTML/PDF senza perdere la scheda

Nel passaggio 5 seleziona il job completato e premi **Apri HTML** oppure **Apri PDF**. Si apre una nuova scheda; il workspace originale resta nella dashboard. Se il job contiene un piano di assessment, ricevi un report di sicurezza. Se contiene output AI, inventari o un piano offline, ricevi un documento di analisi **non equivalente a un penetration test completato**.

`Scarica output originale` consente di conservare il JSON dell'analisi; contiene soltanto ciò che il tool ha salvato. La dashboard non dovrebbe sostituire la scheda corrente durante l'export.

## 10. API aziendale: cosa cambia?

Solo quattro informazioni diventano specifiche del cliente: OpenAPI, base URL autorizzato, credenziali dei profili e regole di ownership/fixture se vuoi testare le scritture. Il motore non conosce il laboratorio. Il limite reale rimane la copertura dei controlli automatici: SQLi/NoSQLi/SSRF, business logic e workflow complessi non sono una suite di exploitation universale.
