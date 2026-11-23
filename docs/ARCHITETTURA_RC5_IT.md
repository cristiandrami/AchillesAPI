# AchillesAPI RC5 — Appunti per capire il codice

Questo documento segue il flusso reale della richiesta: browser → API locale → CLI → motore → report.

## `dashboard/control.py`

- `ToolRequest`: parametri tipizzati che la dashboard può inviare; nessun comando shell arbitrario.
- `RetryStepRequest`: parametri sostitutivi di **un solo task** della suite; ora include due profili, operazione GET, valori path, policy attesa e famiglie injection.
- `suite_skip_reason`: decide perché un task non può partire; non dichiara sicura un'API per un test non eseguito.
- `run_tool`: controlla file caricati, scope, credenziali e permessi; costruisce un comando CLI da registro fisso e avvia un subprocesso supervisionato.
- `prerequisite_options`: legge lo Swagger e restituisce al browser solo metodi, parametri e nomi profilo, mai token.
- `generate_prerequisite`: valida le scelte dell'operatore e genera il documento richiesto. Il builder `ai-plan-guard` crea `{"actions": [...]}` senza ricorrere a prompt liberi.
- `retry_suite_step`: valida i due profili e la GET prima di lanciare `access-probe`; un task già completato non può essere ritentato tramite il flusso di retry.

## `core/task_help_rc5.py`

- `PURPOSES`: dizionario con la descrizione **esplicita di ogni task**.
- `SPECIAL`: requisiti dettagliati per task con più prerequisiti (es. access-probe o workflow).
- `task_help(action)`: produce le tre frasi esposte nella dashboard: *cosa fa*, *cosa serve*, *come leggere i risultati*.
- `assert set(PURPOSES)==set(TOOLS)`: se in futuro aggiungiamo un task senza spiegazione, i test falliscono anziché mostrare una sezione vuota.

## `dashboard/server.py` + `static/job-viewer.js`

- `/api/job-view/{id}` include `task_help_map` per una suite e `task_help` per i singoli job.
- `renderSuite`: ogni task è una sezione espandibile con spiegazione, esito, risultati e retry.
- `addRetryEditor`: `access-probe` presenta i due utenti, GET, ID e policy attesa; `injection-assess` presenta le famiglie da testare.
- `mountPrerequisiteBuilder`: genera i file senza chiedere YAML/JSON all'utente.
- Il rendering utilizza `textContent` e dati sanitizzati dal server; non mostra token in chiaro.

## `core/injection_engine_rc5.py`

- `FAMILIES` e `PAIRS`: le famiglie supportate e le coppie di input di prova, non distruttivi.
- `_select`: analizza le operazioni Swagger, seleziona solo query GET e annota i metodi non testati.
- `_path`: sostituisce i parametri path con valori espliciti e con codifica sicura.
- `_collect`: conserva temporaneamente la risposta per il confronto; il report finale usa soltanto fingerprint, lunghezze, status e tempi.
- `_without_echo`: sostituisce l'input riflesso con un segnaposto. **Senza questo controllo, due input diversi sembrano una injection anche quando il server si limita a ripeterli.**
- `_review`: classifica gli indicatori e chiede revisione; non conferma mai automaticamente una vulnerabilità.
- `injection_assessment`: crea le prove e usa `SafeHTTPClient` con scope esatto, GET-only, budget e rate; non esegue body POST/XML.

## `core/http.py`

`SafeHTTPClient.request` rifiuta redirect automatici, host fuori scope, metodi non autorizzati, conta tentativi e si integra con il registro condiviso della suite. Un errore di rete resta un tentativo conteggiato.

## `cli.py` e `registry_v090.py`

`injection-assess` è un comando CLI registrato nella suite, con dry-run predefinito. Il comando riceve solo input tipizzati e produce un JSON strutturato con risultati da rivedere.

## Laboratorio

Il progetto Northstar Enterprise Lab è separato: **nessun modulo del framework importa il laboratorio**. La ground truth rimane fuori dal codice di testing. I casi command/LDAP/XPath/CRLF/template sono circoscritti o simulati; SQLi usa concatenazione SQLite reale su un database di prova in memoria.
