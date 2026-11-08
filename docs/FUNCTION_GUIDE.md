# Come leggere il nuovo motore professionale (v0.11.0)

Il flusso è `auto_assess_command()` → `build_generic_plan()` →
`describe_smart_checks()` → **solo con `--execute`** →
`run_smart_assessment()` → `_observe()` → `SafeHTTPClient.request()`.

- `read_context()` apre il contesto opzionale (ID e autorizzazioni attese) ma
  non cerca password né contatta l'API.
- `build_generic_plan()` sceglie operazioni GET con input noti, blocca quelle
  sospette e mette da parte le operazioni che cambiano dati.
- `describe_smart_checks()` spiega *quali* controlli intende usare per ciascun
  endpoint e *perché*, senza mandare richieste.
- `run_smart_assessment()` è il motore attivo. Riceve gli endpoint, i profili
  di test e lo scope; sceglie verifiche di autenticazione, CORS, validazione e
  proprietà in base allo schema e ai risultati precedenti.
- `_observe()` fa passare ogni GET dallo stesso client, applicando il budget
  globale e conservando soltanto metadati.
- `_response_checks()` esamina banner, messaggi di errore e caching.
- `_cors_checks()` cerca riflessi dell'Origin arbitrario assieme a credenziali.
- `_invalid_input()` genera una *sola* variazione non distruttiva per il tipo
  del parametro; non è un motore di SQL injection completo.
- `_property_disclosure_checks()` confronta soltanto i nomi dei campi JSON con
  proprietà sensibili o `writeOnly` dello Swagger. Non conserva i valori.
- `_apply_expected_access()` usa un criterio esterno (se presente) per
  confrontare accessi attesi e osservati: non inventa owner o ruoli.
- `correlate_with_ollama()` può interpretare metadati già raccolti, ma non
  sceglie quali richieste inviare e non modifica lo scope.

**Cosa puoi cambiare a mano:** le euristiche di test stanno in `core/smart.py`;
le condizioni di esclusione in `core/generic.py`; i limiti e la sicurezza di
rete in `core/http.py`; gli argomenti CLI in `cli.py`. Prima di modificare una
regola, aggiungi un test in `tests/test_smart.py` e verifica che il budget e
la redazione dei dati rimangano efficaci.

---

# Guida al codice di AchillesAPI v0.10.2

Questa guida ti aiuta a capire **cosa succede quando lanci un comando**, quali file
leggere e quali parti puoi modificare senza toccare altre funzionalità.

## Prima di tutto: come leggere il progetto

- **`cli.py`**: riceve gli argomenti scritti da te nel terminale. Chiama le funzioni
  vere e proprie degli altri moduli. Non è il posto migliore per modificare i test.
- **`core/openapi.py`**: legge e organizza lo Swagger. Se manca un endpoint o un
  parametro, inizia da questo file.
- **`core/generic.py`**: decide quali GET sono possibili e quali richiedono dati.
  È il punto da modificare per cambiare le regole del flusso `auto-assess`.
- **`core/http.py`**: contiene il client sicuro che invia le GET. Le restrizioni su
  scope, metodo, redirect e velocità sono qui: non rimuoverle senza un motivo.
- **`core/auth.py`**: ricava token, API key e cookie dall'ambiente.
- **`core/testgen.py`**: propone test di sicurezza a partire dallo Swagger.
  Le proposte non eseguono traffico.
- **`core/advanced.py`, `core/bola.py`, `core/authorization.py`**: controlli legacy,
  alcuni limitati intenzionalmente a localhost e/o token Bearer.
- **`ai/`**: AI locale Ollama, separata dall'esecuzione dei test.
- **`lab/`**: applicazione per esercitarsi. Non è una dipendenza del motore generico.

## Cosa succede quando avvii `auto-assess`

1. `auto_assess_command()` riceve il file e le opzioni.
2. `analyze_openapi_file()` apre e analizza la specifica.
3. `build_generic_plan()` controlla ogni endpoint. Se una GET richiede un parametro
   che non conosciamo, non inventa un valore: la segna come *bloccata*.
4. `generate_test_plan()` propone controlli di sicurezza in base agli indizi
   contenuti negli schemi.
5. `assess_api()` aggiunge ipotesi passive: non sono vulnerabilità confermate.
6. **Senza `--execute`** si scrive il JSON e non viene contattata l'API.
7. **Con `--execute`** si controllano scope e identità, poi
   `execute_generic_gets()` invia soltanto GET tramite `SafeHTTPClient`.
8. Si salvano status code, tempi ed eventuali errori, non token o corpi HTTP.
9. Le osservazioni non sono una conferma automatica di BOLA o BFLA.

## Dove intervenire per personalizzarlo

| Se vuoi cambiare... | Parti da... |
|---|---|
| Come viene interpretato uno Swagger | `core/openapi.py` |
| Quali endpoint vengono eseguiti automaticamente | `core/generic.py`, `build_generic_plan()` |
| Come sono gestiti i placeholder e gli ID | `core/generic.py`, `_render_path()` |
| I profili di autenticazione | `core/auth.py` |
| I limiti di sicurezza del client | `core/http.py`, `SafeHTTPClient` |
| Quali test vengono suggeriti | `core/testgen.py`, `generate_test_plan()` |
| Il comportamento della riga di comando | `cli.py`, `auto_assess_command()` |
| Come viene usato il modello locale | `ai/local.py`, `ai/intelligence.py` |

## Lessico usato nei commenti

- **Offline**: non contatta il target API.
- **Dry-run**: mostra ciò che farebbe, ma non invia richieste.
- **Scope**: insieme di host e funzioni che sei autorizzato a testare.
- **Candidato**: test potenzialmente utile, ancora da validare.
- **Indicatore**: risposta sospetta, non necessariamente una vulnerabilità.
- **Confermato**: richiede evidenze e un criterio esterno (per esempio la vera
  ownership di una risorsa), non basta un codice HTTP diverso.

## Elenco di tutte le funzioni Python

Le spiegazioni qui sotto si riferiscono al codice della release e sono pensate
per una prima lettura. Docstring e commenti direttamente nei file spiegano
i dettagli vicino alle istruzioni effettivamente eseguite.

### `src/achillesapi/ai/analyzer.py`

- **`analyze_api_locally()`** — Prepara l'analisi della specifica e la affida al modello locale. **Può contattare Ollama locale.**

### `src/achillesapi/ai/intelligence.py`

- **`_validate_intelligence()`** — Convalida il formato delle osservazioni prodotte dall'AI locale. **Non contatta direttamente l'API target.**
- **`correlate_with_ollama()`** — Correla dati già disponibili con il modello locale; non interroga il target. **Può contattare Ollama locale.**

### `src/achillesapi/ai/local.py`

- **`_local_endpoint()`** — Esegue la fase ' local endpoint' del modulo local. **Non contatta direttamente l'API target.**
- **`_extract_json()`** — Ricava il blocco JSON dalla risposta testuale del modello. **Non contatta direttamente l'API target.**
- **`_validate_result()`** — Controlla la struttura e la coerenza del risultato ricevuto dal modello. **Non contatta direttamente l'API target.**
- **`analyze_with_ollama()`** — Invia soltanto dati sanitizzati al modello Ollama locale. **Può contattare Ollama locale.**

### `src/achillesapi/ai/sanitizer.py`

- **`redact_text()`** — Sostituisce stringhe potenzialmente segrete con un segnaposto. **Non contatta direttamente l'API target.**
- **`sanitize()`** — Elimina campi sensibili prima di condividere metadati con l'AI. **Non contatta direttamente l'API target.**

### `src/achillesapi/cli.py`

- **`version()`** — Espone il comando 'version' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Non contatta direttamente l'API target.**
- **`analyze_openapi()`** — Espone il comando 'analyze openapi' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Non contatta direttamente l'API target.**
- **`generate_tests()`** — Espone il comando 'generate tests' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Non contatta direttamente l'API target.**
- **`analyze_evidence()`** — Espone il comando 'analyze evidence' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Non contatta direttamente l'API target.**
- **`map_api()`** — Espone il comando 'map api' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Non contatta direttamente l'API target.**
- **`assess()`** — Espone il comando 'assess' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Non contatta direttamente l'API target.**
- **`_bearer_token_from_profile()`** — Espone il comando ' bearer token from profile' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Non contatta direttamente l'API target.**
- **`auth_profiles()`** — Espone il comando 'auth profiles' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Non contatta direttamente l'API target.**
- **`http_get()`** — Espone il comando 'http get' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Può inviare traffico HTTP all'API.**
- **`bola_check()`** — Espone il comando 'bola check' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Può inviare traffico HTTP all'API.**
- **`_path_values()`** — Converte argomenti NAME=VALUE della CLI in un dizionario. **Non contatta direttamente l'API target.**
- **`bola_sweep_command()`** — Espone il comando 'bola sweep' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Può inviare traffico HTTP all'API.**
- **`bfla_sweep_command()`** — Espone il comando 'bfla sweep' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Può inviare traffico HTTP all'API.**
- **`sqli_check_command()`** — Espone il comando 'sqli check' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Può inviare traffico HTTP all'API.**
- **`fuzz_parameter_command()`** — Espone il comando 'fuzz parameter' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Può inviare traffico HTTP all'API.**
- **`mass_assignment_command()`** — Espone il comando 'mass assignment' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Può inviare traffico HTTP all'API.**
- **`role_matrix_command()`** — Espone il comando 'role matrix' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Può inviare traffico HTTP all'API.**
- **`jwt_inspect_command()`** — Espone il comando 'jwt inspect' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Non contatta direttamente l'API target.**
- **`ai_analyze_command()`** — Espone il comando 'ai analyze' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Può contattare Ollama locale.**
- **`ai_correlate_command()`** — Espone il comando 'ai correlate' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Può contattare Ollama locale.**
- **`scan_command()`** — Espone il comando 'scan' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Può contattare Ollama locale.**
- **`auto_assess_command()`** — Espone il comando 'auto assess' della CLI, controlla le opzioni e presenta il risultato all'operatore. **Può inviare traffico HTTP all'API.**

### `src/achillesapi/core/advanced.py`

- **`require_loopback()`** — Blocca target non locali per proteggere i vecchi test da uso indesiderato. **Non contatta direttamente l'API target.**
- **`_client()`** — Prepara un client HTTP con timeout e senza redirect automatici. **Non contatta direttamente l'API target.**
- **`_url()`** — Costruisce l'URL da base e path, sostituendo i parametri indicati. **Non contatta direttamente l'API target.**
- **`replace()`** — Esegue la fase 'replace' del modulo advanced. **Non contatta direttamente l'API target.**
- **`bola_sweep()`** — Confronta l'accesso alla stessa risorsa da parte di due identità nel motore legacy. **Può inviare traffico HTTP all'API.**
- **`bfla_sweep()`** — Confronta l'accesso a una funzione da parte di identità diverse nel motore legacy. **Può inviare traffico HTTP all'API.**
- **`sqli_probe()`** — Invia un controllo leggero per cercare segnali di errori SQL, senza confermare SQL injection. **Può inviare traffico HTTP all'API.**
- **`fuzz_query_parameter()`** — Prova alcuni valori non distruttivi per verificare la gestione dei parametri GET. **Può inviare traffico HTTP all'API.**
- **`mass_assignment_check()`** — Prepara o invia una PATCH esplicita: la modifica dei dati richiede autorizzazione. **Può inviare traffico HTTP all'API.**
- **`inspect_jwt()`** — Legge i campi di un JWT senza verificarne firma o autenticità. **Non contatta direttamente l'API target.**
- **`decode()`** — Decodifica una parte del JWT e verifica che sia un oggetto JSON. **Non contatta direttamente l'API target.**

### `src/achillesapi/core/assessment.py`

- **`_finding()`** — Prepara un singolo rilievo passivo con dati e severità. **Non contatta direttamente l'API target.**
- **`assess_api()`** — Cerca indizi di possibili problemi nella specifica, senza contattare l'API. **Non contatta direttamente l'API target.**
- **`assessment_to_dict()`** — Trasforma i risultati passivi in un dizionario pronto per il JSON. **Non contatta direttamente l'API target.**

### `src/achillesapi/core/auth.py`

- **`validate_definition()`** — Verifica che ciascun profilo contenga i campi richiesti dal suo tipo. **Non contatta direttamente l'API target.**
- **`unique_names()`** — Impedisce due profili con lo stesso nome. **Non contatta direttamente l'API target.**
- **`__repr__()`** — Mostra una rappresentazione che non rivela i segreti. **Non contatta direttamente l'API target.**
- **`__init__()`** — Inizializza lo stato e le regole di funzionamento del componente. **Non contatta direttamente l'API target.**
- **`from_file()`** — Legge e valida la configurazione dei profili dal disco. **Non contatta direttamente l'API target.**
- **`names()`** — Elenca i nomi dei profili disponibili. **Non contatta direttamente l'API target.**
- **`describe()`** — Mostra profili e nomi delle variabili richieste senza stampare password o token. **Non contatta direttamente l'API target.**
- **`_required_env()`** — Legge un segreto da una variabile d'ambiente e segnala se manca. **Non contatta direttamente l'API target.**
- **`resolve()`** — Converte un profilo in header, query parameter e cookie realmente utilizzabili. **Non contatta direttamente l'API target.**
- **`load_authentication_manager()`** — Carica i profili di autenticazione definiti nel file YAML. **Non contatta direttamente l'API target.**

### `src/achillesapi/core/authorization.py`

- **`_render_path()`** — Sostituisce i segnaposto del percorso con i valori di test forniti. **Non contatta direttamente l'API target.**
- **`replace()`** — Esegue la fase 'replace' del modulo authorization. **Non contatta direttamente l'API target.**
- **`_field_paths()`** — Estrae i nomi dei campi di una risposta JSON per confrontarne la visibilità. **Non contatta direttamente l'API target.**
- **`_response_metadata()`** — Estrae dati delle risposte utili alla matrice senza dichiarare automaticamente vulnerabilità. **Non contatta direttamente l'API target.**
- **`authorization_matrix()`** — Confronta le risposte ottenute con identità diverse nel motore legacy. **Può inviare traffico HTTP all'API.**

### `src/achillesapi/core/bola.py`

- **`body_sha256()`** — Calcola un'impronta della risposta senza mostrarne il contenuto. **Non contatta direttamente l'API target.**
- **`_validate_local_url()`** — Accetta solo URL locali per il vecchio controllo BOLA. **Non contatta direttamente l'API target.**
- **`_request()`** — Esegue una richiesta HTTP nel controllo BOLA legacy. **Può inviare traffico HTTP all'API.**
- **`check_bola()`** — Confronta la risposta a un oggetto tra proprietario e altra identità, senza dedurre ownership. **Può inviare traffico HTTP all'API.**
- **`_canonical_body()`** — Normalizza il corpo di una risposta prima del confronto. **Non contatta direttamente l'API target.**

### `src/achillesapi/core/detection.py`

- **`_headers()`** — Normalizza i nomi degli header per confrontarli senza differenze di maiuscole. **Non contatta direttamente l'API target.**
- **`_finding()`** — Prepara un singolo rilievo passivo con dati e severità. **Non contatta direttamente l'API target.**
- **`analyze_response_evidence()`** — Analizza evidenze HTTP già raccolte: non genera traffico. **Non contatta direttamente l'API target.**
- **`add()`** — Aggiunge un'indicazione al report di analisi delle evidenze. **Non contatta direttamente l'API target.**

### `src/achillesapi/core/generic.py`

- **`_documented_path_value()`** — Esegue la fase ' documented path value' del modulo generic. **Non contatta direttamente l'API target.**
- **`_render_path()`** — Sostituisce i segnaposto del percorso con i valori di test forniti. **Non contatta direttamente l'API target.**
- **`replacement()`** — Sostituisce un singolo segnaposto usando soltanto un valore consentito. **Non contatta direttamente l'API target.**
- **`_metadata_for()`** — Esegue la fase ' metadata for' del modulo generic. **Non contatta direttamente l'API target.**
- **`build_generic_plan()`** — Esegue la fase 'build generic plan' del modulo generic. **Non contatta direttamente l'API target.**
- **`_sanitize_observation()`** — Esegue la fase ' sanitize observation' del modulo generic. **Non contatta direttamente l'API target.**
- **`execute_generic_gets()`** — Esegue la fase 'execute generic gets' del modulo generic. **Può inviare traffico HTTP all'API.**

### `src/achillesapi/core/graph.py`

- **`_endpoint_id()`** — Crea un identificatore stabile per ogni coppia metodo e percorso. **Non contatta direttamente l'API target.**
- **`_decode_pointer_token()`** — Decodifica un pezzo di percorso usato nei riferimenti JSON Pointer. **Non contatta direttamente l'API target.**
- **`_resolve_schema()`** — Trova lo schema effettivo quando compare un riferimento a un componente. **Non contatta direttamente l'API target.**
- **`_walk_properties()`** — Visita ricorsivamente i campi di uno schema, con limiti per evitare loop. **Non contatta direttamente l'API target.**
- **`_content_schemas()`** — Seleziona gli schemi JSON tra i media type di request e response. **Non contatta direttamente l'API target.**
- **`_resource_for_path()`** — Stima la risorsa rappresentata dal percorso, senza affermare che sia certa. **Non contatta direttamente l'API target.**
- **`build_api_graph()`** — Collega endpoint, risorse e schemi in un grafo per identificare possibili relazioni. **Non contatta direttamente l'API target.**
- **`graph_to_dict()`** — Converte il grafo in dati JSON serializzabili. **Non contatta direttamente l'API target.**

### `src/achillesapi/core/http.py`

- **`__init__()`** — Inizializza lo stato e le regole di funzionamento del componente. **Non contatta direttamente l'API target.**
- **`_validate_target()`** — Controlla metodo, protocollo e host prima di qualunque richiesta. **Non contatta direttamente l'API target.**
- **`_safe_headers()`** — Oscura gli header che possono contenere credenziali. **Non contatta direttamente l'API target.**
- **`_safe_url()`** — Oscura i parametri URL identificati come sensibili. **Non contatta direttamente l'API target.**
- **`request()`** — Prepara una richiesta o esegue una GET nei limiti configurati. **Può inviare traffico HTTP all'API.**

### `src/achillesapi/core/openapi.py`

- **`_basic_validate_spec()`** — Controlla i campi minimi della specifica quando il validatore completo non è disponibile. **Non contatta direttamente l'API target.**
- **`load_openapi()`** — Legge il file YAML/JSON e verifica che contenga una specifica OpenAPI valida. **Non contatta direttamente l'API target.**
- **`_resolve_local_ref()`** — Segue un riferimento locale dello Swagger senza scaricare risorse da Internet. **Non contatta direttamente l'API target.**
- **`_resolve_ref_chain()`** — Segue più riferimenti collegati, fermandosi in caso di ciclo. **Non contatta direttamente l'API target.**
- **`_merge_parameters()`** — Unisce i parametri comuni del path con quelli specifici dell'operazione. **Non contatta direttamente l'API target.**
- **`_normalize_security()`** — Distingue autenticazione richiesta, assente o disattivata esplicitamente. **Non contatta direttamente l'API target.**
- **`parse_openapi()`** — Trasforma lo Swagger in un elenco uniforme di endpoint, parametri e requisiti di autenticazione. **Non contatta direttamente l'API target.**
- **`analyze_openapi_file()`** — Unisce lettura, validazione e normalizzazione in un solo passaggio. **Non contatta direttamente l'API target.**

### `src/achillesapi/core/testgen.py`

- **`_resolve_schema()`** — Trova lo schema effettivo quando compare un riferimento a un componente. **Non contatta direttamente l'API target.**
- **`_json_schemas()`** — Individua gli schemi JSON presenti nei corpi di richiesta o risposta. **Non contatta direttamente l'API target.**
- **`_properties()`** — Esamina le proprietà di uno schema, comprese quelle annidate. **Non contatta direttamente l'API target.**
- **`_case()`** — Costruisce una scheda test con obiettivo, prerequisiti ed evidenze richieste. **Non contatta direttamente l'API target.**
- **`generate_test_plan()`** — Crea proposte di test leggendo lo Swagger: non invia richieste. **Non contatta direttamente l'API target.**

### `src/achillesapi/lab/app.py`

- **`current_user()`** — Esegue la fase 'current user' del modulo app. **Non contatta direttamente l'API target.**
- **`health()`** — Esegue la fase 'health' del modulo app. **Non contatta direttamente l'API target.**
- **`get_order_vulnerable()`** — Esegue la fase 'get order vulnerable' del modulo app. **Non contatta direttamente l'API target.**
- **`get_order_secure()`** — Esegue la fase 'get order secure' del modulo app. **Non contatta direttamente l'API target.**
- **`admin_metrics()`** — Esegue la fase 'admin metrics' del modulo app. **Non contatta direttamente l'API target.**
- **`update_profile_vulnerable()`** — Esegue la fase 'update profile vulnerable' del modulo app. **Non contatta direttamente l'API target.**
- **`update_profile_secure()`** — Esegue la fase 'update profile secure' del modulo app. **Non contatta direttamente l'API target.**
- **`search()`** — Esegue la fase 'search' del modulo app. **Non contatta direttamente l'API target.**

### `src/achillesapi/models/api.py`

- **`path_parameters()`** — Restituisce i parametri che compaiono nel percorso dell'endpoint. **Non contatta direttamente l'API target.**
- **`query_parameters()`** — Restituisce i parametri destinati alla query string. **Non contatta direttamente l'API target.**
- **`endpoint_count()`** — Conta le operazioni HTTP rilevate nella specifica. **Non contatta direttamente l'API target.**

## Checklist prima dell'esecuzione

- Verifica che `--base-url` punti all'ambiente giusto (test/staging quando disponibile).
- Verifica che `--allow-host` sia l'hostname autorizzato, non un dominio vicino.
- Usa identità e risorse test approvate, non dati di clienti reali.
- Controlla nel JSON quali operazioni non sono eseguibili per input mancanti.
- Non usare `--allow-insecure-http` con credenziali su reti non protette.
- Tieni basso `--rate` e `--max-requests` per evitare carichi indesiderati.
- Ricorda che anche una GET può avere side effect in API progettate male.
- Non classificare una differenza di status HTTP come vulnerabilità senza una
  policy di autorizzazione o un ownership oracle verificabile.


## Il laboratorio completo e gli script di avvio

- `lab/full_app.py` è una API volutamente vulnerabile e confrontabile con endpoint protetti.
  Il suo codice commenta direttamente **quale controllo manca** e perché la stessa
  richiesta funziona o viene bloccata sui percorsi `/secure/`.
- `lab/export_spec.py` esporta lo Swagger direttamente dalle route, senza
  necessità di avviare il web server.
- `deployment/windows/start-lab.ps1`: avvia la API solo su `127.0.0.1:8000`.
- `deployment/windows/start-ai.ps1`: prepara il modello `achilles-local` tramite Ollama.
- `deployment/windows/run-lab-demo.ps1`: esegue l'analisi e i test del laboratorio.
- `deployment/windows/start-all.ps1`: coordina apertura API, AI opzionale e test.

La procedura e i comandi completi si trovano in [`FULL_LAB_GUIDE.md`](FULL_LAB_GUIDE.md).

## Funzioni del laboratorio completo

- **`current_user()`** — Get the caller's fake identity from a demo Bearer token.  *(solo laboratorio locale)*
- **`require_admin()`** — Require the fake admin role; used as the secure BFLA comparison.  *(solo laboratorio locale)*
- **`_profile_for()`** — Look up a lab profile; never auto-create arbitrary fake accounts.  *(solo laboratorio locale)*
- **`_order_for()`** — Look up a synthetic order in memory; return 404 for an unknown ID.  *(solo laboratorio locale)*
- **`health()`** — Return a harmless status to check that the laboratory is running.  *(solo laboratorio locale)*
- **`order_vulnerable()`** — DELIBERATE BOLA: any signed-in user reads another user's order.  *(solo laboratorio locale)*
- **`order_secure()`** — PROTECTED BOLA control: only the actual owner can read an order.  *(solo laboratorio locale)*
- **`audit_vulnerable()`** — DELIBERATE BFLA: non-admin identities can access an admin function.  *(solo laboratorio locale)*
- **`metrics_secure()`** — PROTECTED BFLA control: only the fake admin identity receives metrics.  *(solo laboratorio locale)*
- **`profile_vulnerable()`** — DELIBERATE property exposure: sends an internal private_note to peers.  *(solo laboratorio locale)*
- **`profile_secure()`** — PROTECTED control: owner-only access and no internal profile fields.  *(solo laboratorio locale)*
- **`profile_update_vulnerable()`** — DELIBERATE mass assignment: lets a user change the is_admin field.  *(solo laboratorio locale)*
- **`profile_update_secure()`** — PROTECTED control: reject attempts to change is_admin.  *(solo laboratorio locale)*
- **`search_vulnerable()`** — SIMULATED SQL error disclosure triggered by a quote canary.  *(solo laboratorio locale)*
- **`search_secure()`** — PROTECTED control: treats apostrophes as regular input data.  *(solo laboratorio locale)*
- **`inventory()`** — Demonstrate schema-aware numeric boundaries and an enum-like category.  *(solo laboratorio locale)*
- **`catalog()`** — Demonstrate an object ID named sku, not order_id or userId.  *(solo laboratorio locale)*
- **`create_report()`** — Create a synthetic report to demonstrate POST -> GET workflow planning.  *(solo laboratorio locale)*
- **`get_report()`** — Read a synthetic report; enforce ownership to provide a safe control.  *(solo laboratorio locale)*
- **`basic_account()`** — Accept demo HTTP Basic credentials (lab-user / lab-pass).  *(solo laboratorio locale)*
- **`partner_summary()`** — Accept a demo API key from the X-API-Key request header.  *(solo laboratorio locale)*
- **`cookie_me()`** — Accept a demo sessionid cookie without requiring a Bearer token.  *(solo laboratorio locale)*


## Nuovi componenti v0.12.0 — workflow autonomi su dati disposable

Leggi anche [WORKFLOWS_PROFESSIONAL_IT.md](WORKFLOWS_PROFESSIONAL_IT.md).

Tutte queste funzioni si trovano in `src/achillesapi/core/workflows.py`:

- **`read_workflows()`**: legge il manifesto YAML e controlla che nomi,
  credenziali, body, passaggi e regole non siano incompleti. **Nessun traffico**.
- **`discover_workflows()`**: cerca corrispondenze tra POST collection e
  GET/PATCH/DELETE item leggendo esclusivamente Swagger. **Nessun traffico**.
- **`draft_workflow_config()`**: genera una bozza con segnaposto da sostituire
  prima di poter eseguire qualunque scrittura. **Nessun traffico**.
- **`_request_schema()`**: trova lo schema JSON del corpo di richiesta da OpenAPI.
- **`_schema_fields()`**: indica quali proprietà sono richieste o `readOnly`.
- **`_validate_workflows()`**: prima di inviare richieste, controlla che tutte
  le operazioni siano nella specifica e che sia prevista una DELETE di cleanup.
- **`workflow_plan()`**: produce il piano eseguibile, ma senza valori dei body.
- **`_render_template()`**: inserisce l'ID creato in un percorso in modo codificato.
- **`_json_pointer()`**: ricava l'ID di prova dalla risposta JSON; non lo salva.
- **`_capture_json()`**: analizza una risposta solo nella memoria temporanea.
- **`_auth_ok()`**: verifica che il profilo sia compatibile con lo schema di
  autenticazione dell'operazione OpenAPI.
- **`_resolve_body_secrets()`**: recupera i segreti dai nomi di variabili
  d'ambiente solo al momento di inviare la richiesta.
- **`_safe_response()`**, **`_observation()`**: costruiscono evidenze senza
  il contenuto dei body e senza token.
- **`run_workflows()`**: **INVIA RICHIESTE SOLO SE AUTORIZZATO**. Crea la risorsa
  (HTTP 201), la legge e verifica il proprio marker casuale, confronta accessi,
  opzionalmente prova campi vietati, tenta DELETE e verifica HTTP 404/410.
  Il risultato segnala chiaramente se la pulizia rimane incompleta.

Dentro `cli.py`:

- **`workflow_discover_command()`**: espone la discovery offline in PowerShell.
- **`workflow_assess_command()`**: controlla opzioni/approvazioni e avvia i workflow.
- **`auto_assess_command()`**: combina controlli GET e workflow facoltativi
  senza permettere alle operazioni di scrittura di superare il budget globale.

Dentro `core/http.py`:

- **`SafeHTTPClient.request()`**: per impostazione predefinita rimane GET-only.
  Solo l'istanza costruita da `run_workflows()` riceve una lista esplicita di
  metodi autorizzati. Il client verifica host, TLS, timeout, numero e frequenza
  delle richieste, disabilita redirect e proxy ereditati dall'ambiente.

**Per personalizzare una nuova API**, normalmente devi modificare solo Swagger,
`auth-profiles.yaml` e la configurazione di workflow. Non modificare Python
per cambiare `owner`, `asset_ref` o gli endpoint del cliente: sono dati del file
YAML, non costanti del framework.

## Aggiunte v0.17–v0.20

- `core/auth_dynamic.py::_validate_auth_url`: blocca auth fuori hostname approvato e HTTP non autorizzato prima di comunicare credenziali.
- `core/auth_dynamic.py::acquire`: esegue una singola POST OAuth2 client credentials oppure login JSON; non memorizza i token nel report, restituisce materiale di autenticazione e scadenza temporanea.
- `core/auth.py::AuthenticationManager.resolve`: per profili dinamici usa la cache del token e gestisce scadenza/limite delle richieste di autenticazione.
- `core/auth_discovery.py::draft_auth_profiles`: da schemi OpenAPI produce template YAML senza password.
- `core/journey_discovery.py::discover_read_journeys`: segue gli schemi JSON, anche array annidati, per trovare possibili collegamenti GET→GET, solo offline.
- `core/journey_discovery.py::journey_draft`: crea un esempio di configurazione YAML da revisionare prima dell'esecuzione.
- `core/journeys.py::read_journey`: legge un piano GET con limite di dimensione.
- `core/journeys.py::_select_operations`: impedisce l'uso di operazioni non GET o non presenti nello Swagger; verifica i riferimenti alle variabili acquisite.
- `core/journeys.py::run_journey`: esegue la sequenza con GET autorizzate, acquisendo e riutilizzando ID JSON in memoria senza salvarli nei report.
- `core/contracts.py::response_contract_issues`: verifica tipi e nomi dei campi della risposta, senza registrare valori sensibili.
- `core/adaptive.py::verify_server_errors`: ripete fino a 3 GET autorizzate che hanno prodotto 5xx in baseline; conserva solo metadati.
- `cli.py::auth_draft_command`, `journey_discover_command`, `journey_assess_command`: comandi di avvio dei moduli; `auto_assess_command` orchestra anche journey e follow-up.

## Nuovi moduli nella v0.23

- `core/workflows.py`: `read_workflows` valida i YAML di fixture; `_validate_workflows` controlla preventivamente che operazioni, profili, parametri e budget siano corretti; `run_workflows` esegue creazione, confronto identità, da zero a cinque mutazioni e cleanup. Ogni passo di mutazione è seguito da GET e controllo ID+marcatore; non viene mai rimosso un oggetto di cui non si possa provare la creazione nell'esecuzione corrente.
- `core/security_inventory.py`: `security_inventory` classifica i test *potenzialmente applicabili* sulla base di OpenAPI. Non invia richieste, non scopre vulnerabilità e specifica quali dati di contesto servono.
- `core/orchestrator.py`: `choose_followups` controlla gli esiti già osservati e prepara una lista ordinata di GET ripetibili con priorità; `run_followups` verifica host, identità compatibili e budget prima di inviare al massimo il numero di richieste consentito. **Nessun testo remoto diventa un URL o un metodo da eseguire.** Le risposte sono convertite in sole osservazioni sicure.
- `core/smart.py`: `_invalid_input` crea semplici input fuori schema, usando anche `minLength` e `format` quando disponibili; non svolge fuzzing volumetrico.
- `cli.py`: `security-inventory` e `agent-review` sono comandi offline; `auto-assess --agent-budget N` esegue selezioni deterministiche aggiuntive soltanto dopo l'assessment GET e nel budget totale.

Per i dettagli e gli esempi PowerShell consulta `docs/GUIDA_COMPLETA_V023_IT.md`.
