# AchillesAPI 1.0.0-rc.2 — architettura e appunti sul codice

Questa guida descrive **cosa fa ogni nuovo modulo, quando viene usato e quali limiti conserva**.
Il codice della RC2 ha commenti brevi in italiano, scritti come appunti pratici. I moduli storici non sono stati riscritti solo per cambiare lo stile dei commenti.

## 1. Percorso di una suite

1. `dashboard/control.py:run_suite()` verifica Swagger, scope, consenso, opzioni e crea un job padre.
2. Per una suite **attiva**, `CampaignLedger.create()` crea un database SQLite in `workspace/reports/<suite_id>.http-ledger.sqlite3` con limite e rate della campagna.
3. `run_tool()` costruisce il comando usando il registro dei tool, senza costruire stringhe shell, e trasmette al processo figlio il percorso del registro.
4. `SafeHTTPClient.request()` valida host/metodo, poi prenota uno slot nel registro **prima** di contattare il target. Anche `auth_dynamic.acquire()` prenota una richiesta per OAuth2/login.
5. Al ritorno il registro viene aggiornato con status HTTP oppure errore di rete. Il report della suite espone `http_telemetry`.
6. Ogni job produce il proprio JSON. Il job padre conserva esiti, motivi dei task saltati e report di qualità.
7. Nella dashboard, `job_view.py` sanifica il contenuto prima di inviarlo al browser; `job-viewer.js` visualizza conteggi e finding.

### `core/campaign_ledger.py`

- `create(path, limit, rate, runtime_seconds)`: crea un registro **nuovo** e applica permessi restrittivi al file.
- `from_environment()`: recupera il registro assegnato dalla suite al subprocesso. Non è obbligatorio fuori da una campagna.
- `reserve()`: prenota atomicamente un credito con `BEGIN IMMEDIATE`. Due processi non possono consumare contemporaneamente l'ultimo credito.
- `finish(ticket, status)`: registra una sola volta la risposta o l'errore.
- `snapshot()`: restituisce solo numeri; non contiene URL, token o corpi di risposta.

**Limiti:** il contatore riguarda le richieste che passano dai client instrumentati. Non controlla traffico generato da applicazioni esterne, proxy non previsti o tool legacy fuori dal registro. Il rate limita gli slot prenotati, non rappresenta una garanzia dell'assenza di burst sulla rete. Il contenimento del traffico aziendale richiede anche proxy/firewall di egress.

### `core/http.py`

`SafeHTTPClient` applica host espliciti, disabilita redirect e proxy da ambiente, limita body/rate, nasconde header e query sensibili. La RC2 aggiunge la prenotazione del credito globale prima di `httpx`. Il dry-run non utilizza crediti. **Il client non autorizza da solo una richiesta:** la CLI e la dashboard verificano anche il consenso all'assessment.

### `core/auth_dynamic.py` e `core/auth.py`

- OAuth2 client credentials e JSON login erano già supportati; ora le rispettive POST sono conteggiate nel budget condiviso.
- `AuthenticationManager.invalidate(name)` invalida un token dinamico memorizzato in memoria.
- `AuthenticationManager.is_dynamic(name)` permette di conoscere se un profilo può essere rinnovato.
- Il comando `access-probe` può usare `--retry-401` per un solo rinnovo **GET-only** con budget esplicito.

**Limiti:** il refresh dopo 401 non è ancora centralizzato in tutti i task. I flussi browser SSO/MFA non sono emulati automaticamente. Le credenziali inline `auth.yaml` rimangono sensibili sul disco.

## 2. Controllo attivo con due identità

### `core/access_probe_rc.py`

- `_choose_get(specification, operation, values)`: trova una GET davvero documentata; richiede i parametri necessari.
- `_render_path(template, values)`: sostituisce i path parameter senza consentire slash, fragment o traversal.
- `compare_identities()`: esegue una GET con l'owner e una con il secondo profilo; mantiene i corpi HTTP solo in memoria; restituisce status e una comparazione conservativa.

Stati principali: `dry_run`, `expected_denial_observed`, `policy_conflict_requires_review`, `unexpected_denial_requires_review`, `inconclusive_or_expected`, `inconclusive_network_failure`.

Un confronto 200/200 rispetto a una policy *deny* genera **requires_review**, non `confirmed`. Per confermare servono policy verificata, ownership certa, contenuto e impatto. L'operatore deve fornire due profili nel proprio `auth.yaml` e un ID appartenente a una **risorsa di test autorizzata**.

Il comando può scegliere una GET compatibile in assenza di `--operation`. Per assessment delicati è consigliato selezionare l'operazione esatta da CLI.

## 3. Verifica e integrità dei report

### `core/release_audit_rc.py`

`audit_campaign(report)` individua task non conclusi, falliti e saltati. Per le campagne attive verifica che ci sia la contabilità HTTP globale. `ready_for_review` significa **pronto per un'ulteriore revisione umana**, non che l'API sia sicura.

### `core/evidence_integrity_rc.py`

- `build_integrity_record(path)`: SHA-256 e dimensione del file; massimo 50 MB; non legge link simbolici.
- `verify_integrity_record(path, record)`: confronta hash e dimensione.

L'hash non è una firma digitale e non identifica l'analista. Il file sorgente del report non deve essere modificato dopo la creazione dell'impronta. Il task della suite usa un assessment figlio già completato, evitando di calcolare l'hash sul report padre mentre cambia.

## 4. Moduli precedenti mantenuti

- `multi_resource.py` / `workflows.py`: creazione di fixture temporanee, marker, lettura, verifica e cleanup in ordine inverso. Scritture solo dopo manifest approvato.
- `advanced.py` / `smart.py` / `vulnerability_engine.py`: controlli di sicurezza e revisione conservativa; i vecchi comandi di laboratorio rimangono volutamente vincolati a loopback.
- `ai_guard_v099.py`: filtro deterministico delle proposte AI. Ollama non può inventare host, comandi o consensi.
- `compatibility_v080.py` / `campaign_v090.py`: preflight e copertura; pianificazione non equivale a verifica eseguita.
- `dashboard/persistence_v080.py`: persistenza dei job. Un processo HTTP interrotto non viene riavviato in automatico dopo un crash.

## 5. Struttura dei test

- `tests/test_rc2.py`: concorrenza SQLite, budget fra client, privacy, GET differenziale, loopback HTTP reale, token OAuth2, SHA-256 e CLI.
- `tests/test_workflows.py`: integrazioni workflow precedenti e cleanup.
- `tests/fixtures/benchmark_specs`: cinque Swagger differenti **offline**; non sono cinque target reali.
- `.github/workflows/tests.yml`: regressione Linux e smoke test Windows.

## 6. Problemi ancora aperti prima della versione stabile

1. Session handling completo per OAuth2 refresh grant, cookie expiry, CSRF, SSO e MFA.
2. Coverage attiva misurata su applicazioni indipendenti con ground truth e policy proprie.
3. Validazione sistematica delle scritture e del cleanup in ambienti differenti, con ripristino degli errori di rete e recovery manuale.
4. Controllo HTTP completo per *ogni* percorso legacy di rete, anche fuori dalla Suite.
5. Pentest della dashboard, threat model e analisi supply-chain completa.

**Decisione di rilascio:** `1.0.0rc2` è una release candidate che aggiunge protezioni e test, **non** una certificazione production-ready.
