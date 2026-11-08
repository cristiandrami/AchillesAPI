# AchillesAPI v0.40 — Manuale pratico della dashboard indipendente

## 0. Cosa cambia

La dashboard di AchillesAPI **non avvia, controlla o importa codice dal laboratorio**. Il laboratorio è una qualunque API HTTP esterna: si avvia in un terminale indipendente. La dashboard importa una specifica OpenAPI, l'indirizzo del target, le credenziali e, dove necessario, un manifesto di risorse di prova. La stessa procedura vale per un ambiente di staging aziendale autorizzato.

La v0.40 corregge il caricamento dei file, aggiunge l'alternativa **incolla YAML/JSON**, un generatore e un editor per `auth.yaml`, credenziali per singolo job non salvate sul disco e un flusso guidato in cinque passaggi. Il catalogo della dashboard include i controlli professionali generici e la gestione dei report. Alcuni vecchi comandi CLI per test mirati su localhost rimangono esclusivamente nella CLI: non sono assimilabili a test generalizzati dello Swagger.

**ATTENZIONE:** i controlli automatici non equivalgono a un penetration test esaustivo. Controlla sempre i risultati, la copertura e le condizioni di cleanup. Il modello Ollama è un supporto consultivo, non può autorizzare nuove azioni.

---

## 1. Installazione Windows, da zero

Prerequisiti: Windows 10/11, `uv` installato e disponibile nel PATH, PowerShell. Se non hai `uv`, installalo seguendo la documentazione ufficiale di astral.sh/uv. L'AI è facoltativa e richiede Ollama installato separatamente.

1. Estrai **AchillesAPI-v0.40.0-Guided-Dashboard.zip** in una cartella scelta da te, ad esempio `C:\Tools\AchillesAPI`. All'interno trovi `achillesapi\pyproject.toml`, `src\`, `tests\` e `docs\`.
2. Apri PowerShell **nella cartella che contiene `pyproject.toml`**, non in quella superiore.
3. Esegui:

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dashboard --extra pdf --extra dev
uv run achillesapi version
uv run achillesapi dashboard --port 8766
```

4. Lascia aperto il terminale: chiuderlo spegne la dashboard.
5. Apri `http://127.0.0.1:8766` nel browser. Il server è collegato soltanto al loopback e non è esposto alla LAN.

**Se ottieni `Failed to parse pyproject.toml`**, apri `pyproject.toml`: la prima riga dev'essere `[build-system]`, **non `{`**. Probabilmente sei nella directory sbagliata o hai sovrascritto il file: estrai nuovamente l'archivio originale.

Su Kali/Linux:

```bash
cd achillesapi
uv python install 3.12
uv sync --python 3.12 --extra dashboard --extra pdf --extra dev
uv run achillesapi dashboard --port 8766
```

---

## 2. Avviare l'API vulnerabile *separatamente*

Scarica ed estrai **Independent-Vulnerable-API-Lab.zip**. È una FastAPI autonoma, senza dipendenze o import da AchillesAPI. La directory `independent-api-lab` contiene:

| File | Significato |
|---|---|
| `app.py` | Codice del server vulnerabile indipendente |
| `start.ps1`, `start.sh` | Script di avvio Windows o Linux |
| `openapi.json` | Swagger/OpenAPI da caricare nella dashboard |
| `auth.yaml` | Istruzioni di autenticazione di AchillesAPI; non contiene token |
| `resources.yaml` | Manifesto temporaneo POST/GET/PATCH/DELETE per i workflow multi-risorsa |
| `README.md` | Guida minimale del solo laboratorio |

**Terminale A, Windows** (dalla directory `independent-api-lab`):

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

**Terminale A, Kali/Linux**:

```bash
chmod +x start.sh
./start.sh
```

Verifica in un browser `http://127.0.0.1:8795/docs` e `http://127.0.0.1:8795/health`. Il server è volutamente vulnerabile e ascolta esclusivamente su `127.0.0.1`. Non aprire porte verso Internet o reti aziendali. La memoria del laboratorio si resetta quando riavvii il processo.

**Terminale B**: avvia AchillesAPI seguendo il paragrafo 1. Sono due processi separati e due cartelle separate. Non copiare i file del laboratorio dentro il framework.

---

## 3. Primo assessment con la dashboard, passo per passo

### Passaggio 1 — Specifica OpenAPI

Nella sezione **1 · Carica la specifica OpenAPI** clicca il selettore file e scegli:

`independent-api-lab/openapi.json`

Il riquadro deve mostrare **Independent Vulnerable Test API — 15 operazioni**. Se il selettore file non funziona, apri `openapi.json` con un editor, copia tutto e incolla il JSON in **Oppure incolla qui il contenuto del file**, quindi premi **Importa testo OpenAPI**. Non usare `auth.yaml` o `resources.yaml` in questa sezione: non sono Swagger.

### Passaggio 2 — Target e scope

Compila esattamente:

| Campo dashboard | Valore laboratorio | Significato |
|---|---|---|
| Base URL | `http://127.0.0.1:8795` | Server verso cui inviare il traffico HTTP |
| Hostname autorizzato | `127.0.0.1` | Host esplicitamente ammesso |
| Limite massimo richieste | `60` | Budget globale delle verifiche supportate |
| Richieste al secondo | `2` | Velocità massima dei test |
| Consenti HTTP con credenziali | **Attivo** | Solo perché è un laboratorio localhost in HTTP |

Se testi un ambiente aziendale: usa `https://...` e lascia disattivata l'opzione HTTP non cifrato.

### Passaggio 3 — Profili e token

**`auth.yaml` non è lo Swagger.** È un file di configurazione usato da AchillesAPI per capire quale header/cookie usare per ogni identità.

Nel laboratorio il file `auth.yaml` è già fornito e contiene:

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

Cosa vuol dire:
- `profiles`: elenco delle identità disponibili.
- `name`: nome corto da usare nel tool; `owner` rappresenta il proprietario della risorsa, `other` un secondo utente, `admin` un amministratore.
- `type: bearer`: invia la credenziale nell'header HTTP `Authorization: Bearer ...`.
- `token_env`: **nome della variabile** che contiene il token, **non il token stesso**. Il file non contiene segreti.

Puoi importare `independent-api-lab/auth.yaml` cliccando **Carica auth.yaml**, oppure premere **Genera esempio auth.yaml**, modificare i profili nell'editor, cliccare **Importa auth.yaml incollato** e, facoltativamente, **Scarica esempio YAML**.

Dopo l'import la dashboard mostra tre campi password, uno per ogni `token_env`. Inserisci:

| Campo segreto | Valore di prova |
|---|---|
| `ACHILLES_LAB_OWNER` | `demo-owner` |
| `ACHILLES_LAB_OTHER` | `demo-other` |
| `ACHILLES_LAB_ADMIN` | `demo-admin` |

Nel campo **Identità da confrontare** scrivi: `owner, other, admin`.

**Importante:** questi valori di prova valgono soltanto per questa API sintetica. I segreti immessi nel browser sono trasferiti via loopback al processo della dashboard e forniti al singolo job tramite environment; non vengono scritti nel file YAML o nel report. Non sono tuttavia equivalenti a un vault aziendale: per segreti sensibili usa una macchina adeguatamente protetta.

### Passaggio 4 — Piano offline, poi assessment attivo

Dalla sezione **4 · Scegli le verifiche**:

1. Categoria `Assessment`, strumento `auto-assess`.
2. Per iniziare lascia spento **Esegui richieste HTTP** e premi **Genera piano offline**. Non contatta l'API target: individua endpoint, blocchi e controlli possibili.
3. Nella sezione **5 · Risultati** clicca **Aggiorna risultati**, poi **Apri risultato** sul job `auto-assess` completato. Leggi gli endpoint senza parametri e quelli che richiedono un ID.
4. Torna alla sezione 4. Abilita **Esegui richieste HTTP** e **Confermo di avere l'autorizzazione**. Lascia **Approvo scritture** disattivato.
5. Premi **Avvia strumento selezionato**. Si avvia la fase di GET controllate: test di accessibilità/autenticazione, alcune verifiche di input, header e CORS, se applicabili.
6. In **Risultati** apri il JSON generato. I codici HTTP e gli indizi non equivalgono automaticamente a vulnerabilità confermate.

### Passaggio 5 — Report

Seleziona il job terminato e usa **Analizza finding** per il triage conservativo oppure **Scarica HTML/PDF/JSON/Markdown**. **Scarica output originale** restituisce il file del comando, anche quando è una bozza YAML.

---

## 4. Testare realmente BOLA/BFLA e workflow multi-risorsa

Per provare accessi contrari alla policy servono risorse con proprietario noto. Le GET generiche non possono inventare ID reali. Il file `resources.yaml` del laboratorio definisce un ciclo controllato di **due risorse temporanee**: prima il progetto, poi il ticket collegato; confronta owner e other e li cancella in ordine inverso.

Carica `independent-api-lab/resources.yaml` nel campo **Manifest / evidenze / configurazione aggiuntiva**. Seleziona lo strumento **`multi-resource-assess`** dalla categoria Workflow. Spunta **Esegui richieste HTTP**, **Confermo autorizzazione** e **Approvo esplicitamente le scritture**; imposta `60` richieste, `2` richieste al secondo, e premi **Avvia strumento**.

Il manifesto comprende sezioni come:

```yaml
resources:
  - name: project
    create: POST /projects
    read: GET /projects/{project_ref}
    delete: DELETE /projects/{project_ref}
    identity: owner
    body: {label: temporary-project}
    marker_field: label
    marker_pointer: /label
    id_pointer: /id
    read_id_pointer: /id
    path_values: {project_ref: '${project.id}'}
    access:
      - {identity: other, expected: deny}
```

Spiegazione operativa:

- `name`: nome interno della risorsa temporanea, usato nelle dipendenze `${project.id}`.
- `create`, `read`, `delete`: operazioni dichiarate in OpenAPI che creano, verificano e cancellano la risorsa.
- `identity`: quale profilo crea e possiede la risorsa.
- `body`: payload approvato per la creazione; non va generato a caso su produzione.
- `marker_field` e `marker_pointer`: campo in cui AchillesAPI inserisce/verifica un marcatore di proprietà unico; se non viene confermato il programma non deve eliminare risorse ambigue.
- `id_pointer`, `read_id_pointer`: JSON Pointer da cui acquisire l'ID nell'output delle POST e GET.
- `path_values`: come il valore letto viene iniettato nei path successivi.
- `access`: policy desiderata; per `other`, l'accesso deve essere negato.
- `mutations`: modifiche PATCH/PUT consentite durante la prova, con verifica dello stato.

Nel secondo elemento `ticket`, il body contiene `project: '${project.id}'`, quindi il ticket usa l'identificativo ottenuto dalla creazione del progetto. La cancellazione avviene **prima sul ticket, poi sul progetto**. La prova ha l'obiettivo di rilevare endpoint vulnerabili intenzionalmente e confermare che i dati temporanei siano stati ripuliti. Dopo una perdita di connessione o un 5xx, controlla sempre `manual_cleanup_required` nel risultato; il cleanup non è garantito universalmente.

Puoi anche selezionare `auto-assess`, caricare lo stesso manifest, scegliere **Più risorse (resources.yaml)**, e approvare le scritture per combinare assessment GET e workflow. Prima prova sempre il piano offline.

---

## 5. Tutti gli strumenti della dashboard, quando usarli

Dalla sezione 4 filtra per categoria oppure usa il menu completo. Il requisito mostrato sotto allo strumento indica se servono uno Swagger, un report precedente o un YAML aggiuntivo.

### Discovery / inventario, **senza traffico**

| Strumento | Funzione |
|---|---|
| `analyze-openapi` | Estrae metodi, path, parametri e schemi |
| `generate-tests` | Crea candidati di test API security |
| `map-api` | Rappresenta relazioni tra risorse |
| `assess` | Analisi statica e potenziali rischi |
| `intelligent-plan` | Esempi di valori e prerequisiti da OpenAPI |
| `security-inventory` | Mappatura di categorie OWASP applicabili |
| `auth-draft` | Bozza di profili di autenticazione da revisionare |
| `scope-audit` | Controlla URL/host rispetto al perimetro dichiarato |

### Workflow

| Strumento | Funzione |
|---|---|
| `workflow-discover` | Trova possibili catene CRUD |
| `workflow-map` | Suggerisce produttori e consumatori di ID |
| `workflow-graph` | Valida dipendenze e cleanup da manifesto |
| `journey-discover` | Propone possibili catene GET |
| `journey-assess` | Esegue una sequenza GET approvata |
| `workflow-assess` | Esegue una risorsa temporanea e cleanup |
| `multi-resource-assess` | Esegue più risorse dipendenti, accessi e cleanup |

### Assessment, sicurezza, evidenze e agent

| Strumento | Funzione |
|---|---|
| `auto-assess` | Motore principale, offline oppure GET attive e workflow approvati |
| `advanced-vuln-assess` | Controlli GET e raccolta di indicatori di sicurezza |
| `vulnerability-triage` | Raccoglie indicatori senza promuoverli automaticamente a finding confermati |
| `differential-review` | Confronta osservazioni HTTP |
| `verify-access-policy` | Confronta un report con policy allow/deny in YAML |
| `analyze-evidence` | Analizza evidenze JSON già raccolte |
| `coverage-report` | Misura quali endpoint sono stati effettivamente raggiunti |
| `benchmark-evaluate` | Confronta ground truth e risultati verificati |
| `adaptive-review` | Propone approfondimenti dalle risposte |
| `agent-review` | Piano deterministico di follow-up |
| `next-actions` | Ordina controlli futuri a partire dalla copertura |
| `ai-prioritize` | Prioritizza con assistenza Ollama opzionale |
| `ai-analyze` | Analisi locale della specifica |
| `ai-correlate` | Correlazione fra Swagger ed evidenze locali |
| `scan` | Assessment passivo, con AI opzionale |
| `autonomous-agent` | Follow-up GET autorizzati con budget |
| `agent-loop-v2` | Fino a due cicli di follow-up autorizzati |
| `auth-profiles` | Elenca i tipi di profilo senza rivelare credenziali |

**Report professionali:** dopo un job puoi esportare PDF, HTML, Markdown e JSON dalla sezione 5. Alcuni vecchi comandi diretti (`sqli-check`, `fuzz-parameter`, `jwt-inspect`, `bola-check`, `bola-sweep`, `bfla-sweep`, `role-matrix`, `http-get`, `mass-assignment-check`) restano disponibili solo nella CLI: sono controlli legacy mirati/localhost, non sono ancora stati convertiti in workflow grafici generici e non li presentiamo come tali. La dashboard consente invece di avviare tutti i motori principali dell'assessment basato su Swagger.

**Quando una funzionalità richiede un report precedente:** seleziona con **Apri risultato** un job completato nella sezione 5, quindi torna alla sezione 4 e avvia il controllo di revisione. Quando richiede YAML/JSON aggiuntivo: caricalo nel campo manifesto della sezione 4.

---

## 6. Come creare `auth.yaml` per una API aziendale reale

Prima di configurare la dashboard raccogli queste informazioni dal referente tecnico o dal proprietario dell'API:

1. Specifica Swagger/OpenAPI completa, possibilmente per l'ambiente di staging.
2. Base URL effettivo della API (ad esempio `https://staging.api.azienda.it/v1`).
3. Host autorizzati, percorsi esclusi, finestre orarie, limiti di richieste.
4. Almeno due account di test con ruoli differenti per verifiche BOLA/BFLA. Per test di ownership, le relative risorse devono avere proprietari noti.
5. Meccanismo reale di autenticazione: Bearer/API key/cookie/Basic/OAuth2/login JSON.
6. ID di risorse di test, policy previste (chi può leggere o modificare cosa), regole di ripristino e autorizzazione alle scritture.

### Esempio Bearer token

```yaml
profiles:
  - name: dipendente
    type: bearer
    token_env: AZIENDA_TESTER_TOKEN
  - name: amministratore
    type: bearer
    token_env: AZIENDA_ADMIN_TOKEN
```

Importa questo YAML nella sezione 3; la dashboard mostrerà due campi segreti. Incolla lì i token di test ottenuti dal cliente. Non mettere il token letterale nel file YAML.

### Esempio API key HTTP header

```yaml
profiles:
  - name: servizio
    type: api_key
    location: header
    parameter_name: X-API-Key
    value_env: AZIENDA_TEST_API_KEY
```

### Esempio autenticazione Basic

```yaml
profiles:
  - name: lettore
    type: basic
    username_env: AZIENDA_BASIC_USER
    password_env: AZIENDA_BASIC_PASS
```

### Esempio cookie di sessione

```yaml
profiles:
  - name: sessione_test
    type: cookie
    parameter_name: sessionid
    value_env: AZIENDA_SESSION_COOKIE
```

### Esempio OAuth2 client credentials

```yaml
profiles:
  - name: client_machine
    type: oauth2_client_credentials
    token_url: https://staging.api.azienda.it/oauth/token
    client_id_env: AZIENDA_CLIENT_ID
    client_secret_env: AZIENDA_CLIENT_SECRET
    scopes: [read]
```

L'URL del grant OAuth2 deve essere autorizzato dallo stesso scope. Se è fuori perimetro o il provider di autenticazione richiede redirect interattivi/SSO, non aspettarti che il tool possa autenticarsi senza configurazione specifica. Esegui un assessment offline per primi.

### Esempio login JSON

```yaml
profiles:
  - name: qa_user
    type: login_json
    login_url: https://staging.api.azienda.it/login
    username_env: AZIENDA_QA_USER
    password_env: AZIENDA_QA_PASS
    username_field: username
    password_field: password
    token_pointer: /access_token
```

Verifica che i campi JSON siano quelli usati dall'API e che il token sia effettivamente restituito in `/access_token`. Il tool non inventa il formato di un login personalizzato.

### Esempio `context.yaml` (opzionale)

Serve a inserire ID reali di **test** e aspettative di autorizzazione che Swagger non conosce. Lo schema preciso è illustrato anche in `docs/PROFESSIONAL_ASSESSMENT.md`. Nella dashboard lo carichi come **Manifest / configurazione aggiuntiva**, scegli **Context (context.yaml)** e selezioni `auto-assess`. Non inserire dati veri di clienti o segreti in questo file.

---

## 7. Procedura per una API vera

1. Apri un nuovo workspace in una macchina controllata, protetta e autorizzata a comunicare con il target.
2. Nella sezione 1 carica lo Swagger dell'API aziendale. L'interfaccia elenca endpoint e metodi.
3. Nella sezione 2 inserisci il **Base URL completo** e il suo hostname autorizzato. Mantieni HTTPS, definisci un budget basso (`20–40`) e `1` richiesta/s all'inizio.
4. Nella sezione 3 importa o genera `auth.yaml`, definisci i ruoli e inserisci credenziali **di test**. Due profili sono utili per confrontare permessi, ma il tool non può dedurre correttamente le policy dai nomi.
5. Nella sezione 4 inizia con `analyze-openapi`, `security-inventory`, `generate-tests`, `workflow-map` e `auto-assess` in modalità offline. Analizza quali operazioni sono saltate e perché.
6. Solo dopo il controllo dello scope abilita `auto-assess` attivo. Valuta differenze tra identità e risposte, sapendo che ogni HTTP 200/403/500 richiede interpretazione contestuale.
7. Se vuoi testare scritture, configura `resources.yaml` **per i soli oggetti disposable** e assicurati che ogni oggetto abbia una procedura di cleanup affidabile. Non copiare il manifesto del laboratorio in produzione: è specifico dei suoi endpoint.
8. Usa `coverage-report`, `vulnerability-triage`, `verify-access-policy` e, se utile, l'analisi Ollama locale per la revisione. I finding non provati vanno classificati come inconcludenti.
9. Scarica i report, verifica la riproducibilità delle evidenze e redigi remediation compatibili con il progetto del cliente.

**Sicurezza:** la dashboard è locale ma non sostituisce un sistema di autorizzazione. Non esporla via port forwarding, reverse proxy o alla LAN. Evita di caricare dati personali e segreti nelle configurazioni o nei log. Per autenticazione/SSO e workflow di business non standard servirà sempre un minimo di contesto applicativo; lo Swagger da solo non basta.

---

## 8. Problemi frequenti e soluzioni

**Il selettore file non apre nulla / il file non appare:** assicurati di essere sulla dashboard v0.40, non su un vecchio server v0.39 ancora in ascolto. Ferma l'istanza vecchia con Ctrl+C, riavvia `uv run achillesapi dashboard --port 8766` nella cartella della nuova versione e fai ricarica completa `Ctrl+F5`. In alternativa incolla OpenAPI, auth o manifest direttamente nei rispettivi editor.

**`Invalid OpenAPI specification`:** il file caricato deve essere `openapi.json` o `.yaml`, non una risposta HTTP, un JWT o `auth.yaml`. Controlla che dichiari `openapi: 3...`, `info` e `paths`.

**`Invalid authentication profile file`:** controlla l'indentazione YAML, `profiles:` e le chiavi `name`, `type`, `token_env` (o quelle richieste dal tipo). Nella configurazione non inserire token hard-coded.

**`Environment variable ... required`**: compila il campo segreto corrispondente in dashboard oppure esporta le variabili nel terminale prima dell'avvio; verifica di aver selezionato il profilo giusto.

**`Target URL is not in the explicit host allowlist`:** Base URL e hostname devono corrispondere senza includere schema/porta nel campo host. Esempio `http://127.0.0.1:8795` e `127.0.0.1`, non `127.0.0.1:8795` nell'hostname.

**`Provide --base-url`**: se lo Swagger non contiene esattamente un server valido, devi compilare Base URL anche per il piano offline.

**`Only one scan may run at a time`:** attendi la conclusione del job attuale. La dashboard limita la concorrenza per non sovraccaricare l'API.

**`Workflow actions require a base URL`**: aggiungi l'indirizzo del target nella sezione 2, anche per la pianificazione.

**`Another task is running` / timeout**: aggiorna lo stato nella sezione 5; se il target è lento abbassa il rate e il budget.

**HTTP 401/403 in molte GET**: verifica credenziali, tipo di autenticazione, scadenza del token e specifica OpenAPI. Un 403 non è di per sé una vulnerabilità; può essere il risultato atteso.

**Ollama offline**: installa Ollama sul computer e avvialo dall'interfaccia o dal terminale. La preparazione del modello richiede download una tantum; le inferenze successive rimangono locali. Non è necessario Ollama per i controlli deterministici.

**Errore nel cleanup**: non ripetere alla cieca una scansione attiva. Controlla il report e, con il proprietario dell'applicazione, verifica se risorse temporanee sono ancora presenti.

---

## 9. Test e limiti dichiarati

Questa revisione è stata validata con test di import file, incolla JSON/YAML, credenziali e scope. È stata effettuata anche una prova end-to-end reale su FastAPI standalone, avviata in un processo separato: upload Swagger e auth, credenziali fornite per job e **12 GET** verso `127.0.0.1:8795`, senza token nei report. Non sono state testate nel browser Windows tutte le combinazioni di ogni strumento, né è stata effettuata una inferenza reale con Ollama. Alcuni controlli legacy specialistici rimangono solo CLI.

**Regola pratica:** se il tool indica un'operazione "blocked" o "manual-only", considera quella parte non testata. Non interpretare il semplice completamento di un job come prova di copertura completa dell'API.
