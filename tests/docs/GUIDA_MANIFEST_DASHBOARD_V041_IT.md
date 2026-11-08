# AchillesAPI v0.41 — Guida al manifest e agli errori della dashboard

## 1. Che cos'è il manifest e perché è richiesto

Il **manifest** (`resources.yaml`) non è lo Swagger e non contiene i token. È una descrizione *approvata da chi esegue il pentest* del ciclo di vita di risorse di test **temporanee**: come crearle con POST, riconoscerle tramite ID e marcatore, confrontarne l'accesso con account diversi, modificarle se consentito e cancellarle con DELETE. AchillesAPI non deve inventare il permesso di modificare dati aziendali solo perché lo Swagger contiene POST o DELETE.

**Se vuoi eseguire soltanto controlli GET**, usa `auto-assess` e **non selezionare «Approvo esplicitamente le scritture»**: non serve alcun manifest. Se invece abiliti le scritture, sono necessari insieme: manifest, `auth.yaml`, URL e host autorizzati, spunta «Esegui richieste», conferma dell'autorizzazione e approvazione delle scritture.

## 2. Avvio del laboratorio indipendente (PowerShell)

Estrai **Independent-Vulnerable-API-Lab.zip** in una cartella diversa da AchillesAPI. Nel primo terminale apri `independent-api-lab` e avvia:

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

Verifica `http://127.0.0.1:8795/docs`. Il laboratorio è separato da AchillesAPI, gestisce dati fittizi in memoria e non deve essere esposto su Internet.

Nel secondo terminale entra nella cartella `achillesapi` (framework v0.41) e usa:

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dashboard --extra pdf --extra dev
uv run achillesapi dashboard --port 8766
```

Apri `http://127.0.0.1:8766` nel browser.

## 3. Configurazione dei cinque passaggi della dashboard

**Passaggio 1 — Swagger:** carica il file `independent-api-lab/openapi.json` dal computer (oppure incollalo). L'app mostra titolo e operazioni.

**Passaggio 2 — Target e limiti:** Base URL `http://127.0.0.1:8795`; host autorizzato `127.0.0.1`; limite richieste `40` per le sole GET, **almeno 30** per le prove complete di scrittura su più risorse; richieste al secondo `2`; attiva «Consenti HTTP non cifrato» perché questo laboratorio usa HTTP su loopback. Su target reali usa HTTPS e l'host autorizzato dal cliente.

**Passaggio 3 — Autenticazione:** importa `independent-api-lab/auth.yaml`:

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

Nei campi segreti generati inserisci rispettivamente `demo-owner`, `demo-other`, `demo-admin`. In «Identità da confrontare» usa `owner,other,admin`. Questi sono **nomi di profilo**, non nomi delle variabili.

**Passaggio 4 — Test:** prima scegli `auto-assess` e premi «Genera piano offline». Per le GET, lascia non selezionata l'approvazione delle scritture, abilita l'esecuzione e conferma l'autorizzazione. Per i test CRUD usa il creatore di manifest descritto qui sotto.

**Passaggio 5 — Risultati:** seleziona il job completato, consulta osservazioni/triage e scarica il report. Un HTTP 200 da un altro utente non dimostra di per sé una BOLA se non è definita la policy di accesso attesa.

## 4. Crea `resources.yaml` senza scriverlo da zero

Nel Passaggio 4 trovi **«Crea il manifest delle risorse di test»**.

1. Clicca «1. Trova workflow nello Swagger». L'app cerca **POST /collection**, **GET /collection/{id}** e **DELETE /collection/{id}**, tutti documentati nello Swagger. La ricerca è offline.
2. Seleziona `POST /projects → GET /projects/{project_ref} → DELETE /projects/{project_ref}` (nel laboratorio è la proposta individuata). Scegli proprietario `owner` e altra identità `other`, marker `label`.
3. Clicca «2. Genera bozza YAML». La dashboard crea la struttura `resources:` e un payload di esempio. **Non invia richieste.**
4. Controlla il campo identificativo: lo Swagger del laboratorio non dichiara il JSON della risposta POST. Perciò la bozza contiene `/REVIEW_ID_FIELD`: sostituisci **entrambe** le occorrenze (`id_pointer` e `read_id_pointer`) con `/id`. Lo puoi verificare dall'app FastAPI o tramite una chiamata autorizzata di prova. Non usare un campo ID inventato su API reali.
5. Modifica il body con dati di test approvati (nel lab basta `label: temporary-resource`). Controlla che il marker sia una proprietà stringa scrivibile e che GET restituisca marker e ID.
6. Clicca «3. Controlla manifest (offline)». Se un campo manca la dashboard ti dirà quale prerequisito verificare. Il controllo non invia richieste.
7. Clicca «4. Usa manifest in assessment». Il YAML viene importato nel workspace e selezionato come manifest multi-resource. Puoi anche cliccare «Scarica resources.yaml» per conservarlo.
8. Seleziona `multi-resource-assess` (o `auto-assess` per test combinati), abilita «Esegui richieste HTTP», conferma autorizzazione e approva le scritture. Prima di procedere assicurati di testare solo dati fittizi e che DELETE abbia l'effetto atteso.

La bozza automatica costruisce **una risorsa indipendente**. Per il test completo con due risorse collegate importa invece `independent-api-lab/resources.yaml`: esso contiene le variabili `${project.id}` e `${ticket.id}`, le PATCH e i cleanup nell'ordine corretto. Anche qui seleziona «Più risorse (resources.yaml)» e usa `multi-resource-assess` oppure `auto-assess` combinato.

### Esempio di manifest pronto per il laboratorio (una risorsa)

```yaml
resources:
  - name: resource
    create: POST /projects
    read: GET /projects/{project_ref}
    delete: DELETE /projects/{project_ref}
    identity: owner
    body:
      label: temporary-resource
    marker_field: label
    marker_pointer: /label
    id_pointer: /id
    read_id_pointer: /id
    path_values:
      project_ref: ${resource.id}
    access:
      - identity: other
        expected: deny
```

**Spiegazione:** `name` è un nome locale del workflow; `create/read/delete` devono esistere nello Swagger; `identity` è il profilo che crea la risorsa; `body` è il JSON della POST; `marker_field` identifica il campo su cui il tool inserisce un valore casuale; `marker_pointer` indica dove il marker compare nella GET; `id_pointer` è il percorso JSON dell'ID restituito dalla POST; `read_id_pointer` è il percorso ID nella GET; `path_values` trasferisce l'ID creato nel percorso; `access` dichiara che l'altro account **non dovrebbe** poter leggere la risorsa. Queste policy devono essere confermate dal proprietario dell'API.

## 5. Valori numerici: limiti e messaggi

- **Richieste al secondo:** minimo `0.1`, massimo `5`, default `1`. Se tenti `40`, il campo viene ricondotto a `5` prima dell'invio. Il backend applica comunque il limite.
- **Numero massimo di richieste:** minimo `1`, massimo `150`, default `40`.
- **Budget follow-up:** minimo `0`, massimo `15`.

Il browser limita gli input numerici anche quando vengono incollati; il server è sempre la seconda linea di controllo.

## 6. Errori comuni: cosa significano e come risolverli

| Messaggio / situazione | Causa | Correzione |
|---|---|---|
| `Combined write assessment requires manifest...` | Approvate scritture senza i prerequisiti | Crea/carica `resources.yaml`, importa auth, attiva esecuzione e conferma scritture; oppure togli la spunta per fare solo GET |
| `rate` oltre 5 | Valore non consentito | Usa `1` o `2`, mai `40` come rate; `40` va in Max Requests |
| `REVIEW_ID_FIELD` | Swagger non dichiara il campo ID di risposta | Verifica il JSON restituito da POST e GET; nel laboratorio sostituisci con `/id` |
| `undefined identity` | Il nome del profilo nel manifest non esiste in `auth.yaml` | Usa esattamente `owner`, `other`, `admin` oppure aggiorna auth.yaml |
| `missing path values` | Un endpoint richiede un parametro dinamico | Aggiungi `path_values`, eventualmente con `${resource.id}` |
| `marker must be writable string` | Campo marker non adatto al controllo di ownership | Scegli una proprietà stringa modificabile dichiarata nello schema e adatta a un marker univoco |
| `Request budget...` | Troppo poche richieste per create/read/delete/verify | Aumenta il budget rispettando il limite, oppure riduci le risorse di test |
| `Target outside scope` | URL e hostname non coincidono | Verifica Base URL e host esplicito autorizzato |
| `Environment variable ... required` | Token/password di un profilo assente | Compila il campo segreto nel Passaggio 3 |
| `Connection refused` | API target spenta o porta sbagliata | Avvia l'API nel terminale indipendente, controlla la porta |
| `Cleanup manual required` | Non è stato possibile verificare la cancellazione | Interrompi ulteriori scritture e verifica manualmente le risorse di test |
| `Ollama` non disponibile | Runtime AI locale non pronto | Avvia Ollama oppure disattiva il modello AI |

I nuovi messaggi per gli errori di validazione non mostrano più oggetti tecnici come `loc`, `ctx` o il contenuto dei segreti. Esiste comunque un messaggio di fallback per errori imprevisti: non è possibile garantire una descrizione specifica di ogni eccezione proveniente da sistemi esterni.

## 7. Come usarlo domani su una vera API

Non usare il manifest del laboratorio né i suoi token. Fai ottenere dal cliente: Swagger/OpenAPI, Base URL degli ambienti autorizzati, hostname/CIDR in scope, account di test con ruoli distinti, identificativi di risorse di test autorizzate, policy di ownership, vincoli di traffico e una procedura di pulizia. Importa lo Swagger, genera il piano offline, imposta le identità, esegui prima GET, poi crea/valida un manifest con **risorse disposable e cleanup garantito nella pratica**. Se il servizio non consente una pulizia affidabile, evita la scrittura automatica e pianifica la verifica manuale con il cliente.

La dashboard è uno strumento di assessment **supervisionato**, non una certificazione di assenza di vulnerabilità. Il laboratorio rimane un processo esterno, completamente indipendente.
