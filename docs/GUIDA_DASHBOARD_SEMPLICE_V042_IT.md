# AchillesAPI v0.42 — Guida semplice alla dashboard

## Cosa cambia

Non devi modificare `resources.yaml`, compilare `REVIEW_ID_FIELD` o conoscere la sintassi del manifest. La dashboard ha una procedura **in quattro schermate** che crea e convalida in automatico la configurazione tecnica. La procedura è offline: non invia richieste all'API. Le operazioni di scrittura richiedono comunque una conferma esplicita.

Il laboratorio è indipendente dal framework; si avvia separatamente nel terminale e AchillesAPI lo vede come qualunque API HTTP autorizzata.

## 1. Avvio del laboratorio (terminal 1, Windows)

Estrai `Independent-Vulnerable-API-Lab.zip` in una cartella e apri PowerShell dentro `independent-api-lab`:

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

Controlla `http://127.0.0.1:8795/docs`. Non chiudere il terminale.

## 2. Avvio di AchillesAPI (terminal 2, Windows)

Estrai `AchillesAPI-v0.42.0-Guided-Workflow.zip` e apri PowerShell in `achillesapi`:

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dashboard --extra pdf --extra dev
uv run achillesapi version
uv run achillesapi dashboard --port 8766
```

Apri `http://127.0.0.1:8766` in un browser sullo stesso computer. La dashboard ascolta solo su loopback.

## 3. Passaggio 1: Swagger

Nel blocco **Carica la specifica OpenAPI** premi il selettore file e scegli `independent-api-lab/openapi.json`, dal pacchetto del laboratorio (non da AchillesAPI). Attendi il messaggio di conferma e l'elenco degli endpoint.

Su un target aziendale: importa lo Swagger/OpenAPI *fornito dal committente* (JSON o YAML). Non è necessario modificare il codice di AchillesAPI.

## 4. Passaggio 2: URL e limiti

| Campo | Laboratorio |
|---|---|
| Base URL | `http://127.0.0.1:8795` |
| Host autorizzato | `127.0.0.1` |
| Massimo richieste | `40` (per test di un solo progetto) |
| Richieste al secondo | `2` |
| Consenti HTTP con credenziali | **Sì**, solo perché è il laboratorio su localhost |

Su un target aziendale: Base URL HTTPS e hostname precisamente incluso nell'autorizzazione del test, limiti pattuiti con il cliente, non abilitare HTTP non cifrato.

## 5. Passaggio 3: account

Carica `independent-api-lab/auth.yaml`. Definisce tre profili (`owner`, `other`, `admin`) e richiede tre token. Inseriscili direttamente nei campi che compaiono:

| Campo | Token laboratorio |
|---|---|
| `ACHILLES_LAB_OWNER` | `demo-owner` |
| `ACHILLES_LAB_OTHER` | `demo-other` |
| `ACHILLES_LAB_ADMIN` | `demo-admin` |

Nel campo «Identità da confrontare» scrivi `owner,other,admin`. I token **non** vanno copiati dentro `auth.yaml`.

### Che cos'è auth.yaml?

È soltanto la descrizione del metodo di autenticazione e dei nomi dei profili. Per il laboratorio:

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

Per una API reale: usa profili di test approvati dal cliente. Nella dashboard puoi generare un modello di `auth.yaml`; non mettere password e token reali nel file.

## 6. Passaggio 4: primo controllo senza scritture

Scegli `auto-assess`, clicca **Genera piano offline**; verifica le informazioni riconosciute. Quindi abilita «Esegui richieste HTTP» e «Confermo di avere l'autorizzazione» e avvia. Per questa modalità GET **non serve alcun manifest**. Guarda l'esito nella sezione risultati.

## 7. Passaggio 4: test che creano e cancellano un oggetto (procedura guidata)

Scorri fino a «**Crea un test di sicurezza che usa risorse temporanee**».

**Schermata 1 — Quale risorsa?** Premi «Trova automaticamente le risorse». Scegli la sequenza `POST /projects → GET /projects/{project_ref} → DELETE /projects/{project_ref}`. Clicca Continua.

**Schermata 2 — Con quali utenti?** Scegli `owner` come proprietario e `other` come altro utente. Mantieni la spunta sulla regola «il secondo utente non deve leggere la risorsa», perché *nel laboratorio* è la regola attesa. Su API reali questa regola va verificata con il cliente. Clicca Continua.

**Schermata 3 — Quali dati?** Nel campo `label` scrivi `verifica-temporanea`; scegli `label` come campo che identifica la risorsa di test. Non servono altri campi per `POST /projects`. Clicca Continua.

**Schermata 4 — Dove si trova l'ID?** Il laboratorio restituisce alla POST qualcosa di simile a:

```json
{"id":"prj-12345"}
```

Quindi in «Nome della proprietà contenente l'ID» scrivi **`id`** (senza barra, non il codice `prj-12345`). Se vuoi incolla l'esempio JSON sopra e premi «Trova il campo ID da questo esempio». Conferma che il laboratorio consente risorse temporanee eliminabili. Premi «Controlla e prepara il test».

Dovresti vedere **«Configurazione pronta»**. Il sistema ha generato, validato e caricato il manifest in automatico. **Non devi aprire o correggere YAML.** Clicca «Vai a eseguire il test».

Ora seleziona «Esegui richieste HTTP», «Confermo di avere l'autorizzazione» e «Approvo esplicitamente le scritture». Verifica che lo strumento selezionato sia `multi-resource-assess`. Clicca «Avvia strumento selezionato». I risultati e l'eventuale necessità di cleanup manuale appariranno nella sezione 5.

La sequenza crea e cancella un progetto temporaneo. Per il workflow **di due risorse** (progetto e ticket) puoi caricare `resources.yaml` originale del laboratorio dalla sezione «Hai già un file di configurazione?», perché è un caso più articolato che richiede dipendenze tra risorse.

## 8. E se domani uso una API aziendale vera?

L'operazione è la stessa:

1. Carichi lo Swagger aziendale.
2. Inserisci il Base URL HTTPS e l'host esattamente autorizzato.
3. Configuri account di test con privilegi diversi usando `auth.yaml`, mantenendo credenziali e token fuori dal file.
4. Avvii `auto-assess` prima **offline**, poi GET autorizzate.
5. Per test con scritture apri la procedura guidata. Scegli la risorsa, inserisci soltanto dati fittizi autorizzati, specifica la regola di accesso attesa e il nome della proprietà ID **realmente restituita** dalla POST (se lo Swagger è incompleto, chiedila allo sviluppatore o verifica su staging).
6. Approvi le scritture solo dopo aver confermato che DELETE può eliminare quella specifica risorsa di test. Se l'API non offre un ciclo di pulizia sicuro, fai solo GET oppure configura manualmente un procedimento concordato col cliente.
7. Controlli i risultati, i finding non confermati e l'esito di cleanup, quindi esporti report HTML/PDF.

**Non è corretto indovinare ID, regole di ownership o una procedura DELETE sicura.** Se mancano nello Swagger, la dashboard deve richiedere un'informazione leggibile, non inventarla né eseguire POST/DELETE su dati reali.

## 9. Problemi comuni

| Messaggio | Cosa fare |
|---|---|
| «Carica prima lo Swagger» | Torna al passaggio 1 e importa OpenAPI |
| «Carica auth.yaml» | Importa i profili al passaggio 3 e compila i token |
| «Il campo label è obbligatorio» | Indica un testo per creare l'oggetto temporaneo |
| «Indica il nome del campo ID» | Guarda la risposta JSON di una POST approvata o chiedi allo sviluppatore: nel laboratorio è `id` |
| «Non sono stati trovati cicli» | Non eseguire scritture: l'API potrebbe non offrire DELETE o non essere sicura per prove disposable |
| «Budget insufficiente» | Aumenta Max Requests entro il limite autorizzato o riduci il test |
| «Impossibile eseguire cleanup» | Consulta il report: può essere necessario cancellare manualmente risorse temporanee |

La dashboard non contiene il laboratorio e non può avviarlo. Il server di test si esegue sempre separatamente nel terminale.
