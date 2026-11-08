# AchillesAPI

**Framework locale per l'analisi di sicurezza delle API a partire da Swagger / OpenAPI.**

AchillesAPI importa una specifica **OpenAPI 3.x** in JSON o YAML, ricostruisce endpoint e superfici di attacco, pianifica ed esegue (solo quando autorizzato) controlli HTTP, correla evidenze, organizza i risultati in una **dashboard web** e può usare **Ollama in locale** per assistere l'analista. Il laboratorio dimostrativo è **separato** dal framework: non è necessario per analizzare un'API reale.

> **Versione documentata: 0.53.0.** Release di sviluppo destinata a penetration test autorizzati. Non è uno scanner universale: le analisi di logica applicativa, l'autenticazione e i workflow richiedono talvolta input dell'operatore. Un finding non equivale automaticamente a una vulnerabilità confermata.

## Indice

- [1. Requisiti](#1-requisiti)
- [2. Installazione in 3 minuti](#2-installazione-in-3-minuti)
- [3. Prima scansione dalla dashboard](#3-prima-scansione-dalla-dashboard)
- [4. Installare e configurare Ollama](#4-installare-e-configurare-ollama)
- [5. Autenticazione e profili](#5-autenticazione-e-profili)
- [6. Suite completa automatizzata](#6-suite-completa-automatizzata)
- [7. Task saltati e generatori guidati](#7-task-saltati-e-generatori-guidati)
- [8. Risultati, evidenze e report](#8-risultati-evidenze-e-report)
- [9. Utilizzo da CLI](#9-utilizzo-da-cli)
- [10. Test con il laboratorio indipendente](#10-test-con-il-laboratorio-indipendente)
- [11. Risoluzione problemi](#11-risoluzione-problemi)
- [12. Sicurezza, limiti e privacy](#12-sicurezza-limiti-e-privacy)

## 1. Requisiti

| Componente | Requisito |
|---|---|
| Sistema operativo | Windows 10/11 (PowerShell) oppure Linux, incluso Kali |
| Python | **3.12 consigliato**; il progetto dichiara `>=3.11`. Evita versioni sperimentali come 3.15 |
| Gestore Python | [`uv`](https://docs.astral.sh/uv/getting-started/installation/) |
| Browser | Browser moderno per la dashboard |
| API | Swagger / **OpenAPI 3.x** `.json`, `.yaml` o `.yml` |
| Ollama | **Facoltativo**, necessario solo per le funzioni AI locali |
| GPU | Non obbligatoria: Ollama può funzionare su CPU; con 8 GB RAM usare un modello piccolo e poca concorrenza |

**Nota:** il download iniziale di dipendenze Python e modelli Ollama necessita di rete. Una volta installati, l'inferenza Ollama non richiede servizi LLM cloud.

## 2. Installazione in 3 minuti

### Windows — PowerShell

1. Installa `uv` seguendo le [istruzioni ufficiali](https://docs.astral.sh/uv/getting-started/installation/) e apri un nuovo terminale.
2. Scarica il progetto, estrai lo ZIP oppure clona il repository, quindi **entra nella cartella contenente `pyproject.toml`**.
3. Esegui:

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dashboard --extra pdf --extra dev
uv run achillesapi version
uv run achillesapi dashboard --port 8766
```

### Kali Linux / Linux

Installa `uv` con le [istruzioni ufficiali](https://docs.astral.sh/uv/getting-started/installation/), poi dalla root del progetto:

```bash
uv python install 3.12
uv sync --python 3.12 --extra dashboard --extra pdf --extra dev
uv run achillesapi version
uv run achillesapi dashboard --port 8766
```

**Apri [http://127.0.0.1:8766](http://127.0.0.1:8766).** La dashboard è disponibile solo su loopback: non esporla direttamente su Internet o sulla LAN. Se la porta è occupata, usa `--port 8767` e cambia l'URL nel browser.

> Per una normale installazione basta `--extra dashboard --extra pdf`; `--extra dev` aggiunge gli strumenti per sviluppare e testare. Il PDF è già compreso nell'extra dashboard, ma l'opzione esplicita non crea problemi.

## 3. Prima scansione dalla dashboard

**Non serve scrivere comandi CLI per l'uso normale.** La pagina iniziale guida attraverso i passaggi seguenti.

### Passaggio 1 — Carica Swagger/OpenAPI

Carica un file `.json`, `.yaml` o `.yml` (OpenAPI 3.x), oppure incolla il contenuto nell'apposito campo. Il documento può provenire dal team di sviluppo o dall'endpoint OpenAPI dell'applicazione (per esempio `/openapi.json`), **se previsto e accessibile con autorizzazione**. Non confondere lo Swagger con un report di evidenze.

### Passaggio 2 — Configura target e scope

Imposta:

- **Base URL:** indirizzo reale dell'API nell'ambiente autorizzato, ad esempio `https://staging.example.com`.
- **Hostname autorizzato:** soltanto il nome host, ad esempio `staging.example.com`, senza `https://`, porta o percorso.
- **Limite richieste** e **richieste al secondo:** controllano il traffico attivo secondo i limiti previsti dallo strumento.

Per provare una normale analisi **offline** non serve abilitare l'esecuzione HTTP. Con HTTP non cifrato e credenziali sono previsti controlli specifici per il solo laboratorio locale (`localhost`/`127.0.0.1`). **Per ambienti reali usa HTTPS**.

### Passaggio 3 — Utenti e autenticazione (facoltativo)

Per endpoint pubblici puoi iniziare senza credenziali. Per test autorizzativi, BOLA/BFLA e accessi differenziati, carica `auth.yaml` o usa il generatore della dashboard; poi fornisci i valori richiesti nei campi per le variabili d'ambiente.

### Passaggio 4 — Scegli i controlli

Esegui prima **Genera piano offline** per osservare la superficie di attacco senza inviare traffico all'API. Per i controlli HTTP, abilita **Esegui richieste HTTP** e conferma di avere autorizzazione sul target. **Le operazioni POST/PATCH/DELETE** hanno approvazioni e manifest aggiuntivi: usa soltanto fixture temporanee, dati fittizi e cleanup verificabile.

### Passaggio 5 — Apri risultati e report

Nella sezione attività puoi visualizzare i job, aprire la pagina interattiva del risultato, filtrare le osservazioni e usare gli export disponibili (HTML/PDF/JSON). Le evidenze di un test attivo sono diverse dalle ipotesi generate da un piano offline.

## 4. Installare e configurare Ollama

L'AI è **opzionale**. AchillesAPI usa Ollama **localmente**, con endpoint previsto `http://127.0.0.1:11434`. Non è richiesto alcun account o token OpenAI; non è implementato un fallback automatico verso modelli cloud. Verifica comunque le policy aziendali sull'uso locale di dati e modelli.

### 4.1 Installa Ollama

**Windows:** installa Ollama da [ollama.com/download](https://ollama.com/download). Avvialo dal menu Start; normalmente resta attivo in background. Apri una **nuova finestra PowerShell**:

```powershell
ollama --version
ollama list
```

**Kali / Linux:** segui le [istruzioni ufficiali Ollama](https://ollama.com/download/linux), ad esempio:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama --version
```

Il comando di installazione remoto va eseguito soltanto dopo aver verificato l'origine e secondo le policy della macchina. Su Linux il servizio potrebbe avviarsi tramite `systemd`; se non è in esecuzione, usa `sudo systemctl start ollama` oppure `ollama serve` in un terminale dedicato (non entrambi sulla stessa porta).

### 4.2 Scarica il modello e crea `achilles-local`

**Dalla cartella principale del repository** (quella che contiene `deployment/Modelfile`):

```powershell
ollama pull llama3.2:3b
ollama create achilles-local -f .\deployment\Modelfile
ollama list
```

Su **Linux**, cambia soltanto il percorso del Modelfile:

```bash
ollama pull llama3.2:3b
ollama create achilles-local -f deployment/Modelfile
ollama list
```

Il `deployment/Modelfile` incluso usa `FROM llama3.2:3b`, parametri per output contenuto e istruzioni per produrre analisi strutturate senza inventare evidenze. **Esegui prima `ollama pull`**: `ollama create` non funziona correttamente se il modello base o il Modelfile non è disponibile.

### 4.3 Verifica Ollama

```powershell
ollama run achilles-local "Spiega brevemente cosa significa BOLA nelle API"
```

In PowerShell verifica anche l'endpoint:

```powershell
Invoke-RestMethod http://127.0.0.1:11434/api/tags
```

Su Linux:

```bash
curl --fail http://127.0.0.1:11434/api/tags
```

Se `achilles-local` compare tra i modelli e l'endpoint risponde, torna alla dashboard, premi **Aggiorna stato**, indica **Modello Ollama: `achilles-local`** e abilita **Usa Ollama locale** oppure **Includi tutti i controlli con Ollama locale** nella suite.

La dashboard dispone anche dei pulsanti **Avvia Ollama** e **Installa modello locale**: potrebbero eseguire operazioni locali e scaricare il modello, quindi richiedono conferma. La procedura manuale qui sopra è utile per diagnosticare eventuali problemi.

### 4.4 Linux: limita Ollama a loopback

Il progetto include `deployment/configure-ollama-kali.sh`, uno script di configurazione del servizio `systemd`. **Verifica il contenuto dello script prima di eseguirlo**, perché modifica la configurazione del servizio:

```bash
sudo bash deployment/configure-ollama-kali.sh
sudo systemctl restart ollama
ss -lntp | grep 11434
```

Il listener deve essere locale (`127.0.0.1:11434`), non `0.0.0.0`. Lo script imposta anche `OLLAMA_NO_CLOUD=1`. Su Windows controlla nelle impostazioni del servizio che Ollama non sia esposto a host remoti.

### 4.5 Requisiti hardware e alternative

- **CPU senza GPU, 8 GB RAM:** `llama3.2:3b` è il modello predefinito del progetto; con carico elevato può risultare lento. Valuta un modello più piccolo, ma **devi impostarne il nome nella dashboard** e la qualità delle risposte può ridursi.
- **GPU NVIDIA compatibile:** l'inferenza può essere più veloce, a seconda di driver, RAM/VRAM e modello.
- **Senza Ollama:** disabilita i controlli AI; discovery, pianificazione offline e controlli tradizionali rimangono disponibili.

## 5. Autenticazione e profili

L'autenticazione non è sempre deducibile dallo Swagger. Usa il generatore guidato della dashboard oppure un file `auth.yaml` con **nomi di variabili**, non token in chiaro.

Esempio Bearer con due identità:

```yaml
profiles:
  - name: owner
    role: user
    type: bearer
    token_env: ACHILLES_OWNER_TOKEN
  - name: other
    role: user
    type: bearer
    token_env: ACHILLES_OTHER_TOKEN
```

**Windows PowerShell** (stessa sessione con cui avvii la dashboard):

```powershell
$env:ACHILLES_OWNER_TOKEN = "<TOKEN_DI_TEST_OWNER>"
$env:ACHILLES_OTHER_TOKEN = "<TOKEN_DI_TEST_OTHER>"
```

**Kali/Linux**:

```bash
export ACHILLES_OWNER_TOKEN='<TOKEN_DI_TEST_OWNER>'
export ACHILLES_OTHER_TOKEN='<TOKEN_DI_TEST_OTHER>'
```

In alternativa inserisci i valori nei campi segreti della dashboard, quando richiesti. Le variabili configurate in un terminale non sono automaticamente disponibili a un processo già avviato in un altro terminale: **riavvia la dashboard nello stesso ambiente** oppure usa i campi della UI.

Altri tipi documentati includono **API key** (header), **Basic**, **cookie**, **OAuth2 client credentials** e **login JSON**, con configurazioni specifiche. Vedi [`examples/auth-profiles.example.yaml`](examples/auth-profiles.example.yaml) e i controlli guidati della dashboard. Non inserire password reali nello Swagger, nel manifest o nel repository Git.

## 6. Suite completa automatizzata

Nella dashboard apri **Suite completa · Un solo avvio**. La suite orchestra le funzionalità applicabili, riutilizza gli assessment precedenti e raggruppa i job figli sotto un'unica esecuzione **collassabile**.

Opzioni disponibili:

| Opzione | Significato |
|---|---|
| **Includi verifiche HTTP attive** | Consente test sul target autorizzato; non è necessario per il piano offline |
| **Includi Ollama locale** | Abilita funzioni AI quando modello e servizio sono disponibili |
| **Controlli aggiuntivi e agent** | Include ulteriori check compatibili con i prerequisiti |
| **Workflow con scritture** | Abilita la valutazione di task POST/PATCH/DELETE solo con manifest, scope e consenso specifici |
| **Budget HTTP suite** | Numero massimo **riservato** di richieste tra i task attivi (intervallo UI: 1–600 nella v0.53) |

**Importante sul budget:** è un limite di pianificazione **conservativo** che riserva capacità per task; non è un conteggio esatto garantito del traffico realmente generato, né un limite di spesa. I controlli applicano anche i loro limiti specifici. Per ambienti condivisi usa rate e budget ridotti e monitora il sistema.

Quando un task non può partire, compare come **saltato/non avviato**, non come test superato. Apri **Risultati suite** per navigare i task e i loro finding nella stessa pagina, oppure apri il risultato individuale.

## 7. Task saltati e generatori guidati

Nella vista della suite espandi il task bloccato e scegli **Completa prerequisiti e riprova soltanto questo task**. Nella v0.53 sono presenti generatori guidati per diversi formati; non serve scrivere direttamente JSON/YAML se il builder copre il tuo caso.

| Task | Dati richiesti | Come prepararli |
|---|---|---|
| `journey-assess` | Manifest di una sequenza GET | Seleziona gli endpoint dello Swagger, identità e valori necessari |
| `workflow-assess` | Manifest workflow | Usa il generatore POST → GET → DELETE quando la specifica supporta una fixture eliminabile; il campo ID `id` viene convertito in `/id` |
| `multi-resource-assess` | Manifest di risorse disposable | Seleziona owner, altre identità, operazioni e cleanup approvato |
| `analyze-evidence` | Bundle di osservazioni HTTP con array `responses` | Genera le evidenze da un precedente `auto-assess` **attivo**; se non esistono risposte reali, non possono essere inventate |
| `verify-access-policy` | Regole di accesso | Definisci nel modulo i ruoli, le risorse e le aspettative `allow`/`deny` |
| `benchmark-evaluate` | Configurazione benchmark + assessment | Inserisci **ground truth confermata indipendentemente** e seleziona l'assessment da valutare |
| Test autenticati | `auth.yaml` e credenziali | Genera/carica i profili e inserisci i token richiesti |

**Esempio di struttura corretta delle evidenze** (se importate da una fonte autorizzata, anziché generate dalla dashboard):

```yaml
responses:
  - method: GET
    path: /health
    status_code: 200
    headers: {}
```

Un normale report di finding **non** sostituisce le evidenze HTTP. La versione 0.53 verifica lo schema `responses` prima di tentare l'analisi. Analogamente, un benchmark **non** deve ricavare automaticamente la verità dai finding dello scanner: servono etichette indipendenti.

Dopo la generazione, premi **Valida** e poi **Riprova task**. Il retry esegue **solo il task scelto**, mantenendolo collegato alla suite; per azioni attive e scritture richiede ancora scope e autorizzazioni. I job della dashboard sono mantenuti in memoria: dopo il riavvio del server i link di esecuzione precedenti potrebbero non essere recuperabili.

## 8. Risultati, evidenze e report

- **Vista suite:** riepilogo dei task completati, falliti e saltati; elenco dei job e risultati navigabili.
- **Viewer interattivo del singolo job:** sezioni espandibili, ricerca/filtri dei finding e dettagli disponibili.
- **Indicatori di sicurezza:** severità e anomalie vengono evidenziate quando presenti nei dati, ma **non equivalgono a conferme di sfruttabilità**.
- **Export:** report HTML, PDF e JSON dove supportati. L'output dipende dai dati prodotti dal relativo task.
- **Ollama:** fornisce supporto interpretativo e correlazione, non prova autonomamente l'esistenza di una vulnerabilità.

Tieni distinte **analisi offline**, **osservazioni HTTP reali**, **ipotesi** e **finding verificati** quando utilizzi il report con un cliente.

## 9. Utilizzo da CLI

La dashboard è l'interfaccia principale, ma i comandi CLI rimangono disponibili:

```powershell
uv run achillesapi --help
uv run achillesapi auto-assess --help
uv run achillesapi analyze-evidence --help
uv run achillesapi workflow-assess --help
```

**Esempio: genera un piano offline da Swagger** (senza richieste al target):

```powershell
uv run achillesapi auto-assess .\swagger.yaml --output .\reports\piano.json
```

**Esempio: test GET su staging autorizzato**:

```powershell
uv run achillesapi auto-assess .\swagger.yaml --base-url https://staging.example.com --allow-host staging.example.com --execute --output .\reports\assessment.json
```

**Esempio: scansione passiva con AI locale** (vedi le opzioni disponibili nella versione installata):

```powershell
uv run achillesapi scan .\swagger.yaml --ai --model achilles-local --output .\reports\scan-ai.json
```

Su Linux usa `/` per i percorsi dei file. Per tutte le opzioni (profili, rate, timeout, manifest e approvazioni) preferisci `uv run achillesapi <nome-comando> --help`: **le opzioni non sono identiche per ogni comando**. Non aggiungere `--execute` o `--approve-writes` senza avere verificato scope, impatto e permessi.

## 10. Test con il laboratorio indipendente

Il **laboratorio vulnerabile** è un progetto **separato** distribuito con un proprio archivio; non è avviato automaticamente da AchillesAPI e non esistono endpoint di laboratorio hardcoded nel framework.

Procedura tipica:

1. Estrai il laboratorio in una cartella **differente** da AchillesAPI.
2. Segui il suo `README` o gli script `start.ps1` (Windows) / `start.sh` (Linux), se presenti in quella distribuzione.
3. Verifica l'indirizzo riportato dal laboratorio; in alcune distribuzioni è `http://127.0.0.1:8795` con documentazione su `/docs`.
4. Esporta/carica lo Swagger del laboratorio nella dashboard AchillesAPI.
5. Imposta Base URL e host autorizzato a `127.0.0.1`. Abilita HTTP non cifrato con credenziali **solo** per questo scenario locale di laboratorio.
6. Esegui un piano offline; poi, se vuoi, autorizza i test HTTP e configura le identità demo previste dal laboratorio.

Non presumere che credenziali o path di una distribuzione precedente del laboratorio siano validi in una versione diversa.

## 11. Risoluzione problemi

<details>
<summary><strong>`uv sync` fallisce, errore su PyYAML / Python</strong></summary>

- Verifica di essere nella directory contenente `pyproject.toml`.
- Usa `uv python install 3.12` e `uv sync --python 3.12 --extra dashboard --extra pdf --extra dev`.
- Controlla `uv run achillesapi version`.
- Se l'errore persiste, conserva **l'output completo**, in particolare la versione Python e la dipendenza coinvolta.

</details>

<details>
<summary><strong>La dashboard non si apre o la porta è occupata</strong></summary>

- Verifica che il comando `uv run achillesapi dashboard --port 8766` sia rimasto in esecuzione.
- Apri `http://127.0.0.1:8766`, non l'URL del target.
- Prova `--port 8767` e aggiorna il browser con `Ctrl+F5`.

</details>

<details>
<summary><strong>`ollama` non è riconosciuto / `Connection refused`</strong></summary>

- Installa Ollama e riapri il terminale perché il `PATH` venga aggiornato.
- Verifica `ollama --version`, `ollama list` e la risposta di `http://127.0.0.1:11434/api/tags`.
- Se il servizio non è attivo, avvialo tramite l'app Ollama, `systemctl` o `ollama serve` (scegli un solo metodo).

</details>

<details>
<summary><strong>`ollama create`: manca il Modelfile o il modello base</strong></summary>

- Da **root del progetto** verifica che esista `deployment/Modelfile`.
- Esegui `ollama pull llama3.2:3b` prima di creare `achilles-local`.
- Windows: `ollama create achilles-local -f .\deployment\Modelfile`.
- Linux: `ollama create achilles-local -f deployment/Modelfile`.

</details>

<details>
<summary><strong>`workflow-assess`: il campo ID deve iniziare con `/`</strong></summary>

Usa il builder della v0.53: nel campo ID inserisci `id` per una risposta `{"id": 123}` o `/data/id` se l'ID si trova in `{"data":{"id":123}}`. Il builder converte automaticamente un campo semplice nel JSON Pointer previsto dal workflow.

</details>

<details>
<summary><strong>`analyze-evidence`: manca l'array `responses`</strong></summary>

Non caricare uno Swagger o un report generico come evidenze. Genera un bundle dal job `auto-assess` che abbia **effettivamente raccolto risposte HTTP** oppure importa un file con struttura `responses: [...]` valida. Se manca il job con risposte reali, esegui prima l'assessment attivo autorizzato.

</details>

<details>
<summary><strong>La suite ha task `skipped` / `failed`</strong></summary>

Espandi il task, controlla il prerequisito segnalato, usa **Genera e valida file** oppure carica una configurazione compatibile e riprova **solo quel task**. Alcuni task richiedono policy approvate o una ground truth che **non può essere dedotta** dallo Swagger. Uno skip non equivale a un successo.

</details>

## 12. Sicurezza, limiti e privacy

- Utilizza AchillesAPI **solo su sistemi e account per cui hai autorizzazione esplicita**.
- Inizia con il **piano offline**. Per i test HTTP limita l'host, il rate e il budget.
- Evita operazioni di scrittura su sistemi produttivi; usa dati sintetici, fixture disposable e cleanup verificabile, previa approvazione.
- Usa **HTTPS** per API reali. L'eccezione HTTP con credenziali è destinata al laboratorio locale.
- Non pubblicare token, password, file `auth.yaml` contenenti segreti o report con dati sensibili.
- Ollama è locale e facoltativo; **il download dei pesi non equivale a inviare i dati del target al modello cloud**, ma occorre comunque verificare installazione, configurazione di rete e policy interne.
- La copertura è **dipendente dalla specifica e dal contesto**: Swagger non descrive sempre le dipendenze tra operazioni, le regole di business o il significato dei ruoli. La suite non garantisce l'individuazione di tutte le vulnerabilità.
- I risultati AI possono essere inaccurati: sono **supporto all'analista**, non sostituiscono la verifica manuale.

---

**Per iniziare subito:** installa con `uv sync`, avvia `uv run achillesapi dashboard --port 8766`, carica lo Swagger ed esegui **Genera piano offline**. Installa Ollama solo se ti servono i controlli AI. Per una campagna completa, configura prima host autorizzato, eventuali identità e approvazioni.
