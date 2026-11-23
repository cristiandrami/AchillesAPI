# AchillesAPI v0.99 — Guida al codice, spiegata come appunti

La versione 0.99 è una **release candidate di sviluppo**. Non è stata certificata per scansioni automatiche in produzione.

## 1. Come leggere il progetto

```text
src/achillesapi/
├── cli.py                           # Collega i comandi del terminale alle funzioni Python
├── core/
│   ├── openapi.py                   # Legge e valida lo Swagger
│   ├── registry_v090.py            # Definisce i 53 task esposti alla dashboard
│   ├── campaign_v090.py            # Decide quali task sono pianificabili
│   ├── http.py                      # Impone scope, limiti di richieste e metodi HTTP
│   ├── access_review_v099.py       # Confronta risposte multiutente gia raccolte
│   ├── mutation_review_v099.py     # Confronta campi prima/dopo un test Mass Assignment
│   ├── workflow_safety_v099.py     # Prova a riconoscere un workflow CRUD senza eseguirlo
│   ├── benchmark_review_v099.py    # Misura precision, recall e F1 con ground truth
│   ├── independent_validation_v099.py # Prova il planner su Swagger diversi
│   ├── ai_guard_v099.py            # Filtra i suggerimenti locali di Ollama
│   ├── evidence_package_v099.py    # Crea un indice di evidenze senza dati sensibili
│   └── release_quality_v099.py     # Spiega quali parti della campagna non sono complete
└── dashboard/
    ├── control.py                   # Valida input, autorizzazioni, job, retry e suite
    ├── server.py                    # Espone API locali e viste protette
    ├── persistence_v080.py         # Salva metadati in SQLite, non i segreti
    └── static/                      # Dashboard e viewer
```

## 2. Nuove funzioni — appunti pratici

### `review_access_evidence(assessment)`

- **Input:** report con `execution_report.observations` e facoltativamente `access_expectations`.
- **Come lavora:** raggruppa le risposte HTTP per endpoint e profilo; confronta le classi 2xx/4xx/5xx.
- **Cosa restituisce:** differenze e possibili conflitti con la policy definita dall'operatore.
- **Cosa NON fa:** non invia richieste, non deduce che una BOLA sia confermata.

### `review_mutations(report)`

- **Input:** `state_comparisons` con `before`, `after`, `protected_fields`, `attempted_fields`.
- **Come lavora:** verifica se un campo protetto tentato cambia effettivamente.
- **Privacy:** il report mostra solo il **nome** del campo, non il suo valore.
- **Nota:** manca ancora la verifica causale completa della modifica sul server.

### `review_workflow_safety(spec)`

- **Input:** Swagger/OpenAPI.
- **Come lavora:** cerca POST di creazione e GET con ID collegato; controlla se esiste una DELETE candidata.
- **Risultato:** solo proposte di workflow, non esegue POST/DELETE.
- **Perché:** uno Swagger non può garantire la correttezza di dati, ownership e cleanup.

### `compare_ground_truth(truth, observed)`

- **Input:** `positive_ids` (verità indipendente) e `verified_positive_ids` (rilevazioni da confrontare).
- **Come lavora:** TP = rilevati e presenti; FP = rilevati ma non presenti; FN = presenti ma non rilevati.
- **Calcoli:** precision = TP/(TP+FP), recall = TP/(TP+FN), F1 = media armonica.
- **Attenzione:** senza veri negativi non calcola specificità.

### `validate_specification_corpus(directory)`

- **Input:** cartella con massimo 25 Swagger JSON/YAML.
- **Come lavora:** verifica parser, inventario endpoint, compatibilità e inferenza workflow.
- **Risultato:** una riga per ogni file con stato e numero di operazioni riconosciute.
- **Nota:** il corpus incluso prova **solo** il funzionamento offline, non una campagna di PT reale.

### `validate_advisory_plan(spec, suggestion)`

- **Input:** Swagger e JSON di azioni suggerite da Ollama.
- **Come lavora:** accetta solo comandi dell'allowlist e operazioni presenti nello Swagger; rifiuta URL, token, payload e comandi arbitrari.
- **Risultato:** `operator_approval_required`; non invia HTTP.

### `build_evidence_package(report)`

- **Input:** report di assessment.
- **Come lavora:** deduplica i rilievi e conserva fingerprint, categorie, gravità e stato di revisione.
- **Privacy:** evita di esportare URL, corpi HTTP, cookie, token e valori dei parametri.
- **Nota:** un indice non sostituisce le prove tecniche originali.

### `diagnose_campaign(report)` e `assess_release_readiness(report)`

- **Input:** report della suite.
- **Come lavorano:** contano task falliti, saltati e non conclusi; rilevano se mancano evidenze HTTP e revisioni.
- **Risultato:** `needs_attention` o `requires_operator_review`; **mai** “API sicura”.

### `SafeHTTPClient.request_statistics`

- **Come lavora:** conta i tentativi avviati da **quella specifica istanza**, le risposte e gli errori di rete.
- **Perché:** non dobbiamo confondere il budget riservato con le richieste realmente inviate.
- **Limite:** gli altri client storici e i subprocessi della suite potrebbero usare altri contatori. Non è ancora un contatore globale di campagna.

## 3. Flusso di una Suite completa

```text
Swagger -> Preflight -> Registry (53 tool)
       -> Controllo scope, budget e consenso
       -> Job CLI figli (uno alla volta)
       -> Report + indice dei risultati
       -> Quality gate + Release readiness
       -> Dashboard con retry dei task falliti
```

**Arresto cooperativo:** se premi Interrompi, il task corrente termina prima che la suite si fermi. Questo riduce il rischio di troncare il cleanup di una fixture temporanea.

**Limite di durata:** la dashboard consente da 1 a 120 minuti; quando il limite viene raggiunto, i task non ancora avviati sono segnati come saltati.

## 4. Come aggiungere una nuova funzione

1. Scrivi una funzione Python in `core/` con un solo compito e una docstring breve in italiano.
2. Fai sì che la funzione restituisca un dizionario JSON, con `engine`, `requests_sent`, `summary`, `limitations`.
3. Aggiungi il comando Typer in `cli.py`.
4. Se il comando deve apparire nella suite, registralo nel catalogo `TOOLS` e in `SUITE_ORDER`.
5. Scrivi test unitari, con casi positivi, negativi e input non validi.
6. Se il task invia HTTP, usa i controlli di scope/consenso esistenti: **non aggirarli**.

## 5. Commenti consigliati

Esempio di commenti leggibili:

```python
# Verifico prima i permessi: senza scope approvato non invio richieste.
if not authorized:
    return {'state': 'blocked'}

# Riutilizzo le risposte gia raccolte, senza interrogare di nuovo l'API.
observations = previous_report.get('observations', [])

# Una differenza fra account richiede controllo di ownership: non e' una BOLA confermata.
status = 'requires_review'
```

Un buon commento spiega *perché* una decisione è stata presa. Evita di ripetere la riga di codice in parole diverse.

## 6. Limiti non risolti

Non è ancora disponibile un agente in grado di comprendere automaticamente qualunque business logic o costruire fixture sicure per ogni API. Il supporto OAuth2 complesso, la telemetria globale di tutti i processi, la conferma automatica dei finding e la validazione end-to-end su cinque servizi **reali** richiedono ulteriore lavoro. Le nuove funzioni offline non sostituiscono i test attivi esistenti.
