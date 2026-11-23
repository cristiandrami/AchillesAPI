# Architettura RC4 — Appunti per capire il codice

## Moduli nuovi

- `core/access_matrix_rc4.py`
  - `read_rules`: carica le regole JSON/YAML con limite di dimensione, senza rete.
  - `preflight_rules`: controlla tutte le regole contro lo Swagger e i profili prima di inviare richieste. Rifiuta operazioni non GET, path non validi, utenti uguali e assenza di policy esplicita.
  - `run_access_matrix`: usa `compare_identities` della RC2 per confrontare due identità per regola; restituisce solo codice HTTP e stato di revisione, non dati/credenziali.
- `core/auth_session_rc4.py`
  - `audit_session_profiles`: descrive se i profili possono acquisire token dinamici, senza risolvere o pubblicare segreti.
- `core/evidence_gate_rc4.py`
  - `review_proof_records`: verifica la presenza di riferimenti a policy, almeno due evidenze e riproduzione dichiarata. Non conferma automaticamente vulnerabilità.
- `core/ai_followup_rc4.py`
  - `local_followup_review`: chiama Ollama **solo in loopback**, usando un indice di evidenze sanitizzato; accetta soltanto nomi esatti di tool ammessi. Proposte non eseguite.
- `core/process_supervisor_rc4.py`
  - `run_cli_bounded`: avvia un subprocesso in un gruppo dedicato, applica timeout, legge solo la coda degli errori e non esegue shell.
  - `_terminate_tree`: chiude il gruppo del processo scaduto; non può certificare il cleanup delle risorse aziendali.

## Collegamenti aggiornati

- `core/registry_v090.py`: registra i quattro task nuovi; tutti i task della suite hanno un comando CLI.
- `cli.py`: definisce argomenti tipizzati, chiama le funzioni dei motori e salva i risultati strutturati.
- `dashboard/control.py`: fa scope check, genera i job, invoca il supervisore e propaga timer/budget condivisi. In caso di timeout di scrittura registra `cleanup_state=unknown_requires_operator_check`.
- `dashboard/static/index.html` e `app.js`: generatore visuale della matrice da Swagger e profili, senza YAML/JSON manuale.
- `dashboard/job_view.py`: mette in evidenza i conflitti da rivedere, separatamente dai finding confermati.

## Esempio di commenti nel progetto

```python
# Prima di inviare una GET, controlliamo tutte le regole del file.
# Se anche una regola contiene un endpoint non valido, blocchiamo la campagna.
```

```python
# L'AI suggerisce test: non puo autorizzare una chiamata HTTP.
# Accettiamo soltanto nomi esatti di strumenti presenti nella allowlist.
```

## Distinzioni importanti

- **Preflight** = compatibilità e autorizzazioni, non test eseguito.
- **Richieste inviate** = tentativi HTTP conteggiati, non sinonimo di risposte registrate.
- **Anomalia** = comportamento sospetto, non prova sufficiente di BOLA.
- **Proof gate** = valutazione della struttura delle evidenze, non loro autenticazione indipendente.
- **Timeout** = processo interrotto; una scrittura parziale richiede verifica manuale del cleanup.

Il framework usa `shell=False`, token di sessione CSRF per le azioni della dashboard, allowlist host, controllo delle scritture e gestione del budget SQLite. Non eseguire campagne attive senza autorizzazione.
