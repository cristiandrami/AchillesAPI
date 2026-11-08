# AchillesAPI v0.43 — Dashboard indipendente, modalità automatica e workflow multipli

## Installazione (PowerShell)

Dopo aver estratto lo ZIP, apri PowerShell nella cartella `achillesapi`:

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dashboard --extra pdf --extra dev
uv run achillesapi version
uv run achillesapi dashboard --port 8766
```

Apri `http://127.0.0.1:8766`. L'API di laboratorio **non** viene avviata né gestita da AchillesAPI: avviala in un terminale separato dal suo progetto standalone, poi trattala come un target esterno.

## Procedura raccomandata

1. **Swagger:** importa il file OpenAPI 3.x `.json/.yaml` del target, o incollane il contenuto. Verifica gli endpoint riconosciuti.
2. **Target:** inserisci il Base URL reale e il suo hostname esplicitamente autorizzato. Configura un budget e un rate bassi; usa HTTPS nei contesti aziendali.
3. **Identità:** importa `auth.yaml` con i nomi dei profili e i nomi delle variabili richieste; compila nella dashboard i token e le password negli appositi campi, senza inserirli nei file YAML.
4. **Verifiche:** seleziona uno strumento. Per i comandi *offline* non vedrai più la casella di esecuzione HTTP: la dashboard imposta automaticamente `execute=false`. Per i test *attivi*, approva scope e richieste. Le scritture hanno bisogno di un manifesto di risorse temporanee con cleanup verificabile.
5. **Risultati:** consulta i job completati, esegui il triage ed esporta il report.

## Procedura richiudibile per POST, PATCH e DELETE

Sotto **Scegli le verifiche** trovi **Configura un test con POST / PATCH / DELETE**. È chiusa inizialmente: clicca il titolo solo se vuoi provare operazioni con scritture. Non devi scrivere YAML: la procedura usa lo Swagger per proporti le possibili triplette POST → GET per ID → DELETE.

Per ogni workflow: scegli la risorsa, seleziona un profilo proprietario e un secondo profilo (facoltativo), indica la policy di accesso, compila i campi richiesti per creare dati *disposable*, quindi indica il nome della proprietà ID restituita dalla POST. Conferma che la cancellazione della risorsa di test è sicura. La dashboard valida offline il manifesto; questa fase **non** invia richieste.

## Swagger con più workflow

Se vengono individuate più risorse CRUD, ripeti la stessa procedura **per ognuna**. Ogni configurazione verificata compare nel menu **Workflow preparati per questa API**. Dal menu puoi selezionare, usare o rimuovere un workflow senza cancellare gli altri (fino a quando rimani sulla pagina). **Per eseguirli usa un workflow alla volta**, controllandone evidenze e cleanup prima del successivo. La dashboard non esegue automaticamente tutti i workflow in batch, né può derivare sempre workflow annidati o dipendenze complesse da uno Swagger incompleto. Per workflow multi-risorsa che dipendono da altri oggetti, il motore può usarli se gli fornisci un manifesto avanzato appropriato.

Ricaricando la pagina o importando un altro Swagger, le configurazioni preparate nella lista possono andare perse: scarica il manifesto YAML se vuoi conservarle. Non è previsto un salvataggio persistente di token o password.

## Limiti della generalità

AchillesAPI **non usa endpoint, ruoli né credenziali del laboratorio dentro la dashboard**. I candidati generati derivano dallo Swagger che carichi. Tuttavia la selezione automatica di triplette CRUD presuppone uno schema riconoscibile (POST della collezione, GET e DELETE della singola risorsa, campo marker di testo). Non sostituisce la conoscenza delle policy, dei dati di prova e del cleanup specifici di ogni API. Alcune API richiedono una configurazione manuale o test supervisionati.

## Selezione intelligente della modalità

Gli strumenti offline (`analyze-openapi`, `generate-tests`, `workflow-map`, `security-inventory` ecc.) avviano sempre un'analisi statica, anche se prima avevi eseguito un controllo attivo. Non viene inviato traffico. Gli strumenti che possono usare la rete mostrano i campi necessari e richiedono scope e autorizzazione espliciti. Se premi **Genera piano offline**, non viene inviato traffico nemmeno con strumenti attivi.

## Cosa non promette la v0.43

Non sono inclusi penetration test di business logic universali, creazione illimitata di risorse o sfruttamento autonomo di ogni vulnerabilità. I moduli avanzati richiedono ancora policy e fixture approvate. La dashboard resta un'interfaccia generica di assessment supervisionato, da usare solo su target autorizzati.
