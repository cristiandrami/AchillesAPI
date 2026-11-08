# AchillesAPI v0.39 — Dashboard totalmente indipendente dal laboratorio

## Architettura

Tre processi indipendenti:

1. **API under test**: un server qualsiasi (il laboratorio standalone è solo un esempio), avviato separatamente.
2. **AchillesAPI dashboard**: applicazione web e motore scanner, avviata separatamente.
3. **Ollama**: servizio opzionale per analisi AI locale. Non è richiesto per eseguire i controlli deterministici.

La dashboard NON include funzioni per caricare una demo specifica, avviare o fermare l'API target, copiare i segreti del laboratorio o scegliere automaticamente un target.

## Primo avvio su Windows (PowerShell)

**Terminale 1: API esterna**

Estrai il pacchetto `Independent-Vulnerable-API-Lab.zip` in una cartella separata ed esegui:

```powershell
cd .\independent-api-lab
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

Verifica in browser `http://127.0.0.1:8795/docs`. Mantieni il terminale aperto.

**Terminale 2: AchillesAPI**

Estrai il pacchetto AchillesAPI in un'altra cartella:

```powershell
cd .\achillesapi
uv python install 3.12
uv sync --python 3.12 --extra dashboard --extra pdf --extra dev
uv run achillesapi dashboard --port 8766
```

Apri `http://127.0.0.1:8766`.

**Terminale 3 (facoltativo): credenziali**

I profili YAML dimostrativi riferiscono a variabili d'ambiente. Per le richieste autenticate, chiudi e riavvia la dashboard da un PowerShell che contenga:

```powershell
$env:ACHILLES_LAB_OWNER = 'demo-owner'
$env:ACHILLES_LAB_OTHER = 'demo-other'
$env:ACHILLES_LAB_ADMIN = 'demo-admin'
uv run achillesapi dashboard --port 8766
```

Le variabili devono esistere **nel processo che avvia AchillesAPI**, non nel terminale del laboratorio. Per un target aziendale sostituisci questi nomi/valori con profili approvati; nessuna credenziale viene impostata automaticamente dalla dashboard.

## Eseguire un assessment tramite dashboard

1. Vai in **New assessment** e carica `independent-api-lab/openapi.json` con il selettore OpenAPI.
2. Imposta **Base URL** = `http://127.0.0.1:8795` e **Approved hostname** = `127.0.0.1`.
3. Imposta un budget massimo, per esempio 40 richieste e un rate di 1 richiesta al secondo.
4. Nel Control Center seleziona `auto-assess`, poi premi **Piano offline**. Il piano non manda traffico al target.
5. Per un assessment GET reale, seleziona **Active assessment** e **Confermo scope e autorizzazione del target**. Se utilizzi `auth.yaml`, importa il file, imposta i profili `owner,other` e abilita **Allow credentialed HTTP (localhost only)**.
6. Premi **Esegui strumento selezionato**. Apri **Assessment activity**, seleziona un job e visualizza il risultato JSON.
7. Scegli **Analyze findings** oppure esporta HTML/PDF.

La dashboard può anche eseguire `multi-resource-assess`: importa `resources.yaml` in **Configurazione aggiuntiva**, importa `auth.yaml`, scegli il tool `multi-resource-assess`, spunta le conferme di autorizzazione e di scrittura su dati temporanei, e avvia. Il manifest impone i controlli sull'identità delle risorse e cleanup. Prima di testare API reali, usa esclusivamente fixture approvate e verifica che i DELETE siano sicuri.

## Uso con una vera API

Ripeti esattamente la sequenza precedente con file OpenAPI, URL HTTPS, host autorizzato e credenziali di test forniti dal cliente. Nessuna modifica al software e nessuna conoscenza del laboratorio sono richieste. Confronti BOLA/BFLA accurati richiedono identità e policy reali; Swagger da solo non dichiara l'ownership dei record.

## Limiti

- I controlli disponibili restano quelli concretamente implementati dalla CLI; non è uno scanner autonomo universale.
- Il server della dashboard è solo locale (loopback) e non è destinato a esposizione pubblica.
- Un download Ollama iniziale può richiedere accesso internet, ma non sono trasmessi dati del target a servizi AI cloud.
- La dashboard non controlla processi o stato dell'API target; l'unica comunicazione con il target avviene quando avvii un assessment attivo autorizzato.
- L'API standalone deve restare isolata su `127.0.0.1` perché contiene vulnerabilità intenzionali.
