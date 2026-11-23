# Independent Vulnerable API Lab v2 — applicazione standalone

**NON fa parte di AchillesAPI.** È una FastAPI indipendente con 30 operazioni, solo dati sintetici in RAM e controlli intenzionalmente vulnerabili e protetti. Avviala separatamente dal terminale; nessun modulo importato da AchillesAPI.

## Avvio Windows (PowerShell)

1. Estrai questo ZIP in `independent-api-lab`.
2. Apri PowerShell nella cartella estratta.
3. Esegui: `powershell -ExecutionPolicy Bypass -File .\start.ps1`
4. Apri `http://127.0.0.1:8795/docs` e `http://127.0.0.1:8795/openapi.json`.

## Avvio Kali / Linux

```bash
chmod +x start.sh
./start.sh
```

Il server è vincolato a **127.0.0.1**, non deve essere pubblicato in rete. Termina il processo con Ctrl+C; il database in RAM si azzera.

## File del pacchetto

- `app.py`: unica implementazione delle API.
- `openapi.json`: contratto API da caricare in AchillesAPI (oppure usare `/openapi.json` in Swagger).
- `auth.yaml`: tre profili Bearer, senza password o token hardcoded nel file.
- `resources.yaml`: fixture di workflow temporaneo progetto → ticket, inclusi marker e cleanup.
- `TEST_MATRIX.md`: **qual è il risultato atteso da ogni controllo**, vulnerabile vs protetto, e cosa il motore non supporta.
- `test_cases.py`: test HTTP che verificano che il laboratorio si comporti come previsto.

I token di prova sono soltanto `demo-owner`, `demo-other`, `demo-admin`. Non riutilizzarli su altri sistemi.
