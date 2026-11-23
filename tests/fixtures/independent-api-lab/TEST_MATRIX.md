# Matrice di verifica — laboratorio indipendente v2

Questo server FastAPI **non importa AchillesAPI** e non sa quale scanner lo testerà. Tutti i dati sono sintetici e si perdono al riavvio. Avvia sempre su `127.0.0.1:8795`.

## Cosa può rilevare il motore attuale

| Endpoint di prova | Endpoint di controllo | Comportamento osservabile | Risultato del motore AchillesAPI v0.46 |
|---|---|---|---|
| `GET /misconfigured/auth` | `GET /secure/auth` | Swagger richiede Bearer, ma il primo risponde 200 anche anonimo | `unauthenticated_access_review` con `auto-assess` attivo |
| `GET /misconfigured/cors` | `GET /secure/cors` | Origine arbitraria riflessa + `Access-Control-Allow-Credentials: true` | `cors_credentialed_origin_reflection` |
| `GET /profile/exposed` | `GET /profile/safe` | Il primo restituisce un campo OpenAPI `writeOnly` | `write_only_property_returned` |
| `GET /misconfigured/cache` | `GET /secure/cache` | Risposta autenticata con `Cache-Control: public` | `authenticated_public_cache` |
| `GET /misconfigured/cache` | `GET /secure/cache` | Header `X-Powered-By` presente solo nella prima | `technology_disclosure` |
| `GET /misconfigured/contract` | `GET /secure/contract` | Tipo `total` restituito diverso dallo schema JSON | `response_contract_mismatch` |
| `GET /misconfigured/error` | `GET /secure/error` | Messaggio **fittizio** di errore SQL | `error_disclosure` (NON SQL injection) |
| `GET /unstable/repeatable` | `GET /unstable/healthy` | Errore 503 riproducibile contro successo 200 | Osservazione 503; possibile follow-up con agent budget |
| `GET /projects/{project_ref}` | `GET /secure/projects/{project_ref}` | Utente `other` legge risorsa creata da `owner` | Con un ID valido + policy, possibile evidenza BOLA; senza policy solo `cross_identity_object_review` |
| `GET /tickets/{ticket_ref}` | `GET /secure/tickets/{ticket_ref}` | Stesso contrasto BOLA su risorsa figlia | Richiede ticket creato prima e ID valido |
| `GET /admin/audit` | `GET /secure/admin/audit` | Account ordinario accede a endpoint amministrativo | Con policy `expected_access`, possibile `authorization_policy_mismatch` / BFLA review |
| `GET /search` | `GET /misconfigured/validation` | Validazione query vincolata; secondo endpoint restituisce un tipo non documentato | Controllo di validazione, non garanzia di finding |

**Non trasformare automaticamente un'indicazione in vulnerabilità confermata.** La policy di accesso dipende dall'applicazione e deve essere fornita e validata da un analista.

## Cosa NON può essere dimostrato automaticamente

- I comandi `analyze-openapi`, `map-api`, `workflow-map`, `security-inventory`, `generate-tests`, `intelligent-plan` e simili **non inviano richieste**. Il risultato atteso è un inventario o piano, non una vulnerabilità.
- `ai-analyze` legge Swagger e produce suggerimenti, non conferme.
- `ai-correlate`, `ai-prioritize`, `next-actions`, `autonomous-agent` e `agent-loop-v2` richiedono risultati precedenti appropriati; i follow-up sono limitati ai controlli autorizzati e supportati.
- Non sono implementate exploitation generalizzate per SQL injection, NoSQLi, SSRF, SSTI, command injection, race condition e business logic. Una stringa "SQL syntax error" **non dimostra** SQLi.
- La verifica dei workflow POST/PATCH/DELETE richiede manifesto di fixture `resources.yaml` e consenso esplicito. Il server supporta `project → ticket` e il relativo cleanup, ma non inventa altre sequenze aziendali.

## Sequenza consigliata dalla dashboard

1. Avvia il laboratorio dal suo terminale.
2. Importa `openapi.json` nella dashboard; base URL `http://127.0.0.1:8795`, hostname `127.0.0.1`.
3. Importa `auth.yaml`. Inserisci i tre valori `demo-owner`, `demo-other`, `demo-admin` nei campi delle rispettive variabili; seleziona i profili `owner,other,admin`.
4. Per il laboratorio locale abilita `allow_insecure_http`, autorizzazione, `execute`; imposta un budget almeno 120 (nella dashboard, se massimo 150) e rate `2–5`.
5. Esegui `auto-assess` **attivo**. Controlla le categorie sopra; i 503 possono essere ritentati con `agent-budget`.
6. Se vuoi confronti BOLA sulle risorse, crea **una risorsa tua di prova** dal Swagger e passa il suo ID come `project_ref` o usa `resources.yaml` con approvazione delle scritture.
7. Esporta HTML/PDF dal job `auto-assess`, poi prova `security-inventory`, `next-actions`, `ai-correlate` e verifica che anche i loro export producano documenti (non necessariamente finding).

## Verifica senza AchillesAPI

Puoi verificare che l'API sia difettosa con `curl` senza installare il framework. Ad esempio:

```powershell
curl.exe -i http://127.0.0.1:8795/misconfigured/auth
curl.exe -i http://127.0.0.1:8795/secure/auth
curl.exe -i http://127.0.0.1:8795/misconfigured/cors -H "Origin: https://example.invalid"
curl.exe -i http://127.0.0.1:8795/misconfigured/cache -H "Authorization: Bearer demo-owner"
```

## Test del server senza scanner

```powershell
uv run --with pytest --with httpx --with fastapi --with uvicorn pytest -q test_cases.py
```

L'API viene generata direttamente da `app.py`; `openapi.json` in questo pacchetto è la sua esportazione statica e corrisponde ai 30 metodi dichiarati.
