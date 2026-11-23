# Modello di sicurezza — v0.90

## Ambito

AchillesAPI è uno strumento per **API esplicitamente autorizzate**. La dashboard è locale (`127.0.0.1`). La modalità offline non invia traffico al target; le modalità attive richiedono Base URL, host approvato e conferma.

## Confini di fiducia

- Lo Swagger e i file caricati sono **input non attendibili**. Si analizzano con parser e limiti di dimensione.
- I comandi CLI partono da un registry fisso; non sono costruiti da stringhe shell arbitrarie.
- I test di scrittura richiedono approvazione, fixture temporanee e cleanup definito. Non interrompere forzatamente un task mentre ripulisce.
- Le risposte di Ollama sono consultive; un suggerimento non modifica host, scope, budget o permessi.
- Gli indicatori senza prova indipendente rimangono `requires_review`.

## Credenziali e report

- `auth.yaml` supporta `token:` inline **in chiaro** oppure variabili d'ambiente. Mantenerlo fuori da Git e da cartelle condivise.
- Il database di cronologia non memorizza la mappa dei segreti usata per i retry.
- La UI normalizza e oscura i campi sensibili. I token inline noti vengono rimossi dai messaggi di errore subprocess esposti nella dashboard.
- Non assumere che un *output raw* esterno sia privo di dati sensibili: trattalo come dato riservato e verifica i report prima di condividerli.
- Il fatto che una stringa non corrisponda a un pattern di redazione non garantisce che sia pubblicabile.

## Arresto e ripresa

Il pulsante Stop è **cooperativo**: impedisce il prossimo task, ma lascia terminare quello in corso. Il riavvio della dashboard recupera lo stato e i report, non riprende le richieste in corso e non sostituisce un piano di cleanup manuale dopo crash del sistema.

## Cosa non dimostra il framework

- Una percentuale di endpoint osservati non dimostra test completi.
- `candidate_not_tested` indica un possibile controllo, non un difetto.
- La risposta 200 a una risorsa non dimostra BOLA senza policy e identità corrette.
- Le verifiche offline OWASP non devono essere presentate come exploit riusciti.
- La v0.90 richiede validazione indipendente prima di poter essere qualificata come strumento unattended production-ready.
