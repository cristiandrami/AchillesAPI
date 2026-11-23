"""Typed, navigable remediation for suite/task failures (RC20).

All issue codes are stable and independent of the locale. UI locations are
allowlisted and secrets/raw requests are never put in a diagnostic artifact.
The fallback is deliberately generic; do not guess a root cause from an
unknown exception or include raw credentials in a report.
"""
from __future__ import annotations

from typing import Any

# code -> (dashboard section ID, input ID, short description, exact repair)
_ISSUES: dict[str, tuple[str, str, str, str]] = {
    'SPEC_REQUIRED': ('step1','specFile','OpenAPI non importato',
                      'Passaggio 1: carica una specifica OpenAPI YAML/JSON o ZIP valida.'),
    'SCOPE_REQUIRED': ('step2','baseUrl','Target HTTP non configurato',
                       'Passaggio 2: inserisci Base URL e hostname esplicitamente autorizzato.'),
    'HTTP_CONSENT_REQUIRED': ('fullSuite','suiteAck','Consenso HTTP assente',
                              'Suite completa: conferma l’autorizzazione HTTP solo se sei autorizzato al test.'),
    'AUTH_REQUIRED': ('step3','authFile','Identità di test mancanti',
                      'Passaggio 3: carica auth.yaml e verifica le credenziali richieste.'),
    'IDENTITIES_REQUIRED': ('authMatrixSection','matrixOperation','Confronto utenti non preparato',
                            'Controlla accessi: seleziona due utenti distinti, una risorsa e la policy attesa.'),
    'POLICY_REQUIRED': ('authMatrixSection','matrixOperation','Policy attesa non definita',
                        'Controlla accessi: salva una regola con proprietario, altro utente e risultato atteso.'),
    'WORKFLOW_REQUIRED': ('workflowCreateSection','guidedCandidate','Workflow temporaneo assente',
                          'Prepara risorse temporanee: scegli un workflow, compila solo dati obbligatori e salva il manifest.'),
    'CLEANUP_REQUIRED': ('workflowCreateSection','guidedCandidate','Cleanup non verificabile',
                         'Prepara risorse temporanee: verifica una DELETE idempotente e un ID di risorsa temporanea.'),
    'WRITES_CONSENT_REQUIRED': ('fullSuite','suiteWritesAck','Scritture non autorizzate',
                                'Suite completa: approva separatamente le scritture solo dopo aver verificato cleanup e scope.'),
    'PATCH_FIELDS_REQUIRED': ('massAssignmentPanel','bodyProbeWorkflowSelect','Campi PATCH non selezionati',
                              'Mass Assignment: seleziona una risorsa e i campi PATCH da verificare; poi prepara una fixture con cleanup.'),
    'AI_UNAVAILABLE': ('agentOptionsSection','ollamaModel','Ollama non pronto',
                       'Agente AI locale: controlla il servizio e scegli un modello installato; gli altri task possono continuare.'),
    'BUDGET_INSUFFICIENT': ('fullSuite','suiteBudget','Budget insufficiente',
                            'Suite completa: aumenta il budget autorizzato o riduci i controlli opzionali.'),
    'EVIDENCE_REQUIRED': ('step5','jobsList','Evidenze precedenti mancanti',
                          'Risultati e report: seleziona un assessment HTTP completato dello stesso target.'),
    'CONFIG_REQUIRED': ('advancedToolsGroup','configFile','Configurazione dedicata mancante',
                        'Altri strumenti: fornisci il file di configurazione richiesto dal task.'),
    'REPORT_INCOMPLETE': ('step5','jobsList','Evidenze insufficienti nel report',
                           'Risultati e report: controlla task saltati, motivazioni ed evidenze riproducibili.'),
    'TASK_ERROR': ('step5','jobsList','Task non completato',
                   'Risultati e report: apri il job e consulta il dettaglio diagnostico. Non presumere la causa.'),
    'NOT_APPLICABLE': ('fullSuite','suitePreview','Controllo non applicabile',
                       'Suite completa: il task è escluso per questo tipo di specifica o campagna.'),
}


def diagnose(code: str, *, action: str = '', detail: str = '') -> dict[str, Any]:
    """Return stable UI routing. `detail` is an operator-safe label, not raw stderr."""
    if code not in _ISSUES:
        code = 'TASK_ERROR'
    section, field, title, instructions = _ISSUES[code]
    return {'code': code, 'action': str(action)[:80], 'section': section,
            'field': field, 'title': title, 'instructions': instructions,
            'detail': str(detail).replace('\r',' ').replace('\n',' ')[:140]}


def reason_code(action: str, reason: str, *, status: str = 'skipped') -> str:
    """Translate known prerequisite causes to codes, scoped by task first.

    This compatibility adapter is necessary because old backends still produce
    human-readable messages. New engines should raise/return codes directly.
    """
    text = str(reason).lower()
    if status in {'failed', 'error'}:
        return 'TASK_ERROR'
    if action in {'rc16-access-auto', 'access-probe', 'access-matrix', 'verify-access-policy'}:
        if any(w in text for w in ('profil', 'identit', 'auth.yaml')): return 'AUTH_REQUIRED'
        if any(w in text for w in ('matrice', 'policy', 'regol', 'id approvat')): return 'POLICY_REQUIRED'
    if action in {'rc16-assess','multi-resource-assess','workflow-assess','journey-assess'}:
        if 'autorizz' in text or 'scrittur' in text: return 'WRITES_CONSENT_REQUIRED'
        if 'cleanup' in text or 'delete' in text: return 'CLEANUP_REQUIRED'
        return 'WORKFLOW_REQUIRED'
    if action in {'rc13-assess','rc15-scan'} and ('patch' in text or 'sonde json' in text):
        return 'PATCH_FIELDS_REQUIRED'
    if 'ollama' in text or ('model' in text and 'locale' in text): return 'AI_UNAVAILABLE'
    if 'budget' in text or 'richieste' in text and 'insuff' in text: return 'BUDGET_INSUFFICIENT'
    if 'swagger' in text or 'openapi' in text and 'carica' in text: return 'SPEC_REQUIRED'
    if 'base url' in text or 'host autorizzato' in text or 'allow-host' in text: return 'SCOPE_REQUIRED'
    if 'consenso' in text or 'autorizzazione del target' in text: return 'HTTP_CONSENT_REQUIRED'
    if 'auth.yaml' in text or 'credenzial' in text: return 'AUTH_REQUIRED'
    if 'cleanup' in text: return 'CLEANUP_REQUIRED'
    if 'json patch' in text or 'campi patch' in text: return 'PATCH_FIELDS_REQUIRED'
    if 'evidenz' in text or 'assessment precedente' in text: return 'EVIDENCE_REQUIRED'
    if 'manifest' in text or 'configurazione' in text: return 'CONFIG_REQUIRED'
    if 'non applicabil' in text or 'duplicat' in text: return 'NOT_APPLICABLE'
    return 'TASK_ERROR' if status == 'failed' else 'NOT_APPLICABLE'


def enrich_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Enrich in-place-free, preserving every legacy field and user-visible status."""
    output = []
    for row in steps:
        item = dict(row)
        if item.get('status') in {'skipped', 'failed', 'error', 'blocked'}:
            code = item.get('issue_code')
            if code not in _ISSUES:
                code = reason_code(str(item.get('action','')),str(item.get('reason','')),
                                   status=str(item.get('status','skipped')))
            item['issue_code'] = code
            item['remediation'] = diagnose(code,action=str(item.get('action','')))
        output.append(item)
    return output


def supported_codes() -> tuple[str, ...]:
    return tuple(sorted(_ISSUES))
