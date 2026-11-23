"""Explain untested capability groups from actual suite outcomes; never invent vulnerabilities."""
from __future__ import annotations
from typing import Any

_GAPS: dict[str, tuple[str, str]] = {
    'access-probe': ('BOLA / autorizzazione per oggetto',
       'Seleziona GET, ID della risorsa, due utenti distinti e regola di accesso attesa.'),
    'access-matrix': ('BOLA / BFLA / matrice dei ruoli',
       'Prepara regole di autorizzazione attese per ruolo/risorsa; lo Swagger non codifica la ownership.'),
    'verify-access-policy': ('Verifica della policy di autorizzazione',
       'Carica una policy esplicita da confrontare con osservazioni HTTP reali.'),
    'workflow-assess': ('Workflow con scritture (POST/PATCH/DELETE)',
       'Configura manifest disposable, identità, ID e cleanup; se hai usato multi-resource-assess evita di eseguire due volte le scritture.'),
    'multi-resource-assess': ('Campagna di risorse temporanee multiple',
       'Crea manifest approvati per ciascun workflow e verifica che le risorse siano eliminabili.'),
    'journey-assess': ('Business Logic multi-step',
       'Configura sequenze applicative e stati attesi per i passaggi dipendenti.'),
    'workflow-graph': ('Grafo delle dipendenze di workflow',
       'Usa un manifest DAG specifico con steps, operation, depends_on e cleanup_step; il manifest disposable non è lo stesso formato.'),
    'analyze-evidence': ('Analisi delle risposte HTTP',
       'Carica/genera un bundle responses derivato da un assessment realmente eseguito.'),
    'ai-analyze': ('Analisi consultiva AI dello Swagger',
       'Abilita AI e avvia Ollama localmente; seleziona un modello installato.'),
    'ai-correlate': ('Correlazione AI delle risposte',
       'Servono Ollama locale e osservazioni HTTP vere, non soltanto uno Swagger.'),
    'ai-followup-safe': ('Follow-up AI consultivo',
       'Servono Ollama e un assessment precedente; il modello non conferma vulnerabilità.'),
    'ai-plan-guard': ('Controllo del piano proposto da AI',
       'Genera un JSON di proposte. Il validatore è deterministico e NON chiama Ollama.'),
    'benchmark-evaluate': ('Benchmark di precisione / richiamo',
       'Carica etichette indipendenti di ground truth: non sono ricavabili automaticamente dalla scansione.'),
    'benchmark-review': ('Revisione del benchmark',
       'Carica un benchmark con etichette indipendenti.'),
}


def explain_suite_gaps(steps: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Summarize *only* non-executed/failed capabilities from real task statuses."""
    gaps = []
    for step in steps:
        if not isinstance(step, dict) or step.get('status') not in {'skipped', 'failed'}:
            continue
        action = step.get('action')
        if action not in _GAPS:
            continue
        capability, next_step = _GAPS[action]
        gaps.append({
            'task': action,
            'status': step['status'],
            'capability': capability,
            'reason': str(step.get('reason') or 'Il task non è stato completato.')[:350],
            'next_step': next_step,
            'interpretation': 'Non testato: non interpretare come assenza della vulnerabilità.',
        })
    return gaps[:61]
