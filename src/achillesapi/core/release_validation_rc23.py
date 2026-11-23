"""RC23 honest evidence/coverage quality gate and optional external-lab checklist."""
from __future__ import annotations

from typing import Any

from achillesapi.core.diagnostics_rc20 import diagnose, enrich_steps


def audit_campaign(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report,dict):raise ValueError('Report must be a JSON object')
    steps=report.get('steps',[])
    if not isinstance(steps,list):raise ValueError('Report steps must be an array')
    rows=enrich_steps([r for r in steps if isinstance(r,dict)])
    status_counts={k:sum(row.get('status')==k for row in rows)
                   for k in ('complete','skipped','failed','blocked')}
    missing=[]
    if report.get('status')=='stopped_by_operator':
        missing.append('Campaign stopped by operator; incomplete steps are not successes')
    if not rows:missing.append('No suite steps or coverage recorded')
    if not report.get('limitations'):missing.append('Missing assessment limitations')
    if report.get('status') in {'complete','completed'} and any(
        r.get('status')=='failed' for r in rows):
        missing.append('Completed campaign contains failed tasks')
    # Excluded steps must be visible in user reports, never counted as passed.
    unresolved=[{'action':r.get('action',''), 'issue':r['remediation']}
                for r in rows if r.get('remediation')]
    issue_counts: dict[str,int] = {}
    for row in unresolved:
        code=row['issue']['code']
        issue_counts[code]=issue_counts.get(code,0)+1
    return {'engine':'achilles-rc23-report-audit','requests_sent':0,
            'quality':'needs_review' if missing or status_counts['failed'] else 'review_ready',
            'task_counts':status_counts,'total_steps':len(rows),
            'missing_elements':missing,'unresolved':unresolved,
            'issue_counts':issue_counts,
            'ready_for_professional_review':not missing and not status_counts['failed'],
            'coverage_ratio':round(status_counts['complete']/len(rows),4) if rows else None,
            'validation':{'northstar':'not_executed_by_offline_audit',
                          'ollama_real':'not_executed_by_offline_audit',
                          'browser_real_backend':'not_executed_by_offline_audit'},
            'limitations':['Report quality is not vulnerability proof.',
                           'Skipped tasks are excluded from executed coverage.',
                           'External labs and local Ollama must be tested on actual installations.']}


def readiness_check(*, regression_passed: int, regression_failed: int,
                    independent_lab_checked: bool = False,
                    northstar_checked: bool = False, ollama_checked: bool = False,
                    browser_checked: bool = False) -> dict[str, Any]:
    if min(regression_passed,regression_failed)<0:raise ValueError('Invalid test counts')
    checks={'regression':regression_passed>0 and regression_failed==0,
            'independent_lab':independent_lab_checked,
            'northstar':northstar_checked,'ollama_real':ollama_checked,
            'browser_real_backend':browser_checked}
    return {'engine':'achilles-rc23-release-gate','checks':checks,
            'ready_for_stable':all(checks.values()),
            'missing':[key for key,val in checks.items() if not val],
            'note':'Non dichiarare pronti laboratori esterni o modelli non realmente collaudati.'}
