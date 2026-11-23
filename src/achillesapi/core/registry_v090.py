"""Registro centrale dei comandi esposti alla suite e alla dashboard.

Ogni tool usa opzioni tipizzate e un comando CLI fisso: non eseguiamo
stringhe di shell provenienti dal browser.
"""
from __future__ import annotations
from typing import Any

# 'requirements' determines positional arguments, not executable shell tokens.
# allow_exec indicates bounded HTTP traffic; 'writes' requires an approved manifest.
TOOLS: dict[str, dict[str, Any]] = {
    # RC4: matrice di accesso a piu GET; policy scritte dall'operatore.
    'access-matrix':         dict(category='Security',requirements='spec-config', active=True, config_flag='--rules'),
    'auth-session-audit':    dict(category='Auth',requirements='auth-only'),
    'rc18-oidc-audit':      dict(category='Auth',requirements='spec'),
    'proof-gate':            dict(category='Reporting',requirements='report'),
    'ai-followup-safe':      dict(category='AI locale',requirements='both',ai=True),
    # RC2: compare realmente due GET (solo con host e profili autorizzati).
    'injection-assess':     dict(category='Security',requirements='spec', active=True),
    # RC15 is selectable in the dashboard, not an unapproved writable suite step.
    'rc15-scan':            dict(category='Security',requirements='spec', active=True),
    'rc16-access-auto':     dict(category='Security', requirements='spec', active=True),
    'rc16-assess':          dict(category='Workflow', requirements='spec-config', active=True, writes=True, config_flag='--config'),
    'rc16-workflows':       dict(category='Workflow', requirements='spec'),
    'access-probe':          dict(category='Security', requirements='spec', active=True),
    # RC2: quality gate e impronta del report, sempre senza rete.
    'campaign-audit':        dict(category='Reporting', requirements='report'),
    'evidence-integrity':    dict(category='Reporting', requirements='report'),
    'analyze-openapi':       dict(category='Discovery',requirements='spec'),
    'compatibility-report':  dict(category='Discovery',requirements='spec'),
    'workflow-infer':        dict(category='Workflow',requirements='spec'),
    'adaptive-plan':         dict(category='AI locale',requirements='spec'),
    'verify-findings':       dict(category='Security',requirements='report'),
    'auth-preflight':         dict(category='Auth',requirements='spec'),
    'security-surfaces':      dict(category='Security',requirements='spec'),
    'risk-matrix':            dict(category='Security',requirements='spec'),
    # v0.99: controlli offline; nessuno possiede il permesso 'active'.
    'workflow-safety':        dict(category='Workflow', requirements='spec'),
    'access-evidence-review': dict(category='Security', requirements='report'),
    'mutation-review':        dict(category='Security', requirements='report'),
    'evidence-package':       dict(category='Reporting', requirements='report'),
    'campaign-diagnostics':   dict(category='Reporting', requirements='report'),
    'release-readiness':      dict(category='Reporting', requirements='report'),
    'benchmark-review':       dict(category='Reporting', requirements='config-report'),
    'ai-plan-guard':          dict(category='AI locale', requirements='spec-config', config_flag='--proposals'),
    # v0.90: analisi statiche, non contattano mai il target.
    'campaign-preflight':     dict(category='Discovery',requirements='spec'),
    'workflow-dependencies':  dict(category='Workflow',requirements='spec'),
    'auth-audit':             dict(category='Auth',requirements='spec'),
    'verification-review':    dict(category='Security',requirements='report'),
    'campaign-quality':       dict(category='Reporting',requirements='report'),
    'generate-tests':        dict(category='Discovery',requirements='spec'),
    'map-api':               dict(category='Discovery',requirements='spec'),
    'assess':                dict(category='Discovery',requirements='spec'),
    'intelligent-plan':      dict(category='Discovery',requirements='spec'),
    'workflow-discover':     dict(category='Workflow',requirements='spec'),
    'workflow-map':          dict(category='Workflow',requirements='spec'),
    'journey-discover':      dict(category='Workflow',requirements='spec'),
    'security-inventory':    dict(category='Security',requirements='spec'),
    'auth-draft':            dict(category='Auth',requirements='spec',yaml=True),
    'ai-analyze':            dict(category='AI locale',requirements='spec',ai=True),
    'ai-correlate':          dict(category='AI locale',requirements='both',ai=True),
    'scan':                  dict(category='AI locale',requirements='spec',ai=True),
    'scope-audit':           dict(category='Security',requirements='scope'),
    'auth-profiles':         dict(category='Auth',requirements='auth-only'),
    'benchmark-evaluate':   dict(category='Reporting',requirements='config-report'),
    'vulnerability-triage':  dict(category='Security',requirements='report'),
    'differential-review':   dict(category='Security',requirements='report'),
    'adaptive-review':       dict(category='Security',requirements='both'),
    'analyze-evidence':      dict(category='Security',requirements='config:json'),
    'coverage-report':       dict(category='Reporting',requirements='both'),
    'next-actions':          dict(category='AI locale',requirements='both',budget=True),
    'agent-review':          dict(category='AI locale',requirements='both',budget=True),
    'ai-prioritize':         dict(category='AI locale',requirements='both',budget=True,ai=True),
    'workflow-graph':        dict(category='Workflow',requirements='spec-config'),
    'verify-access-policy': dict(category='Security',requirements='report-config'),
    # RC13 is selectable as an ordinary dashboard task. The fixed control
    # plane adapter, not a generic shell/CLI builder, executes it.
    'rc13-assess':           dict(category='Assessment', requirements='spec',
                                  active=True, writes=True, ai=True),
    'auto-assess':           dict(category='Assessment',requirements='spec',active=True),
    'advanced-vuln-assess':  dict(category='Assessment',requirements='spec',active=True),
    'journey-assess':        dict(category='Workflow',requirements='spec-config',active=True,config_flag='--journey-config'),
    'workflow-assess':       dict(category='Workflow',requirements='spec-config',active=True,writes=True,config_flag='--workflow-config'),
    'multi-resource-assess': dict(category='Workflow',requirements='spec-config',active=True,writes=True,config_flag='--config'),
    'autonomous-agent':      dict(category='AI locale',requirements='both',active=True,budget=True,ai=True),
    'agent-loop-v2':        dict(category='AI locale',requirements='both',active=True,budget=True,ai=True),
}


# Dependencies are ordered, not inferred from user-controlled strings. The active
# assessment is the source of evidence for the review and AI tools.
SUITE_ORDER = (
    'analyze-openapi', 'compatibility-report', 'campaign-preflight', 'generate-tests', 'map-api', 'assess', 'intelligent-plan', 'adaptive-plan',
    'workflow-discover', 'workflow-map', 'workflow-infer', 'rc16-workflows', 'workflow-dependencies', 'workflow-safety', 'journey-discover', 'security-inventory',
    'auth-draft', 'auth-preflight', 'auth-audit', 'rc18-oidc-audit', 'auth-session-audit', 'security-surfaces', 'risk-matrix', 'scope-audit', 'auth-profiles', 'workflow-graph',
    'auto-assess', 'advanced-vuln-assess', 'injection-assess', 'access-probe', 'access-matrix', 'journey-assess',
    'workflow-assess', 'multi-resource-assess', 'rc16-access-auto', 'rc16-assess',
    'vulnerability-triage', 'verify-findings', 'verification-review', 'access-evidence-review', 'mutation-review', 'differential-review', 'adaptive-review', 'evidence-package',
    'analyze-evidence', 'coverage-report', 'verify-access-policy',
    'benchmark-evaluate', 'benchmark-review', 'ai-plan-guard', 'ai-analyze', 'scan', 'ai-correlate', 'ai-followup-safe',
    'next-actions', 'agent-review', 'ai-prioritize',
    'autonomous-agent', 'agent-loop-v2', 'proof-gate', 'campaign-quality', 'campaign-diagnostics', 'release-readiness', 'campaign-audit', 'evidence-integrity',
)


