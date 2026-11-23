"""Build conservative, offline, sanitized security reports from an assessment JSON.

All findings remain *observations* unless a separate, explicit verification
has taken place. A report file must never implicitly upgrade confidence.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
import re
from typing import Any

_PRIVATE = re.compile(r"(?i)(authorization|cookie|password|passwd|secret|token|api.?key|credential|set-cookie|private.?key)")
_ALLOWED_CONFIDENCE = {"indicator", "low", "medium", "high", "confirmed"}
_ALLOWED_SEVERITY = {"informational", "info", "low", "medium", "high", "critical"}


def _safe_text(value: Any, max_length: int = 500) -> str:
    """Only pass short, printable summaries; censor secret-looking metadata."""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return "[omitted]"
    raw = str(value).replace("\x00", "")[:max_length]
    if _PRIVATE.search(raw):
        # Do not copy dynamic body content or credentials into an exported report.
        return "[redacted: potentially sensitive]"
    return raw


def _safe_category(value: Any) -> str:
    """Preserve fixed taxonomy codes, including AUTH, but never free-form secrets."""
    if isinstance(value, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,99}', value):
        return value
    return _safe_text(value, 100)


def _evidence_metadata(data: Any) -> dict[str, Any]:
    """Allowlist evidence metadata; raw requests, headers, bodies and tokens are forbidden."""
    if not isinstance(data, dict):
        return {}
    keys = ("status", "duration_ms", "content_type", "error_type", "truncated",
            "repeated", "expected", "actual", "result", "identity", "check")
    result = {key: _safe_text(data[key], 100) for key in keys if key in data and not _PRIVATE.search(key)}
    # Structured signals only: never copy property names, header values or body excerpts.
    for flag in ("arbitrary_origin_reflected", "allow_credentials", "cache_control_public",
                 "origin_reflected", "cors_credentials_allowed"):
        if type(data.get(flag)) is bool:
            result[flag] = data[flag]
    if type(data.get("property_count")) is int and 0 <= data["property_count"] <= 100:
        result["property_count"] = data["property_count"]
    elif isinstance(data.get("property_paths"), list):
        result["property_count"] = min(len(data["property_paths"]), 100)
    # Permit only bounded, non-sensitive scanner evidence.  Never show a
    # redirect Location URL, raw headers, body or untrusted response content.
    for field in ('baseline_status', 'probe_status', 'requests_compared'):
        value = data.get(field)
        if type(value) is int and 0 <= value <= 599:
            result[field] = value
    if data.get('redirect_destination_host') == 'example.invalid':
        result['redirect_destination_host'] = 'example.invalid'
    if isinstance(data.get("signatures"), list):
        result["signature_classes"] = sorted(set(data["signatures"]) &
                                             {"SQL_ERROR", "STACK_TRACE", "DEBUG_DISCLOSURE"})
    return result



def _safe_reason(item: dict[str, Any]) -> str:
    """Use stable rule text for known categories, never arbitrary response content."""
    from achillesapi.core.evidence_signals import _CHECKED_LABELS
    category = item.get("category")
    if category in _CHECKED_LABELS:
        return _CHECKED_LABELS[category]
    # Active modules write a bounded, deterministic `reason` field. Earlier
    # versions ignored it, rendering legitimate scanner findings as generic
    # "Review required" messages. Keep all external text sanitized.
    return _safe_text(item.get("why_flagged", item.get("reason", item.get("explanation", "Review required"))), 700)


# Stable explanations for passive OpenAPI observations. These are review items,
# not evidence of a security bypass and must never be labelled "confirmed".
_PASSIVE_EXPLANATIONS = {
    'AUTH-001': ('Requisito di autenticazione esplicitamente disabilitato nello Swagger (security: []).',
                 'Verifica con il proprietario dell’API che la rotta sia pubblica e prova i controlli runtime.'),
    'AUTH-002': ('Lo Swagger non dichiara requisiti security per questa operazione. '
                 'Questo NON dimostra che l’endpoint sia accessibile senza autenticazione.',
                 'Controlla security a livello globale e di operazione; verifica l’accesso reale con e senza credenziali.'),
    'AUTHZ-001': ('Il path contiene un identificatore di oggetto: possibile candidato a un test BOLA. '
                  'Non è stata dimostrata alcuna violazione di autorizzazione.',
                  'Confronta due identità, ownership effettiva e risultati HTTP usando un oggetto di test.'),
    'DATA-001': ('Lo schema della risposta include proprietà potenzialmente sensibili: richiede revisione.',
                 'Confronta le proprietà restituite con la policy di visibilità per il ruolo.'),
    'DATA-002': ('Lo schema di scrittura include proprietà potenzialmente sensibili: richiede revisione.',
                 'Verifica allowlist server-side e persistenza solo su risorse temporanee autorizzate.'),
}


# Only the built-in probes actually recorded by the injection engine may be
# exposed. This prevents arbitrary report content from becoming a credential
# disclosure via a field named `test_payloads`.
_INJECTION_DESCRIPTIONS = {
    'sql_error': ('Possibile SQL Injection basata su errori', 'Una sonda ha generato un messaggio di errore compatibile con un database, assente nella richiesta di controllo.', 'Verifica che l’errore derivi davvero dall’input e non da un errore applicativo generico.'),
    'sql_boolean': ('Possibile SQL Injection booleana', 'Due condizioni logiche opposte hanno prodotto risposte differenti.', 'Confronta le risposte normalizzate e ripeti con controlli negativi: differenze casuali non dimostrano SQLi.'),
    'sql_time': ('Possibile SQL Injection temporale', 'Le sonde presentano tempi differenti.', 'Ripeti più volte con una baseline statistica: il jitter di rete può provocare falsi positivi.'),
    'nosql': ('Possibile NoSQL Injection', 'Operatori di query incompatibili con un valore ordinario hanno alterato la risposta.', 'Conferma che il backend interpreti gli operatori e non restituisca semplicemente dati diversi per input diversi.'),
    'ssti': ('Possibile Server-Side Template Injection', 'Espressioni aritmetiche di prova hanno restituito risultati coerenti con la valutazione del template.', 'Escludi l’eco del payload, il caching e trasformazioni applicative legittime.'),
    'command': ('Possibile Command Injection', 'È comparso un marcatore del test nella risposta.', 'Il marcatore potrebbe essere solo riflesso: non classificare come esecuzione di comandi senza conferma indipendente.'),
    'xpath': ('Possibile XPath Injection', 'Due condizioni XPath-like hanno prodotto risposte differenti.', 'La sintassi si sovrappone a SQL: determina prima la tecnologia usata dal backend.'),
    'ldap': ('Possibile LDAP Injection', 'Una stringa simile a un filtro LDAP ha alterato la risposta rispetto al controllo.', 'Serve provare che la differenza dipenda dalla costruzione del filtro LDAP e non da un confronto ordinario.'),
    'crlf': ('Possibile CRLF / HTTP header injection', 'Una sonda contenente CRLF ha prodotto un header di prova in risposta.', 'Verifica la risposta HTTP effettiva e gli eventuali proxy intermedi; non confondere l’eco con una header injection.'),
}

def _safe_probe_details(item: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    category = item.get('category', '')
    # Bounded GET probes are fixed non-secret strings; accept only EXACT
    # canonical pairs.  Never echo user-supplied 'test_payloads' arbitrarily.
    _fixed_bounded = {
        'possible_open_redirect': ('achilles-check', 'https://example.invalid/achilles-check'),
        'possible_html_reflection': ('ACHILLES_CHECK_92317', '<achilles-ACHILLES_CHECK_92317>'),
        'possible_path_handling_error': ('achilles-not-a-file.txt', '../achilles-not-a-file.txt'),
    }
    if category in _fixed_bounded:
        values = _fixed_bounded[category]
        raw = item.get('test_payloads')
        parm = item.get('field') or item.get('parameter')
        if (raw == list(values) and isinstance(parm, str)
                and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', parm)):
            return list(values), {'location': 'query', 'parameter': parm,
                                  'baseline': values[0]}
        return [], {}
    if not isinstance(category, str) or not category.startswith('possible_') or not category.endswith('_injection'):
        return [], {}
    family = category[len('possible_'):-len('_injection')]
    from achillesapi.core.injection_engine_rc5 import PAIRS
    allowed = PAIRS.get(family)
    actual = item.get('test_payloads')
    if not allowed or not isinstance(actual, list):
        return [], {}
    nested = item.get('test_input') if isinstance(item.get('test_input'), dict) else {}
    location = item.get('location') or nested.get('location')
    parameter = item.get('parameter') or nested.get('parameter')
    if location not in {'query', 'header', 'path'} or not isinstance(parameter, str):
        return [], {}
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', parameter):
        return [], {}
    # The suite report has already escaped CRLF once; re-normalization must
    # not escape it a second time or turn another string into a payload.
    printable = [x.replace('\r', r'\r').replace('\n', r'\n').replace('\t', r'\t') for x in allowed]
    if actual != list(allowed) and actual != printable:
        return [], {}
    return printable, {'location': location, 'parameter': parameter,
                       'baseline': '__achilles_normal_control__'}

def _comparison_evidence(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    result = {}
    for key in ('baseline', 'variants'):
        originals = data.get(key)
        values = originals if key == 'variants' and isinstance(originals, list) else [originals]
        if not isinstance(values, list):
            continue
        clean = []
        for value in values[:3]:
            if not isinstance(value, dict):
                continue
            entry = {}
            for field in ('status', 'length', 'elapsed_ms', 'truncated'):
                v = value.get(field)
                if type(v) in (int, float, bool) or v is None:
                    entry[field] = v
            if isinstance(value.get('body_digest'), str) and re.fullmatch(r'[0-9a-f]{16}', value['body_digest']):
                entry['body_sha256_prefix'] = value['body_digest']
            clean.append(entry)
        if clean:
            result[key] = clean if key == 'variants' else clean[0]
    return result

def _profile_label(value: Any) -> str | None:
    """Only a configured *alias*, never credentials, is shown in an auth finding."""
    if (isinstance(value, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.@-]{0,63}', value)
            and not _PRIVATE.search(value)):
        return value
    return None


def _rule_label(value: Any) -> str | None:
    if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', value):
        return value
    return None


def _safe_access_comparison(item: dict[str, Any]) -> list[dict[str, Any]]:
    """Explicit identities, expected policy and response status; never auth material."""
    result = []
    for entry in item.get('access_comparison', []) if isinstance(item.get('access_comparison'), list) else []:
        if not isinstance(entry, dict):
            continue
        identity = _profile_label(entry.get('profile'))
        expected = entry.get('expected')
        status = entry.get('status_code')
        if not identity or expected not in ('allow', 'deny', 'unknown'):
            continue
        clean = {'profile': identity, 'expected': expected}
        if type(status) is int and 100 <= status <= 599:
            clean['status_code'] = status
        result.append(clean)
        if len(result) >= 2:
            break
    return result


def _finding_explanation(category: str, reason: str, passive: bool) -> tuple[str, str]:
    if category.startswith('possible_') and category.endswith('_injection'):
        family = category[len('possible_'):-len('_injection')]
        found = _INJECTION_DESCRIPTIONS.get(family)
        if found:
            return found[0] + '. ' + found[1], found[2]
    _bounded_explanations = {
        'possible_open_redirect': (
            'Possibile open redirect: la GET ha risposto con un reindirizzamento verso example.invalid, hostname non seguito dal client.',
            'Verifica che la destinazione del redirect sia effettivamente controllabile e non ammessa dalla policy applicativa.'),
        'possible_html_reflection': (
            'Possibile riflessione HTML: il marcatore di prova con parentesi angolari è comparso nella risposta senza codifica.',
            'Una riflessione non equivale a XSS: verifica contesto HTML, escaping e condizioni per l’esecuzione JavaScript.'),
        'possible_path_handling_error': (
            'Possibile gestione non sicura dei percorsi: una sequenza relativa innocua genera una risposta server anomala rispetto al controllo.',
            'Non dimostra path traversal o lettura di file: verifica l’effetto senza usare percorsi sensibili.'),
    }
    if category in _bounded_explanations:
        return _bounded_explanations[category]
    if category.lower() == 'mass_assignment_policy_conflict':
        return ('Possibile Mass Assignment: un campo dichiarato riservato dalla policy è cambiato e la GET successiva ne ha verificato la persistenza.',
                'Verificare la policy di scrittura per questo profilo e controllare che il server applichi un’allowlist dei campi modificabili.')
    if category.lower() == 'bfla_write_policy_conflict':
        return ('Possibile BFLA: un profilo ha ottenuto una risposta incompatibile con la policy su una POST/PATCH di una risorsa temporanea.',
                'Verificare la matrice dei ruoli e lo stato della risorsa dopo l’operazione. Uno stato HTTP non basta a dimostrare l’impatto.')
    if category.lower() in {'authorization_policy_mismatch','authorization_policy_conflict'}:
        return ('Possibile violazione della policy di autorizzazione: almeno una delle identità ha ottenuto una risposta HTTP incompatibile con la propria regola allow/deny.',
                'Verifica proprietà della risorsa, regola di accesso, utente e contenuto restituito prima di confermare una BOLA/BFLA.')
    if category in _PASSIVE_EXPLANATIONS:
        return _PASSIVE_EXPLANATIONS[category]
    if passive:
        return ('Osservazione statica derivata dallo Swagger, non vulnerabilità dimostrata.', 'Verifica il comportamento reale e la policy del servizio.')
    return ('Comportamento anomalo segnalato dal motore sulla base delle evidenze raccolte: ' + reason,
            'Riprodurre la richiesta in un ambiente autorizzato e applicare un controllo negativo prima di confermare.')

def _normalize_observation(item: dict[str, Any], index: int, *, passive: bool) -> dict[str, Any]:
    """Map both AssessmentFinding and active-scanner schemas without losing text."""
    if item.get('source_type') == 'ai_hypothesis':
        from achillesapi.core.ai_observations_rc9 import _bounded
        level = item.get('severity', 'informational')
        if level not in {'informational', 'medium', 'high'}:
            level = 'informational'
        # No request, payload or exploit should ever be synthesized from AI prose.
        return {
            'id': _safe_text(item.get('id', f'AI-{index}'), 64),
            'title': _safe_text(item.get('title', 'AI · ipotesi da verificare'), 180),
            'category': _safe_category(item.get('category', 'AI_UNCLASSIFIED')),
            'operation': _safe_text(item.get('operation', 'Endpoint non specificato'), 180),
            'severity': level, 'ai_label': 'AI - ' + ('Info' if level == 'informational' else level),
            'status': 'ai_unverified', 'confidence': 'unverified', 'source_type': 'ai_hypothesis',
            'reason': _bounded(item.get('reason', '')),
            'what_found': 'Ipotesi del modello AI: non verificata con un test HTTP.',
            'verification_guidance': 'Verificare manualmente oppure avviare un controllo autorizzato prima di classificare la vulnerabilità.',
            'test_payloads': [], 'test_input': {}, 'test_request': None,
            'evidence': {'source': 'ollama_local', 'http_tested': False, 'test_payload_recorded': False},
        }
    category = _safe_category(item.get('category', 'unclassified'))
    title = _safe_text(item.get('title', category), 200)
    operation = _safe_text(item.get('operation') or item.get('endpoint') or 'Operazione non disponibile', 160)
    fallback = _safe_reason(item)
    if category in _PASSIVE_EXPLANATIONS:
        base, action = _PASSIVE_EXPLANATIONS[category]
        reason = base + ' Azione consigliata: ' + action
    elif (item.get('reason') or item.get('why_flagged') or item.get('explanation')):
        reason = fallback
    elif item.get('title'):
        reason = title + ' — osservazione da verificare rispetto alla policy prevista.'
    else:
        reason = fallback
    severity = str(item.get('severity', 'informational')).lower()
    # For metadata-only findings severity cannot imply a confirmed exploit.
    if passive:
        severity = 'informational'
    elif severity not in _ALLOWED_SEVERITY:
        severity = 'informational'
    details = item.get('evidence')
    evidence = _evidence_metadata(details)
    comparison = _comparison_evidence(details)
    if not comparison and isinstance(details, dict):
        comparison = _comparison_evidence(details.get('http_comparison'))
    if comparison:
        evidence['http_comparison'] = comparison
    payloads, test_input = _safe_probe_details(item)
    what, verify = _finding_explanation(category, reason, passive)
    comparison = _safe_access_comparison(item)
    rule_id = _rule_label(item.get('rule_id'))
    if category.lower() in {'authorization_policy_mismatch', 'authorization_policy_conflict', 'bfla_write_policy_conflict'}:
        # The authorization probe compares identities, not injection strings.
        # Retain the operator policy and status, never headers or bearer tokens.
        if str(item.get('expected', '')).lower() in {'allow', 'deny'}:
            evidence['expected_access'] = str(item['expected']).lower()
        if type(item.get('observed_status')) is int and 100 <= item['observed_status'] <= 599:
            evidence['observed_http_status'] = item['observed_status']
        if isinstance(item.get('resource'), str):
            evidence['resource'] = _safe_text(item['resource'], 100)
        if 'expected_access' in evidence or 'observed_http_status' in evidence:
            reason = ('Policy di accesso attesa: ' + str(evidence.get('expected_access', 'non indicata')) +
                      '; risposta HTTP ricevuta: ' + str(evidence.get('observed_http_status', 'non disponibile')) +
                      '. Il risultato deve essere confrontato con ownership e ruolo attesi.')
        else:
            # Keep the matrix's explicit pairwise statuses instead of erasing
            # them with generic 'non disponibile' placeholders.
            reason = fallback
    if category.lower() == 'mass_assignment_policy_conflict':
        pointer = item.get('field')
        if isinstance(pointer, str) and re.fullmatch(r'(?:/[A-Za-z0-9_-]{1,64}){1,5}', pointer):
            evidence['json_field_pointer'] = pointer
        if isinstance(details, dict):
            evidence['persisted_after_patch'] = bool(details.get('persisted'))
            evidence['baseline_was_different'] = bool(details.get('baseline_changed'))
        profile = _profile_label(item.get('profile'))
        if profile:
            evidence['profile_used'] = profile
    if passive and isinstance(details, list):
        evidence = {'source': 'openapi_static_analysis', 'clues': len(details[:20])}
    # Only an operation template is retained. No tokens, raw body or concrete
    # sensitive resource identifier is stored in the normalized report.
    test_request = operation if not passive and re.match(r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) /', operation) else None
    report = {
        'id': _safe_text(item.get('finding_id') or item.get('id') or f'OBS-{index:04d}', 160),
        'title': title, 'category': category, 'operation': operation,
        'severity': severity, 'confidence': 'indicator', 'status': 'requires_review',
        'reason': reason, 'evidence': evidence,
        'what_found': what, 'verification_guidance': verify,
        'test_payloads': payloads, 'test_input': test_input, 'test_request': test_request,
        'access_comparison': comparison, 'rule_id': rule_id,
        'verification_status': _safe_text(item.get('verification_status', 'requires_manual_review'), 80),
        'source_type': 'static_openapi' if passive else 'active_or_analysis',
        'discovery_method': ('Analisi statica OpenAPI; nessuna richiesta HTTP.' if passive else
                             'Osservazione prodotta dal task; consultare i metadati del confronto HTTP e il job origine.'),
    }
    vector = item.get('cvss_vector')
    if isinstance(vector, str):
        from achillesapi.reporting.cvss import score_cvss31
        try:
            report['cvss_vector'] = vector
            report['cvss_base_score'] = score_cvss31(vector)
            report['cvss_origin'] = 'vettore fornito esplicitamente dall’analista'
        except ValueError:
            report.pop('cvss_vector', None)
    return report

def _findings_from_report(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect findings from both GET and disposable workflow assessments."""
    entries = []
    # Standalone active scanners (notably injection-assess) already produce a
    # top-level list. The previous exporter discarded these observations,
    # causing an actual result with findings to appear clean in the dashboard.
    # The same normalized, allowlisted pipeline also handles imported
    # professional reports, so a JSON -> HTML/PDF re-export never loses items.
    direct = raw.get("findings")
    if isinstance(direct, list):
        entries.extend(x for x in direct[:300] if isinstance(x, dict))
    # Authorization comparisons are policy conflicts, not proven BOLA. They
    # still need to be displayed as reviewable observations.
    if (raw.get("engine") == "achilles-active-authorization-rc2"
            and raw.get("executed") is True
            and str(raw.get("status","")).endswith("requires_review")):
        observations = raw.get('observations', [])
        observations = observations if isinstance(observations, list) else []
        participants = []
        for profile_key, expected_key in (('owner', 'expected_owner'), ('other', 'expected_other')):
            profile = raw.get(profile_key)
            matching = next((x for x in observations if isinstance(x, dict)
                             and x.get('identity') == profile), {})
            participants.append({'profile': profile, 'expected': raw.get(expected_key),
                                 'status_code': matching.get('status_code')})
        entries.append({"category": "authorization_policy_conflict",
                        "operation": raw.get("operation", "GET (unknown)"),
                        "severity": "medium", 'access_comparison': participants,
                        "reason": "Confronto fra le due identità della regola: almeno uno stato HTTP è incompatibile con la policy dichiarata. Verificare ownership e contenuto."})
    if raw.get('engine') == 'achilles-access-matrix-rc4':
        reviewed_index = 0
        for rule in raw.get('rules', [])[:150]:
            if not isinstance(rule, dict) or not str(rule.get('status', '')).endswith('requires_review'):
                continue
            reviewed_index += 1
            observed = rule.get('observations', [])
            observed = observed if isinstance(observed, list) else []
            display = ', '.join(
                str(x.get('identity', '?')) + ': HTTP ' + str(x.get('status_code', '?'))
                for x in observed[:2] if isinstance(x, dict)
            )
            entries.append({
                'id': 'POLICY-' + str(reviewed_index).zfill(3),
                'rule_id': rule.get('id'),
                'category': 'authorization_policy_conflict',
                'operation': rule.get('operation', ''), 'severity': 'medium',
                'access_comparison': [
                    {'profile': obs.get('identity'),
                     'expected': rule.get('expected_owner', 'allow') if i == 0
                                 else rule.get('expected_other', 'deny'),
                     'status_code': obs.get('status_code')}
                    for i, obs in enumerate(observed[:2]) if isinstance(obs, dict)
                ],
                'reason': 'La richiesta GET ha restituito stati incompatibili con la policy specificata: '
                          + display + '. Regola attesa primo utente: '
                          + str(rule.get('expected_owner', 'allow')) + '; secondo utente: '
                          + str(rule.get('expected_other', 'deny')) + '. Confrontare l’oggetto restituito prima di confermare.',
                'evidence': {'expected': str(rule.get('expected_other', 'deny')),
                             'actual': display},
            })
    if raw.get('engine') == 'access-policy-verifier-v0.36':
        # Offline verification is NOT a new HTTP test. Surface only exact
        # policy mismatches and identify the source as a matrix review.
        for index, decision in enumerate(raw.get('results', [])[:200]):
            if not isinstance(decision, dict) or decision.get('classification') != 'policy_mismatch_requires_review':
                continue
            statuses = decision.get('observed_statuses', [])
            entries.append({
                'id': 'VERIFY-POLICY-' + str(index+1).zfill(3),
                'rule_id': decision.get('rule_id'),
                'category': 'authorization_policy_conflict',
                'operation': decision.get('operation', ''), 'severity': 'medium',
                'access_comparison': [{'profile': decision.get('identity'),
                                       'expected': decision.get('expected'),
                                       'status_code': statuses[0] if len(statuses) == 1 else None}],
                'reason': ('Verifica offline della regola ' + str(decision.get('rule_id','?')) +
                           ': profilo ' + str(decision.get('identity','?')) +
                           ', policy ' + str(decision.get('expected','?')) +
                           ', stato HTTP osservato ' + ', '.join(str(x) for x in statuses) +
                           '. Il conflitto richiede verifica di ownership e contenuto; non è una BOLA confermata.'),
                'evidence': {'expected': str(decision.get('expected','?')),
                             'actual': ', '.join(str(x) for x in statuses)},
            })
    execution = raw.get("execution_report")
    if isinstance(execution, dict):
        entries.extend(x for x in execution.get("findings", []) if isinstance(x, dict))
    workflow = raw.get("workflow_execution")
    if isinstance(workflow, dict):
        for step in workflow.get("workflows", []):
            if isinstance(step, dict):
                entries.extend(x for x in step.get("findings", []) if isinstance(x, dict))
    multi = raw.get("multi_resource_execution")
    if isinstance(multi, dict):
        entries.extend(x for x in multi.get("findings", []) if isinstance(x, dict))
    # ai-correlate preserves the pre-existing scanner findings in a dedicated
    # section. Export them as observations, never as AI-confirmed flaws.
    analyzed = raw.get("evidence_analysis")
    if isinstance(analyzed, dict):
        original = analyzed.get("scanner_observations")
        if isinstance(original, dict) and isinstance(original.get("findings"), list):
            for x in original["findings"][:200]:
                if isinstance(x, dict):
                    entries.append(x)
    # Suggestions from Ollama are reviewable hypotheses, NOT scanner findings.
    from achillesapi.core.ai_observations_rc9 import extract_ai_observations
    entries.extend(extract_ai_observations(raw))
    return entries


def _source_kind(raw: dict[str, Any]) -> str:
    """Recognize supported job outputs without pretending they all contain HTTP findings."""
    if isinstance(raw.get("plan"), dict):
        return "assessment"
    if any(isinstance(raw.get(k), dict) for k in (
        "execution_report", "multi_resource_execution", "workflow_execution")):
        return "execution_result"
    if isinstance(raw.get("engine"), str):
        return "tool_analysis"
    if any(k in raw for k in ("executive_summary", "cross_correlations", "limitations")):
        return "ai_analysis"
    if isinstance(raw.get("report_schema"), str) and isinstance(raw.get("summary"), dict):
        return "professional_report"
    return "other_json"


def _safe_highlights(raw: dict[str, Any]) -> list[str]:
    """Expose only allowlisted, bounded counters; never print arbitrary model prose or secrets."""
    names = ("engine", "candidate_count", "confirmed_vulnerabilities",
             "requests_sent", "network_requests_sent", "stop_reason",
             "generated_at_utc", "report_schema")
    result = []
    for name in names:
        value = raw.get(name)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            result.append(f"{name}: {value}")
        elif name in ("engine", "stop_reason", "report_schema") and isinstance(value, str):
            result.append(f"{name}: {_safe_text(value, 100)}")
    for name in ("actions", "proposed_actions", "candidates", "operations", "responses"):
        if isinstance(raw.get(name), list):
            result.append(f"{name}: {len(raw[name])} elementi")
    return result[:12]



_SEVERITY_PRIORITY = {'critical':5, 'high':4, 'medium':3, 'low':2, 'info':1, 'informational':1}
_GROUP_NAMES = {
    'authorization':'Autorizzazione e campi riservati', 'injection':'Injection e input',
    'ai':'Ipotesi dell’AI', 'static':'Avvisi statici OpenAPI', 'other':'Altre osservazioni',
}

def _report_group(finding: dict[str, Any]) -> str:
    name = str(finding.get('category', '')).lower()
    if finding.get('source_type') == 'ai_hypothesis': return 'ai'
    if finding.get('source_type') == 'static_openapi': return 'static'
    if any(x in name for x in ('authorization', 'bfla', 'bola', 'mass_assignment')) or name.startswith('authz'):
        return 'authorization'
    if any(x in name for x in ('injection', 'sqli', 'ssti', 'crlf')):
        return 'injection'
    return 'other'

def _finding_groups(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Presentation-only grouping in severity order, preserving duplicate IDs.

    The original observation array is immutable for the purposes of rendering;
    indexes, not reporter-provided IDs, point to each finding. Some child jobs
    legitimately reuse finding IDs (e.g. POLICY-001).
    """
    groups: dict[str, list[int]] = {}
    for index, finding in enumerate(findings):
        groups.setdefault(_report_group(finding), []).append(index)
    result: list[dict[str, Any]] = []
    for category, positions in groups.items():
        positions.sort(key=lambda i: -_SEVERITY_PRIORITY.get(str(findings[i].get('severity', 'informational')), 1))
        top = str(findings[positions[0]].get('severity', 'informational'))
        result.append({'category': category, 'title': _GROUP_NAMES[category],
                       'severity': 'informational' if top == 'info' else top,
                       'count': len(positions),
                       'finding_indices': positions,
                       'finding_ids': [findings[i]['id'] for i in positions]})
    return sorted(result, key=lambda g: -_SEVERITY_PRIORITY.get(g['severity'], 1))


def summarize_assessment(raw: dict[str, Any]) -> dict[str, Any]:
    """Build a minimal immutable-looking report view without changing evidence severity."""
    if not isinstance(raw, dict):
        raise ValueError("Il risultato del job deve essere un oggetto JSON.")
    kind = _source_kind(raw)
    # Non-assessment jobs deserve a genuine document, not a fictitious
    # security finding or a misleading count of tested endpoints.
    if kind != "assessment":
        execution = raw.get("execution_report")
        if not isinstance(execution, dict):
            execution = {}
        counts = raw.get("summary") if kind == "professional_report" else {}
        if not isinstance(counts, dict):
            counts = {}
        entries = _findings_from_report(raw)
        findings = []
        for index, item in enumerate(entries, 1):
            passive = bool(item.get('source_type') == 'static_openapi' or (item.get('finding_id') and item.get('endpoint')))
            finding = _normalize_observation(item, index, passive=passive)
            if kind != 'tool_analysis' and not passive and finding.get('source_type') != 'ai_hypothesis':
                finding['severity'] = 'informational'
            findings.append(finding)
        return {
            "report_schema": "achillesapi.professional.2",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source_version": _safe_text(raw.get("version", "unknown"), 32),
            "source_kind": kind,
            "source_highlights": _safe_highlights(raw),
            "scope_note": "Report offline sanitizzato di un risultato dello strumento selezionato.",
            "summary": {
                "operations_in_spec": counts.get("operations_in_spec", 0) if kind == "professional_report" else 0,
                "operations_by_planner_state": {},
                "target_requests_reported": (
                    (raw.get("http_telemetry") or {}).get("attempted", 0)
                    if raw.get("engine") == "achillesapi-bounded-suite"
                    else execution.get("requests_sent", raw.get("requests_sent", 0))
                    if kind != "professional_report" else counts.get("target_requests_reported", 0)
                ),
                "findings_requiring_review": len(findings),
                "findings_by_severity": dict(Counter(x["severity"] for x in findings)),
                "manual_cleanup_required": bool(raw.get("manual_cleanup_required", False)),
            },
            "findings": findings,
            "finding_groups": _finding_groups(findings),
            "methodology": ["Esportazione del risultato originale con metadati in allowlist.",
                            "Gli output AI e i piani offline non dimostrano vulnerabilità."],
            "limitations": ["Questo non è un assessment di rete completo.",
                            "Nessun finding di sicurezza viene inventato dai risultati di pianificazione.",
                            "Il contenuto JSON originale può essere scaricato separatamente."],
        }
    findings = []
    for index, item in enumerate(_findings_from_report(raw), start=1):
        severity = str(item.get("severity", "informational")).lower()
        confidence = str(item.get("confidence", "indicator")).lower()
        status = str(item.get("status", "requires_review"))
        observation = _normalize_observation(item, index, passive=bool(item.get('source_type') == 'static_openapi' or (item.get('finding_id') and item.get('endpoint'))))
        if status in {'confirmed', 'false_positive'} and not item.get('finding_id'):
            observation['status'] = status
        if confidence in _ALLOWED_CONFIDENCE and not item.get('finding_id'):
            observation['confidence'] = confidence
        if severity in _ALLOWED_SEVERITY and not item.get('finding_id'):
            observation['severity'] = severity
        findings.append(observation)
    plan = raw["plan"]
    operations = plan.get("operations", [])
    if not isinstance(operations, list):
        operations = []
    inventory = Counter(str(x.get("status", "unknown")) for x in operations if isinstance(x, dict))
    counts = Counter(item["severity"] for item in findings)
    exec_status = plan.get("execution", {})
    exec_status = exec_status if isinstance(exec_status, dict) else {}
    workflow = raw.get("workflow_execution")
    workflow = workflow if isinstance(workflow, dict) else {}
    multi = raw.get("multi_resource_execution")
    multi = multi if isinstance(multi, dict) else {}
    return {
        "report_schema": "achillesapi.professional.2",
        "source_kind": "assessment",
        "source_highlights": [],
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_version": _safe_text(raw.get("version", "unknown"), 32),
        "scope_note": "This report contains only sanitized metadata. Verify permitted scope independently.",
        "summary": {
            "operations_in_spec": len(operations),
            "operations_by_planner_state": dict(inventory),
            "target_requests_reported": exec_status.get("requests_sent", 0),
            "findings_requiring_review": sum(x["status"] in {"requires_review", "ai_unverified"} for x in findings),
            "findings_by_severity": dict(counts),
            "manual_cleanup_required": bool(workflow.get("manual_cleanup_required", False)
                                             or multi.get("manual_cleanup_required", False)),
        },
        "findings": findings,
        "finding_groups": _finding_groups(findings),
        "methodology": [
            "OpenAPI-driven planning and scope-controlled HTTP checks",
            "Observations are not proof of exploitability unless independently verified",
            "Disposable writes need operator-approved fixtures and verified cleanup",
            "Local AI suggestions cannot authorize or execute network requests",
        ],
        "limitations": [
            "The absence of a finding does not demonstrate the absence of a vulnerability.",
            "Status codes alone cannot prove BOLA, BFLA, SQL injection or business logic flaws.",
            "Raw HTTP requests and bodies are deliberately not included in this export.",
        ],
    }


def _markdown(report: dict[str, Any]) -> str:
    """Render the sanitized report as a copyable, Markdown-friendly document."""
    summary = report["summary"]
    lines = ["# AchillesAPI — Security Assessment", "", f"Generated: {report['generated_at_utc']}",
             "", "## Executive summary", "", f"Source type: {report.get('source_kind', 'assessment')}",
             f"Operations: {summary['operations_in_spec']}",
             f"Requests (reported): {summary['target_requests_reported']}",
             f"Observations requiring human review: {summary['findings_requiring_review']}",
             f"Manual cleanup required: {summary['manual_cleanup_required']}", "", "## Findings", ""]
    if not report["findings"]:
        lines += ["No automated observations were exported. This is NOT a clean bill of health.", ""]
    for group in report.get('finding_groups', _finding_groups(report['findings'])):
      lines += [f"### {group['title']} · severità massima {group['severity']} · {group['count']} osservazioni", ""]
      for finding_index in group['finding_indices']:
        finding=report['findings'][finding_index]
        lines += [f"#### {finding['id']} — {finding['category']}", "",
                  f"- Operation: `{finding['operation']}`", f"- Severity: {finding['severity']}",
                  f"- Confidence: {finding['confidence']}", f"- Status: {finding['status']}",
                  f"- Rationale: {finding['reason']}",
                  f"- What was found: {finding.get('what_found', '')}",
                  f"- Source: {finding.get('source_type', 'unknown')}",
                  f"- Discovery method: {finding.get('discovery_method', 'See source job')}",
                  f"- AI triage: {finding.get('ai_label', 'not AI')}",
                  f"- Verification: {finding.get('verification_guidance', '')}",
                  f"- Test input: `{json.dumps(finding.get('test_input', {}), ensure_ascii=False)}`",
                  f"- Payloads used: `{json.dumps(finding.get('test_payloads', []), ensure_ascii=False)}`",
                  f"- Evidence metadata: `{json.dumps(finding['evidence'], ensure_ascii=False)}`", ""]
    if report.get("source_highlights"):
        lines += ["## Sintesi del risultato", ""] + [f"- {x}" for x in report["source_highlights"]]
    lines += ["## Methodology", ""] + [f"- {x}" for x in report["methodology"]]
    lines += ["", "## Limitations", ""] + [f"- {x}" for x in report["limitations"]]
    return "\n".join(lines) + "\n"


def _html(report: dict[str, Any]) -> str:
    """Escape every dynamic field: saved assessment files are untrusted content."""
    items = []
    for group in report.get('finding_groups', _finding_groups(report['findings'])):
      items.append('<section class="severity-section"><h2>' + escape(group['title']) +
                   ' · severità massima ' + escape(str(group['severity'])) +
                   ' · ' + str(group['count']) + ' osservazioni</h2>')
      for finding_index in group['finding_indices']:
        entry=report['findings'][finding_index]
        evidence = escape(json.dumps(entry["evidence"], ensure_ascii=False))
        items.append("<article><h3>" + escape(entry["id"] + " — " + entry["category"]) +
                       "</h3><p><strong>Operation:</strong> " + escape(entry["operation"]) +
                       "</p><p><strong>Severity:</strong> " + escape(entry["severity"]) +
                       " | <strong>Confidence:</strong> " + escape(entry["confidence"]) +
                       " | <strong>Status:</strong> " + escape(entry["status"]) +
                       "</p><p><strong>Origine:</strong> " + escape(entry.get("source_type", "unknown")) +
                       " | <strong>Priorità AI:</strong> " + escape(entry.get("ai_label", "non AI")) +
                       "</p><p><strong>Cosa rilevato:</strong> " + escape(entry.get("what_found", "")) +
                       "</p><p><strong>Perché:</strong> " + escape(entry["reason"]) +
                       "</p><p><strong>Come verificare:</strong> " + escape(entry.get("verification_guidance", "")) +
                       "</p><p><strong>Come rilevato:</strong> " + escape(entry.get("discovery_method", "Vedere il job origine")) +
                       "</p><p><strong>Input:</strong> " + escape(json.dumps(entry.get("test_input", {}), ensure_ascii=False)) +
                       "</p><p><strong>Payload inviati:</strong> " + escape(json.dumps(entry.get("test_payloads", []), ensure_ascii=False)) +
                       "</p><pre>" + evidence + "</pre></article>")

      items.append("</section>")
    summary = report["summary"]
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<title>AchillesAPI Security Assessment</title><style>"
            "body{font:16px system-ui,sans-serif;margin:3rem auto;max-width:920px;line-height:1.55;color:#172236}"
            "article{border:1px solid #cfd6df;border-radius:10px;padding:1rem;margin:1rem 0}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f5f8;padding:1rem}"
            "h1,h2,h3{line-height:1.25}</style><h1>AchillesAPI — Security Assessment</h1>"
            "<p>Generated " + escape(report["generated_at_utc"]) + "</p>"
            "<h2>Summary</h2><p>Operations: " + str(summary["operations_in_spec"]) +
            " | Requests reported: " + escape(str(summary["target_requests_reported"])) +
            " | Observations to review: " + str(summary["findings_requiring_review"]) + "</p>"
            "<p>Source type: " + escape(report.get("source_kind", "assessment")) + "</p>"
            "<h2>Sintesi del risultato</h2><ul>" + "".join("<li>" + escape(x) + "</li>" for x in report.get("source_highlights", [])) + "</ul>"
            "<h2>Findings</h2>" + ("".join(items) or "<p>No automated observations. This does not prove security.</p>") +
            "<h2>Limitations</h2><ul>" + "".join("<li>" + escape(x) + "</li>" for x in report["limitations"]) +
            "</ul></html>")


def write_professional_report(input_path: Path, output_dir: Path, formats: tuple[str, ...] = ("json", "md", "html")) -> list[Path]:
    """Convert a previously saved assessment offline; never contact the target."""
    if not formats or any(x not in {"json", "md", "html", "pdf"} for x in formats):
        raise ValueError("Available formats: json, md, html, pdf")
    if input_path.stat().st_size > 25_000_000:
        raise ValueError("Assessment JSON is too large (25 MB limit)")
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    report = summarize_assessment(raw)
    output_dir.mkdir(parents=True, exist_ok=True)
    files = []
    for fmt in dict.fromkeys(formats):
        path = output_dir / f"achilles-report.{fmt}"
        if fmt == "json":
            path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        elif fmt == "md":
            path.write_text(_markdown(report), encoding="utf-8")
        elif fmt == "html":
            path.write_text(_html(report), encoding="utf-8")
        elif fmt == "pdf":
            try:
                from reportlab.lib.styles import getSampleStyleSheet
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
            except ImportError as exc:
                raise ValueError("PDF export requires: uv sync --extra pdf") from exc
            styles = getSampleStyleSheet()
            story = [Paragraph("AchillesAPI — Security Assessment", styles["Title"]), Spacer(1, 18)]
            s = report["summary"]
            story.append(Paragraph(f"Operations: {s['operations_in_spec']}; observations for review: {s['findings_requiring_review']}", styles["Normal"]))
            story.append(Paragraph("Tipo di risultato: " + escape(report.get("source_kind", "assessment")), styles["Normal"]))
            for highlight in report.get("source_highlights", []):
                story.append(Paragraph(escape(highlight), styles["Normal"]))
            for group in report.get("finding_groups", _finding_groups(report["findings"])):
                story += [Spacer(1, 14), Paragraph(
                    escape(f"{group['title']} — severità massima: {group['severity']} ({group['count']})"),
                    styles["Heading2"])]
                for index in group["finding_indices"]:
                    finding = report["findings"][index]
                    story += [Spacer(1, 8), Paragraph(escape(finding["category"]), styles["Heading3"]),
                              Paragraph(escape(finding["operation"]), styles["Normal"]),
                              Paragraph(escape(f"Severità: {finding['severity']}; Stato: {finding['status']}"), styles["Normal"]),
                              Paragraph(escape(finding["reason"]), styles["Normal"]),
                              Paragraph(escape(finding.get("what_found", "")), styles["Normal"]),
                              Paragraph(escape("Origine: " + finding.get("source_type", "unknown") +
                                               " · " + finding.get("ai_label", "")), styles["Normal"]),
                              Paragraph(escape("Payload: " + json.dumps(
                                  finding.get("test_payloads", []), ensure_ascii=False)), styles["Normal"]),
                              Paragraph(escape("Evidenze: " + json.dumps(
                                  finding.get("evidence", {}), ensure_ascii=False)[:1200]), styles["Normal"])]
            story += [Spacer(1, 18), Paragraph("Limitations", styles["Heading2"])]
            story += [Paragraph(escape(x), styles["Normal"]) for x in report["limitations"]]
            SimpleDocTemplate(str(path), pagesize=(595, 842), leftMargin=46, rightMargin=46).build(story)
        files.append(path)
    return files
