"""RC17 deterministic finding correlation and evidence grading.

This module never executes network requests, derives CVSS scores, trusts a
scanner's string 'confirmed' or turns an LLM suggestion into a vulnerability.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

_RANK = {"inconclusive": 0, "potential": 1, "probable": 2, "confirmed": 3}
_SECRET_KEYS = {"authorization", "cookie", "password", "secret", "token", "api_key",
                "access_token", "refresh_token", "payload", "headers", "body"}


def _safe_str(value: Any, size: int) -> str:
    text = str(value) if value is not None else ""
    return text[:size].replace("\n", " ").replace("\r", " ")


def _replay_matches(stages: dict[str, Any]) -> set[tuple[str, str]]:
    matched: set[tuple[str, str]] = set()
    for name in ("verification_replay", "agent_followups"):
        stage = stages.get(name, {})
        if not isinstance(stage, dict):
            continue
        for record in stage.get("results", []) or []:
            if isinstance(record, dict) and record.get("status") == "indicator_reproduced_not_exploit_confirmed":
                matched.add((_safe_str(record.get("operation"), 160),
                             _safe_str(record.get("parameter"), 120)))
        for action in stage.get("actions", []) or []:
            if not isinstance(action, dict):
                continue
            for record in action.get("replay_results", []) or []:
                if (isinstance(record, dict) and record.get("status") ==
                        "indicator_reproduced_not_exploit_confirmed"):
                    matched.add((_safe_str(record.get("operation"), 160),
                                 _safe_str(record.get("parameter"), 120)))
    return matched


def _assessment(item: dict[str, Any], stages: dict[str, Any],
                replayed: set[tuple[str, str]]) -> tuple[str, str, str]:
    evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
    category = _safe_str(item.get("category"), 120).lower()
    expected = item.get("expected") or evidence.get("expected")
    code = item.get("observed_status")
    known_source = item.get("source_engine") in {"workflows", "rc16_assess", "authorization_auto"}
    same_object = item.get("same_temporary_resource_verified") is True
    if (known_source and same_object and expected == "deny" and type(code) is int and
            200 <= code <= 299 and category in {"authorization_policy_mismatch", "bola", "bfla"}):
        return ("probable", "high_policy_dependent",
                "L'identità alternativa ha letto la stessa risorsa temporanea con policy deny; validare la policy aziendale.")
    if (item.get("source_engine") in {"rc15_security", "rc15-scan"} and
            evidence.get("callback_received") is True and
            category in {"ssrf_callback", "xxe_callback",
                         "server_side_callback_observed", "xml_external_entity_callback_observed"}):
        return ("probable", "callback_observed",
                "Callback controllata osservata; questo prova una richiesta esterna, non un'esfiltrazione.")
    if category == "mass_assignment_policy_conflict" and (evidence.get("persisted") is True and
            evidence.get("baseline_changed") is True and evidence.get("expected_policy") == "deny"):
        return ("probable", "observed_state_change",
                "Modifica persistente di un campo dichiarato riservato; validare le regole di business.")
    operation = _safe_str(item.get("operation"), 160)
    field = _safe_str(item.get("parameter") or item.get("field"), 120)
    if (operation, field) in replayed:
        return ("probable", "reproduced_http_indicator",
                "Indicatore HTTP riprodotto con un controllo; non costituisce conferma di exploit.")
    if item.get("verification_status") in {"unverified", "error", "inconclusive", "blocked"}:
        return ("inconclusive", "insufficient", "La verifica non è conclusa o è stata bloccata.")
    return ("potential", "initial_observation", "Osservazione da verificare manualmente con controlli negativi e policy.")


def verify_campaign_findings(findings: list[dict[str, Any]], *,
                             stages: dict[str, Any] | None = None) -> dict[str, Any]:
    """Deduplicate without dropping origins, grade only structured evidence.

    A claimed `verification_status=confirmed` never promotes an item. The
    available engines establish indicators, callback or policy observations,
    not universal exploit proof, so no *confirmed* verdict is generated.
    """
    if not isinstance(findings, list) or len(findings) > 2000:
        raise ValueError("Findings must be a list of at most 2000 entries")
    if stages is not None and not isinstance(stages, dict):
        raise ValueError("Stages must be an object")
    stages = stages or {}
    replays = _replay_matches(stages)
    groups: dict[str, dict[str, Any]] = {}
    for item in findings:
        if not isinstance(item, dict):
            continue
        category = _safe_str(item.get("category") or "unclassified", 120)
        operation = _safe_str(item.get("operation") or "unknown", 160)
        field = _safe_str(item.get("field") or item.get("parameter") or item.get("rule_id") or "", 120)
        workflow = _safe_str(item.get("workflow") or item.get("resource") or "", 100)
        identity = _safe_str(item.get("profile") or "", 64)
        key = [category.lower(), operation, field, workflow, identity]
        fingerprint = hashlib.sha256(json.dumps(key, ensure_ascii=False).encode()).hexdigest()[:20]
        status, strength, note = _assessment(item, stages, replays)
        entry = groups.setdefault(fingerprint, {
            "fingerprint": fingerprint, "category": category, "operation": operation,
            "field": field, "workflow": workflow, "occurrences": 0,
            "sources": [], "status": "inconclusive", "evidence_strength": "insufficient",
            "rationale": "No supported evidence", "reproduced": False,
        })
        entry["occurrences"] += 1
        source = _safe_str(item.get("source_engine") or "unknown", 80)
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if _RANK[status] > _RANK[entry["status"]]:
            entry.update(status=status, evidence_strength=strength, rationale=note)
        entry["reproduced"] = entry["reproduced"] or strength == "reproduced_http_indicator"
    observations = list(groups.values())
    counts = {status: sum(item["status"] == status for item in observations) for status in _RANK}
    return {
        "engine": "achilles-deterministic-verifier-rc17", "version": "1.0.0rc17",
        "reported_findings": len(findings), "unique_findings": len(observations),
        "classification_counts": counts, "confirmed_exploits": 0,
        "reproduced_indicators": sum(row["reproduced"] for row in observations),
        "observations": observations,
        "limitations": [
            "Confirmed is reserved for independently demonstrated exploit proof; none is inferred here.",
            "Positive HTTP response without validated policy and object marker is not BOLA proof.",
            "Reproduced injection anomaly and OAST callback are indicators, not automatic exploitation proof.",
            "Raw HTTP bodies, credentials, mutation payloads and fixture identifiers are not recorded.",
        ],
    }
