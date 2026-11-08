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
    return _safe_text(item.get("why_flagged", item.get("explanation", "Review required")), 700)

def _findings_from_report(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect findings from both GET and disposable workflow assessments."""
    entries = []
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
            findings.append({
                "id": f"OBS-{index:04d}",
                "category": _safe_category(item.get("category", "unclassified")),
                "operation": _safe_text(item.get("operation", "unknown"), 160),
                "severity": (
                    str(item.get("severity", "informational")).lower()
                    if kind == "tool_analysis" and isinstance(raw.get("evidence_analysis"), dict)
                    and str(item.get("severity", "informational")).lower() in _ALLOWED_SEVERITY
                    else "informational"
                ),
                "confidence": "indicator", "status": "requires_review",
                "reason": _safe_reason(item),
                "evidence": _evidence_metadata(item.get("evidence")),
            })
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
                    execution.get("requests_sent", raw.get("requests_sent", 0))
                    if kind != "professional_report" else counts.get("target_requests_reported", 0)
                ),
                "findings_requiring_review": len(findings),
                "findings_by_severity": dict(Counter(x["severity"] for x in findings)),
                "manual_cleanup_required": bool(raw.get("manual_cleanup_required", False)),
            },
            "findings": findings,
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
        findings.append({
            "id": _safe_text(item.get("id", f"OBS-{index:04d}"), 64),
            "category": _safe_category(item.get("category", "unclassified")),
            "operation": _safe_text(item.get("operation", "unknown"), 160),
            "severity": severity if severity in _ALLOWED_SEVERITY else "informational",
            "confidence": confidence if confidence in _ALLOWED_CONFIDENCE else "indicator",
            "status": "requires_review" if status not in {"confirmed", "false_positive"} else status,
            "reason": _safe_reason(item),
            "evidence": _evidence_metadata(item.get("evidence")),
        })
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
            "findings_requiring_review": sum(x["status"] == "requires_review" for x in findings),
            "findings_by_severity": dict(counts),
            "manual_cleanup_required": bool(workflow.get("manual_cleanup_required", False)
                                             or multi.get("manual_cleanup_required", False)),
        },
        "findings": findings,
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
    for finding in report["findings"]:
        lines += [f"### {finding['id']} — {finding['category']}", "",
                  f"- Operation: `{finding['operation']}`", f"- Severity: {finding['severity']}",
                  f"- Confidence: {finding['confidence']}", f"- Status: {finding['status']}",
                  f"- Rationale: {finding['reason']}",
                  f"- Evidence metadata: `{json.dumps(finding['evidence'], ensure_ascii=False)}`", ""]
    if report.get("source_highlights"):
        lines += ["## Sintesi del risultato", ""] + [f"- {x}" for x in report["source_highlights"]]
    lines += ["## Methodology", ""] + [f"- {x}" for x in report["methodology"]]
    lines += ["", "## Limitations", ""] + [f"- {x}" for x in report["limitations"]]
    return "\n".join(lines) + "\n"


def _html(report: dict[str, Any]) -> str:
    """Escape every dynamic field: saved assessment files are untrusted content."""
    items = []
    for entry in report["findings"]:
        evidence = escape(json.dumps(entry["evidence"], ensure_ascii=False))
        items.append("<article><h3>" + escape(entry["id"] + " — " + entry["category"]) +
                     "</h3><p><strong>Operation:</strong> " + escape(entry["operation"]) +
                     "</p><p><strong>Severity:</strong> " + escape(entry["severity"]) +
                     " | <strong>Confidence:</strong> " + escape(entry["confidence"]) +
                     " | <strong>Status:</strong> " + escape(entry["status"]) +
                     "</p><p>" + escape(entry["reason"]) + "</p><pre>" + evidence + "</pre></article>")
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
            for finding in report["findings"]:
                story += [Spacer(1, 12), Paragraph(escape(finding["category"]), styles["Heading2"]),
                          Paragraph(escape(finding["operation"]), styles["Normal"]),
                          Paragraph(escape(finding["reason"]), styles["Normal"])]
            story += [Spacer(1, 18), Paragraph("Limitations", styles["Heading2"])]
            story += [Paragraph(escape(x), styles["Normal"]) for x in report["limitations"]]
            SimpleDocTemplate(str(path), pagesize=(595, 842), leftMargin=46, rightMargin=46).build(story)
        files.append(path)
    return files
