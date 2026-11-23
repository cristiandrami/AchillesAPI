"""Lab-independent browser control plane for approved AchillesAPI CLI operations.

Every command is constructed by a fixed registry. No browser-supplied command,
path or shell fragment is executed. Files are referenced by opaque upload/job IDs.
"""
from __future__ import annotations

import json
import time
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from achillesapi.core.openapi import analyze_openapi_file
from achillesapi.core.production_v031 import scope_audit

ID = re.compile(r'^[0-9a-f]{32}$')
PROFILE = re.compile(r'^[a-zA-Z0-9_.-]{1,64}$')
MAX_CONFIG = 128 * 1024
OLLAMA_MODEL_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,119}$')
OLLAMA_LOOPBACK = 'http://127.0.0.1:11434'


class _NoOllamaRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow an Ollama response to another host (or even another port)."""
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError('Ollama HTTP redirect disabled')


class OllamaTestRequest(BaseModel):
    model: str = Field(min_length=1, max_length=120)


def _local_ollama_json(path: str, payload: dict | None = None, timeout: float = 1.2) -> dict:
    """Contact *only* the hardcoded loopback Ollama API, bypassing env proxies.

    Bound returned data and request duration; do not send target inputs to health
    checks or model self-tests. The path is never supplied by the browser.
    """
    if path not in {'/api/tags', '/api/ps', '/api/generate'}:
        raise ValueError('Unknown local Ollama endpoint')
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    request = urllib.request.Request(
        OLLAMA_LOOPBACK + path,
        data=data,
        headers={'User-Agent': 'AchillesAPI-dashboard',
                 **({'Content-Type': 'application/json'} if data is not None else {})},
        method='POST' if data is not None else 'GET',
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoOllamaRedirect())
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError('Unexpected Ollama HTTP status')
        raw = response.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        raise ValueError('Ollama response exceeds safety limit')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('Invalid Ollama API response')
    return value


def _installed_ollama_executable() -> str | None:
    """Find Ollama on PATH or in the standard Windows user install path."""
    binary = shutil.which('ollama')
    if binary:
        return binary
    if sys.platform == 'win32':
        for env, suffix in [('LOCALAPPDATA', ('Programs', 'Ollama', 'ollama.exe')),
                            ('ProgramFiles', ('Ollama', 'ollama.exe'))]:
            base = os.environ.get(env)
            if base:
                candidate = Path(base).joinpath(*suffix)
                if candidate.is_file():
                    return str(candidate)
    return None


from achillesapi.core.registry_v090 import TOOLS, SUITE_ORDER

# A task being in the "AI" category does NOT imply a request to Ollama.
# Only these CLI commands actually contact the local model.
OLLAMA_REQUIRED = frozenset({'ai-analyze', 'ai-correlate', 'ai-followup-safe'})
OLLAMA_OPTIONAL = frozenset({'adaptive-plan', 'scan', 'ai-prioritize', 'autonomous-agent', 'agent-loop-v2'})

# The dashboard's generic request limit (up to 150) is NOT the accepted CLI
# limit of every engine. Keep limits centralized and never let Typer reject an
# otherwise valid suite task before it has a chance to run.
CLI_REQUEST_LIMITS = {
    'access-probe': (2, 100),
    'access-matrix': (2, 150),
    'injection-assess': (1, 150),
    'rc15-scan': (1, 500),
    'rc16-access-auto': (2, 150),
    'rc16-assess': (1, 500),
    'multi-resource-assess': (1, 500),
    'advanced-vuln-assess': (1, 200),
    'auto-assess': (1, 500),
    'journey-assess': (1, 500),
}

def cli_request_budget(action: str, requested: int) -> int:
    """Adapt an operator-approved budget to one CLI's documented bounds."""
    minimum, maximum = CLI_REQUEST_LIMITS.get(action, (1, 150))
    return max(minimum, min(maximum, requested))


def _ollama_readiness(model: str) -> dict[str, Any]:
    """Local service/model preflight. No OpenAPI data or credentials transmitted."""
    state = {'status': 'unavailable', 'model': model, 'message': ''}
    if not OLLAMA_MODEL_NAME.fullmatch(model):
        state['message'] = 'Nome del modello Ollama non valido.'
        return state
    try:
        response = _local_ollama_json('/api/tags', timeout=1.7)
        names = [x.get('name') for x in response.get('models', [])
                 if isinstance(x, dict) and isinstance(x.get('name'), str)]
        if not names:
            state['message'] = 'Ollama risponde ma nessun modello è installato. Installa o prepara un modello.'
        elif model not in names and not (':' not in model and model + ':latest' in names):
            state['message'] = ('Il modello ' + model + ' non è tra quelli installati. '
                                'Scegline uno nel pannello Ollama e riavvia la suite.')
        else:
            state['status'] = 'ready'
            state['message'] = 'Servizio locale raggiungibile e modello installato. JSON non ancora verificato.'
    except (OSError, ValueError, TypeError, urllib.error.URLError, json.JSONDecodeError) as exc:
        state['message'] = 'Ollama non raggiungibile su 127.0.0.1:11434. Avvialo dal pannello e verifica il modello.'
    return state

def _ai_output_present(action: str, data: dict[str, Any]) -> bool:
    """Require concrete structured output before claiming a model was invoked."""
    if action == 'ai-analyze':
        return isinstance(data.get('ai_analysis'), dict) and data.get('provider') == 'ollama-local-only'
    if action == 'ai-correlate':
        return isinstance(data.get('ai_correlation'), dict) and data.get('provider') == 'ollama-local-only'
    if action == 'ai-followup-safe':
        return data.get('provider') == 'ollama-loopback'
    return any(isinstance(data.get(key), dict) for key in
               ('ai_analysis', 'ai_advisory', 'local_ai_advice'))


class ToolRequest(BaseModel):
    """Typed, bounded UI parameters; no freeform CLI argument input."""
    action: str
    specification_id: str | None = None
    assessment_id: str | None = None
    config_id: str | None = None
    access_rules_id: str | None = None  # Dedicated saved matrix; independent of workflow manifest
    auth_config_id: str | None = None
    base_url: str = ''
    allow_host: str = ''
    execute: bool = False
    approve_writes: bool = False
    acknowledgment: bool = False
    max_requests: int = Field(40,ge=1,le=150)
    rate: float = Field(1.0,ge=0.1,le=5.0)
    budget: int = Field(3,ge=0,le=15)
    profiles: list[str] = Field(default_factory=list,max_length=6)
    operation: str | None = None
    expected_other: str = "unknown"
    expected_owner: str = "allow"
    injection_families: list[str] = Field(default_factory=lambda: ["sql_error","sql_boolean","nosql","ssti","command","xpath","ldap","crlf"],max_length=9)
    path_values: list[str] = Field(default_factory=list,max_length=15)
    ai: bool = False
    model: str = 'achilles-local'
    allow_insecure_http: bool = False
    config_usage: str = 'multi-resource'
    rc13_body_probes: bool = False
    rc13_max_requests: int = Field(150, ge=5, le=1000)
    rc15_callback_base: str | None = Field(default=None, max_length=250)
    rc15_callback_observer: str | None = Field(default=None, max_length=100)
    rc15_fixture_file: str | None = Field(default=None, max_length=80)
    rc15_fixture_marker: str | None = Field(default=None, max_length=120)
    rc15_callback_approved: bool = False
    rc15_approve_xml_oast: bool = False
    rc13_body_fields: list[str] = Field(default_factory=list, max_length=4)
    secrets: dict[str,str] = Field(default_factory=dict,max_length=20)


class RetryStepRequest(BaseModel):
    """Rerun exactly one existing suite step with validated uploaded prerequisites."""
    step_index: int = Field(ge=0, le=100)
    config_id: str | None = None
    auth_config_id: str | None = None
    config_usage: str | None = None
    base_url: str | None = None
    allow_host: str | None = None
    acknowledgment: bool = False
    enable_active: bool = False
    enable_ai: bool = False
    approve_writes: bool = False
    allow_insecure_http: bool = False
    secrets: dict[str, str] = Field(default_factory=dict, max_length=20)
    model: str | None = None
    profiles: list[str] | None = Field(default=None,max_length=6)
    path_values: list[str] | None = Field(default=None,max_length=15)
    operation: str | None = None
    expected_other: str | None = None
    injection_families: list[str] | None = Field(default=None,max_length=9)
    max_total_requests: int | None = Field(default=None, ge=1, le=600)


class RC13DashboardRequest(BaseModel):
    """An independent RC13 campaign with explicit, separate permissions."""
    config: ToolRequest
    active: bool = False
    writes: bool = False
    body_probes: bool = False
    body_probe_fields: list[str] = Field(default_factory=list, max_length=4)
    ai: bool = False
    agent_followups: bool = False
    agent_rounds: int = Field(2, ge=1, le=3)
    agent_budget: int = Field(24, ge=2, le=60)
    max_requests: int = Field(150, ge=1, le=1000)
    rc15_callback_base: str | None = Field(default=None,max_length=250)
    rc15_callback_observer: str | None = Field(default=None,max_length=100)
    rc15_fixture_file: str | None = Field(default=None,max_length=80)
    rc15_fixture_marker: str | None = Field(default=None,max_length=120)
    rc15_callback_approved: bool = False


class SuiteRequest(BaseModel):
    """One-click bounded orchestration of the fixed registry (not arbitrary commands)."""
    config: ToolRequest
    workflow_config_ids: list[str] = Field(default_factory=list, max_length=20)
    include_ai: bool = False
    include_active: bool = False
    include_writes: bool = False
    include_optional: bool = True
    include_rc13: bool = False
    rc17_agent_followups: bool = False
    rc17_agent_rounds: int = Field(2, ge=1, le=3)
    rc17_agent_budget: int = Field(24, ge=2, le=60)
    rc13_body_probes: bool = False
    rc13_body_fields: list[str] = Field(default_factory=list, max_length=4)
    rc13_body_fields_by_workflow: dict[str, list[str]] = Field(default_factory=dict, max_length=20)
    rc13_max_requests: int = Field(100, ge=5, le=300)
    max_total_requests: int = Field(300, ge=1, le=600)
    max_runtime_seconds: int = Field(1800, ge=60, le=7200)

def suite_skip_reason(action: str, config: ToolRequest, request: SuiteRequest,
                      evidence_id: str | None) -> str | None:
    """Honest explanation for features which cannot safely run with this input."""
    tool = TOOLS[action]
    kind = tool['requirements']
    rules_id = config.access_rules_id or (config.config_id if config.config_usage == 'context' else None)
    if action == 'multi-resource-assess' and config.config_usage == 'multi-resource':
        return ('La suite usa già il motore di verifica multi-risorsa per questo manifest: '
                'evitiamo POST/PATCH/DELETE duplicati. Per il motore storico avvia il task singolo.')
    if action in {'access-matrix', 'access-probe', 'verify-access-policy'}:
        if not config.auth_config_id:
            return 'Carica auth.yaml con le identità autorizzate.'
        if not rules_id:
            # A manually configured access-probe retry is a complete policy
            # comparison by itself; only access-matrix and the offline policy
            # verifier require a persisted multi-rule matrix.
            manual_probe = (action == 'access-probe' and bool(config.operation)
                            and len(config.profiles) == 2
                            and config.profiles[0] != config.profiles[1]
                            and config.expected_other in {'allow', 'deny'})
            if not manual_probe:
                return 'Configura e salva la matrice di accesso oppure, per access-probe, seleziona GET, due profili e policy attesa.'
        if action == 'verify-access-policy' and not evidence_id:
            return 'Serve il risultato HTTP di access-matrix della stessa suite; la verifica non inventa evidenze.'
    if action == 'proof-gate' and not evidence_id:
        return 'Serve un assessment precedente; nessun finding sarà confermato automaticamente.'
    if action == 'rc16-access-auto' and (not config.auth_config_id or len(config.profiles) < 2 or not config.path_values):
        return 'Per confrontare gli accessi GET indica almeno due identità, gli ID di prova approvati e la policy allow/deny.'
    if action == 'rc16-assess' and not config.auth_config_id:
        return 'Per i test delle risorse temporanee importa auth.yaml con tutte le identità dichiarate nel manifest.'
    if action == 'access-probe' and (not config.base_url or not config.allow_host):
        return 'Per il confronto GET indica Base URL e host autorizzato.'
    if action == 'rc16-access-auto' and (not config.base_url or not config.allow_host):
        return 'Per confrontare gli accessi GET indica Base URL e host autorizzato, anche nel piano offline.'
    if action == 'injection-assess' and (not config.base_url or not config.allow_host):
        return 'Indica Base URL e host autorizzato anche per il piano offline.'
    if kind in {'spec','both','spec-config'} and not config.specification_id:
        return 'Carica uno Swagger/OpenAPI.'
    if kind in {'scope'} and (not config.base_url or not config.allow_host):
        return 'Indica Base URL e host autorizzato.'
    if kind == 'auth-only' and not config.auth_config_id:
        return 'Carica auth.yaml.'
    if kind in {'spec-config','report-config','config:json','config-report'} and not config.config_id:
        return 'Richiede un manifest o un file di input specifico: non ricavabile automaticamente dallo Swagger.'
    if kind in {'report','both','report-config','config-report'} and not evidence_id and action not in {'campaign-quality','campaign-diagnostics','release-readiness','campaign-audit'}:
        return 'Non è disponibile un assessment precedente valido.'
    if tool.get('ai') and not request.include_ai:
        return 'AI locale non abilitata per questa suite.'
    if action == 'ai-plan-guard' and config.config_usage != 'proposals':
        return 'Richiede proposte actions: usa il generatore guidato nel retry o carica un JSON proposte.'
    if action == 'ai-correlate' and not request.include_active:
        return 'Richiede un assessment con risposte HTTP reali: attiva i test HTTP.'
    if action == 'analyze-evidence' and config.config_usage != 'evidence':
        return 'Serve un file con risposte HTTP. Usa «Genera e valida» dal job auto-assess attivo.'
    if action in {'benchmark-evaluate', 'benchmark-review'} and config.config_usage != 'benchmark':
        return 'Carica una configurazione benchmark, scegli tipo Benchmark e seleziona un assessment.'
    if action in {'workflow-assess','multi-resource-assess','rc16-assess'} and (not request.include_writes or not request.include_active):
        return 'Workflow di scrittura non autorizzati dalla suite.'
    if action == 'journey-assess' and config.config_usage != 'journey':
        return 'Richiede un manifest journey.'
    if action == 'workflow-assess' and config.config_usage != 'workflow':
        return ('Il manifest selezionato è di tipo multi-resource e sarà usato da multi-resource-assess. '
                'Non duplicare le POST/DELETE dello stesso workflow. Per un workflow singolo usa un manifest workflow.')
    if action in {'multi-resource-assess','rc16-assess'} and config.config_usage != 'multi-resource':
        return ('Il manifest selezionato è di tipo workflow singolo e sarà usato da workflow-assess. '
                'Per più risorse prepara un manifest multi-resource.')
    if action == 'workflow-graph' and config.config_usage not in {'multi-resource','workflow'}:
        return 'Richiede un manifest workflow o multi-resource.'
    if action in {'ai-correlate'} and not evidence_id:
        return 'Nessuna evidenza HTTP da correlare.'
    if tool.get('active') and action != 'auto-assess' and not request.include_optional:
        return 'Test aggiuntivi disabilitati.'
    if tool.get('active') and request.include_active and not config.acknowledgment:
        return 'Autorizzazione del target non confermata.'
    return None


def register_control_routes(app:FastAPI, root:Path, uploads:Path, reports:Path,
                            jobs:dict, lock:threading.Lock, csrf:str) -> None:
    """Mount generic security tools and optional locally managed Ollama controls."""
    repo=Path(__file__).resolve().parents[3]
    services: dict[str,subprocess.Popen]={}
    service_lock=threading.Lock()
    suite_worker=threading.local()
    store = app.state.campaign_store
    from achillesapi.dashboard.local_callback_control import LocalCallbackControl
    callback_manager = LocalCallbackControl()
    suite_contexts: dict[str, SuiteRequest] = {}
    for key, value in store.load_suite_contexts().items():
        try:
            suite_contexts[key] = SuiteRequest.model_validate(value)
        except (ValueError, TypeError):
            pass

    def guard(provided:str|None)->None:
        if not provided or not secrets.compare_digest(provided,csrf):
            raise HTTPException(403,'Invalid dashboard session token')

    def file_id(raw:str|None,suffix:str,folder:Path=uploads)->Path:
        if not raw or not ID.fullmatch(raw):raise HTTPException(400,'Invalid file ID')
        file=folder/(raw+suffix)
        if not file.is_file():raise HTTPException(404,'File not found')
        return file

    def uploaded_config(config_id:str|None)->Path:
        return file_id(config_id,'.config.yaml')

    @app.get('/api/control/callback/status')
    def callback_status():
        return callback_manager.status()

    @app.post('/api/control/callback/start')
    def callback_start(x_achilles_token: str | None = Header(None)):
        guard(x_achilles_token)
        try:
            return callback_manager.start()
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post('/api/control/callback/stop')
    def callback_stop(x_achilles_token: str | None = Header(None)):
        guard(x_achilles_token)
        try:
            return callback_manager.stop()
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get('/api/control/autoconfig/{spec_id}')
    def auto_configure_spec(spec_id: str):
        """Return every documented operation, including non-CRUD endpoints."""
        from achillesapi.core.openapi import load_openapi
        from achillesapi.core.autoconfig_rc24 import build_autoconfiguration
        try:
            return build_autoconfiguration(load_openapi(file_id(spec_id, '.yaml')))
        except (ValueError, TypeError, OSError) as exc:
            raise HTTPException(422, 'Autoconfigurazione non disponibile: ' + str(exc)[:180]) from exc

    @app.get('/api/control/autopilot/{spec_id}')
    def autopilot_workspace(spec_id: str):
        """Automatic read-only planning. No OAuth/target/LLM requests on import."""
        from achillesapi.core.openapi import load_openapi
        from achillesapi.core.autonomous_workspace_rc20 import build_workspace
        from achillesapi.core.authorization_planner_rc21 import build_authorization_plan
        from achillesapi.core.scanner_coverage_rc22 import scanner_plan
        try:
            spec = load_openapi(file_id(spec_id,'.yaml'))
            return {'workspace':build_workspace(spec),
                    'authorization':build_authorization_plan(spec),
                    'scanners':scanner_plan(spec),
                    'network_requests_sent':0}
        except (ValueError, TypeError, OSError) as exc:
            raise HTTPException(422, 'Piano automatico non valido: '+str(exc)[:180]) from exc

    @app.post('/api/control/autopilot/preflight')
    def autopilot_preflight(payload: dict, x_achilles_token: str | None = Header(None)):
        """Typed readiness. Boolean approvals are descriptive only, never executed."""
        guard(x_achilles_token)
        from achillesapi.core.openapi import load_openapi
        from achillesapi.core.autonomous_workspace_rc20 import build_workspace
        from achillesapi.core.diagnostics_rc20 import supported_codes
        spec_path = file_id(payload.get('specification_id'), '.yaml')
        allowed={'has_auth','has_policy','has_fixture','has_scope','http_approved',
                 'writes_approved','ai_available'}
        if any(key not in allowed | {'specification_id'} for key in payload):
            raise HTTPException(422,'Preflight: parametro non supportato')
        if any(type(payload[key]) is not bool for key in allowed if key in payload):
            raise HTTPException(422,'Preflight: le conferme devono essere booleane')
        return {'workspace':build_workspace(load_openapi(spec_path),**{
                key:payload.get(key,False) for key in allowed}),
                'supported_issue_codes':supported_codes(),
                'note':'Preflight offline. Non abilita approvazioni lato server.'}

    @app.post('/api/control/rc22/verify-controlled')
    def verify_controlled(payload: dict, x_achilles_token: str | None = Header(None)):
        """Offline evidence verification, no network. Never trust model confirmation."""
        guard(x_achilles_token)
        from achillesapi.core.evidence_verification_rc22 import verify_controlled_cases
        raw=payload.get('cases')
        if not isinstance(raw,list) or len(raw)>500:
            raise HTTPException(422,'Richiesta una lista di massimo 500 casi')
        return verify_controlled_cases(raw)

    @app.get('/api/control/rc23/audit/{job_id}')
    def audit_suite_job(job_id: str, x_achilles_token: str | None = Header(None)):
        guard(x_achilles_token)
        from achillesapi.core.release_validation_rc23 import audit_campaign
        file=file_id(job_id,'.json',reports)
        try:
            return audit_campaign(json.loads(file.read_text(encoding='utf-8')))
        except (ValueError,TypeError,OSError) as exc:
            raise HTTPException(422,'Report di suite non valido: '+type(exc).__name__) from exc

    @app.post('/api/control/rc16/discover')
    def rc16_discover(config: ToolRequest, x_achilles_token: str | None = Header(None)):
        """Offline discovery and nonexecutable draft. It never resolves auth or sends HTTP."""
        guard(x_achilles_token)
        from achillesapi.core.openapi import load_openapi
        from achillesapi.core.workflow_automation_rc16 import (
            discover_resource_workflows, draft_multi_resource_manifest)
        spec_file = file_id(config.specification_id, '.yaml')
        owner = config.profiles[0] if config.profiles else 'REVIEW_OWNER'
        try:
            spec = load_openapi(spec_file)
            return {'discovery': discover_resource_workflows(spec, max_candidates=60),
                    'draft': draft_multi_resource_manifest(spec, owner_profile=owner),
                    'note': 'Bozza non eseguibile: completare i dati REVIEW_, JSON Pointer, ownership e cleanup.'}
        except (ValueError, TypeError, OSError) as exc:
            raise HTTPException(422, 'RC16: impossibile creare bozza: ' + str(exc)[:200]) from exc

    @app.get('/api/control/manifest/candidates/{spec_id}')
    def manifest_candidates(spec_id:str):
        """Discover candidate CRUD trios without contacting the target API."""
        from achillesapi.dashboard.manifest_builder import discover_manifest_candidates, discover_write_operations
        path=file_id(spec_id,'.yaml')
        try:
            return {'candidates':discover_manifest_candidates(str(path)),
                    'write_operations':discover_write_operations(str(path)),
                    'notice':'Solo proposte offline: verifica ownership e cleanup prima di autorizzare scritture.'}
        except (ValueError, OSError) as exc:
            raise HTTPException(422,'Impossibile analizzare lo Swagger: '+str(exc)[:220]) from exc

    @app.post('/api/control/manifest/parent-lookup')
    def manifest_parent_lookup(payload:dict, x_achilles_token:str|None=Header(None)):
        """Optional scoped one-shot GET; no target traffic on OpenAPI import."""
        guard(x_achilles_token)
        from achillesapi.core.openapi import load_openapi, parse_openapi
        from achillesapi.core.auth import load_authentication_manager
        from achillesapi.dashboard.manifest_builder import discover_manifest_candidates
        from achillesapi.dashboard.live_fixture_discovery import resolve_parent_from_get
        spec_path=file_id(payload.get('specification_id'),'.yaml')
        auth_path=file_id(payload.get('auth_config_id'),'.auth.yaml')
        choices=discover_manifest_candidates(str(spec_path))
        index=payload.get('candidate_index')
        if type(index) is not int or not 0<=index<len(choices):
            raise HTTPException(422,'Seleziona un workflow valido prima della GET.')
        try:
            return resolve_parent_from_get(candidate=choices[index],
                variable=payload.get('variable') or '',
                source_operation=payload.get('source_operation') or '',
                pointer=payload.get('pointer') or '',
                base_url=payload.get('base_url') or '',
                allow_host=payload.get('allow_host') or '',
                identity=payload.get('identity') or '',
                auth_manager=load_authentication_manager(auth_path),
                approve_http=payload.get('approve_http') is True,
                allow_insecure_http=payload.get('allow_insecure_http') is True)
        except (ValueError,TypeError,KeyError) as exc:
            raise HTTPException(422,str(exc)[:350]) from exc

    @app.post('/api/control/manifest/probe-id')
    def manifest_probe_id(payload:dict, x_achilles_token:str|None=Header(None)):
        """Opt-in disposable POST/GET/DELETE, never automatic for arbitrary imports."""
        guard(x_achilles_token)
        from achillesapi.core.openapi import load_openapi, parse_openapi
        from achillesapi.core.auth import load_authentication_manager
        from achillesapi.dashboard.manifest_builder import discover_manifest_candidates
        from achillesapi.dashboard.live_fixture_discovery import probe_created_identifier
        spec_path=file_id(payload.get('specification_id'),'.yaml')
        auth_path=file_id(payload.get('auth_config_id'),'.auth.yaml')
        choices=discover_manifest_candidates(str(spec_path))
        index=payload.get('candidate_index')
        if type(index) is not int or not 0<=index<len(choices):
            raise HTTPException(422,'Seleziona un workflow con POST, GET e DELETE.')
        if payload.get('approve_writes') is not True or payload.get('approve_possible_orphan') is not True:
            raise HTTPException(422,'Per creare una risorsa servono entrambe le conferme esplicite: scritture e cleanup incerto.')
        try:
            spec=load_openapi(spec_path)
            return probe_created_identifier(candidate=choices[index], spec=spec,parsed=parse_openapi(spec),
                base_url=payload.get('base_url') or '',allow_host=payload.get('allow_host') or '',
                allow_insecure_http=payload.get('allow_insecure_http') is True,
                identity=payload.get('identity') or '',
                auth_manager=load_authentication_manager(auth_path),
                path_values=payload.get('path_values'),body=payload.get('body'),
                marker_field=payload.get('marker') or '',
                approve_writes=True,approve_possible_orphan=True,
                acknowledge_get_side_effect_risk=payload.get('acknowledge_get_side_effect_risk') is True)
        except (ValueError,TypeError,KeyError) as exc:
            raise HTTPException(422,'Prova non avviata o non completata: '+str(exc)[:320]) from exc

    @app.post('/api/control/manifest/draft')
    def manifest_draft(payload:dict,x_achilles_token:str|None=Header(None)):
        """Render a human-editable proposal, never schedule an HTTP write."""
        guard(x_achilles_token)
        from achillesapi.dashboard.manifest_builder import discover_manifest_candidates,build_manifest_draft
        path=file_id(payload.get('specification_id'),'.yaml')
        choices=discover_manifest_candidates(str(path))
        index=payload.get('candidate_index')
        if type(index) is not int or index<0 or index>=len(choices):
            raise HTTPException(422,'Seleziona un workflow CRUD rilevato nello Swagger.')
        owner=payload.get('identity')
        other=payload.get('other_identity') or None
        if not isinstance(owner,str) or not PROFILE.fullmatch(owner) or (other and (not isinstance(other,str) or not PROFILE.fullmatch(other))):
            raise HTTPException(422,'Indica nomi di profilo validi, ad es. owner e other.')
        try:
            return {'yaml':build_manifest_draft(choices[index],owner,other,payload.get('marker'),payload.get('identifier')),
                    'warning':'La bozza non è autorizzazione alle scritture. Rivedi ogni valore.'}
        except ValueError as exc:raise HTTPException(422,str(exc)) from exc

    @app.post('/api/control/manifest/guided')
    def manifest_guided(payload:dict,x_achilles_token:str|None=Header(None)):
        """Build and preflight an approved fixture from a structured UI form.

        No HTTP call to the target is performed. A failed preflight returns a
        short actionable explanation; raw payloads and secrets are not logged.
        """
        guard(x_achilles_token)
        from achillesapi.dashboard.manifest_builder import discover_manifest_candidates,build_guided_manifest
        from achillesapi.core.openapi import load_openapi,parse_openapi
        from achillesapi.core.multi_resource import plan_multi_resource
        from achillesapi.core.auth import load_authentication_manager
        spec_path=file_id(payload.get('specification_id'),'.yaml')
        auth_path=file_id(payload.get('auth_config_id'),'.auth.yaml')
        candidates=discover_manifest_candidates(str(spec_path))
        index=payload.get('candidate_index')
        if type(index) is not int or index<0 or index>=len(candidates):
            raise HTTPException(422,'Prima scegli un workflow fra quelli trovati nello Swagger.')
        body=payload.get('body')
        if not isinstance(body,dict) or len(json.dumps(body))>8192:
            raise HTTPException(422,'Compila i valori della risorsa di prova. Massimo 8 KB.')
        try:
            owner=payload.get('identity') or ''
            other=payload.get('other_identity') or None
            names=set(load_authentication_manager(auth_path).names)
            if owner not in names or (other and other not in names):
                raise ValueError('Utente non configurato. Torna al passaggio 3 e carica auth.yaml.')
            content=build_guided_manifest(candidates[index],owner=owner,other=other,
                    marker=payload.get('marker') or '', identifier=payload.get('identifier') or '',
                    body=body,deny_other=payload.get('deny_other') is True,
                    path_values=payload.get('path_values') or {},
                    mutation_body=payload.get('mutation_body') or None,
                    mutation_expected_deny=payload.get('mutation_expected_deny') is True,
                    write_action=payload.get('write_action') or None,
                    write_identity=payload.get('write_identity') or None,
                    acknowledge_get_side_effect_risk=payload.get('acknowledge_get_side_effect_risk') is True)
            import yaml
            plan=plan_multi_resource(parse_openapi(load_openapi(spec_path)),
                    load_openapi(spec_path),yaml.safe_load(content),names)
            return {'yaml':content,'valid':True,'required_requests':plan['request_budget_required'],
                    'summary':{'create':candidates[index]['create'],'read':candidates[index]['read'],
                               'delete':candidates[index]['delete'],'identity':owner,
                               'other_identity':other if payload.get('deny_other') else None},
                    'message':'Configurazione pronta. Non sono state inviate richieste alla API. Le scritture richiedono ancora conferma esplicita.'}
        except (ValueError,TypeError,KeyError) as exc:
            raise HTTPException(422,str(exc)[:350]) from exc
        except Exception as exc:
            raise HTTPException(422,'Non posso preparare questo workflow: '+str(exc)[:280]) from exc

    @app.post('/api/control/manifest/compose')
    def compose_manifests(payload: dict, x_achilles_token: str | None = Header(None)):
        """Combine independently approved disposable fixtures, offline, without traffic.

        Each source is a *single* validated resource. We rename its own local ID
        reference to prevent collisions, then preflight the whole plan including
        request budget and cleanup order. Cross-workflow dependencies must be
        explicitly designed in a separate manifest; never invent them.
        """
        guard(x_achilles_token)
        import yaml
        from achillesapi.core.multi_resource import plan_multi_resource
        from achillesapi.core.openapi import load_openapi, parse_openapi
        from achillesapi.core.auth import load_authentication_manager
        spec_path=file_id(payload.get('specification_id'), '.yaml')
        auth_path=file_id(payload.get('auth_config_id'), '.auth.yaml')
        source_ids=payload.get('config_ids')
        if (not isinstance(source_ids, list) or not 1<=len(source_ids)<=10
                or len(set(map(str,source_ids))) != len(source_ids)):
            raise HTTPException(422, 'Seleziona da uno a dieci workflow distinti.')
        resources=[]
        try:
            for position, source_id in enumerate(source_ids, 1):
                source=yaml.safe_load(uploaded_config(source_id).read_text(encoding='utf-8'))
                if not isinstance(source, dict) or set(source)!={'resources'} or not isinstance(source['resources'],list) or len(source['resources']) != 1:
                    raise ValueError('Ogni workflow selezionato deve contenere una singola risorsa valida.')
                item=source['resources'][0]
                if not isinstance(item,dict) or not isinstance(item.get('name'),str):
                    raise ValueError('Manifest di risorsa non valido.')
                old=item['name']
                new=f'workflow_{position}'
                # Cross-resource references cannot be safely inferred when
                # composing independent workflows from separate documents.
                def rename_refs(obj):
                    if isinstance(obj,dict):return {k:rename_refs(v) for k,v in obj.items()}
                    if isinstance(obj,list):return [rename_refs(v) for v in obj]
                    if isinstance(obj,str) and '${' in obj:
                        if obj != '${'+old+'.id}':
                            raise ValueError('Riferimento tra workflow non riconosciuto: configura un manifest con dipendenze esplicite.')
                        return '${'+new+'.id}'
                    return obj
                item=rename_refs(item)
                item['name']=new
                resources.append(item)
            spec=load_openapi(spec_path)
            profiles=set(load_authentication_manager(auth_path).names)
            combined={'resources':resources}
            plan=plan_multi_resource(parse_openapi(spec),spec,combined,profiles)
            content=yaml.safe_dump(combined,sort_keys=False,allow_unicode=True)
            if len(content.encode('utf-8'))>MAX_CONFIG:
                raise ValueError('Manifest aggregato troppo grande.')
            config_id=uuid.uuid4().hex
            destination=uploads/(config_id+'.config.yaml')
            destination.write_text(content,encoding='utf-8')
            os.chmod(destination,0o600)
            return {'id':config_id,'config_usage':'multi-resource',
                    'resources':len(resources),'required_requests':plan['request_budget_required'],
                    'message':'Manifest combinato e verificato offline; nessuna richiesta al target.'}
        except HTTPException:
            raise
        except (ValueError,TypeError,KeyError,OSError) as exc:
            raise HTTPException(422, 'Impossibile unire i workflow: '+str(exc)[:300]) from exc

    @app.post('/api/control/manifest/validate')
    def manifest_validate(payload:dict,x_achilles_token:str|None=Header(None)):
        """Run full multi-resource preflight offline and give actionable errors."""
        guard(x_achilles_token)
        from achillesapi.core.openapi import load_openapi,parse_openapi
        from achillesapi.core.multi_resource import plan_multi_resource
        import yaml
        spec_path=file_id(payload.get('specification_id'),'.yaml')
        auth_path=file_id(payload.get('auth_config_id'),'.auth.yaml')
        content=payload.get('yaml')
        if not isinstance(content,str) or not content or len(content.encode())>MAX_CONFIG:
            raise HTTPException(422,'Incolla un manifest YAML non vuoto (massimo 128 KB).')
        try:
            data=yaml.safe_load(content)
            if 'REVIEW_' in content or 'TODO_' in content:
                raise ValueError('Completa i segnaposto REVIEW_/TODO_ prima della validazione. Se Swagger non dichiara l’ID di risposta, verifica la risposta reale e sostituisci ad esempio /REVIEW_ID_FIELD con /id.')
            from achillesapi.core.auth import load_authentication_manager
            names=set(load_authentication_manager(auth_path).names)
            spec=load_openapi(spec_path)
            plan=plan_multi_resource(parse_openapi(spec),spec,data,names)
            return {'valid':True,'resources':plan['resources'],
                    'required_requests':plan['request_budget_required'],
                    'message':'Preflight offline superato. Restano necessarie approvazione e autorizzazione esplicite.'}
        except Exception as exc:
            # Never include submitted YAML: it may contain sensitive test data.
            raise HTTPException(422,'Manifest non valido: '+str(exc)[:250]+'. Controlla endpoint, marker, ID, profili, parametri e cleanup.') from exc

    @app.get('/api/control/suite/preflight/{spec_id}')
    def preflight_preview(spec_id: str, auth_config_id: str = '', config_id: str = '',
                          access_rules_id: str = '',
                          config_usage: str = '', active: bool = False, writes: bool = False,
                          ai: bool = False, base_url: str = '', allow_host: str = '',
                          authorized: bool = False, optional: bool = True,
                          budget: int = 300, max_requests: int = 40):
        """Mostra quali task si possono pianificare, SENZA HTTP o processi CLI."""
        from achillesapi.core.campaign_v090 import campaign_preflight
        from achillesapi.core.openapi import load_openapi
        if auth_config_id:
            file_id(auth_config_id, '.auth.yaml')
        if config_id:
            uploaded_config(config_id)
        if access_rules_id:
            uploaded_config(access_rules_id)
        if config_usage and config_usage not in {'multi-resource','workflow','journey','context','evidence','benchmark','proposals'}:
            raise HTTPException(422, 'Tipo di configurazione non valido')
        if not (1 <= budget <= 600 and 1 <= max_requests <= 150):
            raise HTTPException(422, 'Budget fuori dai limiti della dashboard')
        try:
            spec = load_openapi(file_id(spec_id,'.yaml'))
            plan = campaign_preflight(spec, TOOLS, SUITE_ORDER,
                has_auth=bool(auth_config_id), has_config=bool(config_id),
                config_usage=config_usage, active=active, writes=writes,
                ai=ai, has_scope=bool(base_url and allow_host and
                    scope_audit(base_url,[allow_host]).get('approved')),
                authorized=authorized, include_optional=optional, max_total_requests=budget,
                per_task_limit=max_requests)
            # Access policy is a separate artifact, not the current workflow type.
            selected_rules = access_rules_id or (config_id if config_usage == 'context' else '')
            valid_rules = None
            if selected_rules and auth_config_id:
                from achillesapi.core.authorization_suite_bridge_rc9 import validated_suite_rules
                try:
                    valid_rules = validated_suite_rules(file_id(spec_id,'.yaml'),
                        file_id(auth_config_id,'.auth.yaml'), uploaded_config(selected_rules))
                except (ValueError,OSError) as exc:
                    raise HTTPException(422, 'Regole della matrice non valide: '+str(exc)[:220]) from exc
            for task in plan['tasks']:
                if task['action'] not in {'access-probe','access-matrix','verify-access-policy'}:
                    continue
                if valid_rules:
                    task['state'] = 'waiting_for_result' if task['action'] == 'verify-access-policy' else 'ready'
                    task['reason'] = (f'{len(valid_rules)} regole GET valide da matrice salvata.'
                         if task['action'] != 'verify-access-policy' else
                         'Usa le evidenze HTTP raccolte da access-matrix della stessa suite.')
                    task['missing_inputs'] = []
                else:
                    task['state'] = 'blocked'
                    task['reason'] = 'Carica auth.yaml e genera la matrice autorizzazioni prima della suite.'
                    task['missing_inputs'] = ['auth', 'access_rules']
            for key in ('ready','blocked','disabled','not_applicable','waiting_for_result'):
                plan['summary'][key] = sum(t['state']==key for t in plan['tasks'])
            from achillesapi.core.diagnostics_rc20 import diagnose, reason_code
            for item in plan['tasks']:
                if item.get('state') in {'blocked','disabled','not_applicable'}:
                    code=reason_code(item['action'],item.get('reason',''))
                    item['issue_code']=code
                    item['remediation']=diagnose(code,action=item['action'])
            return plan
        except (ValueError, OSError) as exc:
            raise HTTPException(422, 'Preflight non disponibile: '+str(exc)[:180]) from exc

    @app.get('/api/control/tools')
    def tool_catalog():
        from achillesapi.core.task_help_rc5 import task_help
        return [{'name':name,**options, 'help':task_help(name)} for name,options in TOOLS.items()]

    @app.post('/api/control/config')
    async def config_upload(file:UploadFile=File(...),x_achilles_token:str|None=Header(None)):
        """Upload typed YAML/JSON fixtures, rules and journeys (no code execution)."""
        guard(x_achilles_token)
        name=Path(file.filename or '').name
        if not name.lower().endswith(('.yaml','.yml','.json')):
            raise HTTPException(400,'Only YAML or JSON configuration files are allowed')
        body=await file.read(MAX_CONFIG+1)
        if not body or len(body)>MAX_CONFIG:raise HTTPException(413,'Configuration must be <=128KB')
        import yaml
        try:
            data=yaml.safe_load(body)
            if not isinstance(data,(dict,list)):raise ValueError('Expected mapping or sequence')
        except (ValueError,yaml.YAMLError,UnicodeError) as exc:
            raise HTTPException(422,'Invalid configuration YAML/JSON') from exc
        new_id=uuid.uuid4().hex
        path=uploads/(new_id+'.config.yaml')
        path.write_bytes(body)
        os.chmod(path,0o600)
        return {'id':new_id,'name':name,'type':'configuration'}

    @app.get('/api/control/services')
    def services_status():
        """Report local Ollama runtime independently of the currently selected task.

        This probes localhost:11434; it never contacts an API target or uploads
        Swagger/credentials to any AI service.
        """
        with service_lock:
            process = services.get('ollama')
            managed = bool(process and process.poll() is None)
        status = {
            'ollama_process': 'running' if managed else 'not-managed',
            'ollama_managed': managed,
            'ollama_installed': bool(_installed_ollama_executable()),
            'ollama': 'offline',
            'ollama_models': [],
            'ollama_loaded_models': [],
            'ollama_message': '',
        }
        try:
            data = _local_ollama_json('/api/tags', timeout=1.1)
            if not isinstance(data.get('models'), list):
                raise ValueError('Unexpected Ollama model list')
            status['ollama'] = 'online'
            status['ollama_models'] = [model['name'] for model in data['models']
                if isinstance(model, dict) and isinstance(model.get('name'), str)][:60]
            status['ollama_message'] = ('Servizio raggiungibile in locale. '
                + ('Seleziona un modello per provarlo.' if status['ollama_models']
                   else 'Nessun modello installato.'))
            try:
                loaded = _local_ollama_json('/api/ps', timeout=0.8)
                status['ollama_loaded_models'] = [model['name'] for model in loaded.get('models', [])
                    if isinstance(model, dict) and isinstance(model.get('name'), str)][:30]
            except (OSError, ValueError, urllib.error.URLError):
                pass  # /api/ps is optional for older Ollama versions
        except (OSError, ValueError, urllib.error.URLError):
            status['ollama_message'] = ('Ollama installato ma non raggiungibile: premi Avvia.'
                if status['ollama_installed'] else
                'Ollama non raggiungibile. Installa Ollama oppure avvialo dal sistema.')
        return status

    @app.post('/api/control/services/ollama/{operation}')
    def ollama_service_action(operation: str, x_achilles_token: str | None = Header(None)):
        """Start Ollama locally, or stop only a child started by this dashboard."""
        guard(x_achilles_token)
        if operation not in {'start', 'stop'}:
            raise HTTPException(400, 'Unknown Ollama operation')
        if operation == 'start':
            try:
                probe = _local_ollama_json('/api/tags', timeout=0.65)
                if not isinstance(probe.get('models'), list):
                    raise ValueError('Ollama model listing unavailable')
            except (OSError, ValueError, urllib.error.URLError):
                pass
            else:
                return {'service': 'ollama', 'state': 'already-running',
                        'message': 'Ollama è già attivo sulla porta locale 11434.'}
        with service_lock:
            process = services.get('ollama')
            if operation == 'stop':
                if not process or process.poll() is not None:
                    raise HTTPException(409, 'Il servizio Ollama non è stato avviato da questa dashboard.')
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                services.pop('ollama', None)
                return {'service': 'ollama', 'state': 'stopped',
                        'message': 'Servizio avviato dalla dashboard arrestato.'}
            if process and process.poll() is None:
                return {'service': 'ollama', 'state': 'starting',
                        'message': 'Ollama è già stato avviato dalla dashboard.'}
            executable = _installed_ollama_executable()
            if not executable:
                raise HTTPException(503, 'Ollama non è installato o non è nel PATH. Installa Ollama e riavvia la dashboard.')
            try:
                with (root / 'ollama.log').open('ab') as log:
                    child = subprocess.Popen(
                        [executable, 'serve'], cwd=str(root),
                        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                        env={**os.environ, 'PYTHONUNBUFFERED': '1',
                             'OLLAMA_HOST': '127.0.0.1:11434'},
                    )
            except OSError as exc:
                raise HTTPException(503, 'Impossibile avviare Ollama in locale. Controlla installazione e log.') from exc
            services['ollama'] = child
            return {'service': 'ollama', 'state': 'starting',
                    'message': 'Avvio richiesto. Controllo della porta locale 11434 in corso.'}

    @app.post('/api/control/ollama/test')
    def test_local_ollama_model(payload: OllamaTestRequest,
                                x_achilles_token: str | None = Header(None)):
        """Send a fixed, non-sensitive JSON test prompt to a local installed model."""
        guard(x_achilles_token)
        if not OLLAMA_MODEL_NAME.fullmatch(payload.model):
            raise HTTPException(422, 'Nome modello Ollama non valido.')
        try:
            listing = _local_ollama_json('/api/tags', timeout=1.5)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise HTTPException(503, 'Ollama non è raggiungibile: avvia il servizio e riprova.') from exc
        installed = [x.get('name') for x in listing.get('models', []) if isinstance(x, dict)]
        if payload.model not in installed and not (
                ':' not in payload.model and payload.model + ':latest' in installed):
            raise HTTPException(422, 'Modello non installato: scegli uno dei modelli elencati.')
        try:
            result = _local_ollama_json('/api/generate', payload={
                'model': payload.model,
                'prompt': 'Return ONLY valid JSON with exactly {"status":"ok"}.',
                'format': 'json', 'stream': False,
                'options': {'temperature': 0, 'num_predict': 96},
            }, timeout=90)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise HTTPException(503, 'Il modello non ha risposto entro il limite o ha restituito un errore. Controlla RAM, modello e log Ollama.') from exc
        try:
            message = json.loads(result.get('response', ''))
        except (ValueError, TypeError):
            raise HTTPException(422, 'Ollama risponde, ma il modello non ha generato JSON valido.')
        if not isinstance(message, dict) or message.get('status') != 'ok':
            raise HTTPException(422, 'Ollama risponde, ma il test JSON ha restituito un formato inatteso.')
        return {'ok': True, 'model': payload.model,
                'message': 'Modello locale funzionante: inferenza e generazione JSON verificate.',
                'data_sent': 'Solo una frase fissa di test, nessun dato del target.'}

    @app.get('/api/control/download/{job_id}')
    def download_job(job_id:str):
        """Download the exact generated YAML or JSON artifact for a finished job."""
        if not ID.fullmatch(job_id):raise HTTPException(400,'Invalid job ID')
        with lock:
            item=jobs.get(job_id)
            if not item or item.get('status')!='complete':
                raise HTTPException(404,'Completed task not found')
            action=item.get('action','assessment')
        ext='.yaml' if action=='auth-draft' else '.json'
        file=reports/(job_id+ext)
        if not file.is_file():raise HTTPException(404,'Generated file missing')
        return FileResponse(file,filename=f'achilles-{action}-{job_id[:8]}{ext}',
            headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

    @app.post('/api/control/ollama/prepare')
    def prepare_model(x_achilles_token:str|None=Header(None)):
        """Explicitly download a fixed base model and build local achilles-local.

        The only non-local traffic is the Ollama model download requested by the
        operator; no Swagger, tokens or target observations are uploaded.
        """
        guard(x_achilles_token)
        executable=_installed_ollama_executable()
        modelfile=repo/'deployment'/'Modelfile'
        if not executable or not modelfile.is_file():
            raise HTTPException(503,'Ollama or the bundled Modelfile is unavailable')
        with lock:
            if any(j['status']=='running' for j in jobs.values()):
                raise HTTPException(409,'Another task is running')
            ident=uuid.uuid4().hex
            jobs[ident]={'id':ident,'status':'running','mode':'install local AI model',
                'exit_code':None,'error':None,'specification_id':None,'action':'ollama-prepare'}
        def install():
            steps=[[executable,'pull','llama3.2:3b'],[executable,'create','achilles-local','-f',str(modelfile)]]
            success=True
            env={**os.environ,'OLLAMA_HOST':'127.0.0.1:11434'}
            try:
                for command in steps:
                    result=subprocess.run(command,cwd=repo,env=env,stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False,timeout=1800)
                    if result.returncode!=0:success=False;break
            except (OSError,subprocess.TimeoutExpired):success=False
            report={'action':'prepare-local-model','success':success,'model':'achilles-local',
                    'base':'llama3.2:3b','target_requests':0,
                    'note':'Model files downloaded by Ollama; no target evidence transmitted.'}
            (reports/(ident+'.json')).write_text(json.dumps(report,indent=2))
            with lock:
                jobs[ident]['status']='complete' if success else 'failed'
                jobs[ident]['exit_code']=0 if success else 1
                if not success:jobs[ident]['error']='Model installation failed; ensure Ollama is running and has disk space.'
        threading.Thread(target=install,daemon=True).start()
        return {'id':ident,'status':'running','action':'ollama-prepare'}

    def _start_rc13(request: RC13DashboardRequest, *, suite_id: str | None = None,
                    ledger_path: str | None = None) -> str:
        """Launch the genuine RC13 CLI as a normal visible, persistent dashboard job."""
        from achillesapi.dashboard.rc13_bridge import rc13_command, rc13_plan
        from achillesapi.dashboard.server import _restricted_secrets, _safe_error
        from achillesapi.core.process_supervisor_rc4 import run_cli_bounded
        cfg = request.config
        if not cfg.specification_id:
            raise HTTPException(422, 'Carica uno Swagger prima di avviare RC13.')
        auth_file = file_id(cfg.auth_config_id, '.auth.yaml') if cfg.auth_config_id else None
        try:
            _restricted_secrets(cfg.secrets, auth_file)
            # Validate manifests/policies before any HTTP, even for active runs
            # that will intentionally exclude unapproved write workflows.
            plan = rc13_plan(cfg, file_id, uploaded_config)
            if request.body_probes:
                from achillesapi.dashboard.rc13_bridge import rc13_paths
                from achillesapi.core.pipeline_rc13 import create_plan
                spec, auth, rules, workflow = rc13_paths(cfg, file_id, uploaded_config)
                plan = create_plan(spec, auth_config=auth, rules_path=rules,
                                   workflow_config=workflow,
                                   body_probe_fields=request.body_probe_fields)
        except (OSError, ValueError, TypeError) as exc:
            raise HTTPException(422, 'Prerequisiti RC13 non validi: ' + str(exc)[:260]) from exc
        if request.active:
            if not cfg.acknowledgment or not cfg.base_url or not cfg.allow_host:
                raise HTTPException(422, 'RC13 attiva: conferma scope, URL e host autorizzato.')
            if not scope_audit(cfg.base_url, [cfg.allow_host])['approved']:
                raise HTTPException(422, 'Target RC13 non compreso nella allowlist.')
            if cfg.base_url.startswith('http://'):
                if cfg.allow_host not in {'localhost', '127.0.0.1'} or not cfg.allow_insecure_http:
                    raise HTTPException(422, 'HTTP senza TLS consentito solo su localhost e con consenso esplicito.')
        if request.writes and (not request.active or not cfg.approve_writes):
            raise HTTPException(422, 'Le scritture RC13 richiedono due conferme esplicite della suite.')
        if request.body_probes and not (request.writes and cfg.approve_writes):
            raise HTTPException(422, 'Le sonde JSON richiedono approvazione separata e manifest temporaneo.')
        if request.body_probes and not (plan.get('body_probe_plan') or {}).get('cases'):
            raise HTTPException(422, 'Seleziona almeno un campo PATCH nella procedura guidata delle sonde JSON. Il manifest resources.yaml già caricato viene riutilizzato automaticamente.')
        if (request.rc15_callback_base or request.rc15_callback_observer):
            if not request.active or not request.rc15_callback_approved:
                raise HTTPException(422, 'Callback RC15 richiede HTTP attivo e consenso OAST separato.')
            try:
                from achillesapi.core.rc15_security import _callback_address
                from urllib.parse import urlsplit
                _callback_address(request.rc15_callback_base or '', '0' * 32)
                observer = urlsplit(request.rc15_callback_observer or '')
                if (observer.scheme != 'http' or observer.hostname not in ('localhost','127.0.0.1','::1')
                        or observer.path not in ('', '/') or observer.username or observer.password
                        or observer.query or observer.fragment):
                    raise ValueError('Observer RC15 deve essere il collector locale')
            except ValueError as exc:
                raise HTTPException(422, 'Configurazione callback RC15 non valida') from exc
        if request.rc15_fixture_file or request.rc15_fixture_marker:
            if not request.rc15_fixture_file or not request.rc15_fixture_marker:
                raise HTTPException(422, 'Fixture traversal RC15 richiede nome *.txt e marker.')
        if request.agent_followups and (not request.active or not request.ai):
            raise HTTPException(422, 'Agente RC17: abilita esecuzione HTTP e AI locale, con scope esplicito.')
        if request.agent_followups and request.max_requests < request.agent_budget + 5:
            raise HTTPException(422, 'Agente RC17: budget totale insufficiente per test base e follow-up.')
        if request.ai and request.active and _ollama_readiness(cfg.model)['status'] != 'ready':
            raise HTTPException(422, 'Ollama locale non disponibile oppure modello non installato. Verifica il pannello Ollama.')
        if request.active and request.max_requests < 5:
            raise HTTPException(422, 'RC13 richiede almeno 5 richieste HTTP per le sonde GET.')
        with lock:
            running = [x for x in jobs.values() if x.get('status') in {'running', 'orchestrating'}]
            if running and (suite_id is None or any(x.get('id') != suite_id for x in running)):
                raise HTTPException(409, 'Un altro job è in esecuzione. Attendi che termini.')
            ident = uuid.uuid4().hex
            target = reports / (ident + '.json')
            try:
                command = rc13_command(cfg, file_id, uploaded_config,
                    active=request.active, writes=request.writes,
                    body_probes=request.body_probes, ai=request.ai,
                    agent_followups=request.agent_followups,
                    agent_rounds=request.agent_rounds, agent_budget=request.agent_budget,
                    max_requests=request.max_requests, output=target,
                    body_probe_fields=request.body_probe_fields,
                    rc15_callback_base=request.rc15_callback_base,
                    rc15_callback_observer=request.rc15_callback_observer,
                    rc15_fixture_file=request.rc15_fixture_file,
                    rc15_fixture_marker=request.rc15_fixture_marker)
            except (ValueError, OSError) as exc:
                raise HTTPException(422, 'Comando RC13 non valido: ' + str(exc)[:240]) from exc
            job = {'id': ident, 'action': 'rc13-assess', 'status': 'running',
                   'specification_id': cfg.specification_id, 'active': request.active,
                   'mode': 'RC13 HTTP autorizzato' if request.active else 'RC13 piano offline',
                   'suite_id': suite_id, 'ai_status': 'pending' if request.ai else 'not_invoked',
                   'rc13_stages': list(plan.get('test_types', {}).keys()),
                   'rc13_writes': request.writes, 'rc13_body_probes': request.body_probes,
                   'rc13_body_fields': request.body_probe_fields,
                   'agent_followups': request.agent_followups,
                   'exit_code': None, 'error': None}
            jobs[ident] = job
            store.save_job(dict(job))
        def work():
            started = time.monotonic()
            try:
                env = {**os.environ, 'PYTHONPATH': os.pathsep.join(
                    [str(repo/'src'), str(repo), os.environ.get('PYTHONPATH', '')])}
                env.update(_restricted_secrets(cfg.secrets, auth_file))
                # _restricted_secrets returns a full env copy, so add PYTHONPATH
                # AFTER merging it (critical when running from an unpacked ZIP).
                env['PYTHONPATH'] = os.pathsep.join(
                    [str(repo/'src'), str(repo), env.get('PYTHONPATH', '')])
                if ledger_path:
                    env['ACHILLES_CAMPAIGN_LEDGER'] = ledger_path
                else:
                    env.pop('ACHILLES_CAMPAIGN_LEDGER', None)
                finished = run_cli_bounded(command, cwd=root, env=env,
                                          timeout=3600 if request.writes else 900)
                complete = finished.returncode == 0 and target.is_file()
                with lock:
                    job = jobs[ident]
                    job['exit_code'] = finished.returncode
                    job['status'] = 'complete' if complete else 'failed'
                    job['duration_ms'] = round((time.monotonic()-started)*1000)
                    if complete:
                        raw = json.loads(target.read_text(encoding='utf-8'))
                        job['http_observations'] = int(raw.get('requests_sent', 0))
                        job['rc13_coverage'] = raw.get('coverage', {}).get('operations_with_evaluable_http_results', 0)
                        state = raw.get('ai', {}).get('status', 'not_invoked')
                        job['ai_status'] = state if request.ai else 'not_invoked'
                        job['manual_cleanup_required'] = bool(raw.get('manual_cleanup_required', False))
                    else:
                        job['error'] = _safe_error(finished.stderr, cfg.secrets, auth_file)
                        if request.writes:
                            job['cleanup_state'] = 'unknown_requires_operator_check'
                    store.save_job(dict(job))
            except (OSError, ValueError, TypeError, subprocess.TimeoutExpired) as exc:
                with lock:
                    job = jobs[ident]
                    job['status'] = 'failed'
                    job['error'] = ('RC13 non completato: ' + type(exc).__name__ +
                        '. Controlla la configurazione e il report del job.')
                    if request.writes:
                        job['cleanup_state'] = 'unknown_requires_operator_check'
                    store.save_job(dict(job))
        threading.Thread(target=work, daemon=True).start()
        return ident

    @app.post('/api/control/rc13/plan')
    def dashboard_rc13_plan(config: ToolRequest, x_achilles_token: str | None = Header(None)):
        """Actual RC13 planning from current dashboard files, no target requests."""
        guard(x_achilles_token)
        from achillesapi.dashboard.rc13_bridge import rc13_plan
        try:
            result = rc13_plan(config, file_id, uploaded_config)
        except (ValueError, OSError, TypeError) as exc:
            raise HTTPException(422, 'Piano RC13 non disponibile: ' + str(exc)[:250]) from exc
        return result

    @app.post('/api/control/rc13/body-fields')
    def dashboard_rc13_body_fields(config: ToolRequest,
                                  x_achilles_token: str | None = Header(None)):
        guard(x_achilles_token)
        from achillesapi.dashboard.rc13_bridge import rc13_plan
        if not config.specification_id:
            raise HTTPException(422, 'Carica prima lo Swagger.')
        try:
            plan = rc13_plan(config, file_id, uploaded_config)
            fields = plan.get('body_probe_options', [])
            diagnostics = []
            if not fields and config.config_usage == 'multi-resource' and config.config_id:
                from achillesapi.core.body_probes_rc11 import resource_probe_diagnostics
                from achillesapi.core.openapi import load_openapi, parse_openapi
                from achillesapi.core.multi_resource import load_multi_resource_config
                from achillesapi.dashboard.rc13_bridge import rc13_paths
                spec_path, _, _, workflow_path = rc13_paths(config, file_id, uploaded_config)
                if workflow_path:
                    swagger = load_openapi(spec_path)
                    manifest = load_multi_resource_config(workflow_path)
                    diagnostics = resource_probe_diagnostics(parse_openapi(swagger), swagger, manifest, fields)
            schema_found = sum(1 for f in fields if f.get('source', '').startswith('openapi'))
            return {'fields': fields, 'workflow_available': bool(plan.get('workflows')),
                    'workflow_request_budget': (plan.get('workflows') or {}).get('request_budget_required', 0),
                    'authorization_rule_count': plan.get('authorization_rule_count', 0),
                    'diagnostics': diagnostics,
                    'message': (f'{len(fields)} campi PATCH disponibili ({schema_found} rilevati dallo Swagger). '
                                'Seleziona quelli autorizzati: il task prepara le modifiche temporanee senza YAML aggiuntivi.'
                                if fields else
                                'Manifest workflows.yaml legacy: i restricted_fields sono già approvati.'
                                if (plan.get('body_probe_plan') or {}).get('cases') else
                                'Nessuna sonda PATCH proposta. Controlla le cause specifiche qui sotto; non significa che la API sia sicura.')}
        except (ValueError, OSError, TypeError) as exc:
            raise HTTPException(422, 'Wizard sonde JSON: ' + str(exc)[:240]) from exc

    @app.post('/api/control/rc13/run')
    def dashboard_rc13_run(request: RC13DashboardRequest,
                           x_achilles_token: str | None = Header(None)):
        guard(x_achilles_token)
        ident = _start_rc13(request)
        return {'id': ident, 'status': 'running', 'action': 'rc13-assess'}

    @app.post('/api/control/jobs')
    def run_tool(config:ToolRequest,x_achilles_token:str|None=Header(None)):
        """Execute a fixed tool with typed arguments; no shell or arbitrary paths."""
        guard(x_achilles_token)
        tool=TOOLS.get(config.action)
        if tool is None:raise HTTPException(400,'Tool not exposed by the dashboard')
        if config.action == 'rc13-assess':
            # Normal task selector and RC13 panel share the same typed,
            # allowlisted implementation. No duplicate execution logic.
            payload = RC13DashboardRequest(
                config=config, active=config.execute,
                writes=bool(config.execute and config.approve_writes),
                body_probes=bool(config.execute and config.rc13_body_probes),
                body_probe_fields=config.rc13_body_fields,
                ai=config.ai, max_requests=config.rc13_max_requests)
            ident = _start_rc13(payload)
            return {'id': ident, 'status': 'running', 'action': 'rc13-assess'}
        if config.action in {'access-matrix', 'verify-access-policy'} and config.access_rules_id:
            config = config.model_copy(deep=True)
            config.config_id = config.access_rules_id
            config.config_usage = 'context'

        kind=tool['requirements']
        spec=None;previous=None;extra=None;auth=None
        if kind in {'spec','both','spec-config'}:
            spec=file_id(config.specification_id,'.yaml')
        if kind in {'report','both','report-config','config-report'}:
            previous=file_id(config.assessment_id,'.json',reports)
            if kind=='both' and config.specification_id:
                prior=jobs.get(config.assessment_id)
                if prior and prior.get('specification_id')!=config.specification_id:
                    raise HTTPException(422,'Il risultato precedente appartiene a uno Swagger diverso. Esegui l’assessment sullo Swagger attuale, poi seleziona il nuovo risultato.')
        if kind in {'spec-config','report-config','config:json','config-report'}:
            extra=uploaded_config(config.config_id)
        if config.auth_config_id:
            auth=file_id(config.auth_config_id,'.auth.yaml')
        from achillesapi.dashboard.server import _restricted_secrets, _safe_error
        try:_restricted_secrets(config.secrets,auth)
        except ValueError as exc:raise HTTPException(400,str(exc)) from exc
        if config.profiles and not auth:
            raise HTTPException(400,'Identity profiles require an auth YAML')
        if any(not PROFILE.fullmatch(p) for p in config.profiles):
            raise HTTPException(400,'Invalid profile name')
        if any(not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_.-]{0,63}=[^\r\n]{1,256}',p) for p in config.path_values):
            raise HTTPException(400,'Path values must use NAME=VALUE')
        if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,64}',config.model):
            raise HTTPException(400,'Invalid local model name')
        if config.action in {'ai-correlate','ai-prioritize','agent-review','next-actions',
                             'autonomous-agent','agent-loop-v2'} and kind=='both' and not config.assessment_id:
            raise HTTPException(422,
                'Questo strumento richiede un risultato precedente. Prima esegui auto-assess '
                '(attivo per ai-correlate), attendi il completamento e seleziona il job in «Analisi precedente».')
        if config.execute and not tool.get('active'):
            # A stale browser toggle must not turn a static analysis into an error.
            config.execute=False
            config.approve_writes=False
        if config.execute:
            if not config.acknowledgment:
                raise HTTPException(400,'Confirm that you are authorized to test this target')
            if not config.base_url or not config.allow_host or not scope_audit(config.base_url,[config.allow_host])['approved']:
                raise HTTPException(400,'Target URL is not in the explicit host allowlist')
            if config.base_url.startswith('http://') and config.allow_host not in {'127.0.0.1','localhost'}:
                raise HTTPException(400,'Unencrypted HTTP assessments restricted to localhost from dashboard')
            if tool.get('writes') and not config.approve_writes:
                raise HTTPException(400,'Explicit disposable write approval required')
        if tool.get('writes') and config.approve_writes and not config.execute:
            raise HTTPException(400,'Write approval requires active execution')
        if tool.get('writes') and not auth:
            raise HTTPException(400,'Write workflows require an auth profile configuration')
        if kind=='scope' and (not config.base_url or not config.allow_host):
            raise HTTPException(400,'Scope audit requires URL and host')
        if config.config_usage not in {'multi-resource','workflow','journey','context','evidence','benchmark','proposals','rc15-security'}:
            raise HTTPException(400,'Unknown manifest type')
        if config.execute and config.approve_writes and config.config_id and config.config_usage=='multi-resource' and config.action in {'auto-assess','multi-resource-assess'}:
            # Refuse generated placeholders before any network traffic, even when
            # the YAML was uploaded manually rather than through the wizard.
            candidate_text=uploaded_config(config.config_id).read_text(encoding='utf-8')
            if 'REVIEW_' in candidate_text or 'TODO_' in candidate_text:
                raise HTTPException(422,'La configurazione contiene valori provvisori (REVIEW_/TODO_): usa la procedura guidata «Crea test con scritture» e compila tutti i campi richiesti.')
        if config.action in {'rc16-assess', 'rc16-access-auto'}:
            if not auth:
                raise HTTPException(422, 'RC16: carica auth.yaml con i profili da confrontare.')
            if config.expected_other not in {'allow', 'deny'}:
                raise HTTPException(422, 'RC16: indica esplicitamente la policy attesa allow/deny.')
            from achillesapi.core.auth import load_authentication_manager
            names = set(load_authentication_manager(auth).names)
            if not config.profiles or any(p not in names for p in config.profiles):
                raise HTTPException(422, 'RC16: scegli identità presenti in auth.yaml.')
            if config.action == 'rc16-access-auto' and (len(config.profiles) < 2 or not config.path_values):
                raise HTTPException(422, 'RC16 GET: servono owner, altro profilo e valori ID nel campo NAME=VALUE.')
            if config.action == 'rc16-assess':
                if config.config_usage != 'multi-resource' or not config.config_id:
                    raise HTTPException(422, 'RC16: carica il manifesto resources.yaml di risorse temporanee.')
                from achillesapi.core.rc16_orchestration import prepare_campaign
                from achillesapi.core.multi_resource import load_multi_resource_config
                from achillesapi.core.openapi import load_openapi
                try:
                    plan16 = prepare_campaign(load_openapi(spec),
                        load_multi_resource_config(uploaded_config(config.config_id)),
                        profiles=names, cross_identity=config.profiles,
                        expected_other=config.expected_other)['plan']
                    if config.execute and config.max_requests < plan16['request_budget_required']:
                        raise ValueError('Budget insufficiente per cleanup: aumentalo oppure riduci i workflow.')
                except (ValueError, OSError, TypeError) as exc:
                    raise HTTPException(422, 'RC16 manifest: ' + str(exc)[:240]) from exc
        if config.action == 'rc15-scan':
            if not config.base_url or not config.allow_host:
                raise HTTPException(422, 'RC15: indica Base URL e host dello scope anche per il piano offline.')
            if len(config.profiles) > 1:
                raise HTTPException(422, 'RC15: scegli al massimo un profilo identità per esecuzione.')
            if config.approve_writes:
                if not config.execute or not config.config_id or config.config_usage != 'rc15-security':
                    raise HTTPException(422, 'RC15: per scritture attive carica un manifest rc15-security e approva l’esecuzione.')
                from achillesapi.core.rc15_security import read_fixtures
                from achillesapi.core.openapi import load_openapi
                try:
                    valid_fixtures = read_fixtures(uploaded_config(config.config_id), load_openapi(spec))
                except (ValueError, OSError) as exc:
                    raise HTTPException(422, 'RC15: manifest fixture non valido: ' + str(exc)[:240]) from exc
                if not valid_fixtures:
                    raise HTTPException(422, 'RC15: manifest senza fixture valide.')
            if config.rc15_callback_base or config.rc15_callback_observer:
                if not config.execute or not config.rc15_callback_approved:
                    raise HTTPException(422, 'RC15: callback SSRF/XXE richiede consenso separato ed esecuzione autorizzata.')
                from achillesapi.core.rc15_security import _callback_address
                try:
                    _callback_address(config.rc15_callback_base or '', '0' * 32)
                except ValueError as exc:
                    raise HTTPException(422, 'RC15: callback non valida: ' + str(exc)[:180]) from exc
                from urllib.parse import urlsplit
                obs = urlsplit(config.rc15_callback_observer or '')
                if obs.scheme != 'http' or obs.hostname not in {'127.0.0.1', 'localhost'}:
                    raise HTTPException(422, 'RC15: observer deve usare soltanto HTTP loopback.')
            if config.rc15_approve_xml_oast and (not config.execute or not config.approve_writes or not config.rc15_callback_approved):
                raise HTTPException(422, 'RC15: XML OAST richiede consenso callback, scrittura e fixture esplicita.')
            if bool(config.rc15_fixture_file) != bool(config.rc15_fixture_marker):
                raise HTTPException(422, 'RC15: traversal richiede percorso file innocuo e marker atteso.')
        if config.action == 'injection-assess':
            from achillesapi.core.injection_engine_rc5 import FAMILIES
            if not config.injection_families or any(f not in FAMILIES for f in config.injection_families):
                raise HTTPException(422,'Scegli almeno una famiglia injection valida.')
        if config.action == 'access-probe':
            if config.expected_owner not in {'allow', 'deny'}:
                raise HTTPException(422, 'Scegli una policy attesa per il primo utente.')
            if config.expected_other not in {'unknown','deny','allow'}:
                raise HTTPException(422, 'Scegli una policy attesa tra allow, deny e unknown.')
            if not auth or len(config.profiles) != 2 or config.profiles[0] == config.profiles[1] or config.max_requests < 2:
                raise HTTPException(422, 'Access probe: carica auth.yaml, scegli due utenti diversi e almeno 2 richieste.')
            from achillesapi.core.auth import load_authentication_manager
            from achillesapi.core.access_probe_rc import _choose_get
            names = set(load_authentication_manager(auth).names)
            if any(name not in names for name in config.profiles):
                raise HTTPException(422, 'Uno dei due profili non è presente nel file auth.yaml.')
            if not config.operation:
                raise HTTPException(422, 'Scegli quale GET eseguire nel confronto multiutente.')
            values = dict(item.split('=', 1) for item in config.path_values)
            try:
                _choose_get(__import__('achillesapi.core.openapi', fromlist=['load_openapi']).load_openapi(spec), config.operation, values)
            except ValueError as exc:
                raise HTTPException(422, 'Operazione GET non utilizzabile: '+str(exc)[:180]) from exc
        # Single-task API preserves its historical asynchronous contract:
        # even an offline model creates a job, whose failure explains Ollama.
        # The full suite, in contrast, preflights and skips missing models.
        ai_preflight = (_ollama_readiness(config.model)
                        if config.action in OLLAMA_REQUIRED or
                        (config.action in OLLAMA_OPTIONAL and config.ai)
                        else None)
        if config.action=='auto-assess' and config.approve_writes:
            if not (config.execute and config.acknowledgment and config.config_id and auth):
                raise HTTPException(400,'Per eseguire anche POST/PATCH/DELETE devi: 1) caricare un manifest YAML in Passaggio 4; 2) caricare auth.yaml in Passaggio 3; 3) attivare Esegui richieste HTTP; 4) confermare autorizzazione e scritture. Per sole GET, disattiva Approvo le scritture.')
            if config.config_usage in {'journey','context'}:
                raise HTTPException(400,'La configurazione journey/context non permette scritture. Disattiva Approvo le scritture oppure scegli il manifest multi-resource.')
        if config.action=='auto-assess' and config.config_usage=='journey' and config.config_id and config.execute:
            uploaded_config(config.config_id)
        if config.action in {'workflow-assess','multi-resource-assess','journey-assess'} and not config.base_url:
            raise HTTPException(400,'Workflow actions require a base URL even in dry-run')
        if config.action=='analyze-evidence':
            # Validate the actual evidence schema BEFORE starting the child job.
            # A valid YAML/JSON file is not necessarily a response evidence bundle.
            import yaml
            from achillesapi.core.detection import analyze_response_evidence, EvidenceAnalysisError
            try:
                data=yaml.safe_load(extra.read_text(encoding='utf-8'))
                analyze_response_evidence(data)
            except (OSError, ValueError, TypeError, EvidenceAnalysisError) as exc:
                raise HTTPException(422,
                    'Il file delle evidenze deve contenere una lista «responses» con '
                    'method, path e status_code (100–599) per ogni risposta. '
                    'Rigeneralo dal job auto-assess attivo oppure carica evidenze HTTP compatibili. '
                    'Dettaglio: '+str(exc)[:160]) from exc
        with lock:
            if any(item['status']=='running' or (item['status']=='orchestrating' and not getattr(suite_worker,'active',False)) for item in jobs.values()):
                raise HTTPException(409,'Another task or suite is running')
            job_id=uuid.uuid4().hex
            # Il thread del task eredita l'ID del registro creato dalla suite.
            # Non passa in HTTP, nei report o nella CLI come argomento.
            campaign_ledger_path = getattr(suite_worker, 'ledger_path', None)
            filename=reports/(job_id+('.yaml' if tool.get('yaml') else '.json'))
            command=[sys.executable,'-m','achillesapi.cli',config.action]
            if kind in {'spec','both','spec-config'}:command.append(str(spec))
            elif kind=='scope':command.append(config.base_url)
            elif kind in {'report','report-config'}:command.append(str(previous))
            elif kind=='config:json':
                evidence_json=reports/(job_id+'-evidence.json')
                evidence_json.write_text(json.dumps(data))
                command.append(str(evidence_json))
            if kind=='both':
                if config.action in {'ai-correlate','ai-prioritize','agent-review',
                                     'autonomous-agent','agent-loop-v2','adaptive-review'}:
                    try:
                        prior_json=json.loads(previous.read_text(encoding='utf-8'))
                        if not isinstance(prior_json,dict):raise ValueError('Risultato JSON non valido')
                        if config.action == 'ai-correlate':
                            from achillesapi.core.evidence_bridge import evidence_from_assessment
                            evidence_from_assessment(prior_json)
                    except (OSError,ValueError,TypeError) as exc:
                        raise HTTPException(422,
                            'Seleziona un job auto-assess ATTIVO completato con osservazioni HTTP. '
                            'Prima esegui auto-assess con richieste HTTP, poi scegli il job '
                            'nella voce «Analisi precedente». Dettaglio: '+str(exc)[:120]) from exc
                if config.action == 'ai-correlate':
                    # The CLI now accepts an AchillesAPI assessment directly. Never pass a
                    # workflow YAML to a command requiring captured HTTP observations.
                    from achillesapi.core.evidence_bridge import evidence_from_assessment
                    try:
                        saved=json.loads(previous.read_text(encoding='utf-8'))
                        evidence_from_assessment(saved)  # Preflight, no target traffic.
                    except (ValueError, OSError, json.JSONDecodeError) as exc:
                        raise HTTPException(422,
                            'AI Correlation richiede un assessment con risposte HTTP. '
                            'Esegui prima auto-assess con “Esegui richieste HTTP”, poi '
                            'scegli il suo risultato nella sezione “Analisi precedente”. '
                            'Un piano offline non contiene risposte da correlare.') from exc
                command.append(str(previous))
            if config.action in {'auth-preflight','auth-audit'} and auth:
                command+=['--auth-config',str(auth)]
            if kind=='auth-only':
                if not auth:raise HTTPException(400,'Carica auth.yaml prima di usare auth-profiles')
                command+=['--config',str(auth)]
            if kind=='config-report':
                # Benchmark requires *independent human labels*, not a raw assessment.
                labels=json.loads(extra.read_text(encoding='utf-8'))
                if not isinstance(labels,dict) or not isinstance(labels.get('positive_ids'),list) or not isinstance(labels.get('verified_positive_ids'),list):
                    raise HTTPException(422,'Benchmark: genera prima etichette indipendenti e finding verificati dal modulo guidato.')
                from achillesapi.core.production_v031 import benchmark_evaluate
                benchmark_evaluate({'positive_ids':labels['positive_ids']},
                                   {'verified_positive_ids':labels['verified_positive_ids']})
                verified_file=reports/(job_id+'-verified-labels.json')
                verified_file.write_text(json.dumps({'verified_positive_ids':labels['verified_positive_ids']}),encoding='utf-8')
                command.extend([str(extra),str(verified_file)])
            if kind=='spec-config':
                if tool.get('config_flag')=='POSITIONAL':command.append(str(extra))
                else:command.extend([tool.get('config_flag','--config'),str(extra)])
            if kind=='report-config':command.append(str(extra))
            if kind=='scope':command+=['--allow-host',config.allow_host]
            if tool.get('budget'):command+=['--budget',str(config.budget)]
            if tool.get('active'):
                if config.base_url:command+=['--base-url',config.base_url]
                if auth:command+=['--auth-config',str(auth)]
                for profile in config.profiles:command+=['--profile',profile] if config.action in {
                    'access-probe','injection-assess','auto-assess','advanced-vuln-assess','autonomous-agent','agent-loop-v2','rc15-scan'} else []
                for value in config.path_values:
                    if config.action in {'access-probe','injection-assess','auto-assess','advanced-vuln-assess','autonomous-agent','agent-loop-v2','rc15-scan'}:
                        command+=['--path-value',value]
                if config.action in {'access-probe','injection-assess','auto-assess','advanced-vuln-assess','multi-resource-assess','workflow-assess','journey-assess','rc15-scan','rc16-assess','rc16-access-auto'}:
                    command+=['--max-requests',str(cli_request_budget(config.action, config.max_requests)),'--rate',str(config.rate)]
                if config.action == 'rc16-assess':
                    for name in config.profiles:command += ['--compare-profile', name]
                    command += ['--expected-other', config.expected_other]
                if config.action == 'rc16-access-auto':
                    command += ['--owner-profile', config.profiles[0],
                                '--expected-other', config.expected_other]
                    for name in config.profiles[1:]:command += ['--other-profile', name]
                    for value in config.path_values:command += ['--path-value', value]
                if config.action == 'access-probe':
                    command+=['--operation',config.operation,'--expected-other',config.expected_other,'--expected-owner',config.expected_owner]
                if config.action in {'auto-assess','advanced-vuln-assess','multi-resource-assess','workflow-assess','journey-assess','agent-loop-v2'}:
                    command+=[]
                if config.action in {'agent-loop-v2'}:command+=['--rate',str(config.rate)]
                # Le prove GET controllano sempre lo scope, anche in dry-run.
                # Senza questo flag, la CLI rifiuterebbe erroneamente il piano offline.
                if not config.execute and config.action in {'access-matrix','access-probe','injection-assess','rc15-scan','rc16-access-auto'} and config.allow_host:
                    command+=['--allow-host',config.allow_host]
                if (config.action in {'access-probe', 'access-matrix','rc16-access-auto'} and not config.execute and
                        config.allow_insecure_http and config.allow_host in {'localhost','127.0.0.1'}):
                    command+=['--allow-insecure-http']
                if config.execute:
                    command+=['--execute','--allow-host',config.allow_host]
                    if config.allow_insecure_http:command+=['--allow-insecure-http']
                    if tool.get('writes'):command+=['--approve-writes']
            if config.action=='auto-assess':
                if config.config_id and config.config_usage=='context':
                    command+=['--context',str(uploaded_config(config.config_id))]
                if config.execute and config.budget:
                    command+=['--agent-budget',str(config.budget)]
                if config.config_id and config.execute:
                    if config.config_usage=='context':pass
                    elif config.config_usage=='journey':
                        command+=['--journey-config',str(uploaded_config(config.config_id))]
                    elif config.approve_writes:
                        flag='--multi-resource-config' if config.config_usage=='multi-resource' else '--workflow-config'
                        command+=[flag,str(uploaded_config(config.config_id)),'--approve-writes']
            if config.action=='rc15-scan':
                if config.approve_writes:
                    command += ['--fixture-config', str(uploaded_config(config.config_id)), '--approve-writes']
                if config.rc15_approve_xml_oast:
                    command += ['--approve-xml-oast']
                if config.rc15_callback_base:
                    command += ['--callback-base', config.rc15_callback_base]
                if config.rc15_callback_observer:
                    command += ['--callback-observer', config.rc15_callback_observer]
                if config.rc15_fixture_file:
                    command += ['--fixture-file', config.rc15_fixture_file,
                                '--fixture-marker', config.rc15_fixture_marker]
            if config.action=='injection-assess':
                command+=['--families',','.join(config.injection_families)]
            if config.action=='adaptive-plan' and config.ai:
                command+=['--ai','--model',config.model]
            if tool.get('ai'):
                # Only commands that actually implement --ai receive it.
                # ai-correlate and ai-analyze always use Ollama, but reject --ai.
                if config.ai and config.action in {'scan','ai-prioritize',
                        'autonomous-agent','agent-loop-v2'}:
                    command+=['--ai']
                command+=['--model',config.model]
            command+=['--output',str(filename)]
            ai_requested = config.action in OLLAMA_REQUIRED or (
                config.action in OLLAMA_OPTIONAL and config.ai)
            jobs[job_id]={'id':job_id,'status':'running','mode':config.action,
                          'ai_status':'pending' if ai_requested else 'not_invoked',
                          'ai_model':config.model if ai_requested else None,
                          'ai_preflight':ai_preflight,
                          'exit_code':None,'error':None,'specification_id':config.specification_id,
                          'action':config.action,'active':config.execute}

        job_timeout = getattr(suite_worker, 'child_timeout', 480)

        def worker():
            task_started = time.monotonic()
            try:
                local_env=_restricted_secrets(config.secrets,auth)
                if campaign_ledger_path:
                    local_env['ACHILLES_CAMPAIGN_LEDGER'] = campaign_ledger_path
                else:
                    # Nessun registro globale ereditato per i job avviati da soli.
                    local_env.pop('ACHILLES_CAMPAIGN_LEDGER', None)
                local_env["PYTHONPATH"]=os.pathsep.join([str(repo/"src"),str(repo),local_env.get("PYTHONPATH","")])
                # Se è un task solo-lettura, il tempo rimanente della campagna
                # limita anche il subprocesso. Le scritture mantengono il tempo
                # per il cleanup; non possiamo promettere che il rollback sia riuscito.
                from achillesapi.core.process_supervisor_rc4 import run_cli_bounded
                complete=run_cli_bounded(command,cwd=root,timeout=job_timeout,env=local_env)
                good=complete.returncode==0 and filename.is_file()
                if good and tool.get('yaml'):
                    import yaml
                    value=yaml.safe_load(filename.read_text(encoding='utf-8'))
                    (reports/(job_id+'.json')).write_text(json.dumps({'draft':value},indent=2))
                evidence_count=0
                if good and not tool.get('yaml'):
                    try:
                        from achillesapi.core.assessment_context import observed_http_count
                        result_data=json.loads(filename.read_text(encoding='utf-8'))
                        if isinstance(result_data,dict):
                            evidence_count=observed_http_count(result_data)
                            if ai_requested:
                                if _ai_output_present(config.action, result_data):
                                    with lock:jobs[job_id]['ai_status']='completed_local'
                                else:
                                    good=False
                                    with lock:
                                        jobs[job_id]['ai_status']='missing_output'
                                        jobs[job_id]['error']='Il task è terminato senza produrre la sezione AI prevista. Nessuna inferenza verificabile.'

                    except (ValueError,OSError,TypeError):pass
                with lock:
                    job=jobs[job_id]
                    job['http_observations']=evidence_count
                    job['duration_ms']=round((time.monotonic()-task_started)*1000)
                    job['exit_code']=complete.returncode
                    job['status']='complete' if good else 'failed'
                    if ai_requested and not good and job.get('ai_status') != 'missing_output':
                        job['ai_status'] = 'failed'
                    if not good and not job.get('error'):job['error']=_safe_error(complete.stderr,config.secrets,auth)
            except subprocess.TimeoutExpired:
                with lock:
                    jobs[job_id]['status']='failed'
                    if ai_requested:jobs[job_id]['ai_status']='failed'
                    jobs[job_id]['duration_ms']=round((time.monotonic()-task_started)*1000)
                    jobs[job_id]['error']='Timeout del task: esecuzione non completata.'
                    if tool.get('writes') and config.execute:
                        # Attenzione: il processo potrebbe essersi fermato prima
                        # della pulizia delle risorse temporanee.
                        jobs[job_id]['cleanup_state']='unknown_requires_operator_check'
            except (OSError, ValueError):
                with lock:
                    jobs[job_id]['status']='failed'
                    jobs[job_id]['duration_ms']=round((time.monotonic()-task_started)*1000)
                    jobs[job_id]['error']='Errore di avvio o elaborazione del task.'
            finally:
                with lock: store.save_job(dict(jobs[job_id]))
        threading.Thread(target=worker,daemon=True).start()
        return {'id':job_id,'status':'running','action':config.action}

    @app.post('/api/control/suite/{suite_id}/stop')
    def stop_suite(suite_id: str, x_achilles_token: str | None = Header(None)):
        """Ferma una suite DOPO il task in corso; non interrompe cleanup HTTP.

        L'interruzione cooperativa evita di uccidere un subprocess che potrebbe
        stare cancellando una fixture temporanea o completando un'operazione.
        """
        guard(x_achilles_token)
        if not ID.fullmatch(suite_id):
            raise HTTPException(404, 'Suite non trovata')
        with lock:
            parent = jobs.get(suite_id)
            if not parent or parent.get('action') != 'full-suite':
                raise HTTPException(404, 'Suite non trovata')
            if parent.get('status') != 'orchestrating':
                raise HTTPException(409, 'La suite non è in esecuzione')
            if str(parent.get('current_step') or '').startswith('Retry:'):
                raise HTTPException(409, 'Il retry è in esecuzione: attendi il cleanup e poi avvia un nuovo task.')
            parent['stop_requested'] = True
            store.save_job(dict(parent))
        return {'id': suite_id, 'stop_requested': True,
                'message': 'La suite si fermerà dopo il task corrente; un eventuale cleanup non viene interrotto.'}

    @app.post('/api/control/suite')
    def run_suite(request: SuiteRequest, x_achilles_token: str | None = Header(None)):
        """Orchestrate every eligible CLI tool sequentially as child jobs.

        Each child goes through the existing single-tool validation and scope
        checks. The parent is not a running CLI job, so it does not bypass the
        existing one-at-a-time safeguard.
        """
        guard(x_achilles_token)
        cfg = request.config
        if not cfg.specification_id:
            raise HTTPException(422, 'Per la suite completa devi caricare OpenAPI.')
        file_id(cfg.specification_id, '.yaml')
        # Every disposable workflow is a validated uploaded configuration.
        # The browser may supply multiple IDs, never YAML or arbitrary paths.
        workflow_ids = list(dict.fromkeys(request.workflow_config_ids))
        # A field approval is scoped to its exact uploaded disposable manifest.
        # A client cannot silently apply a field to another workflow or extend
        # permissions beyond the explicitly approved list.
        if request.rc13_body_fields_by_workflow:
            if not (request.include_rc13 and request.include_writes and request.rc13_body_probes):
                raise HTTPException(422, 'Sonde PATCH: abilita analisi approfondita, scritture e consenso separato.')
            if any(workflow not in workflow_ids or not ID.fullmatch(workflow) or
                   not isinstance(fields, list) or not 1 <= len(fields) <= 4 or
                   any(not isinstance(field,str) or len(field)>240 for field in fields)
                   for workflow, fields in request.rc13_body_fields_by_workflow.items()):
                raise HTTPException(422,'Campi PATCH non validi: approva fino a quattro campi per ogni workflow salvato.')
        if request.include_writes and workflow_ids:
            if not cfg.auth_config_id:
                raise HTTPException(422, 'Multi-workflow: importa auth.yaml prima di approvare scritture.')
            from achillesapi.core.multi_resource import load_multi_resource_config
            for workflow_id in workflow_ids:
                try:
                    load_multi_resource_config(uploaded_config(workflow_id))
                except (ValueError, OSError, TypeError, HTTPException) as exc:
                    raise HTTPException(422, 'Manifest multi-workflow non valido: ' + str(exc)[:180]) from exc
            cfg.config_id = workflow_ids[0]
            cfg.config_usage = 'multi-resource'
        elif not request.include_writes:
            workflow_ids = []
        # Explicitly bounded, deterministic order; no unapproved workflow is
        # inferred from the Swagger and executed with invented write fixtures.
        workflow_tasks = {'rc16-assess'}
        # Run approved disposable workflows before broad injection scans.
        # Otherwise the first endpoints can exhaust the shared ledger before
        # any BFLA/BOPLA campaign starts. The global cap is never increased.
        # Stateful tests must run before broad GET scanners consume the ledger.
        # A journey without an approved journey manifest is still skipped by
        # the existing prerequisite validator, never guessed from the spec.
        early = ('rc16-assess','workflow-assess','journey-assess') if workflow_ids and request.include_active else ('workflow-assess','journey-assess')
        ordered_actions = tuple(a for a in early if a in SUITE_ORDER) + tuple(a for a in SUITE_ORDER if a not in early)
        scheduled = [(action, workflow_id)
                     for action in ordered_actions
                     for workflow_id in (workflow_ids if action in workflow_tasks and workflow_ids else [None])]
        workflow_labels = {}
        approved_manifests = {}
        for workflow_id in workflow_ids:
            from achillesapi.core.multi_resource import load_multi_resource_config
            data = load_multi_resource_config(uploaded_config(workflow_id))
            approved_manifests[workflow_id] = data
            names = [r.get('name','risorsa') for r in data.get('resources', []) if isinstance(r, dict)]
            workflow_labels[workflow_id] = ' · '.join(str(name)[:50] for name in names[:8]) or 'Workflow approvato'
        matrix_rules_id = cfg.access_rules_id or (cfg.config_usage == 'context' and cfg.config_id or None)
        matrix_rules = []
        if matrix_rules_id:
            if not cfg.auth_config_id:
                raise HTTPException(422, 'Per utilizzare la matrice devi caricare auth.yaml.')
            from achillesapi.core.authorization_suite_bridge_rc9 import validated_suite_rules
            try:
                matrix_rules = validated_suite_rules(file_id(cfg.specification_id,'.yaml'),
                    file_id(cfg.auth_config_id,'.auth.yaml'), uploaded_config(matrix_rules_id))
            except (OSError, ValueError) as exc:
                raise HTTPException(422, 'Matrice di accesso non compatibile con Swagger o auth.yaml: '+str(exc)[:240]) from exc
        if request.rc17_agent_followups and not (request.include_active and request.include_ai and request.include_rc13):
            raise HTTPException(422, 'I follow-up dell’agente AI richiedono test HTTP, Ollama locale e analisi approfondita.')
        if request.rc17_agent_followups and request.rc13_max_requests < request.rc17_agent_budget + 5:
            raise HTTPException(422, 'Aumenta il budget HTTP dell’analisi approfondita per i follow-up AI.')
        if request.rc17_agent_followups and _ollama_readiness(cfg.model)['status'] != 'ready':
            raise HTTPException(422, 'Per i follow-up AI, avvia Ollama e scegli un modello installato.')
        if request.include_writes and not (request.include_active and
                cfg.approve_writes and cfg.acknowledgment and cfg.config_id and cfg.auth_config_id):
            raise HTTPException(422, 'Scritture: servono manifest, auth.yaml, autorizzazione HTTP e approvazione esplicita.')
        if request.include_active:
            if not cfg.acknowledgment or not cfg.base_url or not cfg.allow_host or not scope_audit(cfg.base_url,[cfg.allow_host])['approved']:
                raise HTTPException(422, 'Per la suite attiva servono URL, allowlist e conferma autorizzazione.')
            if cfg.base_url.startswith('http://') and cfg.allow_host not in {'localhost','127.0.0.1'}:
                raise HTTPException(422, 'HTTP in chiaro consentito solo su localhost.')
        # The title is metadata from the already-uploaded OpenAPI, never a CLI argument.
        from achillesapi.core.openapi import load_openapi
        from achillesapi.dashboard.suite_identity import suite_identity
        try:
            api_spec = load_openapi(file_id(cfg.specification_id, '.yaml'), validate=False)
        except (OSError, ValueError) as exc:
            raise HTTPException(422, 'Il file Swagger non è leggibile.') from exc
        from achillesapi.core.suite_write_coverage import write_inventory, update_write_execution
        write_coverage = write_inventory(api_spec, approved_manifests)
        # Budget these manifests using the actual disposable lifecycle planner.
        # Invalid manifests are handled by the relevant task validator; never
        # infer that they are safe to execute just from their OpenAPI paths.
        workflow_budget_required: dict[str, int] = {}
        if approved_manifests and cfg.auth_config_id:
            from achillesapi.core.multi_resource import plan_multi_resource
            from achillesapi.core.openapi import parse_openapi
            from achillesapi.core.auth import load_authentication_manager
            parsed_api = parse_openapi(api_spec)
            auth_names = set(load_authentication_manager(
                file_id(cfg.auth_config_id,'.auth.yaml')).names)
            for approved_id, manifest_data in approved_manifests.items():
                try:
                    estimate = plan_multi_resource(parsed_api, api_spec,
                                                   manifest_data, auth_names)
                    workflow_budget_required[approved_id] = max(5, int(estimate['request_budget_required']))
                except (ValueError, TypeError, KeyError, OSError):
                    # Reserve a cautious fallback; the task still must pass
                    # its own strict fixture and permission validation.
                    workflow_budget_required[approved_id] = 25
        with lock:
            if any(j.get('status') in {'running','orchestrating'} for j in jobs.values()):
                raise HTTPException(409, 'Attendi che il job o la suite precedente termini.')
            suite_id = uuid.uuid4().hex
            identity = suite_identity(api_spec, suite_id)
            # Budget effettivo: il registro SQLite è condiviso da ogni subprocesso.
            # Esiste soltanto per le campagne che autorizzano traffico HTTP.
            ledger_path = reports / (suite_id + '.http-ledger.sqlite3')
            if request.include_active:
                from achillesapi.core.campaign_ledger import CampaignLedger
                CampaignLedger.create(ledger_path, limit=request.max_total_requests,
                                      rate=cfg.rate, runtime_seconds=request.max_runtime_seconds)
            jobs[suite_id] = {'id': suite_id, 'status': 'orchestrating', 'action': 'full-suite',
                'mode': 'suite HTTP autorizzata' if request.include_active else 'suite offline',
                'active': request.include_active, 'specification_id': cfg.specification_id,
                **identity, 'total':len(scheduled) + (len(request.rc13_body_fields_by_workflow) if request.include_rc13 and request.rc13_body_fields_by_workflow else int(request.include_rc13)), 'completed_steps': 0, 'current_step': None,
                'exit_code': None, 'error': None}
            safe_copy=request.model_copy(deep=True)
            safe_copy.config.secrets={}  # require explicit reentry for reruns; never persist tokens
            suite_contexts[suite_id]=safe_copy
            store.save_suite_context(suite_id, safe_copy)
        ai_readiness = _ollama_readiness(cfg.model) if request.include_ai else {'status':'disabled','model':cfg.model,'message':'AI non abilitata.'}
        from achillesapi.core.compatibility_v080 import from_file, known_unavailable_actions
        from achillesapi.core.workflow_inference_v080 import infer_workflows
        from achillesapi.core.openapi import load_openapi
        from achillesapi.core.ai_planner_v080 import deterministic_next_steps
        from achillesapi.core.verification_v080 import classify_findings
        coverage = from_file(str(file_id(cfg.specification_id, '.yaml')),
                             has_auth=bool(cfg.auth_config_id),
                             active_allowed=request.include_active,
                             writes_approved=request.include_writes,
                             ai_enabled=request.include_ai)
        unavailable = known_unavailable_actions(coverage)
        workflows = infer_workflows(load_openapi(file_id(cfg.specification_id, '.yaml')))
        from achillesapi.core.auth_readiness_v080 import auth_readiness
        from achillesapi.core.security_surfaces_v080 import security_surfaces
        from achillesapi.core.risk_matrix_v090 import build_risk_matrix
        auth_info = auth_readiness(load_openapi(file_id(cfg.specification_id, '.yaml')),
            str(file_id(cfg.auth_config_id,'.auth.yaml')) if cfg.auth_config_id else None)
        surface_info = security_surfaces(load_openapi(file_id(cfg.specification_id, '.yaml')))
        risk_info = build_risk_matrix(load_openapi(file_id(cfg.specification_id, '.yaml')))
        initial_plan = deterministic_next_steps(coverage, ai_available=request.include_ai)
        from achillesapi.core.campaign_v090 import campaign_preflight
        campaign_plan = campaign_preflight(
            load_openapi(file_id(cfg.specification_id,'.yaml')), TOOLS, SUITE_ORDER,
            has_auth=bool(cfg.auth_config_id), has_config=bool(cfg.config_id),
            config_usage=cfg.config_usage, active=request.include_active,
            writes=request.include_writes, ai=request.include_ai,
            has_scope=bool(cfg.base_url and cfg.allow_host), authorized=cfg.acknowledgment,
            include_optional=request.include_optional,
            max_total_requests=request.max_total_requests, per_task_limit=cfg.max_requests,
            agent_budget=cfg.budget, profile_count=len(cfg.profiles))
        source = reports/(suite_id+'.json')
        report: dict[str, Any] = {'engine': 'achillesapi-bounded-suite', 'version': '1.0', 'achilles_version':'1.0.0rc27',
            'specification_id': cfg.specification_id, **identity, 'mode': 'active' if request.include_active else 'offline',
            'rc13_enabled': request.include_rc13, 'ai_enabled': request.include_ai, 'ai_readiness': ai_readiness, 'writes_approved': request.include_writes, 'max_total_requests': request.max_total_requests,
            'reserved_request_budget': 0, 'http_telemetry': {'scope':'no_active_traffic'}, 'max_runtime_seconds': request.max_runtime_seconds, 'preflight': coverage, 'workflow_proposals': workflows, 'task_preflight': campaign_plan,
            'write_operation_coverage': write_coverage,
            'workflow_request_budget_estimate': workflow_budget_required,
            'workflow_campaign': {'requested': len(workflow_ids), 'validated_config_ids': workflow_ids,
                                  'status': 'approved_manifests_only',
                                  'labels': workflow_labels},
            'adaptive_plan': initial_plan, 'auth_readiness': auth_info, 'security_surfaces': surface_info, 'risk_matrix': risk_info, 'verification': {'summary': {'raw_indicators': 0, 'deduplicated_groups': 0}, 'findings': []},
            'access_matrix': {'loaded': bool(matrix_rules), 'rule_count': len(matrix_rules),
                              'scope': 'operator_supplied_rules',
                              'note': 'access-probe usa la prima regola; access-matrix verifica tutte le regole; verify-access-policy rivede le evidenze della matrice.'},
            'steps': [], 'summary': {'completed': 0, 'failed': 0, 'skipped': 0, 'total':len(scheduled) + (len(request.rc13_body_fields_by_workflow) if request.include_rc13 and request.rc13_body_fields_by_workflow else int(request.include_rc13))},
            'limitations': ['Ogni strumento ha una funzione diversa: un comando di planning non è un test di vulnerabilità.',
                            'I finding richiedono revisione; l’AI non conferma le vulnerabilità.',
                            'La suite riserva un budget complessivo per i controlli attivi e salta i passaggi che supererebbero il limite.',
                            'La suite pianifica tutti i manifest multi-risorsa approvati e isola gli esiti per risorsa; workflow senza fixture approvata non vengono modificati.']}
        def snapshot():
            # Il budget riservato è una stima. Questo contatore include i tentativi
            # HTTP fatti dai subprocessi, inclusi errori e autenticazioni dinamiche.
            if ledger_path.is_file():
                from achillesapi.core.campaign_ledger import CampaignLedger
                report['http_telemetry'] = CampaignLedger(ledger_path).snapshot()
            from achillesapi.core.diagnostics_rc20 import enrich_steps
            report['steps'] = enrich_steps(report['steps'])
            update_write_execution(report['write_operation_coverage'], report['steps'])
            report['diagnostics_version'] = 'rc20-typed'
            source.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
            with lock:
                jobs[suite_id]['completed_steps'] = len(report['steps'])
                jobs[suite_id]['suite_summary'] = dict(report['summary'])
                store.save_job(dict(jobs[suite_id]))

        def runner():
            suite_worker.active=True
            suite_worker.ledger_path = str(ledger_path) if request.include_active else None
            evidence_id = None
            matrix_evidence_id = None
            reserved = 0
            started_at = time.monotonic()
            try:
                snapshot()
                stopped = False
                rc13_completed_writes = False
                if request.include_rc13:
                    # One isolated RC13 job per explicitly approved PATCH manifest.
                    # Never merge unrelated field names or reuse another fixture.
                    selected_targets = [(workflow, fields) for workflow, fields in
                        request.rc13_body_fields_by_workflow.items() if workflow in workflow_ids]
                    if not selected_targets:
                        selected_targets = [(None, request.rc13_body_fields)]
                    for target_workflow, target_fields in selected_targets:
                        # RC13 runs as a real child job, shares the campaign ledger,
                        # and is included in parent reports/export, not just a UI card.
                        with lock:
                            jobs[suite_id]['current_step'] = 'rc13-assess'
                        stage_reason = None
                        max_rc13 = request.rc13_max_requests
                        if request.include_active:
                            from achillesapi.core.campaign_ledger import CampaignLedger
                            remaining_budget = int(CampaignLedger(ledger_path).snapshot()['remaining'])
                            # Leave a protected portion for approved stateful lifecycles.
                            reserved_for_workflows = min(remaining_budget, sum(
                                workflow_budget_required.get(workflow,25) for workflow in workflow_ids))
                            max_rc13 = min(max_rc13, max(0, remaining_budget - reserved_for_workflows))
                            if max_rc13 < 5:
                                stage_reason = 'Budget globale insufficiente per l’analisi approfondita (minimo 5 richieste GET).'
                        if request.rc13_body_probes and not request.include_writes:
                            stage_reason = 'Le sonde sui campi JSON richiedono approvazione separata delle scritture.'
                        if stage_reason:
                            report['steps'].append({'action': 'rc13-assess', 'status': 'skipped', 'reason': stage_reason, 'workflow_config_id':target_workflow})
                            report['summary']['skipped'] += 1
                        else:
                            rc13_cfg = cfg.model_copy(deep=True)
                            if target_workflow:
                                rc13_cfg.config_id = target_workflow
                                rc13_cfg.config_usage = 'multi-resource' 
                            # RC13 chooses one approved identity for GET injection;
                            # the full pairwise auth matrix uses its own identities.
                            if rc13_cfg.profiles:
                                rc13_cfg.profiles = rc13_cfg.profiles[:1]
                            elif rc13_cfg.auth_config_id:
                                from achillesapi.core.auth import load_authentication_manager
                                rc13_cfg.profiles = list(load_authentication_manager(
                                    file_id(rc13_cfg.auth_config_id,'.auth.yaml')).names[:1])
                            rc13_cfg.approve_writes = bool(request.include_writes and cfg.approve_writes and
                                (not workflow_ids or bool(target_workflow)))
                            try:
                                stage_id = _start_rc13(RC13DashboardRequest(
                                    config=rc13_cfg, active=request.include_active,
                                    writes=bool(request.include_writes and
                                        (not workflow_ids or bool(target_workflow))),
                                    body_probes=bool(request.rc13_body_probes and target_fields and (target_workflow or len(workflow_ids)<=1)),
                                    body_probe_fields=target_fields,
                                    ai=bool(request.include_ai and ai_readiness['status'] == 'ready'),
                                    agent_followups=bool(request.rc17_agent_followups and request.include_active
                                        and request.include_ai and ai_readiness['status'] == 'ready'),
                                    agent_rounds=request.rc17_agent_rounds,
                                    agent_budget=request.rc17_agent_budget,
                                    max_requests=max_rc13,
                                    rc15_callback_base=rc13_cfg.rc15_callback_base,
                                    rc15_callback_observer=rc13_cfg.rc15_callback_observer,
                                    rc15_callback_approved=rc13_cfg.rc15_callback_approved),
                                    suite_id=suite_id,
                                    ledger_path=str(ledger_path) if request.include_active else None)
                                while True:
                                    with lock:
                                        child = dict(jobs[stage_id])
                                    if child['status'] not in {'running', 'orchestrating'}:
                                        break
                                    time.sleep(.2)
                                step = {'action': 'rc13-assess', 'job_id': stage_id,
                                    **({'workflow_config_id':target_workflow, 'workflow_label':workflow_labels.get(target_workflow)} if target_workflow else {}),
                                    'approved_patch_fields':len(target_fields),
                                        'status': child['status'],
                                        'http_observations': child.get('http_observations', 0),
                                        'ai_status': child.get('ai_status', 'not_invoked')}
                                if child['status'] == 'complete':
                                    result = json.loads((reports/(stage_id+'.json')).read_text(encoding='utf-8'))
                                    step['candidate_indicators'] = len(result.get('findings', []))
                                    step['coverage'] = result.get('coverage', {})
                                    rc13_completed_writes = bool(request.include_writes and
                                        result.get('stages', {}).get('workflows', {}).get('executed'))
                                    report.setdefault('rc13_coverage_by_workflow', {})[target_workflow or 'general'] = result.get('coverage', {})
                                    report['rc13_coverage'] = result.get('coverage', {})
                                    report['summary']['completed'] += 1
                                else:
                                    step['reason'] = child.get('error', 'Analisi approfondita non completata.')
                                    report['summary']['failed'] += 1
                                report['steps'].append(step)
                            except (HTTPException, ValueError, OSError) as exc:
                                report['steps'].append({'action': 'rc13-assess', 'status': 'skipped', 'workflow_config_id':target_workflow,
                                    'reason': 'Prerequisiti per l’analisi approfondita: ' +
                                       (str(exc.detail) if isinstance(exc, HTTPException) else str(exc))[:250]})
                                report['summary']['skipped'] += 1
                        snapshot()
                for task_index, (action, workflow_id) in enumerate(scheduled):
                    # Fermiamo la suite tra due task, non durante la pulizia di una risorsa.
                    with lock:
                        stop_requested = bool(jobs[suite_id].get('stop_requested'))
                    if time.monotonic() - started_at >= request.max_runtime_seconds:
                        with lock:
                            jobs[suite_id]['stop_requested'] = True
                        report['limitations'].append('Limite temporale della campagna raggiunto; nessun altro task è stato avviato.')
                        stop_requested = True
                    if stop_requested:
                        stopped = True
                        for remaining, remaining_workflow in scheduled[task_index:]:
                            report['steps'].append({'action': remaining, 'workflow_config_id': remaining_workflow,
                                'workflow_label': workflow_labels.get(remaining_workflow), 'status': 'skipped',
                                'reason': 'Task non avviato: arresto richiesto dall’operatore.'})
                            report['summary']['skipped'] += 1
                        snapshot()
                        break
                    # Individual tools always pass their existing safety validator.
                    # Three authorization tasks share the saved matrix; the
                    # verifier waits for a *matrix* result, not generic auto-assess.
                    authorization_context = cfg.model_copy(deep=True)
                    if workflow_id:
                        authorization_context.config_id = workflow_id
                        authorization_context.config_usage = 'multi-resource'
                    if matrix_rules:
                        authorization_context.access_rules_id = matrix_rules_id
                        if action in {'access-matrix','verify-access-policy'}:
                            authorization_context.config_id = matrix_rules_id
                            authorization_context.config_usage = 'context'
                    reason = unavailable.get(action) or suite_skip_reason(action, authorization_context,
                        request, matrix_evidence_id if action == 'verify-access-policy' else evidence_id)
                    if not reason and rc13_completed_writes and action in {'workflow-assess', 'multi-resource-assess'}:
                        reason = 'Workflow temporanei già eseguiti da RC13 nella stessa suite; duplicazione delle scritture evitata.'
                    if not reason and request.include_ai and ai_readiness['status'] != 'ready' and action in OLLAMA_REQUIRED:
                        reason = 'Ollama richiesto ma non disponibile: ' + ai_readiness['message']
                    graph_config_id = None
                    if not reason and action == 'workflow-graph' and cfg.config_id:
                        # A disposable manifest is not a DAG; adapt it read-only
                        # and validate every operation against the current OpenAPI.
                        try:
                            import yaml
                            from achillesapi.core.production_v031 import load_workflow_graph, workflow_graph
                            from achillesapi.core.workflow_graph_bridge_rc9 import derive_disposable_graph
                            parsed_graph = analyze_openapi_file(file_id(cfg.specification_id,'.yaml'))
                            raw_graph = load_workflow_graph(uploaded_config(cfg.config_id))
                            graph = derive_disposable_graph(raw_graph)
                            workflow_graph(parsed_graph, graph)
                            if graph is not raw_graph:
                                graph_config_id = uuid.uuid4().hex
                                (uploads/(graph_config_id+'.config.yaml')).write_text(
                                    yaml.safe_dump(graph,sort_keys=False),encoding='utf-8')
                        except (ValueError, OSError, TypeError) as exc:
                            reason = ('Il workflow non è convertibile in un DAG valido: '+str(exc)[:170]+
                                      '. Verifica POST/GET/DELETE e i riferimenti ${resource.id}.')

                    if reason:
                        skip = {'action':action,'status':'skipped','reason':reason}
                        if workflow_id: skip.update(workflow_config_id=workflow_id, workflow_label=workflow_labels[workflow_id])
                        if action in OLLAMA_REQUIRED or action in OLLAMA_OPTIONAL:
                            skip['ai_status'] = 'not_invoked'
                        report['steps'].append(skip)
                        report['summary']['skipped'] += 1
                        snapshot()
                        continue
                    tool = TOOLS[action]
                    # Budget is reserved for worst-case traffic, not computed from
                    # response counts which may be incomplete.
                    planned_active = bool(request.include_active and tool.get('active'))
                    per_step_cap = (min(cfg.budget, 15) if action in {'autonomous-agent','agent-loop-v2'}
                                    else cli_request_budget(action, cfg.max_requests))
                    # Il limite reale viene applicato dal registro SQLite condiviso.
                    # Il budget *riservato* non è una misura del traffico effettivo.
                    remaining = request.max_total_requests
                    if planned_active:
                        from achillesapi.core.campaign_ledger import CampaignLedger
                        remaining = int(CampaignLedger(ledger_path).snapshot()['remaining'])
                    if planned_active and action == 'access-matrix' and matrix_rules:
                        # Una regola richiede due GET. Controlliamo prima il budget,
                        # altrimenti il task fallirebbe per un prerequisito prevedibile.
                        try:
                            number_of_rules = len(matrix_rules)
                        except (OSError, ValueError, TypeError):
                            number_of_rules = 0
                        if number_of_rules and min(remaining, cfg.max_requests) < 2 * number_of_rules:
                            report['steps'].append({'action': action, 'status': 'skipped',
                                'reason': f'Budget insufficiente: {number_of_rules} regole richiedono almeno {2 * number_of_rules} GET; rimanenti {remaining}. Aumenta il budget della nuova suite.'})
                            report['summary']['skipped'] += 1
                            snapshot()
                            continue
                    minimum_http = CLI_REQUEST_LIMITS.get(action, (1, 150))[0]
                    if planned_active and (remaining < minimum_http or (tool.get('writes') and remaining < per_step_cap)):
                        report['steps'].append({'action': action, 'status': 'skipped',
                            'reason': (f'Budget HTTP insufficiente: {remaining} richieste disponibili, '+
                                       f'{per_step_cap if tool.get("writes") else minimum_http} richieste minime necessarie. '+
                                       'Il budget globale è condiviso fra i test. Per proseguire avvia una nuova campagna con più budget '+
                                       'o riduci le verifiche opzionali; le scritture non partono senza spazio per il cleanup.')})
                        report['summary']['skipped'] += 1
                        snapshot()
                        continue
                    with lock:jobs[suite_id]['current_step'] = action
                    payload = authorization_context.model_copy(deep=True)
                    payload.action = action
                    if action in {'access-matrix', 'verify-access-policy'} and matrix_rules:
                        payload.config_id = matrix_rules_id
                        payload.config_usage = 'context'
                        payload.access_rules_id = matrix_rules_id
                    if action == 'access-probe' and matrix_rules:
                        from achillesapi.core.authorization_suite_bridge_rc9 import probe_from_rule
                        selected = probe_from_rule(matrix_rules[0])
                        for field in ('operation','profiles','path_values','expected_owner','expected_other'):
                            setattr(payload, field, selected[field])
                    if action == 'workflow-graph' and graph_config_id:
                        payload.config_id = graph_config_id
                    if action == 'injection-assess':
                        # A campaign may compare owner/other for access-probe,
                        # but injection-assess deliberately accepts ONE identity.
                        # Passing both previously caused the entire injection
                        # step to fail before sending a single HTTP request.
                        # Use the first explicitly selected identity; if none
                        # was selected, use the first authorized auth.yaml
                        # profile and record the choice for the operator.
                        if payload.profiles:
                            payload.profiles = payload.profiles[:1]
                        elif cfg.auth_config_id:
                            from achillesapi.core.auth import load_authentication_manager
                            configured = load_authentication_manager(file_id(cfg.auth_config_id,'.auth.yaml')).names
                            payload.profiles = list(configured[:1])
                    payload.assessment_id = (suite_id if action in {'campaign-quality', 'campaign-diagnostics', 'release-readiness', 'campaign-audit'} else
                        matrix_evidence_id if action == 'verify-access-policy' else evidence_id
                        if tool['requirements'] in {'both','report','report-config','config-report'} else None)
                    if action == 'verify-access-policy':
                        payload.assessment_id = matrix_evidence_id
                    payload.execute = bool(request.include_active and tool.get('active'))
                    if planned_active and action not in {'autonomous-agent', 'agent-loop-v2'}:
                        payload.max_requests = cli_request_budget(action, min(cfg.max_requests, remaining))
                    payload.ai = bool(request.include_ai and (ai_readiness['status'] == 'ready'
                                or action not in OLLAMA_OPTIONAL))
                    payload.approve_writes = bool(request.include_writes and tool.get('writes') and payload.execute)
                    # In a complete suite, auto-assess is the shared read-only
                    # evidence baseline. The dedicated workflow-assess or
                    # multi-resource-assess step performs an approved fixture
                    # lifecycle once, rather than silently repeating writes.
                    if action == 'auto-assess':
                        payload.approve_writes = False
                    step_started = time.monotonic()
                    # Evitiamo che un singolo comando offline/GET superi da solo
                    # l'intero tempo residuo della suite. Il runtime non è un
                    # rollback: le scritture restano sotto controllo manuale.
                    time_left = max(1, int(request.max_runtime_seconds - (step_started - started_at)))
                    suite_worker.child_timeout = min(480, time_left) if not tool.get('writes') else 480
                    try:
                        child = run_tool(payload, csrf)
                        if planned_active:
                            reserved += per_step_cap
                            report['reserved_request_budget'] = reserved
                        child_id = child['id']
                        with lock:jobs[child_id]['suite_id']=suite_id
                        # Long-running jobs are asynchronous; wait without holding the job lock.
                        deadline = time.monotonic() + 495
                        while True:
                            with lock:child_state = dict(jobs[child_id])
                            if child_state.get('status') != 'running':break
                            if time.monotonic() >= deadline:
                                child_state = {'status':'failed','error':'Timeout di coordinamento della suite.'}
                                break
                            time.sleep(.15)
                        step = {'action':action, 'status':child_state['status'], 'job_id':child_id,
                                **({'workflow_config_id':workflow_id, 'workflow_label':workflow_labels[workflow_id]} if workflow_id else {}),
                                'duration_ms': round((time.monotonic()-step_started)*1000),
                                'http_observations':child_state.get('http_observations',0)}
                        if action in OLLAMA_REQUIRED | OLLAMA_OPTIONAL:
                            step['ai_status'] = child_state.get('ai_status','not_invoked')
                            if request.include_ai and ai_readiness['status'] != 'ready' and action in OLLAMA_OPTIONAL:
                                step['ai_status'] = 'not_invoked'
                                step['ai_note'] = 'Analisi deterministica eseguita senza Ollama: ' + ai_readiness['message']
                            elif step['ai_status'] == 'completed_local':
                                step['ai_note'] = 'Ollama interrogato localmente con il modello ' + cfg.model + '. Output AI presente.'
                        elif TOOLS[action].get('category') == 'AI locale':
                            step['ai_status'] = 'not_invoked'
                            step['ai_note'] = 'Task deterministico: il nome o la categoria AI non implicano una chiamata a Ollama.'

                        if action == 'injection-assess' and payload.profiles:
                            step['tested_identity'] = payload.profiles[0]
                        if action == 'access-probe' and matrix_rules:
                            step['matrix_rule_id'] = matrix_rules[0]['id']
                            step['note'] = 'Access-probe confronta una regola; access-matrix verifica tutte le regole salvate.'
                        if action in {'access-matrix','verify-access-policy'} and matrix_rules:
                            step['matrix_rule_count'] = len(matrix_rules)
                        if child_state['status'] == 'complete':
                            try:
                                result_data = json.loads((reports / (child_id + '.json')).read_text(encoding='utf-8'))
                                from achillesapi.reporting.professional import summarize_assessment
                                step['candidate_indicators'] = len(summarize_assessment(result_data).get('findings', []))
                                step['http_requests_sent'] = int(result_data.get('requests_sent',
                                    (result_data.get('execution_report') or {}).get('requests_sent', 0)) or 0)
                            except (OSError, ValueError, TypeError):
                                pass
                            report['summary']['completed'] += 1
                            if action == 'access-matrix':
                                # Only an ACTIVE matrix result containing real HTTP
                                # observations is suitable for strict policy review.
                                if payload.execute:
                                    matrix_evidence_id = child_id
                            if action == 'auto-assess':
                                evidence_id = child_id
                            elif not evidence_id and action == 'assess':
                                evidence_id = child_id
                        else:
                            report['summary']['failed'] += 1
                            step['reason'] = child_state.get('error') or 'Il comando ha terminato con errore.'
                        report['steps'].append(step)
                    except HTTPException as exc:
                        report['summary']['failed'] += 1
                        report['steps'].append({'action':action,'status':'failed',
                            'duration_ms': round((time.monotonic()-step_started)*1000),
                            'reason':str(exc.detail)[:350]})
                    snapshot()
                # The parent suite report must retain sanitized observations
                # from completed child scanners. Older releases kept them only
                # in child JSON files, so exports and the parent summary showed
                # zero even when the injection engine detected real indicators.
                from achillesapi.reporting.professional import summarize_assessment
                suite_observations = []
                for completed in report['steps']:
                    if completed.get('status') != 'complete' or not completed.get('job_id'):
                        continue
                    try:
                        child_path = reports / (completed['job_id'] + '.json')
                        child_raw = json.loads(child_path.read_text(encoding='utf-8'))
                        normalized = summarize_assessment(child_raw)
                        for observation in normalized.get('findings', []):
                            if len(suite_observations) >= 300:
                                break
                            suite_observations.append({
                                'id': observation.get('id'),
                                'category': observation.get('category'),
                                'operation': observation.get('operation'),
                                'severity': observation.get('severity', 'informational'),
                                'reason': observation.get('reason', 'Requires manual review'),
                                'what_found': observation.get('what_found', ''),
                                'verification_guidance': observation.get('verification_guidance', ''),
                                'test_payloads': observation.get('test_payloads', []),
                                'test_input': observation.get('test_input', {}),
                                'test_request': observation.get('test_request'),
                                'title': observation.get('title', ''),
                                'confidence': observation.get('confidence', 'indicator'),
                                'status': observation.get('status', 'requires_review'),
                                'source_type': observation.get('source_type', 'active_or_analysis'),
                                'ai_label': observation.get('ai_label'),
                                'discovery_method': observation.get('discovery_method', ''),
                                'evidence': observation.get('evidence', {}),
                                'source_action': completed['action'],
                                'source_job_id': completed['job_id'],
                            })
                    except (OSError, ValueError, TypeError, KeyError):
                        continue
                report['findings'] = suite_observations
                from achillesapi.core.coverage_explainer_rc9 import explain_suite_gaps
                report['coverage_gaps'] = explain_suite_gaps(report['steps'])
                report['duration_seconds'] = round(time.monotonic() - started_at, 2)
                report['source_assessment_id'] = evidence_id
                if evidence_id:
                    try:
                        evidence_report=json.loads((reports/(evidence_id+'.json')).read_text(encoding='utf-8'))
                        report['preflight']=from_file(str(file_id(cfg.specification_id,'.yaml')),
                            has_auth=bool(cfg.auth_config_id), active_allowed=request.include_active,
                            writes_approved=request.include_writes, ai_enabled=request.include_ai,
                            assessment=evidence_report)
                        report['verification']=classify_findings(evidence_report)
                        report['adaptive_plan']=deterministic_next_steps(report['preflight'],
                            has_http_evidence=bool(jobs.get(evidence_id, {}).get('http_observations',0)),
                            ai_available=request.include_ai)
                    except (OSError,ValueError,TypeError):
                        report['limitations'].append('Preflight aggiuntivo non disponibile; nessun finding confermato.')
                from achillesapi.core.quality_v090 import assess_campaign_quality
                report['quality_gate'] = assess_campaign_quality(report)
                # Una campagna completa deve mostrare anche i task non eseguiti.
                from achillesapi.core.release_quality_v099 import assess_release_readiness
                report['reported_http_observations'] = report['quality_gate']['metrics']['reported_http_observations']
                report['http_accounting_note'] = 'http_telemetry conta i tentativi HTTP condivisi fra i processi; reported_http_observations è il numero di osservazioni salvate dai tool. Il budget riservato è una stima.'
                report['status'] = ('stopped_by_operator' if stopped else
                    'complete_with_errors' if report['summary']['failed'] else 'complete')
                report['release_readiness'] = assess_release_readiness(report)
                from achillesapi.core.release_validation_rc23 import audit_campaign
                report['quality_rc23'] = audit_campaign(report)
                snapshot()
                with lock:
                    jobs[suite_id]['status'] = 'complete'
                    jobs[suite_id]['exit_code'] = 2 if stopped else (0 if not report['summary']['failed'] else 1)
                    jobs[suite_id]['stopped_by_operator'] = stopped
                    jobs[suite_id]['current_step'] = None
                    store.save_job(dict(jobs[suite_id]))
            except Exception:
                report['status'] = 'interrupted'
                report['limitations'].append('La suite è stata interrotta per un errore interno. I job figli già completati restano consultabili.')
                snapshot()
                with lock:
                    jobs[suite_id]['status'] = 'failed'
                    jobs[suite_id]['error'] = 'Errore interno di orchestrazione; controlla i job figli.'
                    jobs[suite_id]['current_step'] = None
                    store.save_job(dict(jobs[suite_id]))
        threading.Thread(target=runner, daemon=True).start()
        return {'id':suite_id,'status':'orchestrating','action':'full-suite','total':len(scheduled) + (len(request.rc13_body_fields_by_workflow) if request.include_rc13 and request.rc13_body_fields_by_workflow else int(request.include_rc13)),**identity}

    def prerequisite_step(suite_id: str, step_index: int):
        if not ID.fullmatch(suite_id):
            raise HTTPException(404, 'Suite non trovata')
        context = suite_contexts.get(suite_id)
        if context is None:
            raise HTTPException(404, 'Suite non disponibile')
        report_path = reports / (suite_id + '.json')
        try:
            report = json.loads(report_path.read_text(encoding='utf-8'))
            step = report['steps'][step_index]
            if not isinstance(step, dict) or step.get('action') not in TOOLS:
                raise ValueError('Task non valido')
        except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:
            raise HTTPException(404, 'Task della suite non trovato') from exc
        return context, report, step

    def _retry_contract(action: str, context: SuiteRequest,
                        report: dict[str, Any], suite_id: str | None = None) -> dict[str, Any]:
        """UI disclosure contract: only show missing inputs for the selected task."""
        from achillesapi.core.campaign_ledger import CampaignLedger
        cfg=context.config
        tool=TOOLS[action]
        req=tool['requirements']
        usages={
            'journey-assess': ('journey',),
            'workflow-assess': ('workflow',),
            'multi-resource-assess': ('multi-resource',),
            'workflow-graph': ('workflow','multi-resource'),
            'analyze-evidence': ('evidence',),
            'access-matrix': ('context',),
            'rc16-assess': ('multi-resource',),
            'verify-access-policy': ('context',),
            'ai-plan-guard': ('proposals',),
            'benchmark-evaluate': ('benchmark',),
            'benchmark-review': ('benchmark',),
        }
        needs_config=(req in {'spec-config','report-config','config:json','config-report'}
                      or action in usages)
        accepted=usages.get(action)
        saved_matrix_id = cfg.access_rules_id or (cfg.config_id if cfg.config_usage == 'context' else None)
        has_config=bool((saved_matrix_id if action in {'access-matrix','verify-access-policy'}
                          else cfg.config_id) and (action in {'access-matrix','verify-access-policy'}
                          or not accepted or cfg.config_usage in accepted))
        needs_auth=bool(req=='auth-only' or action in {
            'workflow-assess','multi-resource-assess','workflow-graph',
            'access-matrix','access-probe','auth-readiness','auth-audit',
            'rc16-access-auto','rc16-assess'
        })
        active_capable=bool(tool.get('active'))
        active_selected=bool(context.include_active and active_capable)
        needs_source=req in {'report','both','report-config','config-report'} and action not in {
            'campaign-quality','campaign-diagnostics','release-readiness','campaign-audit'
        }
        assessment=(next((step.get('job_id') for step in reversed(report.get('steps', []))
                           if step.get('action')=='access-matrix' and step.get('status')=='complete'
                           and step.get('job_id')), None)
                    if action == 'verify-access-policy' else report.get('source_assessment_id'))
        env_names=[]
        if needs_auth and cfg.auth_config_id:
            try:
                from achillesapi.core.auth import load_authentication_manager
                manager=load_authentication_manager(file_id(cfg.auth_config_id,'.auth.yaml'))
                env_names=sorted({name for item in manager.describe()
                                  for name in item.get('environment_variables',[])
                                  if name not in os.environ})[:20]
            except (ValueError,OSError,HTTPException):
                pass
        return {
            'needs_config':needs_config,'has_config':has_config,
            'config_usages':list(accepted or ('multi-resource','workflow','journey','context','evidence','benchmark','proposals')),
            'current_usage':'context' if action in {'access-matrix','verify-access-policy'} and saved_matrix_id else cfg.config_usage,
            'needs_auth':needs_auth,'has_auth':bool(cfg.auth_config_id),
            'required_secret_variables':env_names,
            'active_capable':active_capable,'active_selected':active_selected,
            'requires_writes':bool(tool.get('writes')),
            'ai_capable':bool(tool.get('ai')),'ai_selected':bool(context.include_ai and tool.get('ai')),
            'needs_source_assessment':needs_source,'has_source_assessment':bool(assessment),
            'has_scope':bool(cfg.base_url and cfg.allow_host and
                             scope_audit(cfg.base_url,[cfg.allow_host]).get('approved')),
            'base_url':cfg.base_url,'allow_host':cfg.allow_host,
            'max_total_requests':context.max_total_requests,
            'reserved_requests':int(report.get('reserved_request_budget',0)),
            'actual_remaining_requests':(CampaignLedger(reports/(suite_id+'.http-ledger.sqlite3')).snapshot()['remaining'] if suite_id and (reports/(suite_id+'.http-ledger.sqlite3')).is_file() else context.max_total_requests),
            'per_task_requests':cfg.max_requests,
        }

    @app.get('/api/control/suite/{suite_id}/prerequisites/{step_index}')
    def prerequisite_options(suite_id: str, step_index: int, auth_config_id: str = ''):
        """Provide only bounded OpenAPI choices; never tokens or raw response bodies."""
        context, report, step = prerequisite_step(suite_id, step_index)
        action = step['action']
        contract=_retry_contract(action,context,report,suite_id)
        if action not in {'access-probe','ai-plan-guard','journey-assess', 'workflow-assess', 'multi-resource-assess', 'rc16-access-auto', 'rc16-assess',
                          'analyze-evidence', 'verify-access-policy', 'benchmark-evaluate', 'workflow-graph', 'auth-profiles', 'access-matrix'}:
            return {'action': action, 'builder': None, 'retry_requirements':contract}
        from achillesapi.core.openapi import load_openapi, parse_openapi
        spec_path = file_id(context.config.specification_id, '.yaml')
        parsed = parse_openapi(load_openapi(spec_path))
        operations = []
        for endpoint in parsed.endpoints:
            operations.append({'operation': endpoint.method + ' ' + endpoint.path,
                               'method': endpoint.method,
                               'parameters': [{'name': p.name, 'required': p.required, 'location': p.location}
                                              for p in endpoint.parameters if p.location in ('path','query')]})
        result = {'action': action, 'builder': action, 'retry_requirements':contract, 'operations': operations[:250],
                  'assessment_available': False, 'assessment_id': report.get('source_assessment_id')}
        if action in {'access-matrix','access-probe','rc16-access-auto','rc16-assess'} and (auth_config_id or context.config.auth_config_id):
            # Solo i nomi dei profili: mai token o password nel browser.
            from achillesapi.core.auth import load_authentication_manager
            auth_path=file_id(auth_config_id or context.config.auth_config_id,'.auth.yaml')
            result['auth_profiles']=load_authentication_manager(auth_path).names
        if action == 'ai-plan-guard':
            from achillesapi.core.ai_planner_v080 import ALLOWED
            result['allowed_actions']=sorted(ALLOWED)
        if action in {'workflow-assess', 'multi-resource-assess','rc16-assess','workflow-graph'}:
            from achillesapi.dashboard.manifest_builder import discover_manifest_candidates
            result['candidates'] = discover_manifest_candidates(str(spec_path))[:80]
        if action in {'analyze-evidence', 'verify-access-policy', 'benchmark-evaluate'}:
            previous = report.get('source_assessment_id')
            if previous and ID.fullmatch(previous) and (reports / (previous + '.json')).is_file():
                result['assessment_available'] = True
                result['assessment_id'] = previous
                try:
                    assessment = json.loads((reports / (previous + '.json')).read_text(encoding='utf-8'))
                    result['observation_pairs'] = sorted({
                        (str(o.get('operation')),str(o.get('identity')))
                        for o in assessment.get('execution_report',{}).get('observations',[])
                        if isinstance(o,dict) and o.get('operation') and o.get('identity')
                    })[:100]
                except (ValueError, OSError, TypeError, AttributeError):
                    result['observation_pairs'] = []
        return result

    @app.post('/api/control/suite/{suite_id}/prerequisites/{step_index}/generate')
    def generate_prerequisite(suite_id: str, step_index: int, payload: dict,
                              x_achilles_token: str | None = Header(None)):
        """Generate typed, validated configuration from explicit form choices, offline."""
        guard(x_achilles_token)
        context, report, step = prerequisite_step(suite_id, step_index)
        action = step['action']
        from achillesapi.core.openapi import load_openapi, parse_openapi
        import yaml
        spec_path = file_id(context.config.specification_id, '.yaml')
        spec = load_openapi(spec_path)
        parsed = parse_openapi(spec)
        lookup = {e.method+' '+e.path: e for e in parsed.endpoints}
        def str_field(key, limit=150):
            value = payload.get(key)
            if not isinstance(value,str) or not value.strip() or len(value)>limit:
                raise ValueError('Compila il campo '+key+' con un valore valido')
            return value.strip()
        try:
            if action == 'auth-profiles':
                from achillesapi.core.auth import AuthenticationFile
                from pydantic import ValidationError
                profs=payload.get('profiles')
                if not isinstance(profs,list) or not 1<=len(profs)<=12:
                    raise ValueError('Definisci da 1 a 12 profili di autenticazione')
                AuthenticationFile.model_validate({'profiles':profs})
                output={'profiles':profs}
                content=yaml.safe_dump(output,sort_keys=False)
                identifier=uuid.uuid4().hex
                dest=uploads/(identifier+'.auth.yaml')
                dest.write_text(content,encoding='utf-8')
                os.chmod(dest,0o600)
                return {'auth_config_id':identifier, 'valid':True,'message':'auth.yaml validato. I token inline saranno letti dal file locale; non vengono inclusi nei report.'}
            elif action == 'journey-assess':
                from achillesapi.core.journeys import read_journey, _select_operations
                entries = payload.get('steps')
                if not isinstance(entries,list) or not 1 <= len(entries) <= 12:
                    raise ValueError('Seleziona da 1 a 12 operazioni GET')
                steps = []
                for entry in entries:
                    if not isinstance(entry,dict): raise ValueError('Passaggio journey non valido')
                    op = entry.get('operation')
                    if op not in lookup or not op.startswith('GET '):
                        raise ValueError('Scegli una GET presente nello Swagger')
                    values = entry.get('values',{})
                    if not isinstance(values,dict) or len(values)>20:
                        raise ValueError('Valori dei parametri non validi')
                    required = {p.name for p in lookup[op].parameters if p.required and p.location in ('path','query')}
                    if required-set(values):
                        raise ValueError('Completa i parametri di '+op+': '+', '.join(sorted(required-set(values))))
                    if any(not isinstance(k,str) or not isinstance(v,(str,int,float)) or not str(v).strip() or len(str(v))>256 for k,v in values.items()):
                        raise ValueError('Valore di parametro non valido')
                    item={'operation':op, 'values':values}
                    if entry.get('identity'):
                        name=entry['identity']
                        if not isinstance(name,str) or not PROFILE.fullmatch(name): raise ValueError('Profilo non valido')
                        item['identity']=name
                    steps.append(item)
                output={'steps':steps}
                _select_operations(parsed,steps)
                usage='journey'
            elif action in {'workflow-assess','workflow-graph'}:
                from achillesapi.core.workflows import read_workflows, _validate_workflows
                from achillesapi.dashboard.manifest_builder import discover_manifest_candidates
                candidates=discover_manifest_candidates(str(spec_path))
                idx=payload.get('candidate_index')
                if type(idx) is not int or not 0<=idx<len(candidates): raise ValueError('Seleziona un workflow CRUD disponibile')
                c=candidates[idx]
                owner=str_field('owner',64)
                other=payload.get('other')
                if not PROFILE.fullmatch(owner) or (other and (not isinstance(other,str) or not PROFILE.fullmatch(other))):
                    raise ValueError('Profili di autenticazione non validi')
                marker=str_field('marker_field',80)
                value=str_field('marker_value',120)
                pointer=str_field('id_pointer',90)
                # The browser asks for an ID *field name* (e.g. 'id'), while
                # the workflow engine needs a JSON Pointer (e.g. '/id').
                # Accept either spelling, including nested pointers.
                if not pointer.startswith('/'):
                    pointer='/' + pointer
                if pointer == '/' or any(not part or part in {'.', '..'} for part in pointer[1:].split('/')):
                    raise ValueError('Campo ID non valido: usa id oppure /id (o /data/id per oggetti annidati)')
                body=payload.get('body')
                if not isinstance(body,dict) or len(body)>35:raise ValueError('Indica i campi JSON della risorsa temporanea')
                body[marker]=value
                wf={'name':'guided_lifecycle',
                    'create':{'operation':c['create'],'identity':owner,'body':body,'marker_field':marker,'id_pointer':pointer},
                    'read':{'operation':c['read'],'identity':owner,'id_parameter':c['path_parameter'],
                            'id_pointer':(c.get('read_id_candidates') or [pointer])[0],
                            'marker_pointer':(c.get('read_marker_pointers',{}).get(marker) or ['/'+marker])[0]},
                    'cleanup':{'operation':c['delete'],'identity':owner}}
                if payload.get('acknowledge_get_side_effect_risk') is True:
                    wf['acknowledge_get_side_effect_risk']=True
                wf['path_values']=payload.get('path_values') or {}
                if other: wf['access']=[{'identity':other,'expected':'deny','category':'BOLA'}]
                output={'workflows':[wf]}
                available=None
                auth_reference=payload.get('auth_config_id') or context.config.auth_config_id
                if auth_reference:
                    from achillesapi.core.auth import load_authentication_manager
                    auth_profile_path=file_id(auth_reference,'.auth.yaml')
                    available=set(load_authentication_manager(auth_profile_path).names)
                temp=uploads/(uuid.uuid4().hex+'.config.yaml')
                try:
                    temp.write_text(yaml.safe_dump(output,sort_keys=False),encoding='utf-8')
                    read_workflows(temp)
                    _validate_workflows(parsed,spec,output['workflows'],available)
                finally: temp.unlink(missing_ok=True)
                usage='workflow'
            elif action in {'multi-resource-assess','rc16-assess'}:
                from achillesapi.core.multi_resource import plan_multi_resource
                from achillesapi.dashboard.manifest_builder import discover_manifest_candidates, build_guided_manifest
                from achillesapi.core.auth import load_authentication_manager
                choices=discover_manifest_candidates(str(spec_path))
                idx=payload.get('candidate_index')
                if type(idx) is not int or not 0<=idx<len(choices):raise ValueError('Seleziona un ciclo CRUD')
                auth_path=file_id(payload.get('auth_config_id') or context.config.auth_config_id,'.auth.yaml')
                names=set(load_authentication_manager(auth_path).names)
                body=payload.get('body')
                if not isinstance(body,dict) or len(body)>35:raise ValueError('Inserisci i campi della risorsa temporanea')
                raw=build_guided_manifest(choices[idx],owner=str_field('owner',64),other=payload.get('other') or None,
                    marker=str_field('marker_field',80),identifier=str_field('id_pointer',90).lstrip('/'),
                    body=body,deny_other=bool(payload.get('other')),
                    path_values=payload.get('path_values') or {},
                    acknowledge_get_side_effect_risk=payload.get('acknowledge_get_side_effect_risk') is True)
                output=yaml.safe_load(raw)
                plan_multi_resource(parsed,spec,output,names)
                usage='multi-resource'
            elif action == 'access-matrix':
                # Le regole sono compilate dal browser, non da un prompt AI.
                from achillesapi.core.access_matrix_rc4 import preflight_rules
                from achillesapi.core.auth import load_authentication_manager
                auth_path=file_id(context.config.auth_config_id,'.auth.yaml')
                names=set(load_authentication_manager(auth_path).names)
                output={'rules':preflight_rules(spec_path, {'rules':payload.get('rules')},
                                               profile_names=names)}
                usage='context'
            elif action == 'verify-access-policy':
                from achillesapi.core.verification_v037 import verify_access_policies
                rules=payload.get('rules')
                if not isinstance(rules,list) or not 1<=len(rules)<=100: raise ValueError('Definisci almeno una regola di accesso')
                for rule in rules:
                    if not isinstance(rule,dict) or rule.get('operation') not in lookup or not rule['operation'].startswith('GET '):
                        raise ValueError('Scegli una GET documentata per ogni regola')
                    if not PROFILE.fullmatch(str(rule.get('identity',''))) or rule.get('expected') not in ('allow','deny'):
                        raise ValueError('Specifica identità e autorizzazione attesa')
                output={'rules':rules}
                verify_access_policies({},rules)
                usage='context'
            elif action == 'analyze-evidence':
                from achillesapi.core.evidence_bridge import evidence_from_assessment
                from achillesapi.core.detection import analyze_response_evidence
                previous=report.get('source_assessment_id')
                if not previous: raise ValueError('Esegui prima auto-assess attivo: non ci sono osservazioni HTTP')
                assessment=json.loads(file_id(previous,'.json',reports).read_text(encoding='utf-8'))
                output=evidence_from_assessment(assessment)
                analyze_response_evidence(output)
                usage='evidence'
            elif action == 'ai-plan-guard':
                from achillesapi.core.ai_guard_v099 import validate_advisory_plan
                from achillesapi.core.ai_planner_v080 import ALLOWED
                actions=payload.get('actions')
                if not isinstance(actions,list) or not 1<=len(actions)<=20:
                    raise ValueError('Seleziona da 1 a 20 proposte dal modulo guidato.')
                clean=[]
                for entry in actions:
                    if not isinstance(entry,dict) or entry.get('action') not in ALLOWED:
                        raise ValueError('Azione non presente nella allowlist AI.')
                    if entry.get('operation') and entry['operation'] not in lookup:
                        raise ValueError('Scegli una operazione prevista dallo Swagger.')
                    clean.append({k:v for k,v in entry.items() if k in ('action','operation') and v})
                output={'actions':clean}
                accepted=validate_advisory_plan(spec,output)
                if accepted['summary']['rejected']:
                    raise ValueError('Una proposta non ha superato la validazione.')
                usage='proposals'
            elif action == 'benchmark-evaluate':
                from achillesapi.core.production_v031 import benchmark_evaluate
                if payload.get('human_verified') is not True:
                    raise ValueError('Conferma che le etichette sono state verificate da una persona e non ricavate automaticamente dallo scanner')
                expected=payload.get('positive_ids')
                verified=payload.get('verified_positive_ids')
                output={'positive_ids':expected,'verified_positive_ids':verified}
                benchmark_evaluate({'positive_ids':expected},{'verified_positive_ids':verified})
                usage='benchmark'
            else:
                raise ValueError('Per questa funzione usa il caricamento del file richiesto o il builder dedicato')
            content=json.dumps(output,ensure_ascii=False,indent=2) if usage in {'evidence','benchmark','proposals'} else yaml.safe_dump(output,sort_keys=False,allow_unicode=True)
            if len(content.encode('utf-8'))>MAX_CONFIG:raise ValueError('Configurazione troppo grande')
            identifier=uuid.uuid4().hex
            dest=uploads/(identifier+'.config.yaml')
            dest.write_text(content,encoding='utf-8')
            os.chmod(dest,0o600)
            return {'id':identifier,'config_usage':usage,'valid':True,
                    'message':'File generato e validato senza contattare il target. Rivedi le autorizzazioni prima del retry.'}
        except (ValueError,TypeError,KeyError,OSError) as exc:
            raise HTTPException(422,'Impossibile generare il file: '+str(exc)[:320]) from exc

    @app.post('/api/control/suite/{suite_id}/retry')
    def retry_suite_step(suite_id: str, retry: RetryStepRequest,
                         x_achilles_token: str | None = Header(None)):
        """Re-run ONE skipped/failed step, never the whole suite. No arbitrary CLI arguments.

        Uploaded document IDs are validated before launching. The new result is linked
        back to its original suite and is visible in the independent job viewer.
        """
        guard(x_achilles_token)
        if not ID.fullmatch(suite_id):
            raise HTTPException(404, 'Suite non trovata')
        with lock:
            parent=jobs.get(suite_id)
            original=suite_contexts.get(suite_id)
            if not parent or parent.get('action') != 'full-suite' or not original:
                raise HTTPException(404, 'Suite non disponibile in questa sessione')
            if parent['status'] != 'complete':
                raise HTTPException(409, 'Attendi la fine della suite o di un altro retry')
            if any(j.get('status') == 'running' for j in jobs.values()):
                raise HTTPException(409, 'Un altro job è in esecuzione')
        file=reports/(suite_id+'.json')
        try:report=json.loads(file.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise HTTPException(404,'Report suite non disponibile') from exc
        steps=report.get('steps',[])
        if retry.step_index>=len(steps):
            raise HTTPException(422, 'Passaggio inesistente')
        entry=steps[retry.step_index]
        action=entry.get('action')
        if action not in SUITE_ORDER or entry.get('status') not in {'skipped','failed'}:
            raise HTTPException(422, 'Puoi rilanciare soltanto un task saltato o fallito')
        ctx=original.model_copy(deep=True)
        cfg=ctx.config
        if entry.get('workflow_config_id') and retry.config_id is None:
            # Re-execute the same approved fixture, not the first workflow of
            # the parent campaign. A replacement requires explicit upload.
            cfg.config_id = entry['workflow_config_id']
            cfg.config_usage = 'multi-resource'
        if retry.config_id is not None:
            uploaded_config(retry.config_id)
            if action in {'access-matrix','verify-access-policy','access-probe'}:
                cfg.access_rules_id=retry.config_id
            else:
                cfg.config_id=retry.config_id
        if retry.auth_config_id is not None:
            file_id(retry.auth_config_id,'.auth.yaml')
            cfg.auth_config_id=retry.auth_config_id
        if retry.config_usage is not None:
            if retry.config_usage not in {'workflow','multi-resource','journey','context','evidence','benchmark','proposals'}:
                raise HTTPException(422,'Tipo manifest non supportato')
            cfg.config_usage=retry.config_usage
        if retry.base_url is not None:cfg.base_url=retry.base_url
        if retry.allow_host is not None:cfg.allow_host=retry.allow_host
        if retry.model is not None:cfg.model=retry.model
        if retry.profiles is not None: cfg.profiles=retry.profiles
        if retry.path_values is not None: cfg.path_values=retry.path_values
        if retry.operation is not None: cfg.operation=retry.operation
        if retry.injection_families is not None: cfg.injection_families=retry.injection_families
        if retry.expected_other is not None:
            if retry.expected_other not in {'unknown','deny','allow'}:
                raise HTTPException(422,'Policy attesa non valida')
            cfg.expected_other=retry.expected_other
        cfg.secrets=retry.secrets  # transient; never in JSON or suite_contexts
        cfg.acknowledgment=retry.acknowledgment
        cfg.allow_insecure_http=retry.allow_insecure_http
        ctx.include_ai=bool(ctx.include_ai or retry.enable_ai)
        ctx.include_active=bool(ctx.include_active or retry.enable_active)
        ctx.include_writes=bool(ctx.include_writes or retry.approve_writes)
        cfg.approve_writes=retry.approve_writes
        if retry.max_total_requests is not None:
            ctx.max_total_requests=retry.max_total_requests
        # A new active run requires the same scope proof as the original suite.
        if ctx.include_active and TOOLS[action].get('active'):
            if not (cfg.acknowledgment and cfg.base_url and cfg.allow_host and
                    scope_audit(cfg.base_url,[cfg.allow_host])['approved']):
                raise HTTPException(422, 'Per il retry HTTP servono Base URL, host autorizzato e conferma.')
            if cfg.base_url.startswith('http://') and cfg.allow_host not in {'localhost','127.0.0.1'}:
                raise HTTPException(422, 'HTTP in chiaro consentito solo su localhost')
        if TOOLS[action].get('writes') and ctx.include_active and not retry.approve_writes:
            raise HTTPException(422, 'Scritture non approvate esplicitamente')
        selected_rules = cfg.access_rules_id or (cfg.config_id if cfg.config_usage == 'context' else None)
        if action in {'access-probe','access-matrix','verify-access-policy'} and selected_rules:
            from achillesapi.core.authorization_suite_bridge_rc9 import validated_suite_rules, probe_from_rule
            try:
                matrix_rules = validated_suite_rules(file_id(cfg.specification_id,'.yaml'),
                    file_id(cfg.auth_config_id,'.auth.yaml'), uploaded_config(selected_rules))
            except (ValueError,OSError) as exc:
                raise HTTPException(422, 'Matrice non valida: '+str(exc)[:220]) from exc
            if action == 'access-probe' and retry.operation is None:
                # Use the operator-approved saved rule when retry has no
                # explicit replacement. Explicit retry form inputs win.
                derived=probe_from_rule(matrix_rules[0])
                cfg.operation=derived['operation']
                cfg.profiles=derived['profiles']
                cfg.expected_owner=derived['expected_owner']
                cfg.expected_other=derived['expected_other']
                cfg.path_values=derived['path_values']
            if action in {'access-matrix','verify-access-policy'}:
                cfg.config_id=selected_rules
                cfg.config_usage='context'
        if action == 'rc16-access-auto':
            if not cfg.auth_config_id or len(cfg.profiles) < 2 or not cfg.path_values or cfg.expected_other not in {'deny','allow'}:
                raise HTTPException(422, 'RC16 GET: importa auth.yaml, scegli proprietario e almeno un altro profilo, completa gli ID NAME=VALUE e indica allow/deny.')
            from achillesapi.core.auth import load_authentication_manager
            names=set(load_authentication_manager(file_id(cfg.auth_config_id,'.auth.yaml')).names)
            if any(name not in names for name in cfg.profiles) or len(set(cfg.profiles)) != len(cfg.profiles):
                raise HTTPException(422, 'RC16 GET: seleziona profili differenti presenti in auth.yaml.')
        if action == 'access-probe':
            # Il retry non parte finché utenti, GET e ID non sono validi.
            if len(cfg.profiles) != 2 or cfg.profiles[0] == cfg.profiles[1] or not cfg.auth_config_id:
                raise HTTPException(422,'Seleziona due profili differenti presenti in auth.yaml.')
            from achillesapi.core.auth import load_authentication_manager
            from achillesapi.core.access_probe_rc import _choose_get
            from achillesapi.core.openapi import load_openapi
            names=set(load_authentication_manager(file_id(cfg.auth_config_id,'.auth.yaml')).names)
            if any(name not in names for name in cfg.profiles):
                raise HTTPException(422,'Un profilo selezionato non esiste in auth.yaml.')
            if not cfg.operation:
                raise HTTPException(422,'Scegli una operazione GET dello Swagger.')
            try:
                values=dict(v.split('=',1) for v in cfg.path_values)
                _choose_get(load_openapi(file_id(cfg.specification_id,'.yaml')),cfg.operation,values)
            except (ValueError,TypeError) as exc:
                raise HTTPException(422,'Completa i parametri della GET: '+str(exc)[:180]) from exc
        evidence_id=(next((step.get('job_id') for step in reversed(report.get('steps', []))
                           if step.get('action')=='access-matrix' and step.get('status')=='complete'), None)
                     if action=='verify-access-policy' else report.get('source_assessment_id'))
        reason=suite_skip_reason(action,cfg,ctx,evidence_id)
        if reason:
            raise HTTPException(422, 'Prerequisiti ancora mancanti: '+reason)
        planned_active=bool(ctx.include_active and TOOLS[action].get('active'))
        cap=min(cfg.budget,15) if action in {'autonomous-agent','agent-loop-v2'} else cli_request_budget(action,cfg.max_requests)
        reserved=int(report.get('reserved_request_budget',0))
        retry_ledger_path = reports / (suite_id + '.http-ledger.sqlite3')
        if planned_active:
            from achillesapi.core.campaign_ledger import CampaignLedger
            if not retry_ledger_path.is_file():
                raise HTTPException(422, 'Registro HTTP della suite non disponibile: avvia una nuova campagna.')
            ledger_state = CampaignLedger(retry_ledger_path).snapshot()
            # A budget increase is explicit in the retry form, never implicit.
            if retry.max_total_requests is not None and retry.max_total_requests > ledger_state['limit']:
                CampaignLedger(retry_ledger_path).extend_limit(retry.max_total_requests, maximum=600)
                ledger_state = CampaignLedger(retry_ledger_path).snapshot()
            remaining_http=int(ledger_state['remaining'])
            minimum_http=CLI_REQUEST_LIMITS.get(action,(1,150))[0]
            if remaining_http < minimum_http or (TOOLS[action].get('writes') and remaining_http < cap):
                raise HTTPException(422, f'Budget HTTP della campagna insufficiente: {remaining_http} richieste rimaste; '+
                    f'per questo task ne servono almeno {cap if TOOLS[action].get("writes") else minimum_http}. '+
                    'Nel retry aumenta esplicitamente il budget (massimo 600) oppure avvia una nuova suite. '+
                    'I tentativi già inviati non vengono azzerati.')
        with lock:
            if parent['status']!='complete' or any(j.get('status')=='running' for j in jobs.values()):
                raise HTTPException(409,'Esecuzione concorrente non consentita')
            parent['status']='orchestrating'
            parent['current_step']='Retry: '+action
        def retry_worker():
            suite_worker.active=True
            # Ogni retry della STESSA campagna riusa il medesimo limite HTTP:
            # l'utente non può ottenere nuove richieste aggirando il budget.
            ledger = reports / (suite_id + '.http-ledger.sqlite3')
            suite_worker.ledger_path = str(ledger) if ledger.is_file() and planned_active else None
            try:
                payload=cfg.model_copy(deep=True)
                payload.action=action
                payload.assessment_id=(suite_id if action in {'campaign-quality','campaign-diagnostics','release-readiness','campaign-audit'} else evidence_id
                    if TOOLS[action]['requirements'] in {'both','report','report-config','config-report'} else None)
                payload.execute=planned_active
                payload.ai=ctx.include_ai
                payload.approve_writes=bool(planned_active and retry.approve_writes and TOOLS[action].get('writes'))
                if action=='auto-assess':payload.approve_writes=bool(planned_active and retry.approve_writes)
                child=run_tool(payload,csrf)
                child_id=child['id']
                with lock:jobs[child_id]['suite_id']=suite_id
                deadline=time.monotonic()+495
                while True:
                    with lock:state=dict(jobs[child_id])
                    if state['status']!='running':break
                    if time.monotonic()>deadline:
                        state={'status':'failed','error':'Timeout del retry'}
                        break
                    time.sleep(.15)
                attempt={'status':state['status'],'job_id':child_id,
                         'http_observations':state.get('http_observations',0)}
                if state['status']!='complete':attempt['reason']=state.get('error') or 'Esecuzione non riuscita'
                if 'attempts' not in entry:
                    entry['attempts']=[{k:v for k,v in entry.items() if k!='attempts'}]
                entry['attempts'].append(dict(attempt))
                entry.update(attempt)
                if state['status']=='complete':entry.pop('reason',None)
                if planned_active:
                    report['reserved_request_budget']=reserved+cap
                    report['max_total_requests']=ctx.max_total_requests
                if state['status']=='complete' and action=='auto-assess':
                    report['source_assessment_id']=child_id
                # Keep non-secret input pointers for subsequent retries in this session.
                cfg.secrets={}
                with lock:suite_contexts[suite_id]=ctx
                store.save_suite_context(suite_id, ctx)
            except HTTPException as exc:
                entry['status']='failed'
                entry['reason']=str(exc.detail)[:350]
            except Exception:
                entry['status']='failed'
                entry['reason']='Retry non riuscito: verifica prerequisiti ed evidenze.'
            finally:
                states=[step.get('status') for step in steps]
                report['summary']={k:states.count(v) for k,v in
                     [('completed','complete'),('failed','failed'),('skipped','skipped')]}
                report['summary']['total']=len(steps)
                report['status']='complete_with_errors' if report['summary']['failed'] else 'complete'
                if ledger.is_file():
                    from achillesapi.core.campaign_ledger import CampaignLedger
                    report['http_telemetry'] = CampaignLedger(ledger).snapshot()
                from achillesapi.core.quality_v090 import assess_campaign_quality
                from achillesapi.core.release_quality_v099 import assess_release_readiness
                report['quality_gate'] = assess_campaign_quality(report)
                report['release_readiness'] = assess_release_readiness(report)
                try:file.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
                except OSError:pass
                with lock:
                    parent['status']='complete'
                    parent['current_step']=None
                    parent['suite_summary']=dict(report['summary'])
                    parent['exit_code']=0 if not report['summary']['failed'] else 1
                    store.save_job(dict(parent))
                suite_worker.active=False
        threading.Thread(target=retry_worker,daemon=True).start()
        return {'id':suite_id,'action':action,'step_index':retry.step_index,'status':'orchestrating'}
