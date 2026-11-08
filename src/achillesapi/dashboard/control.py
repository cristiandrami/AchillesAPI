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

# 'requirements' determines positional arguments, not executable shell tokens.
# allow_exec indicates bounded HTTP traffic; 'writes' requires an approved manifest.
TOOLS: dict[str, dict[str, Any]] = {
    'analyze-openapi':       dict(category='Discovery',requirements='spec'),
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
    'auto-assess':           dict(category='Assessment',requirements='spec',active=True),
    'advanced-vuln-assess':  dict(category='Assessment',requirements='spec',active=True),
    'journey-assess':        dict(category='Workflow',requirements='spec-config',active=True,config_flag='--journey-config'),
    'workflow-assess':       dict(category='Workflow',requirements='spec-config',active=True,writes=True,config_flag='--workflow-config'),
    'multi-resource-assess': dict(category='Workflow',requirements='spec-config',active=True,writes=True,config_flag='--config'),
    'autonomous-agent':      dict(category='AI locale',requirements='both',active=True,budget=True,ai=True),
    'agent-loop-v2':        dict(category='AI locale',requirements='both',active=True,budget=True,ai=True),
}

class ToolRequest(BaseModel):
    """Typed, bounded UI parameters; no freeform CLI argument input."""
    action: str
    specification_id: str | None = None
    assessment_id: str | None = None
    config_id: str | None = None
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
    path_values: list[str] = Field(default_factory=list,max_length=15)
    ai: bool = False
    model: str = 'achilles-local'
    allow_insecure_http: bool = False
    config_usage: str = 'multi-resource'
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
    max_total_requests: int | None = Field(default=None, ge=1, le=600)


class SuiteRequest(BaseModel):
    """One-click bounded orchestration of the fixed registry (not arbitrary commands)."""
    config: ToolRequest
    include_ai: bool = False
    include_active: bool = False
    include_writes: bool = False
    include_optional: bool = True
    max_total_requests: int = Field(300, ge=1, le=600)

# Dependencies are ordered, not inferred from user-controlled strings. The active
# assessment is the source of evidence for the review and AI tools.
SUITE_ORDER = (
    'analyze-openapi', 'generate-tests', 'map-api', 'assess', 'intelligent-plan',
    'workflow-discover', 'workflow-map', 'journey-discover', 'security-inventory',
    'auth-draft', 'scope-audit', 'auth-profiles', 'workflow-graph',
    'auto-assess', 'advanced-vuln-assess', 'journey-assess',
    'workflow-assess', 'multi-resource-assess',
    'vulnerability-triage', 'differential-review', 'adaptive-review',
    'analyze-evidence', 'coverage-report', 'verify-access-policy',
    'benchmark-evaluate', 'ai-analyze', 'scan', 'ai-correlate',
    'next-actions', 'agent-review', 'ai-prioritize',
    'autonomous-agent', 'agent-loop-v2',
)


def suite_skip_reason(action: str, config: ToolRequest, request: SuiteRequest,
                      evidence_id: str | None) -> str | None:
    """Honest explanation for features which cannot safely run with this input."""
    tool = TOOLS[action]
    kind = tool['requirements']
    if kind in {'spec','both','spec-config'} and not config.specification_id:
        return 'Carica uno Swagger/OpenAPI.'
    if kind in {'scope'} and (not config.base_url or not config.allow_host):
        return 'Indica Base URL e host autorizzato.'
    if kind == 'auth-only' and not config.auth_config_id:
        return 'Carica auth.yaml.'
    if kind in {'spec-config','report-config','config:json','config-report'} and not config.config_id:
        return 'Richiede un manifest o un file di input specifico: non ricavabile automaticamente dallo Swagger.'
    if kind in {'report','both','report-config','config-report'} and not evidence_id:
        return 'Non è disponibile un assessment precedente valido.'
    if tool.get('ai') and not request.include_ai:
        return 'AI locale non abilitata per questa suite.'
    if action == 'ai-correlate' and not request.include_active:
        return 'Richiede un assessment con risposte HTTP reali: attiva i test HTTP.'
    if action == 'analyze-evidence' and config.config_usage != 'evidence':
        return 'Serve un file con risposte HTTP. Usa «Genera e valida» dal job auto-assess attivo.'
    if action == 'benchmark-evaluate' and config.config_usage != 'benchmark':
        return 'Carica una configurazione benchmark, scegli tipo Benchmark e seleziona un assessment.'
    if action in {'workflow-assess','multi-resource-assess'} and (not request.include_writes or not request.include_active):
        return 'Workflow di scrittura non autorizzati dalla suite.'
    if action == 'verify-access-policy' and config.config_usage not in {'context'}:
        return 'Richiede una policy di accesso caricata come configurazione context.'
    if action == 'journey-assess' and config.config_usage != 'journey':
        return 'Richiede un manifest journey.'
    if action == 'workflow-assess' and config.config_usage != 'workflow':
        return 'Richiede un manifest workflow.'
    if action == 'multi-resource-assess' and config.config_usage != 'multi-resource':
        return 'Richiede un manifest multi-resource.'
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
    suite_contexts: dict[str, SuiteRequest] = {}  # in-memory, never written into reports

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

    @app.get('/api/control/manifest/candidates/{spec_id}')
    def manifest_candidates(spec_id:str):
        """Discover candidate CRUD trios without contacting the target API."""
        from achillesapi.dashboard.manifest_builder import discover_manifest_candidates
        path=file_id(spec_id,'.yaml')
        try:
            return {'candidates':discover_manifest_candidates(str(path)),
                    'notice':'Solo proposte offline: verifica ownership e cleanup prima di autorizzare scritture.'}
        except (ValueError, OSError) as exc:
            raise HTTPException(422,'Impossibile analizzare lo Swagger: '+str(exc)[:220]) from exc

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
                    body=body,deny_other=payload.get('deny_other') is True)
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

    @app.get('/api/control/tools')
    def tool_catalog():
        return [{'name':name,**options} for name,options in TOOLS.items()]

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
        """Only report the state of the optional LOCAL AI runtime.

        The target API is a separate system. It is never started, stopped,
        discovered, or contacted by this service-status endpoint.
        """
        with service_lock:
            process=services.get('ollama')
            status={'ollama_process': 'running' if process and process.poll() is None else 'not-managed'}
        try:
            with urllib.request.urlopen(urllib.request.Request(
                    'http://127.0.0.1:11434/api/tags',
                    headers={'User-Agent':'AchillesAPI-dashboard'}),timeout=0.7) as response:
                data=json.load(response)
            status['ollama']='online'
            status['ollama_models']=[x.get('name','') for x in data.get('models',[])][:30]
        except (OSError,ValueError,urllib.error.URLError):
            status['ollama']='offline'
            status['ollama_models']=[]
        return status

    @app.post('/api/control/services/ollama/{operation}')
    def ollama_service_action(operation:str,x_achilles_token:str|None=Header(None)):
        """Manage only an Ollama process spawned by this dashboard."""
        guard(x_achilles_token)
        if operation not in {'start','stop'}:
            raise HTTPException(400,'Unknown Ollama operation')
        with service_lock:
            process=services.get('ollama')
            if operation=='stop':
                if not process or process.poll() is not None:
                    raise HTTPException(409,'Ollama was not started by this dashboard')
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill()
                services.pop('ollama',None)
                return {'service':'ollama','state':'stopped'}
            if process and process.poll() is None:
                return {'service':'ollama','state':'already-started'}
            executable=shutil.which('ollama')
            if not executable:
                raise HTTPException(503,'Ollama is not installed or not on PATH')
            log=(root/'ollama.log').open('ab')
            try:
                child=subprocess.Popen([executable,'serve'],cwd=str(root),
                      stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                      env={**os.environ,'PYTHONUNBUFFERED':'1',
                           'OLLAMA_HOST':'127.0.0.1:11434'})
            except OSError as exc:
                raise HTTPException(503,'Could not start local Ollama') from exc
            finally:log.close()
            services['ollama']=child
            return {'service':'ollama','state':'starting'}

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
        executable=shutil.which('ollama')
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

    @app.post('/api/control/jobs')
    def run_tool(config:ToolRequest,x_achilles_token:str|None=Header(None)):
        """Execute a fixed tool with typed arguments; no shell or arbitrary paths."""
        guard(x_achilles_token)
        tool=TOOLS.get(config.action)
        if tool is None:raise HTTPException(400,'Tool not exposed by the dashboard')
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
        if config.config_usage not in {'multi-resource','workflow','journey','context','evidence','benchmark'}:
            raise HTTPException(400,'Unknown manifest type')
        if config.execute and config.approve_writes and config.config_id and config.config_usage=='multi-resource' and config.action in {'auto-assess','multi-resource-assess'}:
            # Refuse generated placeholders before any network traffic, even when
            # the YAML was uploaded manually rather than through the wizard.
            candidate_text=uploaded_config(config.config_id).read_text(encoding='utf-8')
            if 'REVIEW_' in candidate_text or 'TODO_' in candidate_text:
                raise HTTPException(422,'La configurazione contiene valori provvisori (REVIEW_/TODO_): usa la procedura guidata «Crea test con scritture» e compila tutti i campi richiesti.')
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
                    'auto-assess','advanced-vuln-assess','autonomous-agent','agent-loop-v2'} else []
                for value in config.path_values:
                    if config.action in {'auto-assess','advanced-vuln-assess','autonomous-agent','agent-loop-v2'}:
                        command+=['--path-value',value]
                if config.action in {'auto-assess','advanced-vuln-assess','multi-resource-assess','workflow-assess','journey-assess'}:
                    command+=['--max-requests',str(config.max_requests),'--rate',str(config.rate)]
                if config.action in {'auto-assess','advanced-vuln-assess','multi-resource-assess','workflow-assess','journey-assess','agent-loop-v2'}:
                    command+=[]
                if config.action in {'agent-loop-v2'}:command+=['--rate',str(config.rate)]
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
            if tool.get('ai'):
                # Only commands that actually implement --ai receive it.
                # ai-correlate and ai-analyze always use Ollama, but reject --ai.
                if config.ai and config.action in {'scan','ai-prioritize',
                        'autonomous-agent','agent-loop-v2'}:
                    command+=['--ai']
                command+=['--model',config.model]
            command+=['--output',str(filename)]
            jobs[job_id]={'id':job_id,'status':'running','mode':config.action,
                          'exit_code':None,'error':None,'specification_id':config.specification_id,
                          'action':config.action,'active':config.execute}

        def worker():
            try:
                local_env=_restricted_secrets(config.secrets,auth)
                local_env["PYTHONPATH"]=os.pathsep.join([str(repo/"src"),str(repo),local_env.get("PYTHONPATH","")])
                complete=subprocess.run(command,cwd=root,stdin=subprocess.DEVNULL,
                    capture_output=True,text=True,check=False,timeout=480,env=local_env)
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
                        if isinstance(result_data,dict):evidence_count=observed_http_count(result_data)
                    except (ValueError,OSError,TypeError):pass
                with lock:
                    job=jobs[job_id]
                    job['http_observations']=evidence_count
                    job['exit_code']=complete.returncode
                    job['status']='complete' if good else 'failed'
                    if not good:job['error']=_safe_error(complete.stderr,config.secrets)
            except (OSError,subprocess.TimeoutExpired,ValueError):
                with lock:
                    jobs[job_id]['status']='failed'
                    jobs[job_id]['error']='Task failed or exceeded 8 minute execution limit'
        threading.Thread(target=worker,daemon=True).start()
        return {'id':job_id,'status':'running','action':config.action}

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
        if request.include_writes and not (request.include_active and
                cfg.approve_writes and cfg.acknowledgment and cfg.config_id and cfg.auth_config_id):
            raise HTTPException(422, 'Scritture: servono manifest, auth.yaml, autorizzazione HTTP e approvazione esplicita.')
        if request.include_active:
            if not cfg.acknowledgment or not cfg.base_url or not cfg.allow_host or not scope_audit(cfg.base_url,[cfg.allow_host])['approved']:
                raise HTTPException(422, 'Per la suite attiva servono URL, allowlist e conferma autorizzazione.')
            if cfg.base_url.startswith('http://') and cfg.allow_host not in {'localhost','127.0.0.1'}:
                raise HTTPException(422, 'HTTP in chiaro consentito solo su localhost.')
        with lock:
            if any(j.get('status') in {'running','orchestrating'} for j in jobs.values()):
                raise HTTPException(409, 'Attendi che il job o la suite precedente termini.')
            suite_id = uuid.uuid4().hex
            jobs[suite_id] = {'id': suite_id, 'status': 'orchestrating', 'action': 'full-suite',
                'mode': 'suite HTTP autorizzata' if request.include_active else 'suite offline',
                'active': request.include_active, 'specification_id': cfg.specification_id,
                'total': len(SUITE_ORDER), 'completed_steps': 0, 'current_step': None,
                'exit_code': None, 'error': None}
            safe_copy=request.model_copy(deep=True)
            safe_copy.config.secrets={}  # require explicit reentry for reruns; never persist tokens
            suite_contexts[suite_id]=safe_copy
        source = reports/(suite_id+'.json')
        report: dict[str, Any] = {'engine': 'achillesapi-bounded-suite', 'version': '1.0',
            'specification_id': cfg.specification_id, 'mode': 'active' if request.include_active else 'offline',
            'ai_enabled': request.include_ai, 'writes_approved': request.include_writes, 'max_total_requests': request.max_total_requests,
            'reserved_request_budget': 0, 'steps': [], 'summary': {'completed': 0, 'failed': 0, 'skipped': 0, 'total': len(SUITE_ORDER)},
            'limitations': ['Ogni strumento ha una funzione diversa: un comando di planning non è un test di vulnerabilità.',
                            'I finding richiedono revisione; l’AI non conferma le vulnerabilità.',
                            'La suite riserva un budget complessivo per i controlli attivi e salta i passaggi che supererebbero il limite.']}
        def snapshot():
            source.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
            with lock:
                jobs[suite_id]['completed_steps'] = len(report['steps'])
                jobs[suite_id]['suite_summary'] = dict(report['summary'])

        def runner():
            suite_worker.active=True
            evidence_id = None
            reserved = 0
            try:
                snapshot()
                for action in SUITE_ORDER:
                    # Individual tools always pass their existing safety validator.
                    reason = suite_skip_reason(action, cfg, request, evidence_id)
                    if reason:
                        report['steps'].append({'action':action,'status':'skipped','reason':reason})
                        report['summary']['skipped'] += 1
                        snapshot()
                        continue
                    tool = TOOLS[action]
                    # Budget is reserved for worst-case traffic, not computed from
                    # response counts which may be incomplete.
                    planned_active = bool(request.include_active and tool.get('active'))
                    per_step_cap = (min(cfg.budget, 15) if action in {'autonomous-agent','agent-loop-v2'}
                                    else cfg.max_requests)
                    if planned_active and reserved + per_step_cap > request.max_total_requests:
                        report['steps'].append({'action': action, 'status':'skipped',
                            'reason':'Budget HTTP complessivo insufficiente: aumenta il limite totale o riduci i test.'})
                        report['summary']['skipped'] += 1
                        snapshot()
                        continue
                    with lock:jobs[suite_id]['current_step'] = action
                    payload = cfg.model_copy(deep=True)
                    payload.action = action
                    payload.assessment_id = evidence_id if tool['requirements'] in {'both','report','report-config','config-report'} else None
                    payload.execute = bool(request.include_active and tool.get('active'))
                    payload.ai = request.include_ai
                    payload.approve_writes = bool(request.include_writes and tool.get('writes') and payload.execute)
                    if action == 'auto-assess' and request.include_writes:
                        payload.approve_writes = True
                    if action == 'auto-assess' and not request.include_writes:
                        payload.approve_writes = False
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
                                'http_observations':child_state.get('http_observations',0)}
                        if child_state['status'] == 'complete':
                            report['summary']['completed'] += 1
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
                            'reason':str(exc.detail)[:350]})
                    snapshot()
                report['source_assessment_id'] = evidence_id
                report['status'] = 'complete_with_errors' if report['summary']['failed'] else 'complete'
                snapshot()
                with lock:
                    jobs[suite_id]['status'] = 'complete'
                    jobs[suite_id]['exit_code'] = 0 if not report['summary']['failed'] else 1
                    jobs[suite_id]['current_step'] = None
            except Exception:
                report['status'] = 'interrupted'
                report['limitations'].append('La suite è stata interrotta per un errore interno. I job figli già completati restano consultabili.')
                snapshot()
                with lock:
                    jobs[suite_id]['status'] = 'failed'
                    jobs[suite_id]['error'] = 'Errore interno di orchestrazione; controlla i job figli.'
                    jobs[suite_id]['current_step'] = None
        threading.Thread(target=runner, daemon=True).start()
        return {'id':suite_id,'status':'orchestrating','action':'full-suite','total':len(SUITE_ORDER)}

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

    @app.get('/api/control/suite/{suite_id}/prerequisites/{step_index}')
    def prerequisite_options(suite_id: str, step_index: int):
        """Provide only bounded OpenAPI choices; never tokens or raw response bodies."""
        context, report, step = prerequisite_step(suite_id, step_index)
        action = step['action']
        if action not in {'journey-assess', 'workflow-assess', 'multi-resource-assess',
                          'analyze-evidence', 'verify-access-policy', 'benchmark-evaluate', 'workflow-graph', 'auth-profiles'}:
            return {'action': action, 'builder': None}
        from achillesapi.core.openapi import load_openapi, parse_openapi
        spec_path = file_id(context.config.specification_id, '.yaml')
        parsed = parse_openapi(load_openapi(spec_path))
        operations = []
        for endpoint in parsed.endpoints:
            operations.append({'operation': endpoint.method + ' ' + endpoint.path,
                               'method': endpoint.method,
                               'parameters': [{'name': p.name, 'required': p.required, 'location': p.location}
                                              for p in endpoint.parameters if p.location in ('path','query')]})
        result = {'action': action, 'builder': action, 'operations': operations[:250],
                  'assessment_available': False, 'assessment_id': report.get('source_assessment_id')}
        if action in {'workflow-assess', 'multi-resource-assess','workflow-graph'}:
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
                return {'auth_config_id':identifier, 'valid':True,'message':'auth.yaml validato: i token vengono inseriti soltanto al retry e non salvati.'}
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
                    'read':{'operation':c['read'],'identity':owner,'id_parameter':c['path_parameter'],'id_pointer':pointer,'marker_pointer':'/'+marker},
                    'cleanup':{'operation':c['delete'],'identity':owner}}
                if other: wf['access']=[{'identity':other,'expected':'deny','category':'BOLA'}]
                output={'workflows':[wf]}
                temp=uploads/(uuid.uuid4().hex+'.config.yaml')
                try:
                    temp.write_text(yaml.safe_dump(output,sort_keys=False),encoding='utf-8')
                    read_workflows(temp)
                    _validate_workflows(parsed,spec,output['workflows'])
                finally: temp.unlink(missing_ok=True)
                usage='workflow'
            elif action == 'multi-resource-assess':
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
                    body=body,deny_other=bool(payload.get('other')))
                output=yaml.safe_load(raw)
                plan_multi_resource(parsed,spec,output,names)
                usage='multi-resource'
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
            content=json.dumps(output,ensure_ascii=False,indent=2) if usage in {'evidence','benchmark'} else yaml.safe_dump(output,sort_keys=False,allow_unicode=True)
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
        if retry.config_id is not None:
            uploaded_config(retry.config_id)
            cfg.config_id=retry.config_id
        if retry.auth_config_id is not None:
            file_id(retry.auth_config_id,'.auth.yaml')
            cfg.auth_config_id=retry.auth_config_id
        if retry.config_usage is not None:
            if retry.config_usage not in {'workflow','multi-resource','journey','context','evidence','benchmark'}:
                raise HTTPException(422,'Tipo manifest non supportato')
            cfg.config_usage=retry.config_usage
        if retry.base_url is not None:cfg.base_url=retry.base_url
        if retry.allow_host is not None:cfg.allow_host=retry.allow_host
        if retry.model is not None:cfg.model=retry.model
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
        evidence_id=report.get('source_assessment_id')
        reason=suite_skip_reason(action,cfg,ctx,evidence_id)
        if reason:
            raise HTTPException(422, 'Prerequisiti ancora mancanti: '+reason)
        planned_active=bool(ctx.include_active and TOOLS[action].get('active'))
        cap=min(cfg.budget,15) if action in {'autonomous-agent','agent-loop-v2'} else cfg.max_requests
        reserved=int(report.get('reserved_request_budget',0))
        if planned_active and reserved+cap>ctx.max_total_requests:
            raise HTTPException(422, 'Budget insufficiente: aumenta il budget totale prima del retry.')
        with lock:
            if parent['status']!='complete' or any(j.get('status')=='running' for j in jobs.values()):
                raise HTTPException(409,'Esecuzione concorrente non consentita')
            parent['status']='orchestrating'
            parent['current_step']='Retry: '+action
        def retry_worker():
            suite_worker.active=True
            try:
                payload=cfg.model_copy(deep=True)
                payload.action=action
                payload.assessment_id=evidence_id if TOOLS[action]['requirements'] in {'both','report','report-config','config-report'} else None
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
                if state['status']=='complete' and action=='auto-assess':
                    report['source_assessment_id']=child_id
                # Keep non-secret input pointers for subsequent retries in this session.
                cfg.secrets={}
                with lock:suite_contexts[suite_id]=ctx
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
                try:file.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
                except OSError:pass
                with lock:
                    parent['status']='complete'
                    parent['current_step']=None
                    parent['suite_summary']=dict(report['summary'])
                    parent['exit_code']=0 if not report['summary']['failed'] else 1
                suite_worker.active=False
        threading.Thread(target=retry_worker,daemon=True).start()
        return {'id':suite_id,'action':action,'step_index':retry.step_index,'status':'orchestrating'}
