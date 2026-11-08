"""Lab-independent browser control plane for approved AchillesAPI CLI operations.

Every command is constructed by a fixed registry. No browser-supplied command,
path or shell fragment is executed. Files are referenced by opaque upload/job IDs.
"""
from __future__ import annotations

import json
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


def register_control_routes(app:FastAPI, root:Path, uploads:Path, reports:Path,
                            jobs:dict, lock:threading.Lock, csrf:str) -> None:
    """Mount generic security tools and optional locally managed Ollama controls."""
    repo=Path(__file__).resolve().parents[3]
    services: dict[str,subprocess.Popen]={}
    service_lock=threading.Lock()

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
        if config.config_usage not in {'multi-resource','workflow','journey','context'}:
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
            # Convert uploaded YAML/JSON to a well-formed JSON evidence file.
            import yaml
            try:
                data=yaml.safe_load(extra.read_text(encoding='utf-8'))
                if not isinstance(data,(dict,list)):raise ValueError()
            except (OSError,ValueError):raise HTTPException(422,'Invalid evidence')
        with lock:
            if any(item['status']=='running' for item in jobs.values()):
                raise HTTPException(409,'Another task is running')
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
            if kind=='config-report':command.extend([str(extra),str(previous)])
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
