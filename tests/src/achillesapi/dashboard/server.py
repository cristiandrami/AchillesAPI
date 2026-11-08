"""Local-only AchillesAPI dashboard.

No cloud, no remote bind, no arbitrary shell commands. The UI invokes fixed
AchillesAPI CLI actions with a strict allowlist of arguments. Writes require a separately supplied disposable fixture manifest and explicit consent.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any

from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from fastapi.exceptions import RequestValidationError

from achillesapi.core.openapi import analyze_openapi_file
from achillesapi.core.production_v031 import scope_audit

MAX_UPLOAD=2*1024*1024
_NAME=re.compile(r'^[A-Za-z][A-Za-z0-9_-]{0,63}$')
_ROOT=Path(__file__).resolve().parent

class RunRequest(BaseModel):
    """Validated UI request. No freeform CLI arguments or executable code."""
    specification_id:str
    base_url:str=''
    allow_host:str=''
    execute:bool=False
    acknowledgment:bool=False
    max_requests:int=Field(default=40,ge=1,le=100)
    rate:float=Field(default=1.0,ge=0.1,le=5.0)
    auth_config_id:str|None=None
    profiles:list[str]=Field(default_factory=list,max_length=6)
    allow_insecure_http:bool=False
    secrets:dict[str,str]=Field(default_factory=dict,max_length=20)


_SECRET_NAME=re.compile(r'^[A-Z][A-Z0-9_]{2,79}$')

def _restricted_secrets(values:dict[str,str],auth_file:Path|None)->dict[str,str]:
    """Pass secrets only to the child process, never store in files or HTTP responses.

    Only names explicitly referenced in the uploaded auth YAML may be overridden.
    """
    env=os.environ.copy()
    if not values:return env
    if auth_file is None:raise ValueError('Auth YAML richiesto per usare credenziali')
    from achillesapi.core.auth import load_authentication_manager
    manager=load_authentication_manager(auth_file)
    permitted={name for item in manager.describe() for name in item['environment_variables']}
    for name,value in values.items():
        if name not in permitted or not _SECRET_NAME.fullmatch(name) or not isinstance(value,str) or not value or len(value)>4096:
            raise ValueError('Nome o valore credenziale non valido')
        env[name]=value
    return env

def _safe_error(stderr:str,values:dict[str,str])->str:
    """Show a concise actionable CLI failure after removing secret values."""
    detail=(stderr or '').strip()[-1000:]
    for secret in values.values():
        if secret:detail=detail.replace(secret,'[REDACTED]')
    return detail or 'Comando non riuscito: controlla i parametri dello strumento.'

def create_app(workspace:Path|str)->FastAPI:
    """Construct a FastAPI app with instance-local files, jobs and CSRF token."""
    root=Path(workspace).resolve()
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    uploads=root/'uploads';reports=root/'reports'
    for directory in (uploads,reports):directory.mkdir(mode=0o700,exist_ok=True)
    token=secrets.token_urlsafe(32)
    jobs:dict[str,dict[str,Any]]={}
    lock=threading.Lock()
    app=FastAPI(title='AchillesAPI Local Dashboard',docs_url=None,redoc_url=None,openapi_url=None)

    @app.exception_handler(RequestValidationError)
    async def readable_validation_error(request:Request, exc:RequestValidationError):
        """Provide readable field errors, never echo submitted secrets or raw inputs."""
        names={'rate':'Richieste al secondo','max_requests':'Numero massimo richieste',
               'budget':'Budget follow-up','profiles':'Identità','secrets':'Credenziali',
               'specification_id':'Swagger','config_id':'Manifest','auth_config_id':'auth.yaml'}
        issues=[]
        for error in exc.errors()[:8]:
            parts=[str(x) for x in error.get('loc',()) if x!='body']
            field='.'.join(parts)
            label=names.get(field,field or 'Dato inserito')
            ctx=error.get('ctx') or {}
            typ=error.get('type','')
            if typ=='less_than_equal':message=f'massimo consentito {ctx.get("le")}'
            elif typ=='greater_than_equal':message=f'minimo consentito {ctx.get("ge")}'
            elif typ=='missing':message='campo obbligatorio mancante'
            elif typ=='int_parsing':message='inserisci un numero intero valido'
            elif typ in ('float_parsing','finite_number'):message='inserisci un numero valido'
            else:message='valore non valido: controlla il formato e i limiti previsti'
            issues.append(f'{label}: {message}.')
        return JSONResponse(status_code=422,content={'detail':'\n'.join(issues) or 'Dati non validi: verifica i campi.'})


    @app.middleware('http')
    async def local_guard(request:Request,call_next):
        """Reject host-header based rebinding and cross-origin browser mutations."""
        host=request.headers.get('host','').split(':')[0].lower()
        if host not in ('127.0.0.1','localhost','[::1]'):
            return JSONResponse({'detail':'Dashboard is restricted to loopback'},status_code=403)
        if request.method in ('POST','PUT','PATCH','DELETE'):
            origin=request.headers.get('origin')
            if origin:
                parsed=urlsplit(origin)
                if (parsed.scheme!='http' or parsed.hostname not in ('127.0.0.1','localhost')
                    or parsed.netloc.lower()!=request.headers.get('host','').lower()):
                    return JSONResponse({'detail':'Cross-origin writes are disabled'},status_code=403)
        return await call_next(request)

    def require_token(provided:str|None):
        if not provided or not secrets.compare_digest(provided,token):
            raise HTTPException(403,'Invalid dashboard session token')

    @app.get('/api/bootstrap')
    def bootstrap():
        return {'csrf_token':token,'version':'0.46.0','mode':'local-only',
                'warning':'Upload only approved Swagger/config. Target requests require execute and allow_host.'}

    @app.post('/api/import-text')
    def import_text(payload:dict,x_achilles_token:str|None=Header(None)):
        """Import pasted OpenAPI or YAML configuration, keeping separate opaque IDs."""
        require_token(x_achilles_token)
        kind=payload.get('kind');content=payload.get('content');name=payload.get('name','incollato.yaml')
        if kind not in {'openapi','auth','config'} or not isinstance(content,str) or not content.strip():
            raise HTTPException(400,'Indica tipo e contenuto da importare')
        limit=MAX_UPLOAD if kind=='openapi' else 128*1024
        if len(content.encode('utf-8'))>limit:raise HTTPException(413,'Testo troppo grande')
        import yaml
        try: parsed_yaml=yaml.safe_load(content)
        except yaml.YAMLError as exc:raise HTTPException(422,'YAML non valido: '+str(exc)[:180]) from exc
        if not isinstance(parsed_yaml,(dict,list)):raise HTTPException(422,'Il contenuto deve essere un oggetto YAML/JSON')
        ident=uuid.uuid4().hex
        suffix={'openapi':'.yaml','auth':'.auth.yaml','config':'.config.yaml'}[kind]
        dest=uploads/(ident+suffix)
        dest.write_text(content,encoding='utf-8');os.chmod(dest,0o600)
        try:
            if kind=='openapi':
                spec=analyze_openapi_file(dest)
                return {'id':ident,'kind':kind,'name':str(name)[:120],'title':spec.title,'operations':spec.endpoint_count}
            if kind=='auth':
                from achillesapi.core.auth import load_authentication_manager
                manager=load_authentication_manager(dest)
                return {'id':ident,'kind':kind,'name':str(name)[:120],'profiles':manager.describe()}
            return {'id':ident,'kind':kind,'name':str(name)[:120]}
        except Exception as exc:
            dest.unlink(missing_ok=True)
            raise HTTPException(422,'Contenuto non compatibile: '+str(exc)[:240]) from exc

    @app.get('/api/auth-template')
    def auth_template():
        """Generate a clearly explained, generic template; never embed credentials."""
        return {'yaml': 'profiles:\n  - name: tester\n    type: bearer\n    token_env: ACHILLES_TESTER_TOKEN\n  - name: admin\n    type: bearer\n    token_env: ACHILLES_ADMIN_TOKEN\n',
                'explanation':'token_env è il nome della variabile del segreto, non il token. Inserisci i valori segreti nel pannello Credenziali.'}

    @app.get('/api/specs')
    def specs():
        return [{'id':file.stem,'name':file.name} for file in sorted(uploads.glob('*.yaml'))
                if file.is_file()]

    @app.post('/api/upload')
    async def upload(file:UploadFile=File(...),x_achilles_token:str|None=Header(None)):
        """Store bounded OpenAPI YAML/JSON or auth profile YAML; no remote fetching."""
        require_token(x_achilles_token)
        original=Path(file.filename or '').name
        if not original.lower().endswith(('.yaml','.yml','.json')):
            raise HTTPException(400,'Upload a YAML/JSON file')
        body=await file.read(MAX_UPLOAD+1)
        if len(body)>MAX_UPLOAD or not body:
            raise HTTPException(413,'Upload exceeds 2MB or is empty')
        file_id=uuid.uuid4().hex
        dest=uploads/(file_id+'.yaml')
        dest.write_bytes(body)
        os.chmod(dest,0o600)
        try:
            # Auth configurations must be explicitly designated by the user.
            # Here validate as OpenAPI; auth config is uploaded via /api/auth-config.
            parsed=analyze_openapi_file(dest)
        except Exception as exc:
            dest.unlink(missing_ok=True)
            raise HTTPException(422,'Invalid OpenAPI specification') from exc
        return {'id':file_id,'name':original,'title':parsed.title,
                'operations':parsed.endpoint_count}

    @app.post('/api/auth-config')
    async def auth_upload(file:UploadFile=File(...),x_achilles_token:str|None=Header(None)):
        require_token(x_achilles_token)
        body=await file.read(65537)
        if not body or len(body)>65536:
            raise HTTPException(413,'Auth YAML must be <= 64KB')
        from achillesapi.core.auth import load_authentication_manager
        file_id=uuid.uuid4().hex
        dest=uploads/(file_id+'.auth.yaml')
        dest.write_bytes(body);os.chmod(dest,0o600)
        try:
            manager=load_authentication_manager(dest)
        except Exception as exc:
            dest.unlink(missing_ok=True)
            raise HTTPException(422,'Invalid authentication profile file') from exc
        # Never resolve or return credentials.
        return {'id':file_id,'profiles':manager.names,'descriptions':manager.describe(),
                'note':'I segreti possono essere inseriti nel pannello dashboard prima del test o come variabili ambiente.'}

    @app.get('/api/summary/{spec_id}')
    def summary(spec_id:str):
        if not re.fullmatch(r'[0-9a-f]{32}',spec_id):raise HTTPException(400,'Invalid ID')
        target=uploads/(spec_id+'.yaml')
        if not target.is_file():raise HTTPException(404,'Unknown specification')
        parsed=analyze_openapi_file(target)
        return {'title':parsed.title,'operations':parsed.endpoint_count,
                'endpoints':[{'method':ep.method,'path':ep.path} for ep in parsed.endpoints[:250]]}

    @app.post('/api/jobs')
    def run_job(config:RunRequest,x_achilles_token:str|None=Header(None)):
        require_token(x_achilles_token)
        if not re.fullmatch(r'[0-9a-f]{32}',config.specification_id):
            raise HTTPException(400,'Unknown specification')
        spec=uploads/(config.specification_id+'.yaml')
        if not spec.is_file():raise HTTPException(404,'Specification not found')
        if config.execute:
            if not config.acknowledgment:
                raise HTTPException(400,'Confirm explicit authorization and scope before active assessment')
            if not config.base_url or not config.allow_host:
                raise HTTPException(400,'Base URL and exact allowed host are mandatory')
            if not scope_audit(config.base_url,[config.allow_host])['approved']:
                raise HTTPException(400,'Target is outside the declared scope')
            if config.base_url.startswith('http://') and config.allow_insecure_http and config.allow_host not in ('localhost','127.0.0.1'):
                raise HTTPException(400,'Dashboard only allows insecure authenticated HTTP on localhost')
        if any(not _NAME.fullmatch(name) for name in config.profiles):
            raise HTTPException(400,'Invalid profile name')
        if config.profiles and not config.auth_config_id:
            raise HTTPException(400,'Profiles require an authentication configuration')
        auth_file=None
        if config.auth_config_id:
            if not re.fullmatch(r'[0-9a-f]{32}',config.auth_config_id):raise HTTPException(400,'Invalid auth ID')
            auth_file=uploads/(config.auth_config_id+'.auth.yaml')
            if not auth_file.is_file():raise HTTPException(404,'Unknown auth configuration')
        if config.execute and config.base_url.startswith('http://') and auth_file and not config.allow_insecure_http:
            raise HTTPException(400,'Credentialed HTTP requires explicit local-lab approval')
        try:_restricted_secrets(config.secrets,auth_file)
        except ValueError as exc:raise HTTPException(400,str(exc)) from exc
        with lock:
            if any(job['status']=='running' for job in jobs.values()):
                raise HTTPException(409,'Only one scan may run at a time')
            job_id=uuid.uuid4().hex
            report=reports/(job_id+'.json')
            cmd=[sys.executable,'-m','achillesapi.cli','auto-assess',str(spec),
                 '--output',str(report),'--max-requests',str(config.max_requests),'--rate',str(config.rate)]
            if config.base_url:cmd+=['--base-url',config.base_url]
            if config.execute:
                cmd+=['--execute','--allow-host',config.allow_host]
                if config.allow_insecure_http:cmd+=['--allow-insecure-http']
            if auth_file:cmd+=['--auth-config',str(auth_file)]
            for name in config.profiles:cmd+=['--profile',name]
            jobs[job_id]={'id':job_id,'status':'running','mode':'active GET' if config.execute else 'offline plan',
                          'exit_code':None,'error':None,'specification_id':config.specification_id}
        def worker():
            try:
                completed=subprocess.run(cmd,cwd=root,stdin=subprocess.DEVNULL,
                                         capture_output=True,text=True,timeout=600,check=False,
                                         env=_restricted_secrets(config.secrets,auth_file))
                with lock:
                    jobs[job_id]['exit_code']=completed.returncode
                    jobs[job_id]['status']='complete' if completed.returncode==0 and report.is_file() else 'failed'
                    if completed.returncode!=0:
                        jobs[job_id]['error']=_safe_error(completed.stderr, config.secrets)
            except (OSError,subprocess.TimeoutExpired):
                with lock:
                    jobs[job_id]['status']='failed'
                    jobs[job_id]['error']='Process unavailable or timed out'
        threading.Thread(target=worker,daemon=True).start()
        return {'id':job_id,'status':'running'}

    @app.get('/api/jobs')
    def list_jobs():
        with lock:return list(jobs.values())

    @app.get('/api/jobs/{job_id}')
    def get_job(job_id:str):
        with lock:
            if job_id not in jobs:raise HTTPException(404,'Unknown job')
            return dict(jobs[job_id])

    @app.get('/api/results/{job_id}')
    def get_result(job_id:str):
        with lock:
            if job_id not in jobs or jobs[job_id]['status']!='complete':
                raise HTTPException(404,'No completed assessment')
        path=reports/(job_id+'.json')
        try:return json.loads(path.read_text(encoding='utf-8'))
        except (OSError,ValueError) as exc:raise HTTPException(500,'Report unavailable') from exc

    @app.get('/api/triage/{job_id}')
    def triage(job_id:str):
        """Generate conservative vulnerability review without more target traffic."""
        from achillesapi.core.vulnerability_engine import vulnerability_evidence_review
        with lock:
            job=jobs.get(job_id)
            if not job or job['status']!='complete':raise HTTPException(404,'Completed job not found')
            spec_id=job['specification_id']
        parsed=analyze_openapi_file(uploads/(spec_id+'.yaml'))
        saved=json.loads((reports/(job_id+'.json')).read_text(encoding='utf-8'))
        return vulnerability_evidence_review(parsed,saved)

    @app.get('/api/export/{job_id}/{kind}')
    def export(job_id:str,kind:str):
        """Render an escaped, sanitized professional report for download."""
        from achillesapi.reporting.professional import write_professional_report
        if kind not in {'html','json','md','pdf'}:raise HTTPException(400,'Unsupported report type')
        with lock:
            if job_id not in jobs or jobs[job_id]['status']!='complete':
                raise HTTPException(404,'Completed job not found')
        directory=reports/job_id
        source=reports/(job_id+'.json')
        if not source.is_file():
            # auth-draft is a YAML artifact, not a JSON assessment. Build a
            # metadata-only view for the HTML/PDF exporter; never print YAML
            # contents as they may contain authentication configuration data.
            yaml_source=reports/(job_id+'.yaml')
            if yaml_source.is_file():
                source=directory/'export-source.json'
                directory.mkdir(parents=True,exist_ok=True)
                source.write_text(json.dumps({
                    'engine':'yaml-configuration-draft',
                    'source_description':'File di configurazione YAML generato. '
                        'Scarica il file originale per controllare i profili.',
                    'requests_sent':0,
                }),encoding='utf-8')
            else:
                raise HTTPException(404,'Il job non ha prodotto un documento esportabile.')
        try:
            outputs=write_professional_report(source,directory,(kind,))
        except (ValueError,ImportError,OSError) as exc:
            explanation=str(exc)[:220]
            if 'PDF export requires' in explanation or 'reportlab' in explanation.lower():
                explanation='Manca la libreria PDF. Esegui: uv sync --extra dashboard --extra pdf'
            raise HTTPException(422, 'Esportazione '+kind.upper()+' non riuscita: '+explanation) from exc
        return FileResponse(outputs[0],filename=f'achilles-report-{job_id[:8]}.{kind}',
                            content_disposition_type='inline' if kind in {'html','pdf'} else 'attachment',
                            headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

    @app.get('/')
    def index():return FileResponse(_ROOT/'static/index.html',headers={
        'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'",
        'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

    from achillesapi.dashboard.control import register_control_routes
    register_control_routes(app,root,uploads,reports,jobs,lock,token)

    app.mount('/assets',StaticFiles(directory=_ROOT/'static'),name='assets')
    return app


def launch_dashboard(workspace:str='dashboard-data',port:int=8766)->None:
    """Start the UI on loopback only; never expose to the LAN."""
    import uvicorn
    if not 1024 <= port <= 65535:raise ValueError('Port must be between 1024 and 65535')
    uvicorn.run(create_app(workspace),host='127.0.0.1',port=port,
                access_log=False,proxy_headers=False)
