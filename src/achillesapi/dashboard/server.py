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

from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile, Form
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

def _safe_error(stderr:str,values:dict[str,str], auth_file:Path|None=None)->str:
    """Show a concise actionable CLI failure after removing secret values."""
    detail=(stderr or '').strip()[-1000:]
    hidden = [v for v in values.values() if isinstance(v,str) and v]
    if auth_file is not None:
        # I segreti inline sono già presenti in auth.yaml: oscurali anche negli
        # errori della CLI, senza copiare il file in log o nel database.
        try:
            from achillesapi.core.auth import AuthenticationFile
            import yaml
            configuration = AuthenticationFile.model_validate(
                yaml.safe_load(auth_file.read_text(encoding='utf-8')))
            for profile in configuration.profiles:
                for name in ('token','value','username','password','client_id','client_secret'):
                    value = getattr(profile, name, None)
                    if isinstance(value, str) and value:
                        hidden.append(value)
        except (OSError, ValueError, TypeError):
            # Un YAML invalido non deve compromettere la gestione dell'errore.
            pass
    for secret in sorted(set(hidden), key=len, reverse=True):
        detail=detail.replace(secret,'[REDACTED]')
    return detail or 'Comando non riuscito: controlla i parametri dello strumento.'

def create_app(workspace:Path|str)->FastAPI:
    """Construct a FastAPI app with instance-local files, jobs and CSRF token."""
    root=Path(workspace).resolve()
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    uploads=root/'uploads';reports=root/'reports'
    for directory in (uploads,reports):directory.mkdir(mode=0o700,exist_ok=True)
    token=secrets.token_urlsafe(32)
    from achillesapi.dashboard.persistence_v080 import CampaignStore, PersistentJobRegistry
    store=CampaignStore(root)
    jobs:dict[str,dict[str,Any]]=PersistentJobRegistry(store)
    # Recover *results*, not processes. Interrupted suites become inspectable;
    # unfinished steps are explicitly skipped and can be retried by the operator.
    for job in list(jobs.values()):
        if job.get('action')!='full-suite' or not (job.get('error') or '').startswith('Esecuzione interrotta'):
            continue
        source=reports/(job['id']+'.json')
        if not source.is_file():
            continue
        try:
            report=json.loads(source.read_text(encoding='utf-8'))
            from achillesapi.dashboard.control import SUITE_ORDER
            already={item.get('action') for item in report.get('steps', [])}
            for action in SUITE_ORDER:
                if action not in already:
                    report['steps'].append({'action':action,'status':'skipped',
                        'reason':'Task non avviato: dashboard riavviata. Retry manuale disponibile.'})
            states=[item.get('status') for item in report['steps']]
            report['summary']={
                'completed':states.count('complete'), 'failed':states.count('failed'),
                'skipped':states.count('skipped'), 'total':len(states)}
            report['status']='interrupted'
            source.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
            job['status']='complete'
            job['interrupted']=True
            job['completed_steps']=len(states)
            job['suite_summary']=report['summary']
            store.save_job(job)
        except (OSError,ValueError,TypeError,KeyError):
            pass
    lock=threading.Lock()
    app=FastAPI(title='AchillesAPI Local Dashboard',docs_url=None,redoc_url=None,openapi_url=None)
    app.state.campaign_store=store

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
        return {'csrf_token':token,'version':__import__('achillesapi').__version__,'mode':'local-only',
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
            raise HTTPException(422,'Configurazione non valida: controlla nomi dei campi e tipi. Nessun valore segreto viene mostrato.') from exc

    @app.post('/api/rc18/oidc-audit')
    def rc18_oidc_audit(payload:dict,x_achilles_token:str|None=Header(None)):
        """Offline OIDC audit. No token submission and no network access."""
        require_token(x_achilles_token)
        spec_id=payload.get('specification_id')
        if not isinstance(spec_id,str) or not re.fullmatch(r'[0-9a-f]{32}',spec_id):
            raise HTTPException(400, 'Importa prima uno Swagger valido')
        target=uploads/(spec_id+'.yaml')
        if not target.is_file():
            raise HTTPException(404,'Swagger non presente')
        if any(field in payload for field in ('token','access_token','id_token','execute','discovery_url')):
            raise HTTPException(400,'Questo pannello accetta solo JSON pubblico e non esegue richieste HTTP')
        from achillesapi.core.openapi import load_openapi
        from achillesapi.core.oidc_enterprise_rc18 import full_oidc_audit, OIDCSafetyError
        def parse_optional(field):
            value=payload.get(field,'')
            if not isinstance(value,str) or len(value.encode('utf-8'))>128*1024:
                raise HTTPException(413,'JSON metadati/JWKS troppo grande')
            try:
                obj=json.loads(value) if value.strip() else None
            except ValueError as exc:
                raise HTTPException(422,field+': JSON non valido') from exc
            if obj is not None and not isinstance(obj,dict):
                raise HTTPException(422,field+': serve un oggetto JSON')
            return obj
        try:
            report=full_oidc_audit(load_openapi(target), metadata=parse_optional('metadata_json'),
                 jwks=parse_optional('jwks_json'), old_jwks=parse_optional('previous_jwks_json'),
                 expected_issuer=str(payload.get('expected_issuer',''))[:500] or None)
        except OIDCSafetyError as exc:
            raise HTTPException(422,'Audit OIDC: '+str(exc)[:150]) from exc
        return report

    @app.post('/api/rc19/quality/{job_id}')
    def rc19_report_quality(job_id:str, x_achilles_token:str|None=Header(None)):
        """One-purpose offline report QA. Never contacts the target or reveals secrets."""
        require_token(x_achilles_token)
        with lock:
            job=jobs.get(job_id)
            if not job or job.get('status')!='complete':
                raise HTTPException(404,'Scegli un job completato nella sezione risultati')
        source=reports/(job_id+'.json')
        if not source.is_file() or source.stat().st_size>20*1024*1024:
            raise HTTPException(422,'Il job non ha un report JSON di dimensione supportata')
        from achillesapi.core.release_validation_rc19 import quality_gate, RC19ValidationError
        try:
            return quality_gate(json.loads(source.read_text(encoding='utf-8')))
        except (ValueError,TypeError,OSError) as exc:
            raise HTTPException(422,'Report JSON non compatibile con la verifica qualità') from exc

    @app.post('/api/rc19/benchmark/{job_id}')
    def rc19_report_benchmark(job_id:str,payload:dict,x_achilles_token:str|None=Header(None)):
        """One-purpose ground-truth benchmark; accepts only explicit bounded labels."""
        require_token(x_achilles_token)
        with lock:
            job=jobs.get(job_id)
            if not job or job.get('status')!='complete':
                raise HTTPException(404,'Scegli un job completato nella sezione risultati')
        source=reports/(job_id+'.json')
        if not source.is_file() or source.stat().st_size>20*1024*1024:
            raise HTTPException(422,'Il job non ha un report JSON di dimensione supportata')
        expected=payload.get('ground_truth')
        if not isinstance(expected,dict) or len(json.dumps(expected))>256*1024:
            raise HTTPException(422,'Inserisci un oggetto ground truth JSON valido, massimo 256 KB')
        from achillesapi.core.release_validation_rc19 import benchmark_findings, RC19ValidationError
        try:
            return benchmark_findings(json.loads(source.read_text(encoding='utf-8')),expected)
        except (ValueError,TypeError,OSError) as exc:
            raise HTTPException(422,'Ground truth o report non validi: verifica ID, operazioni e categorie') from exc

    @app.get('/api/auth-template')
    def auth_template():
        """Generate a bearer template with inline placeholders (never real credentials)."""
        return {'yaml': 'profiles:\n  - name: owner\n    type: bearer\n    token: "INSERISCI_TOKEN_OWNER"\n  - name: other\n    type: bearer\n    token: "INSERISCI_TOKEN_OTHER"\n',
                'explanation':'Inserisci il token direttamente nel campo token. Il file è sensibile: non pubblicarlo su GitHub e non condividerlo.'}

    @app.get('/api/specs')
    def specs():
        return [{'id':file.stem,'name':file.name} for file in sorted(uploads.glob('*.yaml'))
                if file.is_file()]

    @app.post('/api/upload')
    async def upload(file:UploadFile=File(...),root:str=Form(''),x_achilles_token:str|None=Header(None)):
        """Store bounded OpenAPI YAML/JSON or auth profile YAML; no remote fetching."""
        require_token(x_achilles_token)
        original=Path(file.filename or '').name
        if not original.lower().endswith(('.yaml','.yml','.json','.zip')):
            raise HTTPException(400,'Upload a YAML/JSON file')
        limit = 8*1024*1024 if original.lower().endswith('.zip') else MAX_UPLOAD
        body=await file.read(limit+1)
        if len(body)>limit or not body:
            raise HTTPException(413,'Upload exceeds maximum permitted size or is empty')
        file_id=uuid.uuid4().hex
        if original.lower().endswith('.zip'):
            from achillesapi.core.openapi_bundle_rc18 import import_zip_bundle, OpenAPIBundleError
            dest=uploads/(file_id+'.yaml')
            try:
                summary = import_zip_bundle(body, dest, root_name=root or None)
            except (OpenAPIBundleError, ValueError, OSError) as exc:
                dest.unlink(missing_ok=True)
                raise HTTPException(422, 'Bundle OpenAPI non valido: '+str(exc)[:220]) from exc
            return {'id':file_id,'name':original,'title':summary['title'],
                    'operations':summary['operations'],'bundle':True,
                    'files':summary['files'],'root':summary['root']}
        
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
                'note':'Profili caricati. I segreti inline restano nel file locale e non sono restituiti dal server.'}

    @app.get('/api/summary/{spec_id}')
    def summary(spec_id:str):
        if not re.fullmatch(r'[0-9a-f]{32}',spec_id):raise HTTPException(400,'Invalid ID')
        target=uploads/(spec_id+'.yaml')
        if not target.is_file():raise HTTPException(404,'Unknown specification')
        parsed=analyze_openapi_file(target)
        return {'title':parsed.title,'operations':parsed.endpoint_count,
                'endpoints':[{'method':ep.method,'path':ep.path} for ep in parsed.endpoints[:250]]}

    @app.get('/api/compatibility/{spec_id}')
    def compatibility(spec_id: str, auth_config_id: str = '', active: bool = False,
                      writes: bool = False, ai: bool = False, assessment_id: str = ''):
        """Read-only compatibility/coverage matrix; never contacts the target."""
        from achillesapi.core.compatibility_v080 import from_file, known_unavailable_actions
        if not re.fullmatch(r'[a-f0-9]{32}', spec_id):
            raise HTTPException(400,'Spec ID non valido')
        spec_file=uploads/(spec_id+'.yaml')
        if not spec_file.is_file():
            raise HTTPException(404,'Swagger non caricato')
        if auth_config_id and (not re.fullmatch(r'[a-f0-9]{32}',auth_config_id)
                               or not (uploads/(auth_config_id+'.auth.yaml')).is_file()):
            raise HTTPException(404,'Auth ID non valido')
        assessment=None
        if assessment_id:
            if not re.fullmatch(r'[a-f0-9]{32}',assessment_id):
                raise HTTPException(400,'Assessment ID non valido')
            job=jobs.get(assessment_id)
            if not job or job.get('specification_id') != spec_id or job.get('status')!='complete':
                raise HTTPException(422,'Assessment non compatibile con lo Swagger corrente')
            try: assessment=json.loads((reports/(assessment_id+'.json')).read_text(encoding='utf-8'))
            except (OSError,ValueError) as exc:raise HTTPException(422,'Assessment non disponibile') from exc
        coverage=from_file(str(spec_file),has_auth=bool(auth_config_id),
                           active_allowed=active,writes_approved=writes,ai_enabled=ai,
                           assessment=assessment)
        coverage['inapplicable_tools']=known_unavailable_actions(coverage)
        return JSONResponse(coverage,headers={'Cache-Control':'no-store'})

    @app.get('/api/campaigns')
    def campaign_history():
        """Historical campaign metadata only; no credentials or raw evidence."""
        with lock:
            return [{'id':j['id'],'status':j['status'], 'error':j.get('error'),
                     'summary':j.get('suite_summary',{}), 'interrupted':j.get('interrupted',False),
                     'api_name':j.get('api_name'), 'suite_code':j.get('suite_code'),
                     'display_name':j.get('display_name')}
                    for j in jobs.values() if j.get('action')=='full-suite']

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
            if any(job['status'] in {'running','orchestrating'} for job in jobs.values()):
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
            finally:
                with lock:store.save_job(dict(jobs[job_id]))
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

    @app.get('/job/{job_id}')
    def job_view_page(job_id:str):
        """Dedicated independent tab for completed job exploration."""
        if not re.fullmatch(r'[0-9a-f]{32}',job_id):
            raise HTTPException(404,'Job non trovato')
        with lock:
            if job_id not in jobs:
                raise HTTPException(404,'Job non trovato in questa sessione')
        return FileResponse(_ROOT/'static/job-viewer.html',headers={
            'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

    @app.get('/job/{job_id}/ai')
    def ai_dossier_page(job_id: str):
        """Separate, same-origin read-only dossier for actual AI output."""
        if not re.fullmatch(r'[0-9a-f]{32}', job_id):
            raise HTTPException(404, 'Job non trovato')
        with lock:
            if job_id not in jobs:
                raise HTTPException(404, 'Job non trovato in questa sessione')
        return FileResponse(_ROOT/'static/job-ai.html', headers={
            'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

    @app.get('/api/job-ai/{job_id}')
    def ai_dossier_data(job_id: str):
        """Read AI analyses from each job in a suite without target requests."""
        if not re.fullmatch(r'[0-9a-f]{32}', job_id):
            raise HTTPException(404, 'Job non trovato')
        with lock:
            item = dict(jobs[job_id]) if job_id in jobs else None
        if item is None:
            raise HTTPException(404, 'Job non trovato in questa sessione')
        from achillesapi.dashboard.job_view import ai_dossier_entry
        result = {'job_id': job_id, 'action': item.get('action', ''),
                  'entries': [], 'tasks_without_ai_output': [],
                  'notice': 'Dossier locale e di sola lettura. Le ipotesi AI non sono vulnerabilità confermate.'}
        def append_job(child_id: str, action: str, ai_status: str, execution_status: str) -> None:
            source = reports / (child_id + '.json')
            if execution_status != 'complete' or not source.is_file():
                return
            try:
                # Never read a report exceeding 6 MiB into this view.
                if source.stat().st_size > 6 * 1024 * 1024:
                    result['tasks_without_ai_output'].append({'action': action, 'reason': 'Risultato troppo grande per il dossier'})
                    return
                raw = json.loads(source.read_text(encoding='utf-8'))
                entry = ai_dossier_entry(raw, action=action, job_id=child_id, ai_status=ai_status)
                if entry is not None:
                    result['entries'].append(entry)
                elif action.startswith('ai-') or ai_status not in {'not_invoked', ''}:
                    result['tasks_without_ai_output'].append({'action': action,
                        'reason': 'Nessun output del modello registrato · ' + ai_status})
            except (OSError, ValueError, TypeError):
                result['tasks_without_ai_output'].append({'action': action, 'reason': 'Risultato non leggibile'})
        if item.get('action') == 'full-suite':
            source = reports / (job_id + '.json')
            if source.is_file() and source.stat().st_size <= 6 * 1024 * 1024:
                try:
                    suite = json.loads(source.read_text(encoding='utf-8'))
                    for step in (suite.get('steps', []) if isinstance(suite, dict) else [])[:100]:
                        child_id = step.get('job_id') if isinstance(step, dict) else None
                        if not isinstance(child_id, str) or not re.fullmatch(r'[0-9a-f]{32}', child_id):
                            continue
                        append_job(child_id, str(step.get('action', 'task')),
                                   str(step.get('ai_status', 'not_invoked')),
                                   str(step.get('status', 'unknown')))
                except (OSError, ValueError, TypeError):
                    pass
        else:
            append_job(job_id, str(item.get('action', 'job')),
                       str(item.get('ai_status', 'not_invoked')),
                       str(item.get('status', 'unknown')))
        result['total_ai_outputs'] = len(result['entries'])
        from achillesapi.dashboard.ai_dossier_summary import build_ai_dossier_summary
        result['executive_digest'] = build_ai_dossier_summary(result['entries'])
        if item.get('action') == 'full-suite':
            result['display_name'] = item.get('display_name') or ''
            result['api_name'] = item.get('api_name') or ''
            result['suite_code'] = item.get('suite_code') or job_id[:12]
        return JSONResponse(result, headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

    @app.get('/api/job-view/{job_id}')
    def job_view_data(job_id:str):
        """Normalized, sanitized view. No execution or target traffic."""
        if not re.fullmatch(r'[0-9a-f]{32}',job_id):
            raise HTTPException(404,'Job non trovato')
        with lock:
            job=jobs.get(job_id)
            if not job:
                raise HTTPException(404,'Job non trovato in questa sessione')
            item=dict(job)
        if item.get('status')!='complete' and not (item.get('action')=='full-suite' and item.get('status')=='orchestrating' and (reports/(job_id+'.json')).is_file()):
            return {'id':job_id,'action':item.get('action','job'),
                    'status':item.get('status','unknown'),'error':item.get('error') or '',
                    'completed_steps':item.get('completed_steps'), 'total':item.get('total'),
                    'current_step':item.get('current_step')}
        from achillesapi.dashboard.job_view import viewer_payload
        path=reports/(job_id+'.json')
        if not path.is_file():
            if (reports/(job_id+'.yaml')).is_file():
                raw={'engine':'yaml-configuration-draft','note':'Configurazione YAML creata. Scarica il file per consultarla; i segreti non vengono mostrati qui.'}
            else:
                raise HTTPException(404,'Risultato non disponibile')
        else:
            try:
                raw=json.loads(path.read_text(encoding='utf-8'))
            except (OSError,ValueError) as exc:
                raise HTTPException(422,'Il risultato non è JSON valido') from exc
        data=viewer_payload(raw,action=item.get('action',item.get('mode','job')),job_id=job_id)
        data['status']=item.get('status','complete')
        # Le schede servono anche per i task singoli, non solo per la suite.
        from achillesapi.core.task_help_rc5 import task_help
        from achillesapi.core.registry_v090 import TOOLS
        if item.get('action') in TOOLS:
            data['task_help']=task_help(item['action'])
        if item.get('action')=='full-suite':
            from achillesapi.dashboard.suite_identity import suite_identity
            metadata = {k: item.get(k) or raw.get(k) for k in ('api_name','suite_code','display_name')}
            # Older suite reports may not include human-readable metadata.
            if not metadata.get('display_name'):
                metadata = {**suite_identity({'info':{'title':'API senza titolo'}},job_id), **{k:v for k,v in metadata.items() if v}}
            data.update(metadata)
            steps=raw.get('steps',[])
            data['suite_steps']=__import__('achillesapi.dashboard.job_view',fromlist=['safe_tree']).safe_tree(steps)
            data['task_help_map']={name:task_help(name) for name in TOOLS}
            data['suite_summary']=raw.get('summary',{})
            from achillesapi.dashboard.job_view import safe_tree
            data['compatibility']=safe_tree(raw.get('preflight',{}))
            data['verification']=safe_tree(raw.get('verification',{}))
            data['adaptive_plan']=safe_tree(raw.get('adaptive_plan',{}))
            data['workflow_proposals']=safe_tree(raw.get('workflow_proposals',{}))
            data['auth_readiness']=safe_tree(raw.get('auth_readiness',{}))
            data['security_surfaces']=safe_tree(raw.get('security_surfaces',{}))
            data['risk_matrix']=safe_tree(raw.get('risk_matrix',{}))
            data['task_preflight']=safe_tree(raw.get('task_preflight',{}))
            data['ai_readiness']=safe_tree(raw.get('ai_readiness',{}))
            data['coverage_gaps']=safe_tree(raw.get('coverage_gaps',[]))
            data['quality_gate']=safe_tree(raw.get('quality_gate',{}))
            data['release_readiness']=safe_tree(raw.get('release_readiness',{}))
            data['http_accounting_note']=raw.get('http_accounting_note','')
            data['http_telemetry']=safe_tree(raw.get('http_telemetry',{}))
            findings=[]
            for step in steps:
                child_id=step.get('job_id')
                if step.get('status')!='complete' or not isinstance(child_id,str) or not re.fullmatch(r'[0-9a-f]{32}',child_id):
                    continue
                source=reports/(child_id+'.json')
                if not source.is_file():continue
                try:
                    parsed=json.loads(source.read_text(encoding='utf-8'))
                    from achillesapi.dashboard.job_view import viewer_payload
                    normalized=viewer_payload(parsed,action=step.get('action','job'),job_id=child_id)
                    for f in normalized.get('findings',[])[:100]:
                        if len(findings)>=300:break
                        findings.append({**f,'source_job_id':child_id,'source_action':step.get('action')})
                except (OSError,ValueError,TypeError,KeyError):continue
            data['suite_findings']=findings
        return JSONResponse(data,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

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
