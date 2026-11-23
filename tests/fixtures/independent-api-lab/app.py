"""Independent API lab: 100% synthetic records, deliberately insecure endpoints.

This server is completely independent of AchillesAPI and starts from a terminal.
All state is in RAM; restarting clears projects and tickets.
Never publish this service on a network or internet host.
"""
from __future__ import annotations

from uuid import uuid4
from fastapi import FastAPI, HTTPException, Depends, Query, Header, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

app = FastAPI(title="Independent Vulnerable Test API", version="1.0.0",
    description="Disposable local demo with intentionally vulnerable and protected routes")
_auth = HTTPBearer()
projects: dict[str, dict] = {}
tickets: dict[str, dict] = {}

class ProjectInput(BaseModel):
    label: str = Field(min_length=1,max_length=80)

class TicketInput(ProjectInput):
    project: str

class Update(BaseModel):
    note: str = Field(min_length=1,max_length=120)

class AdminToggle(BaseModel):
    is_admin: bool

def who(token:HTTPAuthorizationCredentials=Depends(_auth)) -> str:
    if token.credentials not in {'demo-owner', 'demo-other', 'demo-admin'}:
        raise HTTPException(401, 'Unknown demo credential')
    return token.credentials

def require(project_id:str, user:str)->dict:
    item=projects.get(project_id)
    if item is None:raise HTTPException(404,'Unknown project')
    if item['owner']!=user:raise HTTPException(403,'Not your project')
    return item

@app.get('/health', tags=['Monitoring'])
def health():return {'status':'ok','service':'independent-test-api'}

@app.get('/projects',tags=['Projects'])
def list_projects(user:str=Depends(who)):
    return {'items':[{'id':x['id'],'label':x['label']} for x in projects.values() if x['owner']==user]}

@app.post('/projects',status_code=201,tags=['Projects'])
def create_project(data:ProjectInput,user:str=Depends(who)):
    key='prj-'+uuid4().hex[:12]
    projects[key]={'id':key,'label':data.label,'owner':user,'note':'','internal_key':'training-only'}
    return {'id':key}

@app.get('/projects/{project_ref}',tags=['Projects'])
def read_project(project_ref:str,user:str=Depends(who)):
    item=projects.get(project_ref)
    if not item:raise HTTPException(404)
    # Deliberately vulnerable: any authenticated demo user reads every project.
    return item

@app.get('/secure/projects/{project_ref}',tags=['Protected examples'])
def secure_project(project_ref:str,user:str=Depends(who)):
    item=require(project_ref,user)
    return {k:v for k,v in item.items() if k != 'internal_key'}

@app.patch('/projects/{project_ref}',tags=['Projects'])
def change_project(project_ref:str,data:Update,user:str=Depends(who)):
    item=require(project_ref,user)
    item['note']=data.note
    return item

@app.delete('/projects/{project_ref}',status_code=204,tags=['Projects'])
def delete_project(project_ref:str,user:str=Depends(who)):
    require(project_ref,user)
    if any(t['project']==project_ref for t in tickets.values()):raise HTTPException(409,'Delete tickets first')
    del projects[project_ref]

@app.post('/projects/{project_ref}/tickets',status_code=201,tags=['Tickets'])
def create_ticket(project_ref:str,data:TicketInput,user:str=Depends(who)):
    require(project_ref,user)
    if data.project!=project_ref:raise HTTPException(422,'Project identifier mismatch')
    key='tkt-'+uuid4().hex[:12]
    tickets[key]={'id':key,'label':data.label,'project':project_ref,'owner':user,'note':''}
    return {'id':key}

@app.get('/tickets/{ticket_ref}',tags=['Tickets'])
def read_ticket(ticket_ref:str,user:str=Depends(who)):
    item=tickets.get(ticket_ref)
    if not item:raise HTTPException(404)
    # Deliberately vulnerable BOLA: other demo users can read this ticket.
    return item

@app.get('/secure/tickets/{ticket_ref}',tags=['Protected examples'])
def secure_ticket(ticket_ref:str,user:str=Depends(who)):
    item=tickets.get(ticket_ref)
    if not item:raise HTTPException(404)
    if item['owner']!=user:raise HTTPException(403)
    return item

@app.patch('/tickets/{ticket_ref}',tags=['Tickets'])
def change_ticket(ticket_ref:str,data:Update,user:str=Depends(who)):
    item=tickets.get(ticket_ref)
    if not item:raise HTTPException(404)
    if item['owner']!=user:raise HTTPException(403)
    item['note']=data.note
    return item

@app.delete('/tickets/{ticket_ref}',status_code=204,tags=['Tickets'])
def delete_ticket(ticket_ref:str,user:str=Depends(who)):
    item=tickets.get(ticket_ref)
    if not item:raise HTTPException(404)
    if item['owner']!=user:raise HTTPException(403)
    del tickets[ticket_ref]

@app.get('/admin/audit',tags=['Authorization examples'])
def audit(user:str=Depends(who)):
    # Deliberate BFLA example: ordinary demo users can access this route.
    return {'events':len(projects)+len(tickets),'scope':'training'}

@app.get('/secure/admin/audit',tags=['Protected examples'])
def secure_audit(user:str=Depends(who)):
    if user!='demo-admin':raise HTTPException(403)
    return {'events':len(projects)+len(tickets),'scope':'training'}

@app.get('/search',tags=['Validation examples'])
def search(q:str=Query(min_length=2,max_length=48)):
    return {'query_length':len(q),'items':[]}


# ---------------------------------------------------------------------------
# EXTRA SECURITY CASES — all synthetic; independent from the AchillesAPI code.
# For every intentionally broken endpoint there is a protected comparison.
# Swagger is generated by FastAPI rather than maintained manually.
# ---------------------------------------------------------------------------
class ProfileOutput(BaseModel):
    username: str
    internal_token: str = Field(json_schema_extra={"writeOnly": True})


@app.get('/profile/exposed', response_model=ProfileOutput, tags=['Information exposure'])
def exposed_profile(user: str = Depends(who)):
    """Deliberate writeOnly contract violation; uses fictitious values."""
    return {'username': user, 'internal_token': 'synthetic-sensitive-value'}


@app.get('/profile/safe', tags=['Protected examples'])
def safe_profile(user: str = Depends(who)):
    return {'username': user}


@app.get('/misconfigured/cors', tags=['CORS examples'])
def permissive_cors(response: Response, origin: str | None = Header(None)):
    """Deliberate arbitrary-Origin reflection WITH credentials for a safe GET."""
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Vary'] = 'Origin'
    return {'kind': 'synthetic-cors-fixture'}


@app.get('/secure/cors', tags=['Protected examples'])
def restricted_cors(response: Response, origin: str | None = Header(None)):
    if origin == 'http://127.0.0.1:9999':
        response.headers['Access-Control-Allow-Origin'] = origin
    return {'kind': 'restricted-cors-fixture'}


@app.get('/misconfigured/cache', tags=['Misconfiguration examples'])
def public_cache(response: Response, user: str = Depends(who)):
    response.headers['Cache-Control'] = 'public, max-age=120'
    response.headers['X-Powered-By'] = 'TrainingFixture/1.0'
    return {'id': 'fixture-account', 'username': user}


@app.get('/secure/cache', tags=['Protected examples'])
def private_cache(response: Response, user: str = Depends(who)):
    response.headers['Cache-Control'] = 'private, no-store'
    return {'id': 'fixture-account'}


@app.get('/misconfigured/auth', tags=['Authentication examples'],
         openapi_extra={'security': [{'HTTPBearer': []}]})
def missing_auth_requirement():
    """OpenAPI declares bearer security; intentionally no auth enforcement."""
    return {'scope': 'lab-only', 'access': 'anonymous-but-declared-protected'}


@app.get('/secure/auth', tags=['Protected examples'])
def enforced_auth(user: str = Depends(who)):
    return {'access': 'authenticated', 'username': user}


@app.get('/unstable/repeatable', tags=['Resilience examples'])
def repeatable_503(response: Response):
    """Stable synthetic 503, suitable for bounded repeatability checks."""
    response.status_code = 503
    return {'detail': 'fixture service temporarily unavailable'}


@app.get('/unstable/healthy', tags=['Protected examples'])
def stable_200():
    return {'status': 'ok'}


@app.get('/misconfigured/validation', tags=['Validation examples'])
def weak_validation(q: str = Query(min_length=3, max_length=12)):
    """Query constraints are declared, but invalid values accepted when called directly?

    FastAPI enforces min/max for standard endpoints, so this fixture uses a
    deliberate contract mismatch in a JSON response instead of misleading tests.
    """
    return {'query_length': 'not-a-number'}


class ContractLedger(BaseModel):
    total: int


@app.get('/misconfigured/contract', response_model=ContractLedger,
         tags=['Response-contract examples'])
def invalid_contract():
    """Deliberately bypass response validation to simulate legacy API contract drift."""
    from fastapi.responses import JSONResponse
    return JSONResponse({'total': 'not-a-number'})


@app.get('/secure/contract', response_model=ContractLedger,
         tags=['Protected examples'])
def valid_contract():
    return {'total': 42}


@app.get('/misconfigured/error', tags=['Error handling examples'])
def verbose_sql_error():
    """A fake SQL error string, not a database or SQL-injection vulnerability."""
    from fastapi.responses import JSONResponse
    return JSONResponse({'error': 'SQL syntax error in fictional query'}, status_code=500)


@app.get('/secure/error', tags=['Protected examples'])
def sanitized_error():
    from fastapi.responses import JSONResponse
    return JSONResponse({'error': 'Request failed'}, status_code=500)
