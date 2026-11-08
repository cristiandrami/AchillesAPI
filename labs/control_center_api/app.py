"""Independent API lab: 100% synthetic records, deliberately insecure endpoints.

The local dashboard launches this service on 127.0.0.1:8795 only.
All state is in RAM; restarting clears projects and tickets.
Never publish this service on a network or internet host.
"""
from __future__ import annotations

from uuid import uuid4
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

app = FastAPI(title="Achilles Control Center Training API", version="1.0.0",
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
def health():return {'status':'ok','service':'control-center-lab'}

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
