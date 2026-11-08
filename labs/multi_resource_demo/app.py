"""Disposable local two-level fixture API; never bind outside loopback."""
from __future__ import annotations
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from uuid import uuid4

app = FastAPI(title='Nested Records Sample API', version='1.0.0',
              description='Intentionally vulnerable local demo for AchillesAPI regression tests')
security = HTTPBearer()
collections = {}
documents = {}

class Fixture(BaseModel):
    label: str = Field(min_length=1,max_length=80)

class DocumentFixture(Fixture):
    parent: str


def identity(value: HTTPAuthorizationCredentials = Depends(security)) -> str:
    if value.credentials not in {'lab-alice','lab-bob'}:
        raise HTTPException(status_code=401,detail='Unknown test identity')
    return value.credentials

@app.get('/health')
def health():
    return {'ok':True}

@app.post('/collections',status_code=201)
def create_collection(body: Fixture, actor: str=Depends(identity)):
    key='col-'+uuid4().hex[:10]
    collections[key]={'id':key,'label':body.label,'owner':actor}
    return {'id':key}

@app.get('/collections/{collection_ref}')
def read_collection(collection_ref: str,actor: str=Depends(identity)):
    obj=collections.get(collection_ref)
    if not obj: raise HTTPException(status_code=404)
    # Intentionally vulnerable BOLA: test identities may read each other's objects.
    return obj

@app.delete('/collections/{collection_ref}',status_code=204)
def delete_collection(collection_ref:str,actor:str=Depends(identity)):
    obj=collections.get(collection_ref)
    if not obj: raise HTTPException(status_code=404)
    if obj['owner'] != actor: raise HTTPException(status_code=403)
    if any(item['parent']==collection_ref for item in documents.values()):
        raise HTTPException(status_code=409,detail='Delete children first')
    del collections[collection_ref]

@app.post('/collections/{collection_ref}/documents',status_code=201)
def create_document(collection_ref:str,body:DocumentFixture,actor:str=Depends(identity)):
    obj=collections.get(collection_ref)
    if not obj: raise HTTPException(status_code=404)
    if obj['owner']!=actor or body.parent!=collection_ref: raise HTTPException(status_code=403)
    key='doc-'+uuid4().hex[:10]
    documents[key]={'id':key,'label':body.label,'parent':collection_ref,'owner':actor}
    return {'id':key}

@app.get('/documents/{document_ref}')
def read_document(document_ref:str,actor:str=Depends(identity)):
    obj=documents.get(document_ref)
    if not obj: raise HTTPException(status_code=404)
    return obj  # Intentionally vulnerable BOLA for authorized test identities.

@app.delete('/documents/{document_ref}',status_code=204)
def delete_document(document_ref:str,actor:str=Depends(identity)):
    obj=documents.get(document_ref)
    if not obj: raise HTTPException(status_code=404)
    if obj['owner']!=actor: raise HTTPException(status_code=403)
    del documents[document_ref]

class SafeChange(BaseModel):
    note: str = Field(min_length=1, max_length=120)

@app.patch('/collections/{collection_ref}')
def change_collection(collection_ref:str, body: SafeChange, actor:str=Depends(identity)):
    """Change only a disposable note; owner and marker remain immutable."""
    obj=collections.get(collection_ref)
    if not obj: raise HTTPException(status_code=404)
    if obj['owner']!=actor:raise HTTPException(status_code=403)
    obj['note']=body.note
    return obj

@app.patch('/documents/{document_ref}')
def change_document(document_ref:str, body: SafeChange, actor:str=Depends(identity)):
    """Change only the note field, allowing regression tests for mutation state."""
    obj=documents.get(document_ref)
    if not obj:raise HTTPException(status_code=404)
    if obj['owner']!=actor:raise HTTPException(status_code=403)
    obj['note']=body.note
    return obj
