"""Independent, deliberately vulnerable FastAPI training target. LOOPBACK ONLY.

This application is not imported by AchillesAPI's production modules.
Never deploy it on a network interface or the public internet.
"""
from __future__ import annotations
from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field
from uuid import uuid4

app = FastAPI(title="Harbor Inventory API (training only)", version="1.0.0", servers=[{"url":"http://127.0.0.1:8765"}])
records = {"inv-b": {"id":"inv-b", "owner":"bob", "label":"Bob's asset", "internal_note":"confidential-demo", "is_approved":False}}

class NewAsset(BaseModel):
    label: str = Field(min_length=3, max_length=60, examples=["temporary-test-asset"])
    owner: str = Field(examples=["alice"])

class Asset(BaseModel):
    id: str
    owner: str
    label: str
    internal_note: str = Field(default="confidential-demo", json_schema_extra={"writeOnly":True})
    is_approved: bool = False

class PatchAsset(BaseModel):
    label: str | None = None
    is_approved: bool | None = None

def who(authorization: str | None) -> str:
    """Resolve deliberately simple training credentials, not production authentication."""
    if authorization == "Bearer demo-alice": return "alice"
    if authorization == "Bearer demo-bob": return "bob"
    if authorization == "Bearer demo-admin": return "admin"
    raise HTTPException(401, "demo token required")

@app.get("/health", tags=["diagnostics"])
def health():
    return {"ok":True}

@app.get("/v2/inventory/{asset_ref}", response_model=Asset, tags=["inventory"])
def vulnerable_read(asset_ref: str, authorization: str | None = Header(None)):
    """Intentionally vulnerable: any logged-in user can read another user's asset."""
    who(authorization)
    if asset_ref not in records: raise HTTPException(404, "missing")
    return records[asset_ref]

@app.get("/v2/secure/inventory/{asset_ref}", response_model=Asset, tags=["inventory"])
def protected_read(asset_ref: str, authorization: str | None = Header(None)):
    actor = who(authorization)
    if asset_ref not in records: raise HTTPException(404, "missing")
    if actor not in (records[asset_ref]["owner"], "admin"): raise HTTPException(403, "forbidden")
    return records[asset_ref]

@app.get("/v2/admin/exports", tags=["admin"])
def vulnerable_admin(authorization: str | None = Header(None)):
    who(authorization)
    return {"export":"demo-data", "count":len(records)}

@app.get("/v2/secure/admin/exports", tags=["admin"])
def protected_admin(authorization: str | None = Header(None)):
    if who(authorization) != "admin": raise HTTPException(403, "admin only")
    return {"export":"demo-data", "count":len(records)}

@app.get("/v2/search", tags=["search"])
def search(term: str = Query(min_length=1, max_length=32), authorization: str | None = Header(None)):
    who(authorization)
    if "'" in term: raise HTTPException(500, "simulated SQL syntax error - no SQL database")
    return {"results": [v["id"] for v in records.values() if term.lower() in v["label"].lower()]}

@app.post("/v2/inventory", status_code=201, response_model=Asset, tags=["inventory"])
def create_asset(payload: NewAsset, authorization: str | None = Header(None)):
    actor = who(authorization)
    if payload.owner != actor and actor != "admin": raise HTTPException(403, "owner mismatch")
    asset_ref = "inv-" + uuid4().hex[:12]
    records[asset_ref] = {"id":asset_ref,"owner":payload.owner,"label":payload.label,
                          "internal_note":"confidential-demo","is_approved":False}
    return records[asset_ref]

@app.patch("/v2/inventory/{asset_ref}", response_model=Asset, tags=["inventory"])
def vulnerable_patch(asset_ref: str, payload: PatchAsset, authorization: str | None = Header(None)):
    who(authorization)
    if asset_ref not in records: raise HTTPException(404, "missing")
    records[asset_ref].update(payload.model_dump(exclude_unset=True))
    return records[asset_ref]

@app.delete("/v2/inventory/{asset_ref}", status_code=204, tags=["inventory"])
def cleanup(asset_ref: str, authorization: str | None = Header(None)):
    actor = who(authorization)
    if asset_ref not in records: raise HTTPException(404, "missing")
    if actor != records[asset_ref]["owner"] and actor != "admin": raise HTTPException(403, "forbidden")
    if asset_ref == "inv-b": raise HTTPException(403, "seed asset cannot be deleted")
    del records[asset_ref]
    return None
