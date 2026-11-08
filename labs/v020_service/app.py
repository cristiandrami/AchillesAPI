"""Independent, loopback-only training API for v0.17-v0.20 integration.

DEMO CREDENTIALS ONLY. Do not expose this intentionally imperfect API on a
public interface or put its tokens into any real service.
"""
from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

app = FastAPI(title="Unrelated Contractor Platform", version="2026.1",
              description="Local verification target, independent from AchillesAPI core.")
scheme = HTTPBearer()


class Org(BaseModel):
    organization_ref: str
    display_name: str


class Listing(BaseModel):
    organizations: list[Org]


class Settings(BaseModel):
    mode: str
    private_key: str = Field(json_schema_extra={"writeOnly": True})


def token_guard(value: HTTPAuthorizationCredentials = Depends(scheme)) -> str:
    """Accept only local demo tokens; no real identity system is involved."""
    if value.credentials not in {"demo-workload-token", "demo-user-token"}:
        raise HTTPException(403, "Invalid demo token")
    return value.credentials


@app.post("/oauth/token")
async def oauth_token(request: Request):
    """Mock OAuth2 client-credentials endpoint (uses demo-only Basic credentials)."""
    authorization = request.headers.get("authorization", "")
    import base64
    required = "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()
    if authorization != required:
        raise HTTPException(401, "Invalid test client")
    body = (await request.body()).decode("utf-8")
    if "grant_type=client_credentials" not in body:
        raise HTTPException(400, "Invalid grant")
    return {"access_token": "demo-workload-token", "token_type": "bearer", "expires_in": 600}


class Login(BaseModel):
    username: str
    password: str


@app.post("/session")
def session(data: Login):
    """JSON-login example returning a nested token pointer."""
    if data.username != "demo-user" or data.password != "demo-password":
        raise HTTPException(401, "Invalid test user")
    return {"session": {"access_token": "demo-user-token"}, "expires_in": 600}


@app.get("/api/organizations", response_model=Listing)
def organizations(token: str = Depends(token_guard)):
    """Produce a nonstandard identifier name for the next GET."""
    return {"organizations": [{"organization_ref": "org-317", "display_name": "Alpha test organization"}]}


@app.get("/api/organizations/{organization_ref}", response_model=Org)
def organization(organization_ref: str, token: str = Depends(token_guard)):
    """Read an object after obtaining its ID from a previous response."""
    if organization_ref != "org-317":
        raise HTTPException(404)
    return {"organization_ref": "org-317", "display_name": "Alpha test organization"}


@app.get("/api/organizations/{organization_ref}/settings", response_model=Settings)
def settings(organization_ref: str, token: str = Depends(token_guard)):
    """Deliberately return a documented writeOnly field: disclosure test."""
    if organization_ref != "org-317":
        raise HTTPException(404)
    return {"mode": "test", "private_key": "LAB-ONLY-DO-NOT-USE"}


@app.get("/api/failure")
def failure(token: str = Depends(token_guard)):
    """Stable 503 used to test bounded adaptive verification, not an exploit."""
    raise HTTPException(503, "Synthetic test failure")


@app.get("/health")
def health():
    """Return service readiness without credentials."""
    return {"ok": True}
