"""Training API: deliberately insecure endpoints paired with secure controls.

This API uses fake users, fake objects and in-memory state. It is not a real
application and MUST be served on 127.0.0.1 only. Vulnerable endpoints are
intentional demonstrations, never production patterns.
"""

from __future__ import annotations

import secrets
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.security import (
    APIKeyCookie,
    APIKeyHeader,
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
)
from pydantic import BaseModel, Field

app = FastAPI(
    title="AchillesAPI Full Training Lab",
    version="1.0.0",
    description=(
        "LOCAL TRAINING ONLY. Synthetic users and resources. Some routes intentionally "
        "omit authorization or expose errors; similarly named /secure/ routes enforce controls."
    ),
    servers=[{"url": "http://127.0.0.1:8000"}],
)

# Every token/password in this lab is fake, publicly documented and safe ONLY
# for local training. Real APIs must use proper secret storage and rotation.
DEMO_TOKENS = {"alice-token": "alice", "bob-token": "bob", "admin-token": "admin"}
DEMO_ROLES = {"alice": "user", "bob": "user", "admin": "admin"}
DEMO_API_KEYS = {"partner-demo-key": "partner"}
DEMO_SESSIONS = {"alice-session": "alice", "bob-session": "bob"}

_BEARER = HTTPBearer(auto_error=False)
_BASIC = HTTPBasic(auto_error=False)
_API_KEY = APIKeyHeader(name="X-API-Key", auto_error=False)
_COOKIE = APIKeyCookie(name="sessionid", auto_error=False)

# In-memory fixtures: stop/restart the API to restore the default dataset.
ORDERS: dict[str, dict[str, str]] = {
    "order-alice": {"id": "order-alice", "owner": "alice", "item": "Laptop stand"},
    "order-bob": {"id": "order-bob", "owner": "bob", "item": "Keyboard"},
}
PROFILES: dict[str, dict[str, Any]] = {
    "alice": {"username": "alice", "displayName": "Alice", "is_admin": False, "private_note": "internal-demo-only", "api_token": "synthetic-not-a-real-token"},
    "bob": {"username": "bob", "displayName": "Bob", "is_admin": False, "private_note": "internal-demo-only", "api_token": "synthetic-not-a-real-token"},
}
REPORTS: dict[str, dict[str, str]] = {}


class ProfileDetailed(BaseModel):
    """Intentionally overexposed profile format used by a vulnerable GET."""

    username: str
    displayName: str
    is_admin: bool
    private_note: str
    api_token: str = Field(description="Synthetic internal field, never a real credential")


class ProfilePublic(BaseModel):
    """Safe profile format: return only public fields after ownership checks."""

    username: str
    displayName: str


class ProfilePatch(BaseModel):
    """Accepted profile data, including a restricted field for the lab exercise."""

    displayName: str | None = Field(default=None, min_length=1, max_length=60)
    is_admin: bool | None = Field(
        default=None,
        description="Server-controlled admin flag; the vulnerable route accepts it anyway.",
        json_schema_extra={"readOnly": True},
    )


class ReportCreate(BaseModel):
    """Body used to demonstrate a POST -> GET resource workflow."""

    title: str = Field(min_length=1, max_length=80, examples=["Approved testing report"])


class ReportOut(BaseModel):
    """Non-sensitive representation of a synthetic report."""

    report_ref: str
    owner: str
    title: str


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_BEARER),
) -> str:
    """Get the caller's fake identity from a demo Bearer token.

    In practice: send `Authorization: Bearer alice-token`, or use the auth
    profile from `examples/full-lab-auth.yaml`. Invalid tokens return 401.
    This dependency is not a vulnerability; endpoints decide permissions.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Demo Bearer token required")
    user = DEMO_TOKENS.get(credentials.credentials)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid demo token")
    return user


def require_admin(username: Annotated[str, Depends(current_user)]) -> str:
    """Require the fake admin role; used as the secure BFLA comparison."""
    if DEMO_ROLES[username] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return username


def _profile_for(username: str) -> dict[str, Any]:
    """Look up a lab profile; never auto-create arbitrary fake accounts."""
    profile = PROFILES.get(username)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


def _order_for(order_id: str) -> dict[str, str]:
    """Look up a synthetic order in memory; return 404 for an unknown ID."""
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return order


@app.get("/health", tags=["01 - Health"])
def health() -> dict[str, str]:
    """Return a harmless status to check that the laboratory is running."""
    return {"status": "ok", "service": "achillesapi-full-lab"}


@app.get("/api/orders/{order_id}", tags=["02 - BOLA vulnerable"])
def order_vulnerable(
    order_id: Annotated[str, Field(examples=["order-bob"])],
    caller: Annotated[str, Depends(current_user)],
) -> dict[str, str]:
    """DELIBERATE BOLA: any signed-in user reads another user's order.

    Try `order-bob` with alice-token. The server validates the token but DOES
    NOT compare caller to the order owner. Compare with `/api/secure/orders`.
    """
    del caller  # Demonstrates the missing ownership check on purpose.
    return _order_for(order_id).copy()


@app.get("/api/secure/orders/{order_id}", tags=["02 - BOLA protected"])
def order_secure(
    order_id: Annotated[str, Field(examples=["order-bob"])],
    caller: Annotated[str, Depends(current_user)],
) -> dict[str, str]:
    """PROTECTED BOLA control: only the actual owner can read an order."""
    order = _order_for(order_id)
    if order["owner"] != caller:
        raise HTTPException(status_code=403, detail="Order belongs to a different user")
    return order.copy()


@app.get("/api/admin/audit", tags=["03 - BFLA vulnerable"])
def audit_vulnerable(caller: Annotated[str, Depends(current_user)]) -> dict[str, str]:
    """DELIBERATE BFLA: non-admin identities can access an admin function."""
    return {"viewer": caller, "restricted_metric": "training-only", "policy": "admin-only"}


@app.get("/api/admin/metrics", tags=["03 - BFLA protected"])
def metrics_secure(caller: Annotated[str, Depends(require_admin)]) -> dict[str, str]:
    """PROTECTED BFLA control: only the fake admin identity receives metrics."""
    return {"viewer": caller, "restricted_metric": "training-only"}


@app.get("/api/profiles/{username}", response_model=ProfileDetailed, tags=["04 - BOPLA vulnerable"])
def profile_vulnerable(
    username: Annotated[str, Field(examples=["bob"])],
    caller: Annotated[str, Depends(current_user)],
) -> dict[str, Any]:
    """DELIBERATE property exposure: sends an internal private_note to peers.

    This route checks authentication only. Compare with `/api/secure/profiles`.
    """
    del caller
    return _profile_for(username).copy()


@app.get("/api/secure/profiles/{username}", response_model=ProfilePublic, tags=["04 - BOPLA protected"])
def profile_secure(
    username: Annotated[str, Field(examples=["bob"])],
    caller: Annotated[str, Depends(current_user)],
) -> dict[str, str]:
    """PROTECTED control: owner-only access and no internal profile fields."""
    if caller != username:
        raise HTTPException(status_code=403, detail="Own profile only")
    profile = _profile_for(username)
    return {"username": str(profile["username"]), "displayName": str(profile["displayName"])}


@app.patch("/api/profiles/{username}", tags=["05 - Mass assignment vulnerable"])
def profile_update_vulnerable(
    username: Annotated[str, Field(examples=["alice"])],
    changes: ProfilePatch,
    caller: Annotated[str, Depends(current_user)],
) -> dict[str, Any]:
    """DELIBERATE mass assignment: lets a user change the is_admin field.

    Only execute against local fake profiles. Stop/restart the lab to reset.
    """
    if caller != username:
        raise HTTPException(status_code=403, detail="Own profile only")
    profile = _profile_for(username)
    profile.update(changes.model_dump(exclude_unset=True))
    return profile.copy()


@app.patch("/api/secure/profiles/{username}", tags=["05 - Mass assignment protected"])
def profile_update_secure(
    username: Annotated[str, Field(examples=["alice"])],
    changes: ProfilePatch,
    caller: Annotated[str, Depends(current_user)],
) -> dict[str, Any]:
    """PROTECTED control: reject attempts to change is_admin."""
    if caller != username:
        raise HTTPException(status_code=403, detail="Own profile only")
    if changes.is_admin is not None:
        raise HTTPException(status_code=422, detail="is_admin is server controlled")
    profile = _profile_for(username)
    if changes.displayName is not None:
        profile["displayName"] = changes.displayName
    return profile.copy()


@app.get("/api/search", tags=["06 - SQLi signal vulnerable"])
def search_vulnerable(
    q: Annotated[str, Query(max_length=256)] = "",
    caller: Annotated[str, Depends(current_user)] = "",
) -> dict[str, str]:
    """SIMULATED SQL error disclosure triggered by a quote canary.

    There is NO actual SQL database or injectable query. This endpoint safely
    reproduces the *observable signal* detected by the legacy sqli-check.
    """
    del caller
    if "'" in q:
        raise HTTPException(status_code=500, detail="sqlite error: near quote (simulated)")
    return {"query": q, "result": "no results"}


@app.get("/api/secure/search", tags=["06 - SQLi signal protected"])
def search_secure(
    q: Annotated[str, Query(max_length=256)] = "",
    caller: Annotated[str, Depends(current_user)] = "",
) -> dict[str, str]:
    """PROTECTED control: treats apostrophes as regular input data."""
    del caller
    return {"query": q, "result": "no results"}


@app.get("/api/inventory", tags=["07 - Input validation"])
def inventory(
    limit: Annotated[int, Query(ge=1, le=20)] = 5,
    category: Annotated[str | None, Query(pattern="^(tools|books|office)$")] = None,
) -> dict[str, Any]:
    """Demonstrate schema-aware numeric boundaries and an enum-like category."""
    return {"limit": limit, "category": category, "items": ["lab-item-1"]}


@app.get("/api/catalog/{sku}", tags=["08 - Nonstandard identifiers"])
def catalog(
    sku: Annotated[str, Field(examples=["SKU-1001"])],
) -> dict[str, str]:
    """Demonstrate an object ID named sku, not order_id or userId."""
    if sku != "SKU-1001":
        raise HTTPException(status_code=404, detail="SKU not found")
    return {"sku": sku, "name": "Demo safety goggles"}


@app.post("/api/reports", response_model=ReportOut, status_code=201, tags=["09 - Workflow"])
def create_report(payload: ReportCreate, caller: Annotated[str, Depends(current_user)]) -> ReportOut:
    """Create a synthetic report to demonstrate POST -> GET workflow planning.

    `auto-assess` will *not* send this POST. Operators can create reports
    manually for isolated lifecycle tests. IDs exist only in memory.
    """
    key = f"lab-{secrets.token_hex(4)}"
    REPORTS[key] = {"report_ref": key, "owner": caller, "title": payload.title}
    return ReportOut(**REPORTS[key])


@app.get("/api/reports/{report_ref}", response_model=ReportOut, tags=["09 - Workflow"])
def get_report(
    report_ref: str,
    caller: Annotated[str, Depends(current_user)],
) -> ReportOut:
    """Read a synthetic report; enforce ownership to provide a safe control."""
    report = REPORTS.get(report_ref)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if report["owner"] != caller:
        raise HTTPException(status_code=403, detail="Own report only")
    return ReportOut(**report)


@app.get("/api/basic/account", tags=["10 - Auth variants"])
def basic_account(credentials: HTTPBasicCredentials | None = Depends(_BASIC)) -> dict[str, str]:
    """Accept demo HTTP Basic credentials (lab-user / lab-pass)."""
    if credentials is None or not (secrets.compare_digest(credentials.username, "lab-user")
                                   and secrets.compare_digest(credentials.password, "lab-pass")):
        raise HTTPException(status_code=401, detail="Basic authentication required")
    return {"identity": "lab-user", "method": "basic"}


@app.get("/api/partner/summary", tags=["10 - Auth variants"])
def partner_summary(key: str | None = Depends(_API_KEY)) -> dict[str, str]:
    """Accept a demo API key from the X-API-Key request header."""
    if key not in DEMO_API_KEYS:
        raise HTTPException(status_code=401, detail="API key required")
    return {"identity": DEMO_API_KEYS[key], "method": "api_key"}


@app.get("/api/session/me", tags=["10 - Auth variants"])
def cookie_me(sessionid: str | None = Depends(_COOKIE)) -> dict[str, str]:
    """Accept a demo sessionid cookie without requiring a Bearer token."""
    if sessionid not in DEMO_SESSIONS:
        raise HTTPException(status_code=401, detail="Session cookie required")
    return {"identity": DEMO_SESSIONS[sessionid], "method": "cookie"}
