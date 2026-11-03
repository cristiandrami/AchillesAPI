"""A tiny local API with vulnerable and protected order endpoints.

This application is intentionally vulnerable for local training only. Never
expose it to a public network or deploy it as a real service.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

app = FastAPI(
    title="AchillesAPI Local Security Lab",
    version="1.1.0",
    description=(
        "Local-only training API for BOLA, BFLA and mass-assignment security exercises."
    ),
)

_bearer = HTTPBearer(auto_error=False)
_TOKENS = {"alice-token": "alice", "bob-token": "bob", "admin-token": "admin"}
_ROLES = {"alice": "user", "bob": "user", "admin": "admin"}
_PROFILES = {"alice": {"username": "alice", "displayName": "Alice", "is_admin": False},
             "bob": {"username": "bob", "displayName": "Bob", "is_admin": False}}
_ORDERS = {
    "order-alice": {"id": "order-alice", "owner": "alice", "item": "Laptop stand"},
    "order-bob": {"id": "order-bob", "owner": "bob", "item": "Mechanical keyboard"},
}


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Bearer token required")
    username = _TOKENS.get(credentials.credentials)
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid bearer token")
    return username


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "AchillesAPI Local BOLA Lab"}


@app.get("/api/orders/{order_id}", tags=["orders"])
def get_order_vulnerable(
    order_id: str, username: str = Depends(current_user)
) -> dict[str, str]:
    """Intentionally vulnerable: authenticates the caller but never checks ownership."""
    del username
    order = _ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return order.copy()


@app.get("/api/secure/orders/{order_id}", tags=["orders", "secure"])
def get_order_secure(
    order_id: str, username: str = Depends(current_user)
) -> dict[str, str]:
    """Control endpoint: only the owner can read the order."""
    order = _ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    if order["owner"] != username:
        raise HTTPException(status_code=403, detail="Forbidden")
    return order.copy()


@app.get("/api/admin/metrics", tags=["authorization", "admin"])
def admin_metrics(username: str = Depends(current_user)) -> dict[str, str]:
    """Role-protected endpoint for BFLA training."""
    if _ROLES.get(username) != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return {"service": "local-lab", "metric": "training-only"}


@app.patch("/api/profiles/{username}", tags=["mass-assignment"])
def update_profile_vulnerable(
    username: str, payload: dict, caller: str = Depends(current_user)
) -> dict:
    """Intentionally vulnerable: mass-assigns every caller-supplied field."""
    if caller != username:
        raise HTTPException(status_code=403, detail="Own profile only")
    profile = _PROFILES.setdefault(username, {"username": username, "displayName": username, "is_admin": False})
    profile.update(payload)
    return profile.copy()


@app.patch("/api/secure/profiles/{username}", tags=["mass-assignment", "secure"])
def update_profile_secure(
    username: str, payload: dict, caller: str = Depends(current_user)
) -> dict:
    """Control endpoint: only the explicitly allowed displayName is mutable."""
    if caller != username:
        raise HTTPException(status_code=403, detail="Own profile only")
    profile = _PROFILES.setdefault(username, {"username": username, "displayName": username, "is_admin": False})
    if set(payload) - {"displayName"}:
        raise HTTPException(status_code=422, detail="Unsupported profile field")
    if "displayName" in payload:
        profile["displayName"] = str(payload["displayName"])
    return profile.copy()


@app.get("/api/search", tags=["input-validation"])
def search(q: str = Query(default="", max_length=256), username: str = Depends(current_user)) -> dict[str, str]:
    """Harmless search endpoint for parameter fuzzing and safe SQLi canaries."""
    del username
    return {"query": q, "result": "no matching records"}
