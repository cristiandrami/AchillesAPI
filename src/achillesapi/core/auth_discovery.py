"""Generate human-reviewable, secret-free auth profile drafts from OpenAPI."""
from __future__ import annotations

import re
from typing import Any

from achillesapi.models.api import ParsedAPI


def draft_auth_profiles(parsed: ParsedAPI) -> dict[str, Any]:
    """Choose profile formats from declared schemes, without resolving secrets."""
    results = []
    manual = []
    for scheme in parsed.security_schemes:
        name = re.sub(r"[^a-zA-Z0-9_]", "_", scheme.scheme_name).upper()
        item: dict[str, Any] = {"name": scheme.scheme_name}
        if scheme.type == "http" and (scheme.scheme or "").lower() == "bearer":
            item.update(type="bearer", token_env="ACHILLES_" + name + "_TOKEN")
        elif scheme.type == "http" and (scheme.scheme or "").lower() == "basic":
            item.update(type="basic", username_env="ACHILLES_" + name + "_USER",
                        password_env="ACHILLES_" + name + "_PASSWORD")
        elif scheme.type == "apiKey" and scheme.in_ in {"query", "header", "cookie"}:
            item.update(type="api_key", location=scheme.in_, parameter_name=scheme.parameter_name,
                        value_env="ACHILLES_" + name + "_KEY")
        elif scheme.type == "oauth2" and isinstance(scheme.flows, dict) and isinstance(scheme.flows.get("clientCredentials"), dict):
            flow = scheme.flows["clientCredentials"]
            if isinstance(flow.get("tokenUrl"), str) and flow["tokenUrl"].startswith(("http://", "https://")):
                item.update(type="oauth2_client_credentials", token_url=flow["tokenUrl"],
                            client_id_env="ACHILLES_" + name + "_CLIENT_ID",
                            client_secret_env="ACHILLES_" + name + "_CLIENT_SECRET")
            else:
                manual.append(scheme.scheme_name + ": specify a concrete token URL")
                continue
        else:
            manual.append(scheme.scheme_name + ": configure a compatible auth flow manually")
            continue
        results.append(item)
    return {"profiles": results, "manual_configuration_required": manual}
