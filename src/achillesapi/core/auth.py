"""Local authentication profiles: inline YAML values or environment variables.

Inline values are sensitive. Do not commit auth.yaml to version control.
"""
from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class AuthenticationConfigError(ValueError):
    """Raised when an authentication profile is invalid or incomplete."""


class ProfileDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, pattern=r"^[A-Za-z0-9_.-]+$")
    role: str | None = None
    type: Literal["bearer", "api_key", "basic", "cookie", "oauth2_client_credentials", "oauth2_refresh_token", "oauth2_authorization_code", "login_json"]
    token_env: str | None = None
    token: str | None = Field(default=None, repr=False, min_length=1)
    username_env: str | None = None
    username: str | None = Field(default=None, repr=False, min_length=1)
    password_env: str | None = None
    password: str | None = Field(default=None, repr=False, min_length=1)
    value_env: str | None = None
    value: str | None = Field(default=None, repr=False, min_length=1)
    location: Literal["header", "query", "cookie"] | None = None
    parameter_name: str | None = None
    header_name: str | None = None
    # Dynamic auth: no credentials stored in YAML, no remote token URL inferred.
    token_url: str | None = None
    login_url: str | None = None
    refresh_token_env: str | None = None
    refresh_token: str | None = Field(default=None, repr=False, min_length=1)
    authorization_code_env: str | None = None
    code_verifier_env: str | None = None
    redirect_uri: str | None = None
    client_id_env: str | None = None
    client_id: str | None = Field(default=None, repr=False, min_length=1)
    client_secret_env: str | None = None
    client_secret: str | None = Field(default=None, repr=False, min_length=1)
    scopes: list[str] = Field(default_factory=list)
    # RC18: opt-in local JWT signature+claims verification before using a token.
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks: dict | None = Field(default=None, repr=False)
    oidc_jwks_file: str | None = None
    username_field: str = "username"
    password_field: str = "password"
    token_pointer: str = "/access_token"

    @model_validator(mode="after")
    def validate_definition(self) -> "ProfileDefinition":
        """In pratica: Verifica che ciascun profilo contenga i campi richiesti dal suo tipo.

    Attenzione: Questa funzione non contatta direttamente l'API target.
    """
        if any((self.oidc_issuer, self.oidc_audience, self.oidc_jwks, self.oidc_jwks_file)):
            if not (self.oidc_issuer and self.oidc_audience and
                    (self.oidc_jwks is not None) != (self.oidc_jwks_file is not None)):
                raise ValueError('OIDC verification requires pinned issuer, audience, and exactly one JWKS source')
            if self.type not in {'bearer', 'oauth2_client_credentials', 'oauth2_refresh_token',
                                 'oauth2_authorization_code', 'login_json'}:
                raise ValueError('OIDC JWT verification requires a bearer token profile')
        if self.type == "oauth2_client_credentials" and not (
            self.token_url and (self.client_id_env or self.client_id) and (self.client_secret_env or self.client_secret)
        ):
            raise ValueError("oauth2_client_credentials requires token_url and client ID/secret environment names")
        if self.type == "oauth2_refresh_token" and not (
            self.token_url and (self.client_id_env or self.client_id)
            and (self.refresh_token_env or self.refresh_token)
        ):
            raise ValueError("oauth2_refresh_token needs token_url, client_id and refresh_token")
        if self.type == "oauth2_authorization_code" and not (
            self.token_url and (self.client_id_env or self.client_id)
            and self.authorization_code_env and self.code_verifier_env and self.redirect_uri
        ):
            raise ValueError("authorization_code requires explicit token_url, client ID, code, PKCE verifier and redirect URI")
        if self.type == "login_json" and not (
            self.login_url and (self.username_env or self.username) and (self.password_env or self.password)
        ):
            raise ValueError("login_json requires login_url and username/password environment names")
        if self.type in {"oauth2_client_credentials", "oauth2_refresh_token", "oauth2_authorization_code", "login_json"} and (
            self.location is not None or self.value_env or self.token_env or self.value or self.token
        ):
            raise ValueError("dynamic profiles cannot specify static token or location")
        if self.type == "bearer" and not (self.token_env or self.token):
            raise ValueError("bearer profiles require token or token_env")
        if self.type == "basic" and not ((self.username_env or self.username) and (self.password_env or self.password)):
            raise ValueError("basic profiles require username/password or username_env/password_env")
        if self.type in {"api_key", "cookie"}:
            if not (self.value_env or self.value):
                raise ValueError(f"{self.type} profiles require value or value_env")
            if not self.parameter_name:
                raise ValueError(f"{self.type} profiles require parameter_name")
        if self.type == "api_key" and self.location is None:
            raise ValueError("api_key profiles require location: header, query or cookie")
        if self.type == "cookie" and self.location not in {None, "cookie"}:
            raise ValueError("cookie profiles only support cookie location")
        # Reject ambiguous credentials rather than silently choosing one source.
        for inline, env, key in (
            (self.token, self.token_env, "token"),
            (self.username, self.username_env, "username"),
            (self.password, self.password_env, "password"),
            (self.value, self.value_env, "value"),
            (self.client_id, self.client_id_env, "client_id"),
            (self.client_secret, self.client_secret_env, "client_secret"),
            (self.refresh_token, self.refresh_token_env, "refresh_token"),
        ):
            if inline is not None and env is not None:
                raise ValueError(f"Use {key} OR {key}_env, not both")
        if self.type in {"bearer", "basic"} and self.location is not None:
            raise ValueError(f"{self.type} profiles use the Authorization header")
        return self


class AuthenticationFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profiles: list[ProfileDefinition] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_names(self) -> "AuthenticationFile":
        """In pratica: Impedisce due profili con lo stesso nome.

    Attenzione: Questa funzione non contatta direttamente l'API target.
    """
        names = [profile.name for profile in self.profiles]
        if len(names) != len(set(names)):
            raise ValueError("authentication profile names must be unique")
        return self


@dataclass(repr=False)
class AuthenticationMaterial:
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        """In pratica: Mostra una rappresentazione che non rivela i segreti.

    Attenzione: Questa funzione non contatta direttamente l'API target.
    """
        return "AuthenticationMaterial(headers=[REDACTED], params=[REDACTED], cookies=[REDACTED])"


class AuthenticationManager:
    """Load profiles and resolve inline YAML or environment-backed secrets."""

    def __init__(self, config: AuthenticationFile) -> None:
        """In pratica: Inizializza lo stato e le regole di funzionamento del componente.

    Attenzione: Questa funzione non contatta direttamente l'API target.
    """
        self._profiles = {profile.name: profile for profile in config.profiles}
        self._dynamic_cache: dict[str, tuple[AuthenticationMaterial, float]] = {}
        self._rotated_refresh_tokens: dict[str, str] = {}
        self._used_authorization_codes: set[str] = set()
        self.auth_requests_made = 0
        self.max_auth_requests = 10
        self._base_dir: Path | None = None

    @classmethod
    def from_file(cls, path: str | Path) -> "AuthenticationManager":
        """In pratica: Legge e valida la configurazione dei profili dal disco.

    Attenzione: Questa funzione non contatta direttamente l'API target.
    """
        config_path = Path(path)
        try:
            raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise AuthenticationConfigError("Unable to read authentication config: invalid or unreadable YAML (content suppressed)") from exc
        if not isinstance(raw, dict):
            raise AuthenticationConfigError("Authentication config must be a YAML object.")
        try:
            manager = cls(AuthenticationFile.model_validate(raw))
            manager._base_dir = config_path.resolve().parent
            return manager
        except ValidationError as exc:
            if any("authentication profile names must be unique" in error.get("msg", "") for error in exc.errors(include_input=False)):
                raise AuthenticationConfigError("Authentication profile names must be unique") from exc
            raise AuthenticationConfigError("Invalid authentication config: check field names, credential types, and required values (details suppressed to protect secrets)") from exc

    def invalidate(self, name: str) -> None:
        """Scarta un token dinamico: al prossimo resolve faremo login di nuovo.

        Nota: non richiamiamo mai il server automaticamente per metodi di scrittura.
        """
        if name not in self._profiles:
            raise AuthenticationConfigError('Profilo di autenticazione sconosciuto')
        self._dynamic_cache.pop(name, None)

    def is_dynamic(self, name: str) -> bool:
        """Indica se il profilo può ottenere un token rinnovabile."""
        profile = self._profiles.get(name)
        return bool(profile and profile.type in {'oauth2_client_credentials', 'oauth2_refresh_token', 'oauth2_authorization_code', 'login_json'})

    @property
    def names(self) -> list[str]:
        """In pratica: Elenca i nomi dei profili disponibili.

    Attenzione: Questa funzione non contatta direttamente l'API target.
    """
        return sorted(self._profiles)

    def describe(self) -> list[dict[str, str | list[str]]]:
        """Return safe profile metadata without resolving or exposing secrets."""
        # IN PRATICA: Mostra profili e nomi delle variabili richieste senza stampare password o token.
        # SICUREZZA: Non contatta direttamente l'API target.
        result: list[dict[str, str | list[str]]] = []
        for profile in self._profiles.values():
            env_names = [name for name in (
                profile.token_env, profile.username_env,
                profile.password_env, profile.value_env,
                profile.client_id_env, profile.client_secret_env,
                profile.refresh_token_env, profile.authorization_code_env,
                profile.code_verifier_env,
            ) if name]
            item: dict[str, str | list[str]] = {
                "name": profile.name,
                "type": profile.type,
                "location": profile.location or ("cookie" if profile.type == "cookie" else "header"),
                "environment_variables": env_names,
            }
            if profile.role:
                item["role"] = profile.role
            result.append(item)
        return sorted(result, key=lambda item: str(item["name"]))

    @staticmethod
    def _required_env(name: str | None, profile_name: str) -> str:
        """In pratica: Legge un segreto da una variabile d'ambiente e segnala se manca.

    Attenzione: Questa funzione non contatta direttamente l'API target.
    """
        if not name:
            raise AuthenticationConfigError(f"Profile {profile_name!r} has no environment variable configured.")
        value = os.environ.get(name)
        if value is None or value == "":
            raise AuthenticationConfigError(
                f"Environment variable {name!r} required by profile {profile_name!r} is not set."
            )
        return value

    def _enforce_oidc(self, profile: ProfileDefinition, material: AuthenticationMaterial) -> None:
        """Pin JWT signature/issuer/audience before giving tokens to any HTTP task."""
        if not profile.oidc_issuer:
            return
        from achillesapi.core.oidc_enterprise_rc18 import verify_access_token, OIDCSafetyError
        public_jwks = profile.oidc_jwks
        if profile.oidc_jwks_file:
            path = Path(profile.oidc_jwks_file)
            if (path.is_absolute() or self._base_dir is None or
                    not (self._base_dir / path).resolve().is_relative_to(self._base_dir)):
                raise AuthenticationConfigError('OIDC JWKS path must be local to auth.yaml directory')
            path = (self._base_dir / path).resolve()
            try:
                if path.stat().st_size > 128 * 1024:
                    raise ValueError('JWKS too large')
                import json
                public_jwks = json.loads(path.read_text(encoding='utf-8'))
            except (OSError, ValueError) as exc:
                raise AuthenticationConfigError('OIDC public JWKS file unavailable or invalid') from exc
        bearer = material.headers.get('Authorization', '')
        if not bearer.startswith('Bearer '):
            raise AuthenticationConfigError('OIDC verification requires bearer token')
        try:
            result = verify_access_token(bearer[7:], public_jwks or {},
                                         expected_issuer=profile.oidc_issuer,
                                         expected_audience=profile.oidc_audience or '',
                                         required_scopes=tuple(profile.scopes))
        except (OIDCSafetyError, TypeError, ValueError) as exc:
            raise AuthenticationConfigError('OIDC token verification configuration invalid') from exc
        if result['status'] != 'verified':
            raise AuthenticationConfigError('OIDC token signature or claims validation failed: '+result['reason'])

    def resolve(self, name: str, *, allowed_hosts: set[str] | None = None,
                allow_insecure_http: bool = False) -> AuthenticationMaterial:
        """In pratica: Converte un profilo in header, query parameter e cookie realmente utilizzabili.

    Attenzione: Questa funzione non contatta direttamente l'API target.
    """
        profile = self._profiles.get(name)
        if profile is None:
            raise AuthenticationConfigError(f"Unknown authentication profile {name!r}.")
        if profile.type in {"oauth2_client_credentials", "oauth2_refresh_token", "oauth2_authorization_code", "login_json"}:
            if not allowed_hosts:
                raise AuthenticationConfigError("Dynamic authentication requires an explicit approved host allowlist")
            # Even a cached token can only be used while the original grant
            # endpoint remains inside the currently approved scope.
            from achillesapi.core.auth_dynamic import _validate_auth_url
            auth_url = profile.login_url if profile.type == "login_json" else profile.token_url
            _validate_auth_url(auth_url, allowed_hosts, allow_insecure_http)
            cached = self._dynamic_cache.get(name)
            if cached and cached[1] > time.monotonic():
                return cached[0]
            if (profile.type == 'oauth2_authorization_code' and name in self._used_authorization_codes
                    and name not in self._rotated_refresh_tokens):
                raise AuthenticationConfigError(
                    'Authorization Code PKCE già utilizzato; esegui un nuovo consenso OIDC/OAuth oppure fornisci refresh token')
            if self.auth_requests_made >= self.max_auth_requests:
                raise AuthenticationConfigError("Dynamic authentication request budget exceeded")
            # Count an attempted request even if the endpoint refuses credentials.
            self.auth_requests_made += 1
            from achillesapi.core.auth_dynamic import acquire_with_refresh
            material, expiry, rotated = acquire_with_refresh(
                profile, allowed_hosts=allowed_hosts,
                allow_insecure_http=allow_insecure_http,
                refresh_override=self._rotated_refresh_tokens.get(name),
                prefer_refresh=(profile.type == 'oauth2_authorization_code'
                                and name in self._rotated_refresh_tokens))
            if profile.type == 'oauth2_authorization_code':
                self._used_authorization_codes.add(name)
            if rotated:
                self._rotated_refresh_tokens[name] = rotated
            self._enforce_oidc(profile, material)
            self._dynamic_cache[name] = (material, expiry)
            return material
        material = AuthenticationMaterial()
        if profile.type == "bearer":
            token = profile.token if profile.token is not None else self._required_env(profile.token_env, name)
            material.headers["Authorization"] = f"Bearer {token}"
        elif profile.type == "basic":
            username = profile.username if profile.username is not None else self._required_env(profile.username_env, name)
            password = profile.password if profile.password is not None else self._required_env(profile.password_env, name)
            encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
            material.headers["Authorization"] = f"Basic {encoded}"
        else:
            value = profile.value if profile.value is not None else self._required_env(profile.value_env, name)
            key = profile.parameter_name or ""
            if profile.type == "cookie" or profile.location == "cookie":
                material.cookies[key] = value
            elif profile.location == "query":
                material.params[key] = value
            else:
                material.headers[profile.header_name or key] = value
        self._enforce_oidc(profile, material)
        return material


def load_authentication_manager(path: str | Path) -> AuthenticationManager:
    """In pratica: Carica i profili di autenticazione definiti nel file YAML.

    Attenzione: Non contatta direttamente l'API target.
    """
    return AuthenticationManager.from_file(path)
