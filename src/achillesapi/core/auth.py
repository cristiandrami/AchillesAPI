"""Local authentication profiles backed exclusively by environment variables.

Secrets are never stored in profile files or returned by inspection helpers.
"""
from __future__ import annotations

import base64
import os
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
    type: Literal["bearer", "api_key", "basic", "cookie"]
    token_env: str | None = None
    username_env: str | None = None
    password_env: str | None = None
    value_env: str | None = None
    location: Literal["header", "query", "cookie"] | None = None
    parameter_name: str | None = None
    header_name: str | None = None

    @model_validator(mode="after")
    def validate_definition(self) -> "ProfileDefinition":
        if self.type == "bearer" and not self.token_env:
            raise ValueError("bearer profiles require token_env")
        if self.type == "basic" and not (self.username_env and self.password_env):
            raise ValueError("basic profiles require username_env and password_env")
        if self.type in {"api_key", "cookie"}:
            if not self.value_env:
                raise ValueError(f"{self.type} profiles require value_env")
            if not self.parameter_name:
                raise ValueError(f"{self.type} profiles require parameter_name")
        if self.type == "api_key" and self.location is None:
            raise ValueError("api_key profiles require location: header, query or cookie")
        if self.type == "cookie" and self.location not in {None, "cookie"}:
            raise ValueError("cookie profiles only support cookie location")
        if self.type in {"bearer", "basic"} and self.location is not None:
            raise ValueError(f"{self.type} profiles use the Authorization header")
        return self


class AuthenticationFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profiles: list[ProfileDefinition] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_names(self) -> "AuthenticationFile":
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
        return "AuthenticationMaterial(headers=[REDACTED], params=[REDACTED], cookies=[REDACTED])"


class AuthenticationManager:
    """Load named profiles and resolve their secrets from the process environment."""

    def __init__(self, config: AuthenticationFile) -> None:
        self._profiles = {profile.name: profile for profile in config.profiles}

    @classmethod
    def from_file(cls, path: str | Path) -> "AuthenticationManager":
        config_path = Path(path)
        try:
            raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise AuthenticationConfigError(f"Unable to read authentication config: {exc}") from exc
        if not isinstance(raw, dict):
            raise AuthenticationConfigError("Authentication config must be a YAML object.")
        try:
            return cls(AuthenticationFile.model_validate(raw))
        except ValidationError as exc:
            raise AuthenticationConfigError(f"Invalid authentication config: {exc}") from exc

    @property
    def names(self) -> list[str]:
        return sorted(self._profiles)

    def describe(self) -> list[dict[str, str | list[str]]]:
        """Return safe profile metadata without resolving or exposing secrets."""
        result: list[dict[str, str | list[str]]] = []
        for profile in self._profiles.values():
            env_names = [name for name in (
                profile.token_env, profile.username_env,
                profile.password_env, profile.value_env,
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
        if not name:
            raise AuthenticationConfigError(f"Profile {profile_name!r} has no environment variable configured.")
        value = os.environ.get(name)
        if value is None or value == "":
            raise AuthenticationConfigError(
                f"Environment variable {name!r} required by profile {profile_name!r} is not set."
            )
        return value

    def resolve(self, name: str) -> AuthenticationMaterial:
        profile = self._profiles.get(name)
        if profile is None:
            raise AuthenticationConfigError(f"Unknown authentication profile {name!r}.")
        material = AuthenticationMaterial()
        if profile.type == "bearer":
            token = self._required_env(profile.token_env, name)
            material.headers["Authorization"] = f"Bearer {token}"
        elif profile.type == "basic":
            username = self._required_env(profile.username_env, name)
            password = self._required_env(profile.password_env, name)
            encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
            material.headers["Authorization"] = f"Basic {encoded}"
        else:
            value = self._required_env(profile.value_env, name)
            key = profile.parameter_name or ""
            if profile.type == "cookie" or profile.location == "cookie":
                material.cookies[key] = value
            elif profile.location == "query":
                material.params[key] = value
            else:
                material.headers[profile.header_name or key] = value
        return material


def load_authentication_manager(path: str | Path) -> AuthenticationManager:
    return AuthenticationManager.from_file(path)
