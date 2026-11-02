"""Typed representations of the API surface extracted from OpenAPI."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ParameterInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    location: str = Field(alias="in")
    required: bool = False
    description: str | None = None
    schema_: dict[str, Any] = Field(default_factory=dict, alias="schema")
    style: str | None = None
    explode: bool | None = None


class SecurityRequirementInfo(BaseModel):
    """A security requirement: scheme name mapped to required scopes."""

    schemes: dict[str, list[str]] = Field(default_factory=dict)


class SecuritySchemeInfo(BaseModel):
    scheme_name: str
    type: str
    scheme: str | None = None
    bearer_format: str | None = None
    in_: str | None = Field(default=None, alias="in")
    parameter_name: str | None = Field(default=None, alias="name")
    description: str | None = None
    flows: dict[str, Any] | None = None
    open_id_connect_url: str | None = Field(default=None, alias="openIdConnectUrl")


class EndpointInfo(BaseModel):
    """Normalized metadata for one HTTP operation."""

    path: str
    method: str
    operation_id: str | None = None
    summary: str | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    parameters: list[ParameterInfo] = Field(default_factory=list)
    request_body: dict[str, Any] | None = None
    responses: dict[str, Any] = Field(default_factory=dict)
    security: list[SecurityRequirementInfo] = Field(default_factory=list)
    security_is_explicitly_disabled: bool = False
    servers: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def path_parameters(self) -> list[ParameterInfo]:
        return [parameter for parameter in self.parameters if parameter.location == "path"]

    @property
    def query_parameters(self) -> list[ParameterInfo]:
        return [parameter for parameter in self.parameters if parameter.location == "query"]


class ParsedAPI(BaseModel):
    """The normalized API description produced by the OpenAPI parser."""

    title: str
    version: str
    openapi_version: str
    description: str | None = None
    servers: list[dict[str, Any]] = Field(default_factory=list)
    security_schemes: list[SecuritySchemeInfo] = Field(default_factory=list)
    endpoints: list[EndpointInfo] = Field(default_factory=list)

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)
