from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    kind: str
    name: str | None = None
    file: str
    line: int | None = None
    function: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    kind: str


class NormalizedGraph(BaseModel):
    backend: str
    root: str
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class CryptoFinding(BaseModel):
    api_name: str
    node_id: str
    file: str
    line: int | None = None
    function: str | None = None
    algorithm: str
    primitive: str
    provider: str | None = None
    arguments: list[str] = Field(default_factory=list)
    risk: Literal["info", "low", "medium", "high", "critical"] = "info"
    rule_ids: list[str] = Field(default_factory=list)
    rule_messages: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)

