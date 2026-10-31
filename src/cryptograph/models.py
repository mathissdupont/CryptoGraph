from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_serializer


class GraphNode(BaseModel):
    id: str
    kind: str
    name: str | None = None
    file: str
    line: int | None = None
    function: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)

    @field_serializer('properties', when_used='json')
    def serialize_properties(self, value):
        # Keep binary literals explicit; decoding arbitrary bytes as UTF-8 loses
        # their type and can fail on otherwise valid Python source.
        def encode(item):
            if isinstance(item, bytes):
                return {'python_literal_type': 'bytes', 'hex': item.hex()}
            if isinstance(item, complex):
                return {'python_literal_type': 'complex', 'real': item.real, 'imag': item.imag}
            if item is Ellipsis:
                return {'python_literal_type': 'ellipsis'}
            if isinstance(item, dict):
                return {key: encode(child) for key, child in item.items()}
            if isinstance(item, (tuple, list)):
                return [encode(child) for child in item]
            return item
        return encode(value)


class GraphEdge(BaseModel):
    source: str
    target: str
    kind: str


class NormalizedGraph(BaseModel):
    backend: str
    root: str
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    export_metadata: dict[str, Any] = Field(default_factory=dict)


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

