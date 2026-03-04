"""
humanroot.server.schemas
-------------------------
Request / response models for the FastAPI layer.
Uses dataclasses — no pydantic required at the server level
(though pydantic is available and FastAPI will use it if present).
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class IssueDRCRequest:
    human_id: str
    agent_id: str
    scopes: list[str]
    expires_in: str = "24h"
    provider: str = "custom"
    identity_method: str = "email"
    max_delegation_depth: int = 3
    constraints: dict = field(default_factory=dict)
    revocation_endpoint: str | None = None


@dataclass
class SubDelegateRequest:
    parent_drc_id: str
    agent_id: str
    scopes: list[str]
    expires_in: str = "1h"
    provider: str = "custom"
    constraints: dict = field(default_factory=dict)


@dataclass
class RevokeRequest:
    drc_id: str
    reason: str | None = None
