"""
humanroot.models
----------------
Data model for the Delegation Root Certificate (DRC).
Uses stdlib dataclasses — no external dependencies.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Principal:
    """The human who issues the delegation."""
    human_id: str
    identity_method: str = "email"


@dataclass
class AgentRef:
    """The agent receiving the delegation."""
    agent_id: str
    provider: str = "custom"


@dataclass
class Authority:
    """Scope and constraints granted by the principal."""
    scopes: list[str]
    constraints: dict[str, Any] = field(default_factory=dict)
    max_delegation_depth: int = 3


@dataclass
class DelegationRootCertificate:
    """A signed, structured record of a human delegation act."""

    expires_at: datetime
    principal: Principal
    agent: AgentRef
    authority: Authority

    version: str = "0.1"
    drc_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    revocation_endpoint: str | None = None
    parent_drc_id: str | None = None   # None = root certificate
    root_hash: str | None = None       # SHA-256 of the serialised root DRC
    signature: str | None = None       # JWS compact token

    def __post_init__(self):
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")

    def is_root(self) -> bool:
        return self.parent_drc_id is None

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    def unsigned_payload(self) -> dict[str, Any]:
        """Return the serialisable dict used for signing (signature excluded)."""
        return {
            "version": self.version,
            "drc_id": self.drc_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "principal": {
                "human_id": self.principal.human_id,
                "identity_method": self.principal.identity_method,
            },
            "agent": {
                "agent_id": self.agent.agent_id,
                "provider": self.agent.provider,
            },
            "authority": {
                "scopes": self.authority.scopes,
                "constraints": self.authority.constraints,
                "max_delegation_depth": self.authority.max_delegation_depth,
            },
            "revocation_endpoint": self.revocation_endpoint,
            "parent_drc_id": self.parent_drc_id,
            "root_hash": self.root_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        """Full serialisation including signature."""
        d = self.unsigned_payload()
        d["signature"] = self.signature
        return d
