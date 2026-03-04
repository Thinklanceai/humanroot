"""
humanroot.delegate
------------------
Public one-liner API: delegate()
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from humanroot.crypto import sign_drc
from humanroot.models import AgentRef, Authority, DelegationRootCertificate, Principal

_DURATION_RE = re.compile(r"^(\d+)(s|m|h|d)$")

def _parse_duration(s: str) -> timedelta:
    m = _DURATION_RE.match(s.strip())
    if not m:
        raise ValueError(f"Invalid duration '{s}'. Use: 30s, 10m, 24h, 7d")
    value, unit = int(m.group(1)), m.group(2)
    return {"s": timedelta(seconds=value), "m": timedelta(minutes=value),
            "h": timedelta(hours=value),   "d": timedelta(days=value)}[unit]


def delegate(
    *,
    human_id: str,
    agent_id: str,
    scopes: list[str],
    expires_in: str = "24h",
    provider: str = "custom",
    identity_method: str = "email",
    max_delegation_depth: int = 3,
    constraints: dict | None = None,
    revocation_endpoint: str | None = None,
    signing_key: Optional[EllipticCurvePrivateKey] = None,
) -> DelegationRootCertificate:
    """Issue a root Delegation Root Certificate (DRC)."""
    now = datetime.now(timezone.utc)
    drc = DelegationRootCertificate(
        issued_at=now,
        expires_at=now + _parse_duration(expires_in),
        principal=Principal(human_id=human_id, identity_method=identity_method),
        agent=AgentRef(agent_id=agent_id, provider=provider),
        authority=Authority(
            scopes=sorted(scopes),
            constraints=constraints or {},
            max_delegation_depth=max_delegation_depth,
        ),
        revocation_endpoint=revocation_endpoint,
        parent_drc_id=None,
        root_hash=None,
    )
    if signing_key is not None:
        drc = sign_drc(drc, signing_key)
    return drc
