"""
humanroot.chain
---------------
Propagation model: sub-delegation with scope restriction and depth enforcement.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Optional

from humanroot.crypto import hash_drc, sign_drc
from humanroot.models import AgentRef, Authority, DelegationRootCertificate
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey


class DelegationError(Exception):
    pass


def sub_delegate(
    parent: DelegationRootCertificate,
    *,
    agent_id: str,
    provider: str = "custom",
    scopes: list[str],
    expires_at: datetime,
    constraints: dict | None = None,
    revocation_endpoint: str | None = None,
    signing_key: Optional[EllipticCurvePrivateKey] = None,
) -> DelegationRootCertificate:
    now = datetime.now(timezone.utc)

    if parent.is_expired():
        raise DelegationError("Cannot sub-delegate from an expired DRC")

    parent_scopes = set(parent.authority.scopes)
    child_scopes = set(scopes)
    extra = child_scopes - parent_scopes
    if extra:
        raise DelegationError(
            f"Child scopes {extra} are not present in parent DRC (scope expansion forbidden)"
        )

    if parent.authority.max_delegation_depth <= 0:
        raise DelegationError("max_delegation_depth exhausted — no further delegation allowed")

    if expires_at > parent.expires_at:
        raise DelegationError("Child DRC cannot expire after its parent")

    if expires_at <= now:
        raise DelegationError("expires_at must be in the future")

    root_hash = hash_drc(parent) if parent.is_root() else parent.root_hash

    child = DelegationRootCertificate(
        issued_at=now,
        expires_at=expires_at,
        principal=parent.principal,
        agent=AgentRef(agent_id=agent_id, provider=provider),
        authority=Authority(
            scopes=sorted(scopes),
            constraints=constraints or {},
            max_delegation_depth=parent.authority.max_delegation_depth - 1,
        ),
        revocation_endpoint=revocation_endpoint or parent.revocation_endpoint,
        parent_drc_id=parent.drc_id,
        root_hash=root_hash,
    )

    if signing_key is not None:
        child = sign_drc(child, signing_key)

    return child


def reconstruct_chain(
    drc: DelegationRootCertificate,
    store: dict[str, DelegationRootCertificate],
) -> list[DelegationRootCertificate]:
    chain: list[DelegationRootCertificate] = []
    current = drc
    visited: set[str] = set()

    while True:
        if current.drc_id in visited:
            raise DelegationError(f"Cycle detected at drc_id={current.drc_id}")
        visited.add(current.drc_id)
        chain.append(current)
        if current.parent_drc_id is None:
            break
        parent_id = current.parent_drc_id
        if parent_id not in store:
            raise DelegationError(f"Missing DRC in store: {parent_id}")
        current = store[parent_id]

    chain.reverse()
    return chain


def validate_chain(
    chain: list[DelegationRootCertificate],
    public_keys: dict[str, object] | None = None,
) -> None:
    if not chain:
        raise DelegationError("Empty chain")

    from humanroot.crypto import verify_drc

    if not chain[0].is_root():
        raise DelegationError("First element of chain must be a root DRC")

    for i, drc in enumerate(chain):
        if drc.is_expired():
            raise DelegationError(f"DRC {drc.drc_id} is expired")

        if i > 0:
            parent = chain[i - 1]
            extra = set(drc.authority.scopes) - set(parent.authority.scopes)
            if extra:
                raise DelegationError(f"DRC {drc.drc_id} expands scope: {extra}")
            if drc.authority.max_delegation_depth >= parent.authority.max_delegation_depth:
                raise DelegationError(
                    f"DRC {drc.drc_id} did not decrement delegation depth"
                )

        if public_keys and drc.signature:
            key = public_keys.get(drc.principal.human_id)
            if key and not verify_drc(drc, key):
                raise DelegationError(f"Invalid signature on DRC {drc.drc_id}")
