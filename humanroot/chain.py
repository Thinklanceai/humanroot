"""
humanroot.chain
---------------
Propagation model: sub-delegation with scope restriction and depth
enforcement.

Hardened in 0.2.0 — `validate_chain` is strict by default:
- every DRC in the chain MUST be signed and verifiable against the
  principal's public key (a chain that merely "looks" consistent no
  longer validates);
- structural invariants are re-checked at validation time, not only
  at creation time: parent linkage, child expiry bounded by parent
  expiry, scope subset, depth decrement, and root_hash matching the
  recomputed hash of the actual root.
Pass strict=False to get the 0.1 structural-only behavior.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Optional

from humanroot.crypto import hash_drc, sign_drc, verify_drc
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
    strict: bool = True,
) -> None:
    """Validate a delegation chain.

    strict=True (default): every DRC must carry a signature that
    verifies against the public key registered for its principal in
    `public_keys`. A missing signature or missing key is an error,
    not a silent pass.

    strict=False: structural validation only (0.1 behavior), with
    signatures checked opportunistically when both signature and key
    are present.
    """
    if not chain:
        raise DelegationError("Empty chain")

    if not chain[0].is_root():
        raise DelegationError("First element of chain must be a root DRC")

    expected_root_hash = hash_drc(chain[0])

    for i, drc in enumerate(chain):
        if drc.is_expired():
            raise DelegationError(f"DRC {drc.drc_id} is expired")

        if i > 0:
            parent = chain[i - 1]

            if drc.parent_drc_id != parent.drc_id:
                raise DelegationError(
                    f"DRC {drc.drc_id} parent linkage broken: "
                    f"expected {parent.drc_id}, got {drc.parent_drc_id}"
                )

            if drc.expires_at > parent.expires_at:
                raise DelegationError(
                    f"DRC {drc.drc_id} expires after its parent"
                )

            extra = set(drc.authority.scopes) - set(parent.authority.scopes)
            if extra:
                raise DelegationError(f"DRC {drc.drc_id} expands scope: {extra}")

            if drc.authority.max_delegation_depth >= parent.authority.max_delegation_depth:
                raise DelegationError(
                    f"DRC {drc.drc_id} did not decrement delegation depth"
                )

            if drc.root_hash != expected_root_hash:
                raise DelegationError(
                    f"DRC {drc.drc_id} root_hash does not match the chain root"
                )

        if strict:
            if not drc.signature:
                raise DelegationError(
                    f"DRC {drc.drc_id} is unsigned — strict validation requires signatures"
                )
            if not public_keys or drc.principal.human_id not in public_keys:
                raise DelegationError(
                    f"No public key provided for principal {drc.principal.human_id}"
                )
            if not verify_drc(drc, public_keys[drc.principal.human_id]):
                raise DelegationError(f"Invalid signature on DRC {drc.drc_id}")
        else:
            if public_keys and drc.signature:
                key = public_keys.get(drc.principal.human_id)
                if key and not verify_drc(drc, key):
                    raise DelegationError(f"Invalid signature on DRC {drc.drc_id}")
