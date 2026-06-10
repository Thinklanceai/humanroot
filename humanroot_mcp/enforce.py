"""
humanroot_mcp.enforce
---------------------
Enforcement engine for the MCP proxy.

Loads a DRC (or full chain) from disk, validates it — strictly when a
principal public key is provided — and decides, per tool call, whether
the call is covered by the delegation.

Scope grammar:
  tool:<name>   exact tool authorization
  tool:*        wildcard — all tools

Argument constraints live in the leaf DRC's authority.constraints,
keyed by tool name, then by argument name:

  "constraints": {
    "read_file":  { "path": { "prefix": "/Users/x/project" } },
    "send_email": { "to":   { "equals": "team@example.com" } }
  }

Semantics are fail-closed: a constrained argument that is missing,
non-string (for prefix), or out of bounds denies the call.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from humanroot.chain import DelegationError, reconstruct_chain, validate_chain
from humanroot.crypto import pem_to_public_key
from humanroot.models import (
    AgentRef,
    Authority,
    DelegationRootCertificate,
    Principal,
)


class EnforcementError(Exception):
    pass


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def _dict_to_drc(d: dict) -> DelegationRootCertificate:
    return DelegationRootCertificate(
        version=d["version"],
        drc_id=d["drc_id"],
        issued_at=datetime.fromisoformat(d["issued_at"]),
        expires_at=datetime.fromisoformat(d["expires_at"]),
        principal=Principal(**d["principal"]),
        agent=AgentRef(**d["agent"]),
        authority=Authority(**d["authority"]),
        revocation_endpoint=d.get("revocation_endpoint"),
        parent_drc_id=d.get("parent_drc_id"),
        root_hash=d.get("root_hash"),
        signature=d.get("signature"),
    )


def load_chain(drc_path: str | Path) -> list[DelegationRootCertificate]:
    """Load a DRC file: a single DRC object, a list, or {"chain": [...]}.

    Returns the ordered chain root→leaf.
    """
    raw = json.loads(Path(drc_path).read_text())
    if isinstance(raw, dict) and "chain" in raw:
        raw = raw["chain"]
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list) or not raw:
        raise EnforcementError(f"Unrecognized DRC file format: {drc_path}")

    drcs = [_dict_to_drc(d) for d in raw]
    store = {d.drc_id: d for d in drcs}
    leaves = [d for d in drcs if not any(o.parent_drc_id == d.drc_id for o in drcs)]
    if len(leaves) != 1:
        raise EnforcementError(
            f"DRC file must contain exactly one leaf certificate, found {len(leaves)}"
        )
    return reconstruct_chain(leaves[0], store)


class Enforcer:
    """Validates a delegation chain once, then decides per tool call."""

    def __init__(
        self,
        chain: list[DelegationRootCertificate],
        mode: str,
    ) -> None:
        self.chain = chain
        self.leaf = chain[-1]
        self.root = chain[0]
        self.mode = mode

    @classmethod
    def from_files(
        cls,
        drc_path: str | Path,
        pubkey_path: str | Path | None = None,
    ) -> "Enforcer":
        chain = load_chain(drc_path)
        if pubkey_path is not None:
            pub = pem_to_public_key(Path(pubkey_path).read_bytes())
            keys = {drc.principal.human_id: pub for drc in chain}
            try:
                validate_chain(chain, public_keys=keys, strict=True)
            except DelegationError as e:
                raise EnforcementError(f"DRC chain failed strict validation: {e}")
            mode = "strict"
        else:
            try:
                validate_chain(chain, strict=False)
            except DelegationError as e:
                raise EnforcementError(f"DRC chain failed structural validation: {e}")
            mode = "structural"
        return cls(chain, mode)

    def check(self, tool_name: str, arguments: dict | None) -> Decision:
        if self.leaf.is_expired():
            return Decision(False, f"delegation expired at {self.leaf.expires_at.isoformat()}")

        scopes = set(self.leaf.authority.scopes)
        if "tool:*" not in scopes and f"tool:{tool_name}" not in scopes:
            return Decision(
                False,
                f"tool '{tool_name}' is not covered by delegation scopes {sorted(scopes)}",
            )

        rules = self.leaf.authority.constraints.get(tool_name)
        if rules:
            args = arguments or {}
            for arg_name, rule in rules.items():
                if not isinstance(rule, dict):
                    return Decision(False, f"malformed constraint for '{arg_name}'")
                value = args.get(arg_name)
                if "equals" in rule:
                    if value != rule["equals"]:
                        return Decision(
                            False,
                            f"argument '{arg_name}'={value!r} violates equals constraint",
                        )
                if "prefix" in rule:
                    prefixes = rule["prefix"]
                    if isinstance(prefixes, str):
                        prefixes = [prefixes]
                    if not isinstance(value, str) or not any(
                        value.startswith(p) for p in prefixes
                    ):
                        return Decision(
                            False,
                            f"argument '{arg_name}'={value!r} violates prefix constraint",
                        )

        return Decision(True, "covered by delegation")
