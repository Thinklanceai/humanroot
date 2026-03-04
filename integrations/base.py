"""
humanroot.integrations.base
----------------------------
Base class for all framework integrations.
Each integration wraps an agent call and:
  1. Attaches the DRC to the call context
  2. Verifies the DRC is valid and not expired before calling
  3. Records the action with a reference to the DRC
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from humanroot.models import DelegationRootCertificate


class DRCValidationError(Exception):
    pass


def validate_before_call(drc: DelegationRootCertificate) -> None:
    """Raise DRCValidationError if DRC is not usable."""
    if drc is None:
        raise DRCValidationError("No DRC attached — all agent calls require a DRC")
    if drc.is_expired():
        raise DRCValidationError(f"DRC {drc.drc_id} is expired")
    if drc.authority.max_delegation_depth < 0:
        raise DRCValidationError(f"DRC {drc.drc_id} has exhausted delegation depth")


def build_action_record(
    drc: DelegationRootCertificate,
    framework: str,
    action: str,
    inputs: dict[str, Any],
) -> dict[str, Any]:
    """Build a structured action record referencing the DRC."""
    return {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "framework": framework,
        "action": action,
        "drc_id": drc.drc_id,
        "parent_drc_id": drc.parent_drc_id,
        "root_hash": drc.root_hash,
        "human_id": drc.principal.human_id,
        "agent_id": drc.agent.agent_id,
        "scopes": drc.authority.scopes,
        "inputs_summary": {k: str(v)[:120] for k, v in inputs.items()},
    }
