"""
humanroot.server.revocation
----------------------------
Revocation store.
Revoking a DRC cascades to all its children instantly.
"""
from __future__ import annotations

from datetime import datetime, timezone

from server.db import get_conn


def revoke(drc_id: str, reason: str | None = None) -> list[str]:
    """
    Revoke a DRC and all its descendants.
    Returns the list of all revoked drc_ids.
    """
    revoked_ids = _collect_descendants(drc_id)
    revoked_ids.insert(0, drc_id)

    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.executemany(
            "INSERT OR IGNORE INTO revocations (drc_id, revoked_at, reason) VALUES (?, ?, ?)",
            [(did, now, reason) for did in revoked_ids],
        )
    return revoked_ids


def is_revoked(drc_id: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM revocations WHERE drc_id = ?", (drc_id,)
        ).fetchone()
    return row is not None


def get_revocation(drc_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM revocations WHERE drc_id = ?", (drc_id,)
        ).fetchone()
    if not row:
        return None
    return {"drc_id": row["drc_id"], "revoked_at": row["revoked_at"], "reason": row["reason"]}


def _collect_descendants(drc_id: str) -> list[str]:
    """BFS to find all child DRC ids."""
    result: list[str] = []
    queue = [drc_id]
    with get_conn() as conn:
        while queue:
            current = queue.pop(0)
            rows = conn.execute(
                "SELECT drc_id FROM drcs WHERE parent_drc_id = ?", (current,)
            ).fetchall()
            for row in rows:
                child_id = row["drc_id"]
                result.append(child_id)
                queue.append(child_id)
    return result
