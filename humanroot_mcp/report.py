"""
humanroot_mcp.report
--------------------
Builds the evidence package from a verified audit log.

The report only exists if the log verifies — integrity first, then
aggregation. Output is structured to serve directly as record-keeping
(EU AI Act Art. 12) and human-oversight (Art. 14) supporting evidence:
who delegated, to which agent, under which scopes, what was allowed,
what was denied, over which period — all under a hash chain signed by
a dedicated audit key.
"""
from __future__ import annotations

import json
from pathlib import Path

from humanroot_mcp.audit import verify_log


def build_report(log_path: str | Path, audit_pub_path: str | Path) -> dict:
    integrity = verify_log(log_path, audit_pub_path)
    report: dict = {
        "report_type": "humanroot_delegation_audit",
        "version": "0.3",
        "log_file": str(log_path),
        "integrity": integrity,
    }
    if not integrity["valid"]:
        report["sessions"] = []
        report["totals"] = {}
        return report

    sessions: list[dict] = []
    current: dict | None = None
    totals = {"calls": 0, "allowed": 0, "denied": 0}
    first_ts = None
    last_ts = None

    with Path(log_path).open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            ts = entry.get("ts")
            first_ts = first_ts or ts
            last_ts = ts
            event = entry.get("event")

            if event == "session_start":
                current = {
                    "started_at": ts,
                    "ended_at": None,
                    "human_id": entry.get("human_id"),
                    "agent_id": entry.get("agent_id"),
                    "drc_id": entry.get("drc_id"),
                    "root_hash": entry.get("root_hash"),
                    "scopes": entry.get("scopes"),
                    "validation_mode": entry.get("validation_mode"),
                    "calls": 0,
                    "allowed": 0,
                    "denied": 0,
                    "denials": [],
                }
                sessions.append(current)
            elif event in ("allow", "deny"):
                totals["calls"] += 1
                bucket = "allowed" if event == "allow" else "denied"
                totals[bucket] += 1
                if current is not None:
                    current["calls"] += 1
                    current[bucket] += 1
                    if event == "deny":
                        current["denials"].append(
                            {
                                "ts": ts,
                                "tool": entry.get("tool"),
                                "reason": entry.get("reason"),
                                "args_sha256": entry.get("args_sha256"),
                            }
                        )
            elif event == "session_end" and current is not None:
                current["ended_at"] = ts
                current = None

    report["period"] = {"from": first_ts, "to": last_ts}
    report["sessions"] = sessions
    report["totals"] = totals
    report["eu_ai_act"] = {
        "art_12_record_keeping": {
            "claim": (
                "Automatic, tamper-evident recording of agent tool invocations "
                "over the operating period, hash-chained and signed."
            ),
            "events_recorded": integrity["entries"],
            "integrity_verified": True,
        },
        "art_14_human_oversight": {
            "claim": (
                "Every recorded session operates under an explicit, scope-bound, "
                "expiring delegation certificate issued by an identified human; "
                "out-of-scope actions were blocked before execution."
            ),
            "sessions": len(sessions),
            "out_of_scope_actions_blocked": totals["denied"],
            "strict_signature_validation": all(
                s.get("validation_mode") == "strict" for s in sessions
            )
            if sessions
            else False,
        },
    }
    return report
