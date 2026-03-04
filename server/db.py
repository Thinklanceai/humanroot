"""
humanroot.server.db
-------------------
SQLite persistence for DRCs and keys.
No ORM — pure sqlite3 stdlib.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

DB_PATH = Path("humanroot.db")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS drcs (
            drc_id          TEXT PRIMARY KEY,
            version         TEXT NOT NULL,
            issued_at       TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            human_id        TEXT NOT NULL,
            identity_method TEXT NOT NULL,
            agent_id        TEXT NOT NULL,
            provider        TEXT NOT NULL,
            scopes          TEXT NOT NULL,   -- JSON array
            constraints     TEXT NOT NULL,   -- JSON object
            max_depth       INTEGER NOT NULL,
            revocation_endpoint TEXT,
            parent_drc_id   TEXT,
            root_hash       TEXT,
            signature       TEXT
        );

        CREATE TABLE IF NOT EXISTS revocations (
            drc_id      TEXT PRIMARY KEY,
            revoked_at  TEXT NOT NULL,
            reason      TEXT
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            key_id      TEXT PRIMARY KEY,
            human_id    TEXT NOT NULL,
            public_pem  TEXT NOT NULL,
            created_at  TEXT NOT NULL
        );
        """)


# ---------------------------------------------------------------------------
# DRC persistence
# ---------------------------------------------------------------------------

def save_drc(drc_dict: dict) -> None:
    with get_conn() as conn:
        conn.execute("""
        INSERT OR REPLACE INTO drcs VALUES (
            :drc_id, :version, :issued_at, :expires_at,
            :human_id, :identity_method, :agent_id, :provider,
            :scopes, :constraints, :max_depth,
            :revocation_endpoint, :parent_drc_id, :root_hash, :signature
        )
        """, {
            "drc_id": drc_dict["drc_id"],
            "version": drc_dict["version"],
            "issued_at": drc_dict["issued_at"],
            "expires_at": drc_dict["expires_at"],
            "human_id": drc_dict["principal"]["human_id"],
            "identity_method": drc_dict["principal"]["identity_method"],
            "agent_id": drc_dict["agent"]["agent_id"],
            "provider": drc_dict["agent"]["provider"],
            "scopes": json.dumps(drc_dict["authority"]["scopes"]),
            "constraints": json.dumps(drc_dict["authority"]["constraints"]),
            "max_depth": drc_dict["authority"]["max_delegation_depth"],
            "revocation_endpoint": drc_dict.get("revocation_endpoint"),
            "parent_drc_id": drc_dict.get("parent_drc_id"),
            "root_hash": drc_dict.get("root_hash"),
            "signature": drc_dict.get("signature"),
        })


def load_drc(drc_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM drcs WHERE drc_id = ?", (drc_id,)
        ).fetchone()
    if not row:
        return None
    return _row_to_dict(row)


def list_drcs(human_id: str | None = None, agent_id: str | None = None) -> list[dict]:
    query = "SELECT * FROM drcs WHERE 1=1"
    params: list = []
    if human_id:
        query += " AND human_id = ?"
        params.append(human_id)
    if agent_id:
        query += " AND agent_id = ?"
        params.append(agent_id)
    query += " ORDER BY issued_at DESC"
    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def _row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "drc_id": row["drc_id"],
        "version": row["version"],
        "issued_at": row["issued_at"],
        "expires_at": row["expires_at"],
        "principal": {
            "human_id": row["human_id"],
            "identity_method": row["identity_method"],
        },
        "agent": {
            "agent_id": row["agent_id"],
            "provider": row["provider"],
        },
        "authority": {
            "scopes": json.loads(row["scopes"]),
            "constraints": json.loads(row["constraints"]),
            "max_delegation_depth": row["max_depth"],
        },
        "revocation_endpoint": row["revocation_endpoint"],
        "parent_drc_id": row["parent_drc_id"],
        "root_hash": row["root_hash"],
        "signature": row["signature"],
    }


# ---------------------------------------------------------------------------
# Key persistence
# ---------------------------------------------------------------------------

def save_key(key_id: str, human_id: str, public_pem: str, created_at: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO api_keys VALUES (?, ?, ?, ?)",
            (key_id, human_id, public_pem, created_at),
        )


def load_public_key(human_id: str) -> str | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT public_pem FROM api_keys WHERE human_id = ? ORDER BY created_at DESC LIMIT 1",
            (human_id,),
        ).fetchone()
    return row["public_pem"] if row else None
