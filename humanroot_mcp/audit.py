"""
humanroot_mcp.audit
-------------------
Tamper-evident audit log.

Each entry is a JSON object canonicalized with RFC 8785, chained by
hash (prev_hash → entry_hash) and signed with an Ed25519 key dedicated
to the audit log. Arguments are never stored in clear — only their
SHA-256 — so the log proves *what was authorized* without leaking
*what was said*.

The chain resumes across sessions: on open, the last entry_hash on
disk becomes the prev_hash of the next entry.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

GENESIS = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def args_digest(arguments: dict | None) -> str:
    return hashlib.sha256(rfc8785.dumps(arguments or {})).hexdigest()


def load_or_create_audit_key(key_path: str | Path) -> Ed25519PrivateKey:
    key_path = Path(key_path)
    if key_path.exists():
        return load_pem_private_key(key_path.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    key_path.chmod(0o600)
    pub_path = key_path.with_suffix(".pub.pem")
    pub_path.write_bytes(
        key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return key


class AuditLog:
    def __init__(self, log_path: str | Path, key_path: str | Path) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._key = load_or_create_audit_key(key_path)
        self._prev_hash = self._last_hash_on_disk()

    def _last_hash_on_disk(self) -> str:
        if not self.log_path.exists():
            return GENESIS
        last = None
        with self.log_path.open("rb") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return GENESIS
        try:
            return json.loads(last)["entry_hash"]
        except (json.JSONDecodeError, KeyError):
            raise ValueError(
                f"Audit log {self.log_path} has a corrupt final line — refusing to append"
            )

    def record(self, event: str, **fields) -> dict:
        body = {
            "ts": _now(),
            "event": event,
            "prev_hash": self._prev_hash,
            **fields,
        }
        canonical = rfc8785.dumps(body)
        entry_hash = hashlib.sha256(canonical).hexdigest()
        signature = self._key.sign(canonical).hex()
        entry = {**body, "entry_hash": entry_hash, "signature": signature}
        with self.log_path.open("a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
            f.flush()
        self._prev_hash = entry_hash
        return entry


def verify_log(log_path: str | Path, audit_pub_path: str | Path) -> dict:
    """Verify hash chaining and signatures over the entire log.

    Returns {"valid": bool, "entries": int, "error": str | None,
    "first_invalid_line": int | None}.
    """
    pub: Ed25519PublicKey = load_pem_public_key(Path(audit_pub_path).read_bytes())
    prev = GENESIS
    count = 0
    with Path(log_path).open() as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                body = {
                    k: v
                    for k, v in entry.items()
                    if k not in ("entry_hash", "signature")
                }
                canonical = rfc8785.dumps(body)
                if entry["prev_hash"] != prev:
                    raise ValueError("broken hash chain")
                if hashlib.sha256(canonical).hexdigest() != entry["entry_hash"]:
                    raise ValueError("entry hash mismatch")
                pub.verify(bytes.fromhex(entry["signature"]), canonical)
                prev = entry["entry_hash"]
                count += 1
            except Exception as e:
                return {
                    "valid": False,
                    "entries": count,
                    "error": str(e),
                    "first_invalid_line": lineno,
                }
    return {"valid": True, "entries": count, "error": None, "first_invalid_line": None}
