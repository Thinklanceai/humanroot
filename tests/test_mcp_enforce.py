import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from humanroot import delegate, sub_delegate
from humanroot.crypto import generate_keypair, public_key_to_pem

from humanroot_mcp.audit import AuditLog, verify_log
from humanroot_mcp.enforce import Enforcer, EnforcementError, load_chain

ALICE = "alice@example.com"


def write_chain(tmp: Path, drcs) -> Path:
    path = tmp / "drc.json"
    path.write_text(json.dumps({"chain": [d.to_dict() for d in drcs]}))
    return path


class TestEnforcer(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_keypair()
        self.root = delegate(
            human_id=ALICE,
            agent_id="agent-a",
            scopes=["tool:read_file", "tool:list_directory"],
            expires_in="1h",
            constraints={"read_file": {"path": {"prefix": "/safe"}}},
            signing_key=self.priv,
        )

    def make_enforcer(self, tmp: Path, pubkey=True) -> Enforcer:
        drc_path = write_chain(tmp, [self.root])
        pub_path = None
        if pubkey:
            pub_path = tmp / "pub.pem"
            pub_path.write_bytes(public_key_to_pem(self.pub))
        return Enforcer.from_files(drc_path, pub_path)

    def test_strict_load(self):
        with TemporaryDirectory() as d:
            enf = self.make_enforcer(Path(d))
            self.assertEqual(enf.mode, "strict")

    def test_structural_load_without_key(self):
        with TemporaryDirectory() as d:
            enf = self.make_enforcer(Path(d), pubkey=False)
            self.assertEqual(enf.mode, "structural")

    def test_scope_allow_and_deny(self):
        with TemporaryDirectory() as d:
            enf = self.make_enforcer(Path(d))
            self.assertTrue(enf.check("list_directory", {}).allowed)
            self.assertFalse(enf.check("delete_file", {}).allowed)

    def test_wildcard_scope(self):
        with TemporaryDirectory() as d:
            star = delegate(
                human_id=ALICE, agent_id="agent-a", scopes=["tool:*"],
                expires_in="1h", signing_key=self.priv,
            )
            path = write_chain(Path(d), [star])
            pub_path = Path(d) / "pub.pem"
            pub_path.write_bytes(public_key_to_pem(self.pub))
            enf = Enforcer.from_files(path, pub_path)
            self.assertTrue(enf.check("anything_at_all", {}).allowed)

    def test_prefix_constraint(self):
        with TemporaryDirectory() as d:
            enf = self.make_enforcer(Path(d))
            self.assertTrue(enf.check("read_file", {"path": "/safe/notes.md"}).allowed)
            self.assertFalse(enf.check("read_file", {"path": "/etc/passwd"}).allowed)

    def test_constraint_fail_closed_on_missing_arg(self):
        with TemporaryDirectory() as d:
            enf = self.make_enforcer(Path(d))
            self.assertFalse(enf.check("read_file", {}).allowed)
            self.assertFalse(enf.check("read_file", {"path": 42}).allowed)

    def test_expired_denied(self):
        with TemporaryDirectory() as d:
            enf = self.make_enforcer(Path(d))
            enf.leaf = type(enf.leaf)(
                **{
                    **{f: getattr(enf.leaf, f) for f in (
                        "version", "drc_id", "principal", "agent", "authority",
                        "revocation_endpoint", "parent_drc_id", "root_hash", "signature",
                    )},
                    "issued_at": datetime.now(timezone.utc) - timedelta(hours=2),
                    "expires_at": datetime.now(timezone.utc) - timedelta(hours=1),
                }
            )
            self.assertFalse(enf.check("list_directory", {}).allowed)

    def test_tampered_chain_refused_in_strict(self):
        with TemporaryDirectory() as d:
            tmp = Path(d)
            data = json.loads(json.dumps({"chain": [self.root.to_dict()]}))
            data["chain"][0]["authority"]["scopes"] = ["tool:*"]
            drc_path = tmp / "drc.json"
            drc_path.write_text(json.dumps(data))
            pub_path = tmp / "pub.pem"
            pub_path.write_bytes(public_key_to_pem(self.pub))
            with self.assertRaises(EnforcementError):
                Enforcer.from_files(drc_path, pub_path)

    def test_sub_delegated_chain_loads(self):
        with TemporaryDirectory() as d:
            child = sub_delegate(
                self.root, agent_id="agent-b", scopes=["tool:read_file"],
                expires_at=self.root.expires_at - timedelta(minutes=5),
                signing_key=self.priv,
            )
            path = write_chain(Path(d), [self.root, child])
            chain = load_chain(path)
            self.assertEqual(len(chain), 2)
            self.assertEqual(chain[-1].agent.agent_id, "agent-b")


class TestAudit(unittest.TestCase):
    def test_chain_and_verify(self):
        with TemporaryDirectory() as d:
            tmp = Path(d)
            log = tmp / "audit.jsonl"
            key = tmp / "audit_key.pem"
            a = AuditLog(log, key)
            a.record("session_start", drc_id="x")
            a.record("allow", tool="read_file", drc_id="x")
            a.record("deny", tool="rm", drc_id="x", reason="not in scope")
            result = verify_log(log, key.with_suffix(".pub.pem"))
            self.assertTrue(result["valid"])
            self.assertEqual(result["entries"], 3)

    def test_resume_across_sessions(self):
        with TemporaryDirectory() as d:
            tmp = Path(d)
            log = tmp / "audit.jsonl"
            key = tmp / "audit_key.pem"
            AuditLog(log, key).record("session_start", drc_id="x")
            AuditLog(log, key).record("session_start", drc_id="y")
            result = verify_log(log, key.with_suffix(".pub.pem"))
            self.assertTrue(result["valid"])
            self.assertEqual(result["entries"], 2)

    def test_tamper_detected(self):
        with TemporaryDirectory() as d:
            tmp = Path(d)
            log = tmp / "audit.jsonl"
            key = tmp / "audit_key.pem"
            a = AuditLog(log, key)
            a.record("allow", tool="read_file", drc_id="x")
            a.record("allow", tool="read_file", drc_id="x")
            lines = log.read_text().splitlines()
            entry = json.loads(lines[0])
            entry["tool"] = "delete_everything"
            lines[0] = json.dumps(entry, separators=(",", ":"))
            log.write_text("\n".join(lines) + "\n")
            result = verify_log(log, key.with_suffix(".pub.pem"))
            self.assertFalse(result["valid"])
            self.assertEqual(result["first_invalid_line"], 1)


if __name__ == "__main__":
    unittest.main()
