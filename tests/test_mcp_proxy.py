"""
End-to-end test of the wrap proxy against a fake MCP server.

The fake server speaks newline-delimited JSON-RPC: it answers
initialize and tools/call, which is all the proxy path needs. The test
drives the real CLI in a subprocess, exactly as an MCP host would.
"""
import json
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from humanroot import delegate
from humanroot.crypto import generate_keypair, public_key_to_pem

FAKE_SERVER = textwrap.dedent(
    """
    import json, sys
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        if msg.get("method") == "initialize":
            out = {"jsonrpc": "2.0", "id": msg["id"],
                   "result": {"protocolVersion": "2024-11-05",
                              "capabilities": {}, "serverInfo": {"name": "fake"}}}
        elif msg.get("method") == "tools/call":
            out = {"jsonrpc": "2.0", "id": msg["id"],
                   "result": {"content": [{"type": "text", "text": "SERVER_EXECUTED"}]}}
        else:
            continue
        sys.stdout.write(json.dumps(out) + "\\n")
        sys.stdout.flush()
    """
)


class TestProxyE2E(unittest.TestCase):
    def test_allow_deny_audit_report(self):
        with TemporaryDirectory() as d:
            tmp = Path(d)
            server_py = tmp / "fake_server.py"
            server_py.write_text(FAKE_SERVER)

            priv, pub = generate_keypair()
            drc = delegate(
                human_id="alice@example.com",
                agent_id="claude-desktop",
                scopes=["tool:read_file"],
                expires_in="1h",
                constraints={"read_file": {"path": {"prefix": "/safe"}}},
                signing_key=priv,
            )
            drc_path = tmp / "drc.json"
            drc_path.write_text(json.dumps(drc.to_dict()))
            pub_path = tmp / "public.pem"
            pub_path.write_bytes(public_key_to_pem(pub))
            log_path = tmp / "audit.jsonl"
            key_path = tmp / "audit_key.pem"

            requests = "\n".join(
                json.dumps(m)
                for m in [
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2024-11-05"}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                     "params": {"name": "read_file",
                                "arguments": {"path": "/safe/doc.md"}}},
                    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "read_file",
                                "arguments": {"path": "/etc/passwd"}}},
                    {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                     "params": {"name": "delete_file",
                                "arguments": {"path": "/safe/doc.md"}}},
                ]
            ) + "\n"

            proc = subprocess.run(
                [sys.executable, "-m", "humanroot_mcp.cli", "wrap",
                 "--drc", str(drc_path), "--pubkey", str(pub_path),
                 "--log", str(log_path), "--audit-key", str(key_path),
                 "--", sys.executable, str(server_py)],
                input=requests, capture_output=True, text=True, timeout=30,
            )

            responses = {}
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                msg = json.loads(line)
                if "id" in msg:
                    responses[msg["id"]] = msg

            self.assertIn(1, responses)
            self.assertEqual(
                responses[1]["result"]["serverInfo"]["name"], "fake"
            )
            self.assertEqual(
                responses[2]["result"]["content"][0]["text"], "SERVER_EXECUTED"
            )
            self.assertTrue(responses[3]["result"].get("isError"))
            self.assertIn("denied", responses[3]["result"]["content"][0]["text"])
            self.assertTrue(responses[4]["result"].get("isError"))
            self.assertIn("delete_file", responses[4]["result"]["content"][0]["text"])

            from humanroot_mcp.audit import verify_log
            integrity = verify_log(log_path, key_path.with_suffix(".pub.pem"))
            self.assertTrue(integrity["valid"])

            from humanroot_mcp.report import build_report
            report = build_report(log_path, key_path.with_suffix(".pub.pem"))
            self.assertTrue(report["integrity"]["valid"])
            self.assertEqual(report["totals"]["allowed"], 1)
            self.assertEqual(report["totals"]["denied"], 2)
            self.assertTrue(
                report["eu_ai_act"]["art_14_human_oversight"]["strict_signature_validation"]
            )


if __name__ == "__main__":
    unittest.main()
