"""
humanroot_mcp.proxy
-------------------
Transparent stdio proxy between an MCP host (Claude Desktop, Claude
Code, Cursor, ...) and any MCP server.

Everything except tools/call passes through byte-identical in both
directions — initialize, tools/list, resources, prompts, notifications.
tools/call requests are checked against the delegation; denials are
answered in-band as MCP tool errors (isError: true) so the agent sees
a readable explanation instead of a protocol failure, and the denied
request never reaches the wrapped server.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading

from humanroot.crypto import hash_drc

from humanroot_mcp.audit import AuditLog, args_digest
from humanroot_mcp.enforce import Decision, Enforcer


def _denial_response(request_id, reason: str, drc_id: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"HumanRoot: action denied — {reason}. "
                        f"This call is outside the human delegation certificate "
                        f"(drc_id={drc_id}). Ask the human to extend the delegation "
                        f"if this action is genuinely required."
                    ),
                }
            ],
            "isError": True,
        },
    }


class Proxy:
    def __init__(
        self,
        enforcer: Enforcer,
        audit: AuditLog,
        child_cmd: list[str],
    ) -> None:
        self.enforcer = enforcer
        self.audit = audit
        self.child_cmd = child_cmd
        self._stdout_lock = threading.Lock()

    def _write_host(self, raw: str) -> None:
        with self._stdout_lock:
            sys.stdout.write(raw if raw.endswith("\n") else raw + "\n")
            sys.stdout.flush()

    def _handle_host_line(self, line: str, child_stdin) -> None:
        stripped = line.strip()
        if not stripped:
            return
        try:
            msg = json.loads(stripped)
        except json.JSONDecodeError:
            child_stdin.write(line)
            child_stdin.flush()
            return

        if isinstance(msg, dict) and msg.get("method") == "tools/call":
            params = msg.get("params") or {}
            tool = params.get("name", "")
            arguments = params.get("arguments") or {}
            decision: Decision = self.enforcer.check(tool, arguments)

            self.audit.record(
                "allow" if decision.allowed else "deny",
                tool=tool,
                args_sha256=args_digest(arguments),
                drc_id=self.enforcer.leaf.drc_id,
                root_hash=self.enforcer.leaf.root_hash
                or hash_drc(self.enforcer.root),
                reason=decision.reason,
            )

            if not decision.allowed:
                if "id" in msg:
                    self._write_host(
                        json.dumps(
                            _denial_response(
                                msg["id"], decision.reason, self.enforcer.leaf.drc_id
                            ),
                            separators=(",", ":"),
                        )
                    )
                return

        child_stdin.write(stripped + "\n")
        child_stdin.flush()

    def run(self) -> int:
        child = subprocess.Popen(
            self.child_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )

        self.audit.record(
            "session_start",
            agent_id=self.enforcer.leaf.agent.agent_id,
            human_id=self.enforcer.leaf.principal.human_id,
            drc_id=self.enforcer.leaf.drc_id,
            root_hash=self.enforcer.leaf.root_hash or hash_drc(self.enforcer.root),
            scopes=sorted(self.enforcer.leaf.authority.scopes),
            validation_mode=self.enforcer.mode,
            wrapped_command=self.child_cmd,
        )

        def pump_child_to_host():
            for line in child.stdout:
                self._write_host(line.rstrip("\n"))

        t = threading.Thread(target=pump_child_to_host, daemon=True)
        t.start()

        try:
            for line in sys.stdin:
                self._handle_host_line(line, child.stdin)
        except (BrokenPipeError, KeyboardInterrupt):
            pass
        finally:
            try:
                child.stdin.close()
            except Exception:
                pass
            child.wait(timeout=10)
            t.join(timeout=5)
            self.audit.record("session_end", drc_id=self.enforcer.leaf.drc_id)

        return child.returncode or 0
