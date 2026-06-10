#!/usr/bin/env python3
"""
humanroot-mcp CLI
-----------------
Usage:
  humanroot-mcp wrap --drc drc.json [--pubkey keys/public.pem] -- <server command...>
  humanroot-mcp report --log ~/.humanroot/audit.jsonl [--out report.json]
  humanroot-mcp verify-log --log ~/.humanroot/audit.jsonl

Example (Claude Desktop config):
  "filesystem": {
    "command": "humanroot-mcp",
    "args": ["wrap", "--drc", "/Users/x/.humanroot/drc.json",
             "--pubkey", "/Users/x/.humanroot/public.pem", "--",
             "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/x/project"]
  }
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_DIR = Path.home() / ".humanroot"
DEFAULT_LOG = DEFAULT_DIR / "audit.jsonl"
DEFAULT_AUDIT_KEY = DEFAULT_DIR / "audit_key.pem"


def cmd_wrap(args) -> int:
    from humanroot_mcp.audit import AuditLog
    from humanroot_mcp.enforce import Enforcer, EnforcementError
    from humanroot_mcp.proxy import Proxy

    if not args.command:
        print("wrap: missing server command after --", file=sys.stderr)
        return 2

    try:
        enforcer = Enforcer.from_files(args.drc, args.pubkey)
    except (EnforcementError, FileNotFoundError, ValueError) as e:
        print(f"humanroot-mcp: refusing to start — {e}", file=sys.stderr)
        return 1

    if enforcer.mode == "structural":
        print(
            "humanroot-mcp: WARNING — no --pubkey provided, chain validated "
            "structurally only (signatures not verified). Provide the principal "
            "public key for strict mode.",
            file=sys.stderr,
        )

    audit = AuditLog(args.log, args.audit_key)
    print(
        f"humanroot-mcp: delegation active — drc_id={enforcer.leaf.drc_id} "
        f"scopes={sorted(enforcer.leaf.authority.scopes)} mode={enforcer.mode}",
        file=sys.stderr,
    )
    return Proxy(enforcer, audit, args.command).run()


def cmd_report(args) -> int:
    from humanroot_mcp.report import build_report

    pub = args.audit_pub or str(Path(args.audit_key).with_suffix(".pub.pem"))
    report = build_report(args.log, pub)
    output = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(output)
        print(f"Report written to {args.out}", file=sys.stderr)
    else:
        print(output)
    return 0 if report["integrity"]["valid"] else 1


def cmd_verify_log(args) -> int:
    from humanroot_mcp.audit import verify_log

    pub = args.audit_pub or str(Path(args.audit_key).with_suffix(".pub.pem"))
    result = verify_log(args.log, pub)
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="humanroot-mcp")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_wrap = sub.add_parser("wrap", help="Wrap an MCP server with delegation enforcement")
    p_wrap.add_argument("--drc", required=True, help="Path to the DRC or chain JSON file")
    p_wrap.add_argument("--pubkey", default=None, help="Principal public key PEM (enables strict validation)")
    p_wrap.add_argument("--log", default=str(DEFAULT_LOG), help="Audit log path")
    p_wrap.add_argument("--audit-key", default=str(DEFAULT_AUDIT_KEY), help="Audit signing key path")
    p_wrap.add_argument("command", nargs=argparse.REMAINDER, help="-- followed by the MCP server command")
    p_wrap.set_defaults(func=cmd_wrap)

    p_report = sub.add_parser("report", help="Build the audit evidence report")
    p_report.add_argument("--log", default=str(DEFAULT_LOG))
    p_report.add_argument("--audit-key", default=str(DEFAULT_AUDIT_KEY))
    p_report.add_argument("--audit-pub", default=None)
    p_report.add_argument("--out", default=None)
    p_report.set_defaults(func=cmd_report)

    p_verify = sub.add_parser("verify-log", help="Verify audit log integrity")
    p_verify.add_argument("--log", default=str(DEFAULT_LOG))
    p_verify.add_argument("--audit-key", default=str(DEFAULT_AUDIT_KEY))
    p_verify.add_argument("--audit-pub", default=None)
    p_verify.set_defaults(func=cmd_verify_log)

    args = parser.parse_args(argv)
    if getattr(args, "command", None) and args.command and args.command[0] == "--":
        args.command = args.command[1:]
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
