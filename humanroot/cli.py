#!/usr/bin/env python3
"""
humanroot CLI
-------------
Usage:
  humanroot issue   --human-id alice@example.com --agent-id my-agent --scopes email.read calendar.write
  humanroot verify  --drc-file drc.json
  humanroot chain   --drc-id <uuid> --server http://localhost:8001
  humanroot revoke  --drc-id <uuid> --server http://localhost:8001
  humanroot status  --drc-id <uuid> --server http://localhost:8001
  humanroot keygen  --out keys/
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_issue(args):
    from humanroot import delegate
    from humanroot.crypto import generate_keypair, private_key_to_pem, public_key_to_pem, sign_drc

    signing_key = None
    if args.key:
        from humanroot.crypto import pem_to_private_key
        signing_key = pem_to_private_key(Path(args.key).read_bytes())

    drc = delegate(
        human_id=args.human_id,
        agent_id=args.agent_id,
        scopes=args.scopes,
        expires_in=args.expires_in,
        provider=args.provider,
        max_delegation_depth=args.max_depth,
        signing_key=signing_key,
    )

    output = drc.to_dict()

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(output, indent=2, default=str))
        print(f"DRC written to {out_path}")
    else:
        print(json.dumps(output, indent=2, default=str))

    print(f"\n✓ DRC issued: {drc.drc_id}", file=sys.stderr)


def cmd_verify(args):
    from humanroot.crypto import pem_to_public_key, verify_drc
    from humanroot.models import (
        DelegationRootCertificate, Principal, AgentRef, Authority
    )
    from datetime import datetime

    drc_dict = json.loads(Path(args.drc_file).read_text())

    drc = DelegationRootCertificate(
        version=drc_dict["version"],
        drc_id=drc_dict["drc_id"],
        issued_at=datetime.fromisoformat(drc_dict["issued_at"]),
        expires_at=datetime.fromisoformat(drc_dict["expires_at"]),
        principal=Principal(**drc_dict["principal"]),
        agent=AgentRef(**drc_dict["agent"]),
        authority=Authority(**drc_dict["authority"]),
        parent_drc_id=drc_dict.get("parent_drc_id"),
        root_hash=drc_dict.get("root_hash"),
        signature=drc_dict.get("signature"),
    )

    print(f"DRC ID    : {drc.drc_id}")
    print(f"Human     : {drc.principal.human_id}")
    print(f"Agent     : {drc.agent.agent_id}")
    print(f"Scopes    : {', '.join(drc.authority.scopes)}")
    print(f"Expires   : {drc.expires_at.isoformat()}")
    print(f"Expired   : {drc.is_expired()}")
    print(f"Root      : {drc.is_root()}")

    if args.pubkey and drc.signature:
        pub = pem_to_public_key(Path(args.pubkey).read_bytes())
        valid = verify_drc(drc, pub)
        print(f"Signature : {'✓ valid' if valid else '✗ INVALID'}")
    elif drc.signature:
        print(f"Signature : present (use --pubkey to verify)")
    else:
        print(f"Signature : none")


def cmd_chain(args):
    import urllib.request
    url = f"{args.server.rstrip('/')}/drc/{args.drc_id}/chain"
    with urllib.request.urlopen(url) as r:
        data = json.loads(r.read())

    print(f"Chain length : {data['length']}")
    print(f"Any revoked  : {data['any_revoked']}")
    print()
    for i, drc in enumerate(data["chain"]):
        prefix = "ROOT" if i == 0 else f"HOP {i}"
        print(f"  [{prefix}] {drc['drc_id']}")
        print(f"         agent  : {drc['agent']['agent_id']}")
        print(f"         scopes : {', '.join(drc['authority']['scopes'])}")
        print(f"         depth  : {drc['authority']['max_delegation_depth']}")
        if i < data["length"] - 1:
            print(f"           ↓")


def cmd_revoke(args):
    import urllib.request
    url = f"{args.server.rstrip('/')}/drc/revoke"
    payload = json.dumps({"drc_id": args.drc_id, "reason": args.reason}).encode()
    req = urllib.request.Request(url, data=payload,
                                  headers={"Content-Type": "application/json"},
                                  method="POST")
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read())

    print(f"✓ Revoked {data['count']} DRC(s):")
    for did in data["revoked"]:
        print(f"  - {did}")


def cmd_status(args):
    import urllib.request
    url = f"{args.server.rstrip('/')}/drc/{args.drc_id}/status"
    with urllib.request.urlopen(url) as r:
        data = json.loads(r.read())

    status = "✗ REVOKED" if data["revoked"] else "✓ active"
    print(f"DRC {args.drc_id} : {status}")
    if data.get("revocation"):
        rev = data["revocation"]
        print(f"  Revoked at : {rev['revoked_at']}")
        if rev.get("reason"):
            print(f"  Reason     : {rev['reason']}")


def cmd_keygen(args):
    from humanroot.crypto import generate_keypair, private_key_to_pem, public_key_to_pem

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    priv, pub = generate_keypair()
    priv_path = out_dir / "private.pem"
    pub_path = out_dir / "public.pem"

    priv_path.write_bytes(private_key_to_pem(priv))
    pub_path.write_bytes(public_key_to_pem(pub))

    priv_path.chmod(0o600)  # private key readable only by owner

    print(f"✓ Keys generated:")
    print(f"  Private : {priv_path}")
    print(f"  Public  : {pub_path}")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="humanroot",
        description="HumanRoot — Delegation Root Certificate CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # issue
    p_issue = sub.add_parser("issue", help="Issue a root DRC")
    p_issue.add_argument("--human-id", required=True)
    p_issue.add_argument("--agent-id", required=True)
    p_issue.add_argument("--scopes", nargs="+", required=True)
    p_issue.add_argument("--expires-in", default="24h")
    p_issue.add_argument("--provider", default="custom")
    p_issue.add_argument("--max-depth", type=int, default=3)
    p_issue.add_argument("--key", help="Path to private key PEM for signing")
    p_issue.add_argument("--out", help="Write DRC JSON to file")

    # verify
    p_verify = sub.add_parser("verify", help="Inspect and verify a DRC file")
    p_verify.add_argument("--drc-file", required=True)
    p_verify.add_argument("--pubkey", help="Public key PEM to verify signature")

    # chain
    p_chain = sub.add_parser("chain", help="Show full delegation chain")
    p_chain.add_argument("--drc-id", required=True)
    p_chain.add_argument("--server", default="http://localhost:8001")

    # revoke
    p_revoke = sub.add_parser("revoke", help="Revoke a DRC and its children")
    p_revoke.add_argument("--drc-id", required=True)
    p_revoke.add_argument("--reason", default=None)
    p_revoke.add_argument("--server", default="http://localhost:8001")

    # status
    p_status = sub.add_parser("status", help="Check revocation status")
    p_status.add_argument("--drc-id", required=True)
    p_status.add_argument("--server", default="http://localhost:8001")

    # keygen
    p_keygen = sub.add_parser("keygen", help="Generate an ES256 key pair")
    p_keygen.add_argument("--out", default="./keys")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Normalise hyphenated args to underscored attrs
    if hasattr(args, "human_id") is False and hasattr(args, "human-id"):
        pass  # argparse handles this automatically with dest

    commands = {
        "issue": cmd_issue,
        "verify": cmd_verify,
        "chain": cmd_chain,
        "revoke": cmd_revoke,
        "status": cmd_status,
        "keygen": cmd_keygen,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
