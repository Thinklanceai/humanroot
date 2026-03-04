from humanroot import delegate, generate_keypair, verify_drc, sub_delegate
from datetime import timedelta

# Génère une paire de clés pour Alice
priv, pub = generate_keypair()

# Alice délègue à un agent
drc = delegate(
    human_id="alice@example.com",
    agent_id="mon-agent-v1",
    scopes=["email.read", "calendar.write"],
    expires_in="24h",
    signing_key=priv,
)

print("=== DRC root ===")
print(f"ID       : {drc.drc_id}")
print(f"Human    : {drc.principal.human_id}")
print(f"Agent    : {drc.agent.agent_id}")
print(f"Scopes   : {drc.authority.scopes}")
print(f"Signé    : {drc.signature is not None}")
print(f"Valide   : {verify_drc(drc, pub)}")

# L'agent délègue à un sous-agent (scope réduit)
child = sub_delegate(
    drc,
    agent_id="sous-agent-v1",
    scopes=["email.read"],
    expires_at=drc.expires_at - timedelta(hours=1),
)

print("\n=== DRC child ===")
print(f"ID       : {child.drc_id}")
print(f"Parent   : {child.parent_drc_id}")
print(f"Scopes   : {child.authority.scopes}")
print(f"Depth    : {child.authority.max_delegation_depth}")
print(f"RootHash : {child.root_hash[:16]}...")
