import dataclasses
import unittest
from datetime import timedelta
from humanroot import (
    delegate, sub_delegate, reconstruct_chain, validate_chain,
    DelegationError, generate_keypair, verify_drc,
)

ALICE = "alice@example.com"

def signed_chain(priv):
    root = delegate(human_id=ALICE, agent_id="agent-a",
                    scopes=["email.read", "calendar.write"],
                    expires_in="2h", max_delegation_depth=2,
                    signing_key=priv)
    child = sub_delegate(root, agent_id="agent-b", scopes=["email.read"],
                         expires_at=root.expires_at - timedelta(minutes=10),
                         signing_key=priv)
    return root, child

class TestChain(unittest.TestCase):
    def test_sub_delegate_basic(self):
        root = delegate(human_id=ALICE, agent_id="agent-a",
                        scopes=["email.read", "calendar.write"],
                        expires_in="1h", max_delegation_depth=2)
        child = sub_delegate(root, agent_id="agent-b", scopes=["email.read"],
                             expires_at=root.expires_at - timedelta(minutes=1))
        self.assertEqual(child.parent_drc_id, root.drc_id)
        self.assertIsNotNone(child.root_hash)
        self.assertEqual(child.authority.max_delegation_depth, 1)
        self.assertTrue(set(child.authority.scopes) <= set(root.authority.scopes))

    def test_scope_expansion_forbidden(self):
        root = delegate(human_id=ALICE, agent_id="agent-a",
                        scopes=["email.read"], expires_in="1h")
        with self.assertRaises(DelegationError):
            sub_delegate(root, agent_id="agent-b",
                         scopes=["email.read", "database.write"],
                         expires_at=root.expires_at - timedelta(minutes=1))

    def test_depth_exhausted(self):
        root = delegate(human_id=ALICE, agent_id="agent-a",
                        scopes=["email.read"], expires_in="1h",
                        max_delegation_depth=1)
        child = sub_delegate(root, agent_id="agent-b", scopes=["email.read"],
                             expires_at=root.expires_at - timedelta(minutes=1))
        self.assertEqual(child.authority.max_delegation_depth, 0)
        with self.assertRaises(DelegationError):
            sub_delegate(child, agent_id="agent-c", scopes=["email.read"],
                         expires_at=root.expires_at - timedelta(minutes=1))

    def test_expiry_cannot_exceed_parent(self):
        root = delegate(human_id=ALICE, agent_id="agent-a",
                        scopes=["email.read"], expires_in="1h")
        with self.assertRaises(DelegationError):
            sub_delegate(root, agent_id="agent-b", scopes=["email.read"],
                         expires_at=root.expires_at + timedelta(hours=1))

    def test_reconstruct_chain(self):
        root = delegate(human_id=ALICE, agent_id="agent-a",
                        scopes=["email.read", "calendar.write"],
                        expires_in="2h", max_delegation_depth=2)
        child = sub_delegate(root, agent_id="agent-b", scopes=["email.read"],
                             expires_at=root.expires_at - timedelta(minutes=10))
        grandchild = sub_delegate(child, agent_id="agent-c", scopes=["email.read"],
                                  expires_at=child.expires_at - timedelta(minutes=5))
        store = {root.drc_id: root, child.drc_id: child, grandchild.drc_id: grandchild}
        chain = reconstruct_chain(grandchild, store)
        self.assertEqual(len(chain), 3)
        self.assertEqual(chain[0].drc_id, root.drc_id)
        self.assertEqual(chain[-1].drc_id, grandchild.drc_id)

    def test_strict_validate_signed_chain_passes(self):
        priv, pub = generate_keypair()
        root, child = signed_chain(priv)
        store = {root.drc_id: root, child.drc_id: child}
        chain = reconstruct_chain(child, store)
        validate_chain(chain, public_keys={ALICE: pub})

    def test_strict_rejects_unsigned_chain(self):
        root = delegate(human_id=ALICE, agent_id="agent-a",
                        scopes=["email.read"], expires_in="1h")
        with self.assertRaises(DelegationError):
            validate_chain([root])

    def test_strict_rejects_missing_key(self):
        priv, _ = generate_keypair()
        root, child = signed_chain(priv)
        chain = reconstruct_chain(child, {root.drc_id: root, child.drc_id: child})
        with self.assertRaises(DelegationError):
            validate_chain(chain, public_keys={})

    def test_strict_rejects_wrong_root_hash(self):
        priv, pub = generate_keypair()
        root, child = signed_chain(priv)
        forged_child = dataclasses.replace(child, root_hash="0" * 64)
        with self.assertRaises(DelegationError):
            validate_chain([root, forged_child], public_keys={ALICE: pub})

    def test_strict_rejects_broken_linkage(self):
        priv, pub = generate_keypair()
        root, child = signed_chain(priv)
        forged_child = dataclasses.replace(child, parent_drc_id="not-the-parent")
        with self.assertRaises(DelegationError):
            validate_chain([root, forged_child], public_keys={ALICE: pub})

    def test_non_strict_structural_only(self):
        root = delegate(human_id=ALICE, agent_id="agent-a",
                        scopes=["email.read", "calendar.write"],
                        expires_in="2h", max_delegation_depth=2)
        child = sub_delegate(root, agent_id="agent-b", scopes=["email.read"],
                             expires_at=root.expires_at - timedelta(minutes=10))
        store = {root.drc_id: root, child.drc_id: child}
        chain = reconstruct_chain(child, store)
        validate_chain(chain, strict=False)

    def test_delegate_signed(self):
        priv, pub = generate_keypair()
        drc = delegate(human_id=ALICE, agent_id="my-agent-v1",
                       scopes=["email.read", "calendar.write"],
                       expires_in="24h", signing_key=priv)
        self.assertIsNotNone(drc.signature)
        self.assertTrue(drc.is_root())
        self.assertTrue(verify_drc(drc, pub))

if __name__ == "__main__":
    unittest.main()
