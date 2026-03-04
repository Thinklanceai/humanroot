import unittest
from datetime import datetime, timedelta, timezone
from humanroot import (
    delegate, sub_delegate, reconstruct_chain, validate_chain,
    DelegationError, generate_keypair, verify_drc,
)

class TestChain(unittest.TestCase):
    def test_sub_delegate_basic(self):
        root = delegate(human_id="alice@example.com", agent_id="agent-a",
                        scopes=["email.read", "calendar.write"],
                        expires_in="1h", max_delegation_depth=2)
        child = sub_delegate(root, agent_id="agent-b", scopes=["email.read"],
                             expires_at=root.expires_at - timedelta(minutes=1))
        self.assertEqual(child.parent_drc_id, root.drc_id)
        self.assertIsNotNone(child.root_hash)
        self.assertEqual(child.authority.max_delegation_depth, 1)
        self.assertTrue(set(child.authority.scopes) <= set(root.authority.scopes))

    def test_scope_expansion_forbidden(self):
        root = delegate(human_id="alice@example.com", agent_id="agent-a",
                        scopes=["email.read"], expires_in="1h")
        with self.assertRaises(DelegationError):
            sub_delegate(root, agent_id="agent-b",
                         scopes=["email.read", "database.write"],
                         expires_at=root.expires_at - timedelta(minutes=1))

    def test_depth_exhausted(self):
        root = delegate(human_id="alice@example.com", agent_id="agent-a",
                        scopes=["email.read"], expires_in="1h",
                        max_delegation_depth=1)
        child = sub_delegate(root, agent_id="agent-b", scopes=["email.read"],
                             expires_at=root.expires_at - timedelta(minutes=1))
        self.assertEqual(child.authority.max_delegation_depth, 0)
        with self.assertRaises(DelegationError):
            sub_delegate(child, agent_id="agent-c", scopes=["email.read"],
                         expires_at=root.expires_at - timedelta(minutes=1))

    def test_expiry_cannot_exceed_parent(self):
        root = delegate(human_id="alice@example.com", agent_id="agent-a",
                        scopes=["email.read"], expires_in="1h")
        with self.assertRaises(DelegationError):
            sub_delegate(root, agent_id="agent-b", scopes=["email.read"],
                         expires_at=root.expires_at + timedelta(hours=1))

    def test_reconstruct_chain(self):
        root = delegate(human_id="alice@example.com", agent_id="agent-a",
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

    def test_validate_chain_passes(self):
        root = delegate(human_id="alice@example.com", agent_id="agent-a",
                        scopes=["email.read", "calendar.write"],
                        expires_in="2h", max_delegation_depth=2)
        child = sub_delegate(root, agent_id="agent-b", scopes=["email.read"],
                             expires_at=root.expires_at - timedelta(minutes=10))
        store = {root.drc_id: root, child.drc_id: child}
        chain = reconstruct_chain(child, store)
        validate_chain(chain)  # should not raise

    def test_delegate_signed(self):
        priv, pub = generate_keypair()
        drc = delegate(human_id="alice@example.com", agent_id="my-agent-v1",
                       scopes=["email.read", "calendar.write"],
                       expires_in="24h", signing_key=priv)
        self.assertIsNotNone(drc.signature)
        self.assertTrue(drc.is_root())
        self.assertTrue(verify_drc(drc, pub))

if __name__ == "__main__":
    unittest.main()
