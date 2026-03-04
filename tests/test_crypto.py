import unittest
from datetime import datetime, timedelta, timezone
from humanroot.crypto import generate_keypair, sign_drc, verify_drc, hash_drc
from humanroot.models import DelegationRootCertificate, Principal, AgentRef, Authority

def make_drc():
    now = datetime.now(timezone.utc)
    return DelegationRootCertificate(
        expires_at=now + timedelta(hours=1),
        principal=Principal(human_id="alice@example.com"),
        agent=AgentRef(agent_id="agent-1"),
        authority=Authority(scopes=["email.read", "calendar.write"]),
    )

class TestCrypto(unittest.TestCase):
    def test_generate_keypair(self):
        priv, pub = generate_keypair()
        self.assertIsNotNone(priv)
        self.assertIsNotNone(pub)

    def test_sign_and_verify(self):
        drc = make_drc()
        priv, pub = generate_keypair()
        signed = sign_drc(drc, priv)
        self.assertIsNotNone(signed.signature)
        self.assertTrue(verify_drc(signed, pub))

    def test_verify_with_wrong_key(self):
        drc = make_drc()
        priv, _ = generate_keypair()
        _, wrong_pub = generate_keypair()
        signed = sign_drc(drc, priv)
        self.assertFalse(verify_drc(signed, wrong_pub))

    def test_verify_unsigned_raises(self):
        drc = make_drc()
        _, pub = generate_keypair()
        with self.assertRaises(ValueError):
            verify_drc(drc, pub)

    def test_hash_deterministic(self):
        drc = make_drc()
        self.assertEqual(hash_drc(drc), hash_drc(drc))
        self.assertEqual(len(hash_drc(drc)), 64)

    def test_hash_changes_with_content(self):
        now = datetime.now(timezone.utc)
        drc1 = DelegationRootCertificate(
            expires_at=now + timedelta(hours=1),
            principal=Principal(human_id="alice@example.com"),
            agent=AgentRef(agent_id="agent-1"),
            authority=Authority(scopes=["email.read"]),
        )
        drc2 = DelegationRootCertificate(
            expires_at=now + timedelta(hours=1),
            principal=Principal(human_id="alice@example.com"),
            agent=AgentRef(agent_id="agent-2"),
            authority=Authority(scopes=["email.read"]),
        )
        self.assertNotEqual(hash_drc(drc1), hash_drc(drc2))

if __name__ == "__main__":
    unittest.main()
