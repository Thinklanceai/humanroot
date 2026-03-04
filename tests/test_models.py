import unittest
from datetime import datetime, timedelta, timezone
from humanroot.models import DelegationRootCertificate, Principal, AgentRef, Authority

def make_drc(**kwargs):
    now = datetime.now(timezone.utc)
    defaults = dict(
        expires_at=now + timedelta(hours=1),
        principal=Principal(human_id="alice@example.com"),
        agent=AgentRef(agent_id="agent-1"),
        authority=Authority(scopes=["email.read"]),
    )
    defaults.update(kwargs)
    return DelegationRootCertificate(**defaults)

class TestModels(unittest.TestCase):
    def test_basic_creation(self):
        drc = make_drc()
        self.assertEqual(drc.version, "0.1")
        self.assertIsNotNone(drc.drc_id)
        self.assertTrue(drc.is_root())
        self.assertFalse(drc.is_expired())

    def test_expiry_validation(self):
        now = datetime.now(timezone.utc)
        with self.assertRaises(ValueError):
            make_drc(expires_at=now - timedelta(minutes=1))

    def test_is_expired(self):
        now = datetime.now(timezone.utc)
        drc = make_drc(
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
        )
        self.assertTrue(drc.is_expired())

    def test_is_root_false(self):
        drc = make_drc(parent_drc_id="some-parent-uuid")
        self.assertFalse(drc.is_root())

    def test_unsigned_payload_excludes_signature(self):
        drc = make_drc()
        payload = drc.unsigned_payload()
        self.assertNotIn("signature", payload)

if __name__ == "__main__":
    unittest.main()
