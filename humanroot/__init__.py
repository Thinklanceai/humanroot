"""HumanRoot — Delegation Root Certificate for Autonomous Agents."""

from humanroot.delegate import delegate
from humanroot.models import DelegationRootCertificate, Principal, AgentRef, Authority
from humanroot.chain import sub_delegate, reconstruct_chain, validate_chain, DelegationError
from humanroot.crypto import generate_keypair, sign_drc, verify_drc, hash_drc

__all__ = [
    "delegate",
    "DelegationRootCertificate",
    "Principal",
    "AgentRef",
    "Authority",
    "sub_delegate",
    "reconstruct_chain",
    "validate_chain",
    "DelegationError",
    "generate_keypair",
    "sign_drc",
    "verify_drc",
    "hash_drc",
]
