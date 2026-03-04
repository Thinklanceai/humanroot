"""
humanroot.crypto
----------------
Cryptographic helpers: key generation, signing (ES256 via PyJWT), verification.
Dependencies: cryptography, PyJWT — both already installed.
"""
from __future__ import annotations

import hashlib
import json
import dataclasses

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    generate_private_key,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
    load_pem_private_key, load_pem_public_key,
)

from humanroot.models import DelegationRootCertificate


def generate_keypair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    private_key = generate_private_key(SECP256R1(), default_backend())
    return private_key, private_key.public_key()


def private_key_to_pem(key: EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def public_key_to_pem(key: EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def pem_to_private_key(pem: bytes) -> EllipticCurvePrivateKey:
    return load_pem_private_key(pem, password=None, backend=default_backend())


def pem_to_public_key(pem: bytes) -> EllipticCurvePublicKey:
    return load_pem_public_key(pem, backend=default_backend())


def hash_drc(drc: DelegationRootCertificate) -> str:
    payload = drc.unsigned_payload()
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def sign_drc(
    drc: DelegationRootCertificate,
    private_key: EllipticCurvePrivateKey,
) -> DelegationRootCertificate:
    payload = drc.unsigned_payload()
    token = jwt.encode(payload, private_key, algorithm="ES256")
    if isinstance(token, bytes):
        token = token.decode()
    return dataclasses.replace(drc, signature=token)


def verify_drc(
    drc: DelegationRootCertificate,
    public_key: EllipticCurvePublicKey,
) -> bool:
    if not drc.signature:
        raise ValueError("DRC has no signature to verify")
    try:
        jwt.decode(
            drc.signature,
            public_key,
            algorithms=["ES256"],
            options={"verify_exp": False},
        )
        return True
    except jwt.PyJWTError:
        return False
