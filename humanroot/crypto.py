"""
humanroot.crypto
----------------
Cryptographic helpers: key generation, signing (ES256 via PyJWT),
verification.

Hardened in 0.2.0:
- Canonicalization is RFC 8785 (JCS) via the `rfc8785` library —
  deterministic bytes, no `default=str` ambiguity.
- `expires_at` is enforced cryptographically: signing embeds `exp`
  and `iat` as registered JWT claims and verification rejects
  expired tokens.
- Payload binding: verification decodes the JWS and compares every
  claim against the certificate's own fields, so a valid signature
  lifted from one DRC cannot be attached to another.
"""
from __future__ import annotations

import dataclasses
import hashlib

import jwt
import rfc8785
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


def canonical_bytes(payload: dict) -> bytes:
    """RFC 8785 (JCS) canonical serialization of a JSON-compatible dict.

    Raises if the payload contains non-JSON types — strictness is the
    point: a certificate that cannot be canonicalized deterministically
    must not be hashed or signed.
    """
    return rfc8785.dumps(payload)


def hash_drc(drc: DelegationRootCertificate) -> str:
    return hashlib.sha256(canonical_bytes(drc.unsigned_payload())).hexdigest()


def _claims_for(drc: DelegationRootCertificate) -> dict:
    claims = drc.unsigned_payload()
    claims["iat"] = int(drc.issued_at.timestamp())
    claims["exp"] = int(drc.expires_at.timestamp())
    return claims


def sign_drc(
    drc: DelegationRootCertificate,
    private_key: EllipticCurvePrivateKey,
) -> DelegationRootCertificate:
    token = jwt.encode(_claims_for(drc), private_key, algorithm="ES256")
    if isinstance(token, bytes):
        token = token.decode()
    return dataclasses.replace(drc, signature=token)


def verify_drc(
    drc: DelegationRootCertificate,
    public_key: EllipticCurvePublicKey,
) -> bool:
    """Verify a DRC signature.

    Returns False when the signature is invalid, expired, or signs a
    payload that does not match this certificate's fields. Raises
    ValueError only when the DRC carries no signature at all.
    """
    if not drc.signature:
        raise ValueError("DRC has no signature to verify")
    try:
        decoded = jwt.decode(
            drc.signature,
            public_key,
            algorithms=["ES256"],
            options={"require": ["exp", "iat"], "verify_exp": True},
        )
    except jwt.PyJWTError:
        return False

    expected = _claims_for(drc)
    return decoded == expected
