from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf_expand(shared: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared)


@dataclass
class SigKeyPair:
    sk: ed25519.Ed25519PrivateKey
    pk: ed25519.Ed25519PublicKey

    @staticmethod
    def generate() -> "SigKeyPair":
        sk = ed25519.Ed25519PrivateKey.generate()
        return SigKeyPair(sk=sk, pk=sk.public_key())

    def pk_bytes(self) -> bytes:
        return self.pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, msg: bytes) -> bytes:
        return self.sk.sign(msg)


def sig_verify(pk_bytes: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes)
        pk.verify(sig, msg)
        return True
    except Exception:
        return False


@dataclass
class KemKeyPair:
    sk: x25519.X25519PrivateKey
    pk: x25519.X25519PublicKey

    @staticmethod
    def generate() -> "KemKeyPair":
        sk = x25519.X25519PrivateKey.generate()
        return KemKeyPair(sk=sk, pk=sk.public_key())

    def pk_bytes(self) -> bytes:
        return self.pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sk_bytes(self) -> bytes:
        return self.sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )


def wrap_to_device(pk_kem_bytes: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """HPKE-like wrapping: X25519 KEM + HKDF + ChaCha20-Poly1305.

    Output format: eph_pub(32) || nonce(12) || aead_ct.
    """
    pk = x25519.X25519PublicKey.from_public_bytes(pk_kem_bytes)
    eph_sk = x25519.X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    shared = eph_sk.exchange(pk)
    key = hkdf_expand(shared, b"RSMAIL-WRAP", 32)
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, plaintext, aad)
    eph_bytes = eph_pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return eph_bytes + nonce + ct


def unwrap_from_device(sk_kem: x25519.X25519PrivateKey, wrap: bytes, aad: bytes) -> bytes:
    if len(wrap) < 32 + 12 + 16:
        raise ValueError("wrap too short")
    eph_bytes = wrap[:32]
    nonce = wrap[32:44]
    ct = wrap[44:]
    eph_pk = x25519.X25519PublicKey.from_public_bytes(eph_bytes)
    shared = sk_kem.exchange(eph_pk)
    key = hkdf_expand(shared, b"RSMAIL-WRAP", 32)
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ct, aad)


def kem_encap_epoch(ek_epoch_bytes: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate to epoch public key. Returns (ct_e, shared_secret)."""
    ek = x25519.X25519PublicKey.from_public_bytes(ek_epoch_bytes)
    eph_sk = x25519.X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    shared = eph_sk.exchange(ek)
    ct_e = eph_pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return ct_e, shared


def kem_decap_epoch(dk_epoch: x25519.X25519PrivateKey, ct_e: bytes) -> bytes:
    eph_pk = x25519.X25519PublicKey.from_public_bytes(ct_e)
    return dk_epoch.exchange(eph_pk)


def aead_encrypt(shared_secret: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    key = hkdf_expand(shared_secret, b"RSMAIL-MSG", 32)
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, plaintext, aad)
    return nonce, ct


def aead_decrypt(shared_secret: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    key = hkdf_expand(shared_secret, b"RSMAIL-MSG", 32)
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext, aad)


def epoch_keypair_generate() -> KemKeyPair:
    """Generate an epoch KEM keypair (X25519)."""
    return KemKeyPair.generate()


def epoch_sk_from_bytes(raw: bytes) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(raw)


def epoch_sk_to_bytes(sk: x25519.X25519PrivateKey) -> bytes:
    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
