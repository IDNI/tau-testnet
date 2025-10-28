"""Helpers for deterministic libp2p identities without patching dependencies."""
from __future__ import annotations

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
import nacl.utils

from libp2p.crypto.keys import KeyPair, KeyType, PrivateKey, PublicKey


IDENTITY_SEED_SIZE = 32


class Ed25519PublicKeyCompat(PublicKey):
    """Thin wrapper over `nacl.signing.VerifyKey` with libp2p's interface."""

    def __init__(self, verify_key: VerifyKey) -> None:
        self._verify_key = verify_key

    def to_bytes(self) -> bytes:
        return bytes(self._verify_key)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Ed25519PublicKeyCompat":
        return cls(VerifyKey(data))

    def get_type(self) -> KeyType:
        return KeyType.Ed25519

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._verify_key.verify(data, signature)
        except BadSignatureError:
            return False
        return True


class Ed25519PrivateKeyCompat(PrivateKey):
    """`nacl.signing.SigningKey` backed private key compatible with libp2p."""

    def __init__(self, signing_key: SigningKey) -> None:
        self._signing_key = signing_key

    @classmethod
    def generate(cls) -> "Ed25519PrivateKeyCompat":
        seed = nacl.utils.random(IDENTITY_SEED_SIZE)
        return cls(SigningKey(seed))

    @classmethod
    def from_bytes(cls, data: bytes) -> "Ed25519PrivateKeyCompat":
        if len(data) != IDENTITY_SEED_SIZE:
            raise ValueError(f"Ed25519 identity seed must be {IDENTITY_SEED_SIZE} bytes, got {len(data)}")
        return cls(SigningKey(data))

    def to_bytes(self) -> bytes:
        return bytes(self._signing_key)

    def get_type(self) -> KeyType:
        return KeyType.Ed25519

    def sign(self, data: bytes) -> bytes:
        signed = self._signing_key.sign(data)
        return signed.signature

    def get_public_key(self) -> PublicKey:
        return Ed25519PublicKeyCompat(self._signing_key.verify_key)


def keypair_from_seed(seed: bytes) -> KeyPair:
    """Return a libp2p `KeyPair` from a persisted 32-byte Ed25519 seed."""
    priv = Ed25519PrivateKeyCompat.from_bytes(seed)
    return KeyPair(private_key=priv, public_key=priv.get_public_key())


def generate_seed() -> bytes:
    """Generate a fresh 32-byte seed suitable for `keypair_from_seed`."""
    return nacl.utils.random(IDENTITY_SEED_SIZE)
