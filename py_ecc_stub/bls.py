"""
Stub implementation of BLS signature operations for testing purposes.
The public key is the private key, and signatures are a hash of private key and message.
"""
import hashlib

class G2Basic:
    @staticmethod
    def KeyGen(seed: bytes) -> bytes:
        # Generate a 48-byte private key stub using SHA-512 and truncate
        return hashlib.sha512(seed).digest()[:48]

    @staticmethod
    def SkToPk(sk: bytes) -> bytes:
        # Treat the private key as the public key stub.
        return sk

    @staticmethod
    def Sign(privkey: bytes, message_hash: bytes) -> bytes:
        return hashlib.sha256(privkey + message_hash).digest()

    @staticmethod
    def Verify(pubkey: bytes, message_hash: bytes, signature: bytes) -> bool:
        expected = hashlib.sha256(pubkey + message_hash).digest()
        return expected == signature

    @staticmethod
    def AggregatePKs(pks: list[bytes]) -> bytes:
        # Stub for public key aggregation/validation.
        # Simply return the first key or empty bytes if none.
        return pks[0] if pks else b""