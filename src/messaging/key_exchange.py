import secrets
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
from cryptography.hazmat.backends import default_backend
import hmac

from src.exceptions import KeyExchangeError


class KeyExchange:
    """
    Manages ECDH key generation and shared secret derivation.
    Uses SECP256R1 (P-256) curve.
    """

    def generate_ephemeral_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generates a temporary (ephemeral) key pair for a single session.

        Returns:
            Tuple[bytes, bytes]: (private_key_bytes, public_key_bytes) in PEM format.
        """
        # 1. Generate key on P-256 curve
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # 2. Serialize to bytes (for network transmission)
        private_bytes = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )

        public_bytes = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )

        return private_bytes, public_bytes

    def perform_ecdh(self, private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
        """
        Performs ECDH math: (My Private) * (Peer Public).
        Results in the same point for both parties.
        """
        try:
            # Deserialize keys back to objects
            private_key = self._load_private_key(private_key_bytes)
            peer_public_key = self._load_public_key(peer_public_key_bytes)

            # Perform the exchange
            shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
            return shared_key
        except Exception as e:
            raise KeyExchangeError(f"ECDH exchange failed: {str(e)}")

    def derive_shared_secret_hkdf(self, shared_secret: bytes, salt: bytes, info: bytes) -> bytes:
        """
        Derives a secure AES encryption key from the raw ECDH shared secret using HKDF.
        """
        # HKDF distributes entropy to make the key uniform suitable for AES
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes for AES-256
            salt=salt,  # Public salt (usually ephemeral public key)
            info=info,  # Context info
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)

    def verify_key_exchange_success(self, key1: bytes, key2: bytes) -> bool:
        """
        Constant-time comparison to prevent timing attacks.
        """
        return hmac.compare_digest(key1, key2)

    # Helper methods (private)
    def _load_private_key(self, key_bytes: bytes):
        from cryptography.hazmat.primitives import serialization
        return serialization.load_pem_private_key(key_bytes, password=None)

    def _load_public_key(self, key_bytes: bytes):
        from cryptography.hazmat.primitives import serialization
        return serialization.load_pem_public_key(key_bytes)
