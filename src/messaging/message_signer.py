import base64
from typing import Dict, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature

from src.exceptions import SignatureError


class MessageSigner:
    """
    Handles creation and verification of ECDSA digital signatures.
    Uses SHA-256 for hashing before signing.
    """

    def sign_message(self, message_bytes: bytes, private_key) -> bytes:
        """Low-level signing operation."""
        try:
            signature = private_key.sign(
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return signature
        except Exception as e:
            raise SignatureError(f"Signing failed: {str(e)}")

    def verify_signature(self, message_bytes: bytes, signature: bytes, public_key) -> bool:
        """Low-level verification operation."""
        try:
            public_key.verify(
                signature,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def sign_message_hash(self, message: str, private_key) -> Dict[str, str]:
        """
        Full pipeline: Hash -> Sign -> Pack to Dict.
        We sign the SHA-256 hash of the message, not the message itself.
        """
        # 1. Hash the message
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message.encode('utf-8'))
        message_hash = digest.finalize()

        # 2. Sign the hash
        signature = self.sign_message(message_hash, private_key)

        # 3. Return result
        return {
            "message_hash": base64.b64encode(message_hash).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "algorithm": "ECDSA-SHA256"
        }

    def verify_message_signature(self, message: str, signature_dict: Dict[str, str], public_key) -> bool:
        """
        Full pipeline: Hash incoming text -> Verify against signature.
        """
        try:
            # 1. Recreate hash from received text
            digest = hashes.Hash(hashes.SHA256())
            digest.update(message.encode('utf-8'))
            calculated_hash = digest.finalize()

            # 2. Decode signature
            signature_bytes = base64.b64decode(signature_dict["signature"])

            # 3. Verify
            return self.verify_signature(calculated_hash, signature_bytes, public_key)
        except Exception:
            return False
