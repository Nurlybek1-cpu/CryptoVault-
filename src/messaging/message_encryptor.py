import os
import base64
from typing import Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from src.exceptions import EncryptionError


class MessageEncryptor:
    """
    Handles message encryption and decryption using AES-256-GCM.
    Ensures Confidentiality (secrecy) and Integrity (anti-tampering).
    """

    def encrypt_message(self, plaintext: str, encryption_key: bytes) -> Dict[str, str]:
        """
        Encrypts a text string.

        Args:
            plaintext: The source text.
            encryption_key: 32-byte secret key derived via ECDH.

        Returns:
            Dict: Contains nonce, ciphertext, and auth_tag (Base64 encoded).
        """
        try:
            # 1. Generate unique Nonce (12 bytes)
            # CRITICAL: Never reuse a nonce with the same key
            nonce = os.urandom(12)

            # 2. Initialize cipher
            cipher = AESGCM(encryption_key)

            # 3. Encrypt
            # AESGCM automatically appends Auth Tag to ciphertext
            ciphertext_with_tag = cipher.encrypt(nonce, plaintext.encode('utf-8'), None)

            # 4. Separate ciphertext and auth_tag (last 16 bytes)
            auth_tag = ciphertext_with_tag[-16:]
            actual_ciphertext = ciphertext_with_tag[:-16]

            # 5. Encode to Base64 for JSON transport
            return {
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(actual_ciphertext).decode('utf-8'),
                "auth_tag": base64.b64encode(auth_tag).decode('utf-8')
            }
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {str(e)}")

    def decrypt_message(self, encrypted_data: Dict[str, str], encryption_key: bytes) -> str:
        """
        Decrypts a message and verifies the auth tag.
        """
        try:
            # 1. Decode from Base64
            nonce = base64.b64decode(encrypted_data["nonce"])
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            auth_tag = base64.b64decode(encrypted_data.get("auth_tag", ""))

            # Reassemble for the library (ciphertext + tag)
            full_ciphertext = ciphertext + auth_tag

            # 2. Initialize cipher
            cipher = AESGCM(encryption_key)

            # 3. Decrypt (raises InvalidTag if tampering detected)
            plaintext_bytes = cipher.decrypt(nonce, full_ciphertext, None)

            return plaintext_bytes.decode('utf-8')

        except InvalidTag:
            # Critical security event
            raise EncryptionError("Message authentication failed - potential tampering detected")
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {str(e)}")
