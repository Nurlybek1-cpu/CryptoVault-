import os
import json
import base64
from typing import Dict, List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.exceptions import GroupMessagingError


class GroupManager:
    """
    Manages group chats and shared encryption keys.
    """

    def __init__(self, storage_backend=None):
        # In-memory storage: {group_id: key_bytes}
        self.group_keys: Dict[str, bytes] = {}
        self.group_members: Dict[str, List[str]] = {}

    def create_group(self, group_name: str, creator_id: str) -> str:
        """Creates a new group and generates a master key."""
        group_id = f"group_{os.urandom(4).hex()}"
        group_key = AESGCM.generate_key(bit_length=256)  # Shared key

        self.group_keys[group_id] = group_key
        self.group_members[group_id] = [creator_id]

        return group_id

    def get_group_key(self, group_id: str) -> bytes:
        if group_id not in self.group_keys:
            raise GroupMessagingError(f"Group {group_id} not found or access denied")
        return self.group_keys[group_id]

    def add_key_from_invite(self, group_id: str, key_b64: str):
        """Imports a group key received from an invitation."""
        try:
            key_bytes = base64.b64decode(key_b64)
            self.group_keys[group_id] = key_bytes
        except Exception as e:
            raise GroupMessagingError(f"Failed to import group key: {e}")

    def encrypt_group_message(self, group_id: str, message: str) -> Dict:
        """Encrypts a message using the shared group key."""
        try:
            key = self.get_group_key(group_id)
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)

            # Encrypt
            ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)

            return {
                "group_id": group_id,
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
            }
        except Exception as e:
            raise GroupMessagingError(f"Group encryption failed: {e}")

    def decrypt_group_message(self, encrypted_data: Dict) -> str:
        """Decrypts a group message."""
        try:
            group_id = encrypted_data["group_id"]
            nonce = base64.b64decode(encrypted_data["nonce"])
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])

            key = self.get_group_key(group_id)
            aesgcm = AESGCM(key)

            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise GroupMessagingError(f"Group decryption failed: {e}")
