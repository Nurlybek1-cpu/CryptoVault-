import logging
import base64
import json
from typing import Dict, List, Optional, Union
from datetime import datetime
from cryptography.hazmat.primitives import serialization

from src.exceptions import (
    MessagingError, KeyExchangeError, EncryptionError,
    SignatureError, MessageVerificationError
)
from src.messaging.key_exchange import KeyExchange
from src.messaging.message_encryptor import MessageEncryptor
from src.messaging.message_signer import MessageSigner
from src.messaging.group_manager import GroupManager


class MessagingModule:
    """
    Main controller for the Secure Messaging Module.
    Orchestrates Key Exchange, Encryption, Signatures, and Group Chat.
    """

    def __init__(self, user_id, private_key, storage_backend=None):
        self.logger = logging.getLogger(__name__)
        self.user_id = user_id
        self.private_key = private_key
        self.public_key = private_key.public_key()

        # Cache for recipient public keys {user_id: public_key_bytes}
        self.key_cache = {}

        # Message history (simulation of a database)
        self.message_history = []

        self.config = {
            "key_rotation_interval": 3600,
            "algorithm": "AES-256-GCM"
        }

        # Initialize sub-modules
        self.key_exchange = KeyExchange()
        self.encryptor = MessageEncryptor()
        self.signer = MessageSigner()
        self.group_manager = GroupManager()

    def _encrypt_message_content(self, plaintext: str, enc_key: bytes) -> Dict:
        """Internal: Calls the encryptor."""
        return self.encryptor.encrypt_message(plaintext, enc_key)

    def _decrypt_message_content(self, encrypted_dict: Dict, enc_key: bytes) -> str:
        """Internal: Calls the decryptor."""
        return self.encryptor.decrypt_message(encrypted_dict, enc_key)

    def _sign_message(self, message_content: str) -> Dict:
        """Internal: Signs the message hash with my private key."""
        return self.signer.sign_message_hash(message_content, self.private_key)

    def _verify_message_signature(self, message: str, signature_dict: Dict, sender_pubkey) -> bool:
        """Internal: Verifies the sender's signature."""
        return self.signer.verify_message_signature(message, signature_dict, sender_pubkey)

    def get_recipient_public_key(self, recipient_id: str) -> bytes:
        """
        Retrieves the recipient's public key from storage/cache.
        """
        if recipient_id in self.key_cache:
            return self.key_cache[recipient_id]

        raise MessagingError(f"Public key for user {recipient_id} not found")

    def send_message(self, recipient_id: str, message: str) -> Dict:
        """
        Orchestrates the secure sending process.

        Pipeline:
        1. Get Recipient Public Key.
        2. Generate Ephemeral Keys (for PFS).
        3. Derive Shared Secret (ECDH).
        4. Sign Message (Identity).
        5. Encrypt Message (Confidentiality).
        6. Package to JSON.
        """
        try:
            self.logger.info(f"Initiating secure message to {recipient_id}")

            # 1. Get recipient's long-term public key
            recipient_pub_bytes = self.get_recipient_public_key(recipient_id)

            # 2. Generate my ephemeral keys (PFS)
            eph_private_bytes, eph_public_bytes = self.key_exchange.generate_ephemeral_keypair()

            # 3. ECDH Exchange
            raw_shared = self.key_exchange.perform_ecdh(eph_private_bytes, recipient_pub_bytes)
            encryption_key = self.key_exchange.derive_shared_secret_hkdf(
                shared_secret=raw_shared,
                salt=eph_public_bytes,
                info=b"cryptovault_message_key"
            )

            # 4. Sign (Authentication)
            signature_data = self._sign_message(message)

            # 5. Encrypt (Confidentiality)
            encrypted_data = self._encrypt_message_content(message, encryption_key)

            # 6. Build Payload
            payload = {
                "header": {
                    "sender_id": self.user_id,
                    "recipient_id": recipient_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "algorithm": "ECDH-P256-AES256GCM-ECDSA"
                },
                "ephemeral_public_key": base64.b64encode(eph_public_bytes).decode('utf-8'),
                "encrypted_content": encrypted_data,
                "signature": signature_data
            }

            self._log_event("MESSAGE_SENT", f"To: {recipient_id}, Size: {len(message)}")
            self.message_history.append(payload)

            return payload

        except Exception as e:
            self.logger.error(f"Failed to send message: {str(e)}")
            raise MessagingError(f"Send failed: {str(e)}")

    def receive_message(self, message_payload: Dict) -> Dict:
        """
        Orchestrates the secure receiving process.
        Pipeline: Extract Keys -> ECDH -> Derive Secret -> Decrypt -> Verify Signature.
        """
        try:
            header = message_payload.get("header", {})
            sender_id = header.get("sender_id")

            self.logger.info(f"Receiving message from {sender_id}")

            # 1. Get Sender's Long-term Public Key (for Signature verification)
            sender_pubkey_bytes = self.get_recipient_public_key(sender_id)
            sender_longterm_pubkey = serialization.load_pem_public_key(sender_pubkey_bytes)

            # 2. Get Sender's Ephemeral Public Key (from payload)
            eph_pub_key_bytes = base64.b64decode(message_payload["ephemeral_public_key"])

            # 3. ECDH: Calculate Shared Secret
            # Serialize my private key to bytes for the internal method
            private_bytes = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            raw_shared = self.key_exchange.perform_ecdh(
                private_bytes,
                eph_pub_key_bytes
            )

            # 4. Derive Decryption Key
            decryption_key = self.key_exchange.derive_shared_secret_hkdf(
                shared_secret=raw_shared,
                salt=eph_pub_key_bytes,
                info=b"cryptovault_message_key"
            )

            # 5. Decrypt
            encrypted_content = message_payload["encrypted_content"]
            plaintext = self._decrypt_message_content(encrypted_content, decryption_key)

            # 6. Verify Signature
            signature_data = message_payload["signature"]
            is_valid = self._verify_message_signature(
                plaintext,
                signature_data,
                sender_longterm_pubkey
            )

            if not is_valid:
                raise SignatureError(f"Invalid signature from sender {sender_id}")

            self._log_event("MESSAGE_RECEIVED", f"From: {sender_id}, Verified: True")

            return {
                "sender_id": sender_id,
                "content": plaintext,
                "timestamp": header.get("timestamp"),
                "verified": True
            }

        except Exception as e:
            self.logger.error(f"Failed to receive message: {str(e)}")
            raise MessagingError("Message decryption or verification failed")

    # --- GROUP MESSAGING METHODS ---

    def create_group(self, group_name: str) -> str:
        """Creates a new group."""
        gid = self.group_manager.create_group(group_name, self.user_id)
        self.logger.info(f"Created group {gid}")
        return gid

    def invite_user_to_group(self, group_id: str, recipient_id: str) -> Dict:
        """
        Sends the group key to another user via secure direct message.
        """
        # 1. Get group key
        key_bytes = self.group_manager.get_group_key(group_id)
        key_b64 = base64.b64encode(key_bytes).decode('utf-8')

        # 2. Create invite payload
        invite_message = json.dumps({
            "type": "GROUP_INVITE",
            "group_id": group_id,
            "key": key_b64
        })

        # 3. Send as standard encrypted message
        return self.send_message(recipient_id, invite_message)

    def process_invite_message(self, decrypted_content: str):
        """
        Parses incoming message. If it's an invite, saves the key.
        """
        try:
            data = json.loads(decrypted_content)
            if data.get("type") == "GROUP_INVITE":
                self.group_manager.add_key_from_invite(data["group_id"], data["key"])
                self.logger.info(f"Joined group {data['group_id']}")
                return True
        except:
            pass
        return False

    def send_group_message(self, group_id: str, message: str) -> Dict:
        """Sends a message to a group."""
        # Encrypt with group key
        encrypted_content = self.group_manager.encrypt_group_message(group_id, message)

        # Sign with personal key
        signature = self._sign_message(message)

        return {
            "header": {
                "sender_id": self.user_id,
                "type": "GROUP_MESSAGE",
                "timestamp": datetime.utcnow().isoformat()
            },
            "content": encrypted_content,
            "signature": signature
        }

    def receive_group_message(self, payload: Dict) -> Dict:
        """Receives and verifies a group message."""
        sender_id = payload["header"]["sender_id"]
        encrypted_content = payload["content"]

        # 1. Decrypt (using Shared Group Key)
        plaintext = self.group_manager.decrypt_group_message(encrypted_content)

        # 2. Verify Sender Signature (using Sender's Public Key)
        sender_pub_bytes = self.get_recipient_public_key(sender_id)
        sender_pub = serialization.load_pem_public_key(sender_pub_bytes)

        if not self._verify_message_signature(plaintext, payload["signature"], sender_pub):
            raise SignatureError("Group message signature invalid")

        return {
            "sender_id": sender_id,
            "group_id": encrypted_content["group_id"],
            "content": plaintext,
            "verified": True
        }

    def _log_event(self, event_type: str, details: str):
        """Secure logging."""
        self.logger.info(f"MESSAGING_EVENT: {event_type} - {details}")
