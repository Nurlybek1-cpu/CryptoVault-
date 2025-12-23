import unittest
import sys
import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from src.messaging.messaging_module import MessagingModule
from src.exceptions import MessagingError, EncryptionError, SignatureError

# Добавляем путь к src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestMessagingUnits(unittest.TestCase):

    def setUp(self):
        """Preparation before EACH test"""
        # 1. Create Alice
        self.alice_priv = ec.generate_private_key(ec.SECP256R1())
        self.alice = MessagingModule("alice", self.alice_priv)

        # 2. Create Bob
        self.bob_priv = ec.generate_private_key(ec.SECP256R1())
        self.bob = MessagingModule("bob", self.bob_priv)

        # 3. Exchange Keys
        bob_pub_bytes = self.bob_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.alice.key_cache["bob"] = bob_pub_bytes

        alice_pub_bytes = self.alice_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.bob.key_cache["alice"] = alice_pub_bytes

    # --- ✅ SEND MESSAGE TESTS (6+ required) ---

    def test_01_send_success(self):
        """Happy path sending"""
        payload = self.alice.send_message("bob", "Hi")
        self.assertIn("encrypted_content", payload)

    def test_02_send_unknown_recipient(self):
        """Fail when user not in cache"""
        with self.assertRaises(MessagingError):
            self.alice.send_message("unknown_user", "Hi")

    def test_03_send_empty_message(self):
        """Send empty string"""
        payload = self.alice.send_message("bob", "")
        self.assertIsNotNone(payload)  # Should work

    def test_04_send_large_message(self):
        """Send large payload (1MB)"""
        large_msg = "A" * 1024 * 1024
        payload = self.alice.send_message("bob", large_msg)
        self.assertIn("ciphertext", payload["encrypted_content"])

    def test_05_send_structure_check(self):
        """Verify JSON structure"""
        payload = self.alice.send_message("bob", "Test")
        required = ["header", "ephemeral_public_key", "encrypted_content", "signature"]
        for field in required:
            self.assertIn(field, payload)

    def test_06_send_creates_new_keys_pfs(self):
        """Verify Perfect Forward Secrecy (Keys change each time)"""
        msg1 = self.alice.send_message("bob", "Test")
        msg2 = self.alice.send_message("bob", "Test")
        # Ephemeral keys MUST be different
        self.assertNotEqual(msg1["ephemeral_public_key"], msg2["ephemeral_public_key"])

    # --- ✅ RECEIVE MESSAGE TESTS (7+ required) ---

    def test_07_receive_success(self):
        """Happy path receiving"""
        payload = self.alice.send_message("bob", "Secret")
        decoded = self.bob.receive_message(payload)
        self.assertEqual(decoded["content"], "Secret")

    def test_08_receive_tampered_ciphertext(self):
        """Integrity check (AES-GCM Auth Tag)"""
        payload = self.alice.send_message("bob", "Secret")
        # Corrupt the ciphertext
        raw_cipher = base64.b64decode(payload["encrypted_content"]["ciphertext"])
        corrupted = raw_cipher[:-1] + b'\x00'  # Change last byte
        payload["encrypted_content"]["ciphertext"] = base64.b64encode(corrupted).decode()

        with self.assertRaises(MessagingError):  # Should fail decryption
            self.bob.receive_message(payload)

    def test_09_receive_invalid_signature(self):
        """Signature verification fail"""
        payload = self.alice.send_message("bob", "Secret")
        # Tamper with the signature bytes
        payload["signature"]["signature"] = base64.b64encode(b'bad_sig').decode()

        with self.assertRaises(MessagingError):  # Should fail verification
            self.bob.receive_message(payload)

    def test_10_receive_unknown_sender(self):
        """Sender not in cache"""
        payload = self.alice.send_message("bob", "Secret")
        payload["header"]["sender_id"] = "mallory"  # Mallory is not in Bob's cache

        with self.assertRaises(MessagingError):
            self.bob.receive_message(payload)

    def test_11_receive_replay_protection_check(self):
        """Check nonce usage (Internal logic)"""
        payload = self.alice.send_message("bob", "Secret")
        # AES-GCM ensures integrity, so modifying nonce breaks auth tag
        payload["encrypted_content"]["nonce"] = base64.b64encode(os.urandom(12)).decode()
        with self.assertRaises(MessagingError):
            self.bob.receive_message(payload)

    def test_12_receive_wrong_recipient(self):
        """Message intended for someone else (Simulated)"""
        # If Bob tries to decrypt with HIS key, but Alice encrypted for CHARLIE
        charlie_priv = ec.generate_private_key(ec.SECP256R1())
        charlie = MessagingModule("charlie", charlie_priv)

        # Setup: Alice knows Charlie
        charlie_pub = charlie_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.alice.key_cache["charlie"] = charlie_pub

        # Alice sends to Charlie
        payload = self.alice.send_message("charlie", "For Charlie")

        # Bob tries to read it
        with self.assertRaises(Exception):  # Crypto error (wrong private key math)
            self.bob.receive_message(payload)

    def test_13_receive_malformed_json(self):
        """Missing fields"""
        with self.assertRaises(Exception):
            self.bob.receive_message({})

    # --- ✅ GROUP MESSAGING TESTS (7+ required) ---

    def test_14_group_create(self):
        gid = self.alice.create_group("Test Group")
        self.assertTrue(gid.startswith("group_"))

    def test_15_group_invite_flow(self):
        gid = self.alice.create_group("Team")
        invite = self.alice.invite_user_to_group(gid, "bob")

        # Bob accepts
        decrypted = self.bob.receive_message(invite)
        result = self.bob.process_invite_message(decrypted["content"])
        self.assertTrue(result)
        self.assertIn(gid, self.bob.group_manager.group_keys)

    def test_16_group_send_receive(self):
        gid = self.alice.create_group("Team")
        # Manually add key to Bob to skip invite (for unit test speed)
        key = self.alice.group_manager.get_group_key(gid)
        self.bob.group_manager.group_keys[gid] = key

        payload = self.alice.send_group_message(gid, "Hi Team")
        decoded = self.bob.receive_group_message(payload)
        self.assertEqual(decoded["content"], "Hi Team")

    def test_17_group_access_denied(self):
        """Reading group message without key"""
        gid = "group_unknown"
        payload = {
            "header": {"sender_id": "alice"},
            "content": {"group_id": gid, "nonce": "", "ciphertext": ""}
        }
        with self.assertRaises(Exception):
            self.bob.receive_group_message(payload)

    def test_18_group_signature_verify(self):
        """Group message signature check"""
        gid = self.alice.create_group("Team")
        key = self.alice.group_manager.get_group_key(gid)
        self.bob.group_manager.group_keys[gid] = key

        payload = self.alice.send_group_message(gid, "Hi")
        # Tamper signature
        payload["signature"]["signature"] = base64.b64encode(b'bad').decode()

        with self.assertRaises(SignatureError):
            self.bob.receive_group_message(payload)

    def test_19_group_invite_wrong_type(self):
        """Processing a normal message as invite"""
        res = self.bob.process_invite_message('{"type": "CHAT", "msg": "hi"}')
        self.assertFalse(res)

    def test_20_group_invite_malformed(self):
        """Processing garbage as invite"""
        res = self.bob.process_invite_message('NOT JSON')
        self.assertFalse(res)


if __name__ == '__main__':
    print("🚀 RUNNING COMPREHENSIVE UNIT TESTS...")
    unittest.main()
