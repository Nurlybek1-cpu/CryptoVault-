import sys
import os
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.messaging.messaging_module import MessagingModule

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')


def generate_user_keys():
    """Helper: Generate keys for test user."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def get_pubkey_bytes(public_key):
    """Helper: Serialize public key."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def test_secure_chat():
    print("--- 🚀 START SECURE CHAT TEST ---")

    # 1. Create Users
    print("\n[1] Generating users...")
    alice_priv, alice_pub = generate_user_keys()
    bob_priv, bob_pub = generate_user_keys()

    alice_id = "user_alice"
    bob_id = "user_bob"

    alice_module = MessagingModule(alice_id, alice_priv)
    bob_module = MessagingModule(bob_id, bob_priv)

    # 2. Key Exchange (Simulation)
    print("[2] Simulating public key exchange...")
    alice_module.key_cache[bob_id] = get_pubkey_bytes(bob_pub)
    bob_module.key_cache[alice_id] = get_pubkey_bytes(alice_pub)

    # 3. Alice sends message
    message_text = "Hello Bob! This is a secure message for Module 2."
    print(f"\n[3] Alice sending: '{message_text}'")

    try:
        encrypted_packet = alice_module.send_message(bob_id, message_text)
        print("   ✅ Message encrypted and sent.")
        print(f"   📦 Payload snippet: {str(encrypted_packet)[:80]}...")
    except Exception as e:
        print(f"   ❌ Send failed: {e}")
        return

    # 4. Bob receives message
    print("\n[4] Bob receiving packet...")
    try:
        decrypted_data = bob_module.receive_message(encrypted_packet)

        print(f"   ✅ Message decrypted!")
        print(f"   📨 Sender: {decrypted_data['sender_id']}")
        print(f"   📝 Content: {decrypted_data['content']}")
        print(f"   🔐 Verified: {decrypted_data['verified']}")

        # 5. Validation
        if decrypted_data['content'] == message_text:
            print("\n--- 🎉 TEST PASSED SUCCESSFULLY! ---")
            print("End-to-End Encryption (E2EE) verified.")
        else:
            print("\n--- ❌ ERROR: Content mismatch! ---")

    except Exception as e:
        print(f"   ❌ Receive failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_secure_chat()
