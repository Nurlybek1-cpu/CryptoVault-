import sys
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from src.messaging.messaging_module import MessagingModule

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def get_keys():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub


def test_groups():
    print("--- 👥 GROUP CHAT TEST ---")

    # 1. Create Alice and Bob
    alice_priv, alice_pub = get_keys()
    bob_priv, bob_pub = get_keys()

    alice = MessagingModule("alice", alice_priv)
    bob = MessagingModule("bob", bob_priv)

    # Key Exchange
    alice.key_cache["bob"] = bob_pub
    bob.key_cache["alice"] = alice_pub

    # 2. Alice creates group
    group_id = alice.create_group("Project Team")
    print(f"✅ Group created: {group_id}")

    # 3. Alice invites Bob
    print("📧 Alice sending invitation...")
    invite_packet = alice.invite_user_to_group(group_id, "bob")

    # 4. Bob accepts invite
    decrypted_invite = bob.receive_message(invite_packet)
    bob.process_invite_message(decrypted_invite["content"])
    print("✅ Bob joined the group")

    # 5. Bob sends to group
    msg_text = "Hello everyone! Module 2 is complete!"
    print(f"💬 Bob posts: '{msg_text}'")
    group_packet = bob.send_group_message(group_id, msg_text)

    # 6. Alice reads group message
    decrypted_group_msg = alice.receive_group_message(group_packet)
    print(f"📩 Alice reads: '{decrypted_group_msg['content']}'")

    if decrypted_group_msg['content'] == msg_text:
        print("\n--- TEST PASSED SUCCESSFULLY! ---")


if __name__ == "__main__":
    test_groups()
