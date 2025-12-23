from .messaging_module import MessagingModule
from .key_exchange import KeyExchange
from src.messaging.message_encryptor import MessageEncryptor
from src.messaging.message_signer import MessageSigner
from typing import Dict, Optional
from src.exceptions import (
    MessagingError, KeyExchangeError, EncryptionError,
    SignatureError
)


class MessagingModule:
    def __init__(self, private_key, storage_backend=None):
        # ... (старый код __init__) ...

        # Инициализация подмодулей
        # self.key_exchange = KeyExchange() # Это мы раскомментировали в прошлый раз
        self.encryptor = MessageEncryptor()
        self.signer = MessageSigner()

    # --- ДОБАВЬТЕ ЭТИ НОВЫЕ МЕТОДЫ В КЛАСС ---

    def _encrypt_message_content(self, plaintext: str, enc_key: bytes) -> Dict:
        """Внутренний метод: вызывает шифратор."""
        return self.encryptor.encrypt_message(plaintext, enc_key)

    def _decrypt_message_content(self, encrypted_dict: Dict, enc_key: bytes) -> str:
        """Внутренний метод: вызывает дешифратор."""
        return self.encryptor.decrypt_message(encrypted_dict, enc_key)

    def _sign_message(self, message_content: str) -> Dict:
        """Внутренний метод: подписывает сообщение моим приватным ключом."""
        return self.signer.sign_message_hash(message_content, self.private_key)

    def _verify_message_signature(self, message: str, signature_dict: Dict, sender_pubkey) -> bool:
        """Внутренний метод: проверяет подпись отправителя."""
        return self.signer.verify_message_signature(message, signature_dict, sender_pubkey)
