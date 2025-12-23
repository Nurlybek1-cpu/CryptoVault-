"""
Transaction signature verification for CryptoVault blockchain.
"""

import base64
import json
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


class TransactionVerifier:
    """
    Provides ECDSA-based signing and verification helpers for transactions.
    """

    def _serialize_tx_core(self, transaction: Dict[str, Any]) -> bytes:
        """
        Serialize core transaction fields (without signature) deterministically.
        """
        tx_data = {
            "sender": transaction["sender"],
            "recipient": transaction["recipient"],
            "amount": transaction["amount"],
            "timestamp": transaction["timestamp"],
        }
        tx_bytes = json.dumps(tx_data, sort_keys=True).encode("utf-8")
        return tx_bytes

    def verify_transaction_signature(
        self,
        transaction: Dict[str, Any],
        sender_pubkey: Any,
    ) -> bool:
        """
        Verify that the transaction was signed by the owner of sender_pubkey.
        """
        if "signature" not in transaction:
            return False

        try:
            signature = base64.b64decode(transaction["signature"])
        except Exception:
            return False

        tx_bytes = self._serialize_tx_core(transaction)

        try:
            sender_pubkey.verify(
                signature,
                tx_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def sign_transaction(
        self,
        transaction: Dict[str, Any],
        private_key: Any,
    ) -> Dict[str, Any]:
        """
        Sign transaction with sender's private key and attach base64 signature.
        """
        tx_bytes = self._serialize_tx_core(transaction)

        signature = private_key.sign(
            tx_bytes,
            ec.ECDSA(hashes.SHA256()),
        )

        transaction["signature"] = base64.b64encode(signature).decode()
        return transaction

    def validate_transaction(
        self,
        transaction: Dict[str, Any],
        sender_pubkey: Optional[Any] = None,
    ) -> bool:
        """
        Validate transaction fields and, optionally, its signature.
        """
        required = ["sender", "recipient", "amount", "timestamp", "signature"]
        if not all(field in transaction for field in required):
            return False

        try:
            if transaction["amount"] <= 0:
                return False
        except Exception:
            return False

        if sender_pubkey is not None:
            return self.verify_transaction_signature(transaction, sender_pubkey)

        return True


