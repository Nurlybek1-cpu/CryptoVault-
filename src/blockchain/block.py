"""
Block class for CryptoVault blockchain.
Implements deterministic SHA-256 hashing and simple Proof of Work.
"""

import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional

from src.exceptions import BlockValidationError, ProofOfWorkError

logger = logging.getLogger(__name__)


class Block:
    """
    Represents a single block in the blockchain.

    Hashing is deterministic: identical block data always yields the same
    SHA-256 hex digest. Proof of Work requires the block hash to start with
    a number of leading zeros defined by `difficulty`.
    """

    def __init__(
        self,
        index: int,
        transactions: List[Any],
        previous_hash: str,
        merkle_root: str,
        difficulty: int = 4,
    ) -> None:
        if index < 0:
            raise BlockValidationError("Block index cannot be negative")

        if difficulty < 1:
            raise BlockValidationError("Difficulty must be at least 1")

        self.index: int = index
        self.transactions: List[Any] = transactions
        self.previous_hash: str = previous_hash
        self.merkle_root: str = merkle_root
        self.timestamp: int = int(time.time())
        self.difficulty: int = difficulty
        self.nonce: int = 0
        self.hash: Optional[str] = None

        # Calculate initial hash
        self.hash = self.calculate_hash()

        logger.debug(
            "Block created index=%s prev=%s merkle=%s difficulty=%s nonce=%s hash=%s",
            self.index,
            self.previous_hash,
            self.merkle_root,
            self.difficulty,
            self.nonce,
            self.hash,
        )

    def calculate_hash(self) -> str:
        """
        Calculate SHA-256 hash of the block using deterministic JSON encoding.
        """
        block_data = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "difficulty": self.difficulty,
        }

        block_string = json.dumps(block_data, sort_keys=True)
        hash_object = hashlib.sha256(block_string.encode())
        return hash_object.hexdigest()

    def validate_pow(self) -> bool:
        """
        Validate Proof of Work by checking leading zeros defined by difficulty.
        """
        target_prefix = "0" * self.difficulty
        return bool(self.hash and self.hash.startswith(target_prefix))

    def mine(self) -> str:
        """
        Increment nonce until a valid Proof of Work is found.
        """
        while True:
            self.hash = self.calculate_hash()
            if self.validate_pow():
                return self.hash
            self.nonce += 1

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert block to dictionary representation.
        """
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "hash": self.hash,
            "transactions": self.transactions,
        }

    @classmethod
    def from_dict(cls, block_dict: Dict[str, Any]) -> "Block":
        """
        Reconstruct a Block instance from its dictionary representation.
        """
        required_fields = [
            "index",
            "previous_hash",
            "merkle_root",
            "timestamp",
            "nonce",
            "difficulty",
            "hash",
            "transactions",
        ]
        missing = [field for field in required_fields if field not in block_dict]
        if missing:
            raise BlockValidationError(
                f"Missing required fields in block data: {missing}"
            )

        block = cls(
            index=block_dict["index"],
            transactions=block_dict["transactions"],
            previous_hash=block_dict["previous_hash"],
            merkle_root=block_dict["merkle_root"],
            difficulty=block_dict["difficulty"],
        )
        # Restore persisted values
        block.timestamp = block_dict["timestamp"]
        block.nonce = block_dict["nonce"]
        block.hash = block_dict["hash"]

        # Ensure integrity
        calculated_hash = block.calculate_hash()
        if calculated_hash != block.hash:
            raise BlockValidationError(
                "Loaded block hash does not match calculated hash"
            )

        return block

    def __repr__(self) -> str:
        return (
            f"Block(index={self.index}, "
            f"hash={self.hash[:16] if self.hash else 'None'}..., "
            f"timestamp={self.timestamp})"
        )

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Block):
            return False
        return self.hash == other.hash