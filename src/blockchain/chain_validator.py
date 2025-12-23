"""
Chain validation utilities for CryptoVault blockchain.
"""

import hashlib
import json
import time
from typing import List

from src.blockchain.block import Block


class ChainValidator:
    """
    Provides block-level and chain-level validation helpers.
    """

    def validate_block(self, block: Block, previous_block: Block) -> bool:
        # Basic structure
        if not block.hash or not block.previous_hash:
            return False

        # Hash integrity
        calculated_hash = block.calculate_hash()
        if calculated_hash != block.hash:
            return False

        # Proof of Work
        if not block.validate_pow():
            return False

        # Link to previous block
        if block.previous_hash != previous_block.hash:
            return False

        # Timestamp ordering and tolerance (allow 10 minutes into future)
        if block.timestamp < previous_block.timestamp:
            return False
        if block.timestamp > time.time() + 600:
            return False

        return True

    def validate_chain(self, blockchain: List[Block]) -> bool:
        if len(blockchain) == 0:
            return False

        genesis = blockchain[0]
        if genesis.index != 0:
            return False
        if genesis.previous_hash != "0" * 64:
            return False

        for i in range(1, len(blockchain)):
            current_block = blockchain[i]
            previous_block = blockchain[i - 1]
            if not self.validate_block(current_block, previous_block):
                return False

        return True

    def verify_transaction_in_block(self, transaction: dict, block: Block) -> bool:
        tx_string = json.dumps(transaction, sort_keys=True)
        tx_hash = hashlib.sha256(tx_string.encode()).hexdigest()

        for tx in block.transactions:
            if json.dumps(tx, sort_keys=True) == tx_string:
                return True

        return False

