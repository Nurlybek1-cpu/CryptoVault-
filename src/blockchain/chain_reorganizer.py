"""
Chain reorganization utilities for CryptoVault blockchain.
"""

from typing import List, Dict, Any

from src.blockchain.block import Block
from src.blockchain.chain_validator import ChainValidator
from src.exceptions import ChainReorganizationError


class ChainReorganizer:
    """
    Handles fork resolution and chain reorganization using the
    longest valid chain rule with a configurable reorg depth limit.
    """

    def __init__(self, validator: ChainValidator, max_reorg_depth: int = 100) -> None:
        self.validator = validator
        self.max_reorg_depth = max_reorg_depth

    def is_chain_valid(self, chain: List[Block]) -> bool:
        """
        Validate a chain using the underlying ChainValidator.
        """
        return self.validator.validate_chain(chain)

    def find_longest_chain(
        self,
        received_chain: List[Block],
        current_chain: List[Block],
    ) -> List[Block]:
        """
        Compare current and received chains and return the longest valid one.
        """
        if not self.is_chain_valid(current_chain):
            if self.is_chain_valid(received_chain):
                return received_chain
            raise ChainReorganizationError("Both chains invalid")

        if not self.is_chain_valid(received_chain):
            return current_chain

        if len(received_chain) > len(current_chain):
            return received_chain
        return current_chain

    def find_fork_point(self, chain1: List[Block], chain2: List[Block]) -> int:
        """
        Find index where two chains diverge (last common block index).
        """
        fork_index = 0
        for i in range(min(len(chain1), len(chain2))):
            if chain1[i].hash == chain2[i].hash:
                fork_index = i
            else:
                break
        return fork_index

    def reorganize_chain(
        self,
        new_chain: List[Block],
        old_chain: List[Block],
    ) -> Dict[str, Any]:
        """
        Reorganize blockchain to adopt a new longer valid chain.
        """
        if not self.is_chain_valid(new_chain):
            raise ChainReorganizationError("Invalid chain received")

        fork_point = self.find_fork_point(new_chain, old_chain)

        # Enforce maximum reorg depth
        blocks_removed = len(old_chain) - fork_point - 1
        if blocks_removed > self.max_reorg_depth:
            raise ChainReorganizationError(
                f"Reorg depth {blocks_removed} exceeds limit {self.max_reorg_depth}"
            )

        blocks_added = len(new_chain) - fork_point - 1

        removed_transactions = []
        for i in range(fork_point + 1, len(old_chain)):
            for tx in old_chain[i].transactions:
                removed_transactions.append(tx)

        return {
            "success": True,
            "fork_point": fork_point,
            "blocks_removed": blocks_removed,
            "blocks_added": blocks_added,
            "transactions_restored": len(removed_transactions),
            "removed_transactions": removed_transactions,
        }


