"""
Proof of Work (PoW) mining and difficulty adjustment for CryptoVault.
"""

import logging
from typing import List

from src.blockchain.block import Block
from src.exceptions import ProofOfWorkError

logger = logging.getLogger(__name__)


class ProofOfWork:
    """
    Simple PoW engine that searches for a nonce producing a hash with
    `difficulty` leading zeros.
    """

    def mine_block(self, block: Block) -> dict:
        """
        Find a valid nonce for the given block.

        Returns mining metadata including attempts and final hash.
        """
        nonce = 0
        block.nonce = nonce
        block.hash = block.calculate_hash()

        while not block.validate_pow():
            nonce += 1
            block.nonce = nonce
            block.hash = block.calculate_hash()
            if nonce % 10000 == 0:
                logger.info("Mining... nonce: %s", nonce)

        return {
            "success": True,
            "nonce": nonce,
            "hash": block.hash,
            "attempts": nonce,
            "difficulty": block.difficulty,
        }

    def validate_pow(self, block: Block) -> bool:
        """
        Validate that the block hash meets the difficulty target.
        """
        target = "0" * block.difficulty
        return bool(block.hash and block.hash.startswith(target))

    def adjust_difficulty(self, blocks: List[Block], target_time: float = 600) -> int:
        """
        Adjust difficulty based on average time of recent blocks.
        """
        if not blocks:
            raise ProofOfWorkError("No blocks available for difficulty adjustment")

        # If fewer than 10 blocks, keep current difficulty
        if len(blocks) < 10:
            return blocks[-1].difficulty

        recent_blocks = blocks[-10:]
        time_span = recent_blocks[-1].timestamp - recent_blocks[0].timestamp
        average_time = time_span / max(1, (len(recent_blocks) - 1))

        current_difficulty = blocks[-1].difficulty

        if average_time < target_time / 2:
            new_difficulty = current_difficulty + 1
        elif average_time > target_time * 2:
            new_difficulty = max(1, current_difficulty - 1)
        else:
            new_difficulty = current_difficulty

        return new_difficulty

