"""
Merkle tree implementation for CryptoVault blockchain.
Provides deterministic SHA-256 hashing and Merkle proofs for transactions.
"""

import hashlib
import json
from typing import List, Tuple, Optional

from src.exceptions import MerkleTreeError


class MerkleTree:
    """
    Simple Merkle tree that stores all levels for proof generation.
    Leaves and nodes are hex strings (SHA-256 digests).
    """

    def __init__(self, transactions: List[object]) -> None:
        transaction_hashes: List[str] = []
        for transaction in transactions:
            tx_string = json.dumps(transaction, sort_keys=True)
            tx_hash = hashlib.sha256(tx_string.encode()).hexdigest()
            transaction_hashes.append(tx_hash)

        self.tree: List[List[str]] = self.build_tree(transaction_hashes)
        self.root: Optional[str] = self.tree[-1][0] if self.tree else None

    def build_tree(self, hashes: List[str]) -> List[List[str]]:
        if not hashes:
            return []

        # Duplicate last leaf if odd count
        if len(hashes) % 2 != 0:
            hashes = hashes + [hashes[-1]]

        current_level = hashes
        tree: List[List[str]] = [current_level]

        while len(current_level) > 1:
            next_level: List[str] = []
            if len(current_level) % 2 != 0:
                current_level = current_level + [current_level[-1]]

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1]
                combined = left + right
                parent = hashlib.sha256(combined.encode()).hexdigest()
                next_level.append(parent)

            tree.append(next_level)
            current_level = next_level

        return tree

    def get_root(self) -> Optional[str]:
        return self.root

    def get_proof(self, transaction_hash: str) -> List[Tuple[str, str]]:
        if not self.tree:
            raise MerkleTreeError("Merkle tree is empty")

        leaves = self.tree[0]
        if transaction_hash not in leaves:
            raise MerkleTreeError("Transaction not in tree")

        index = leaves.index(transaction_hash)
        proof: List[Tuple[str, str]] = []

        for level in range(len(self.tree) - 1):
            level_nodes = self.tree[level]

            if index % 2 == 0:
                sibling_index = index + 1
                if sibling_index < len(level_nodes):
                    sibling = level_nodes[sibling_index]
                    proof.append(("right", sibling))
            else:
                sibling_index = index - 1
                sibling = level_nodes[sibling_index]
                proof.append(("left", sibling))

            index = index // 2

        return proof

    def verify_proof(
        self,
        transaction_hash: str,
        proof: List[Tuple[str, str]],
        merkle_root: str,
    ) -> bool:
        current_hash = transaction_hash

        for direction, sibling_hash in proof:
            if direction == "right":
                combined = current_hash + sibling_hash
            else:
                combined = sibling_hash + current_hash
            current_hash = hashlib.sha256(combined.encode()).hexdigest()

        return current_hash == merkle_root