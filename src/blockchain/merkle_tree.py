"""
Merkle tree implementation for CryptoVault blockchain.
Provides efficient data verification through cryptographic hash trees.
"""

import hashlib
from typing import List, Optional, Tuple
from exceptions import MerkleTreeError


class MerkleTree:
    """
    Binary Merkle tree implementation using SHA-256 hashing.
    
    Attributes:
        tree (List[List[bytes]]): 2D list representing tree levels
        root (bytes): Root hash of the entire tree
        leaf_count (int): Number of leaf nodes
    
    The Merkle tree is built from bottom-up, with leaves at level 0
    and root at the top level. Each internal node is the hash of its
    two children concatenated together.
    """
    
    def __init__(self, data: Optional[List[bytes]] = None) -> None:
        """
        Initialize Merkle tree from data.
        
        Args:
            data: List of bytes to create tree from. If None, creates empty tree.
        
        Raises:
            MerkleTreeError: If data is empty list.
        """
        self.tree: List[List[bytes]] = []
        self.root: bytes = b''
        self.leaf_count: int = 0
        
        if data is not None:
            if len(data) == 0:
                raise MerkleTreeError("Cannot create Merkle tree from empty data list")
            self.build_tree(data)
    
    @staticmethod
    def _hash(data: bytes) -> bytes:
        """
        Calculate SHA-256 hash (Bitcoin-style double hash).
        
        Args:
            data: Bytes to hash
        
        Returns:
            bytes: SHA-256 hash of input
        """
        return hashlib.sha256(data).digest()
    
    def _handle_odd_leaves(self, leaves: List[bytes]) -> List[bytes]:
        """
        Handle odd number of leaves by duplicating the last leaf.
        
        This ensures the tree is properly balanced and allows for
        consistent proof generation and verification.
        
        Args:
            leaves: Current level of tree leaves
        
        Returns:
            List[bytes]: Leaves with odd one duplicated if needed
        """
        if len(leaves) % 2 == 1:
            # Duplicate the last leaf for odd-sized levels
            leaves = leaves + [leaves[-1]]
        return leaves
    
    def build_tree(self, data: List[bytes]) -> bytes:
        """
        Build Merkle tree from data and return root hash.
        
        Creates a complete binary tree by hashing pairs of elements
        at each level until a single root hash remains.
        
        Args:
            data: List of bytes to build tree from
        
        Returns:
            bytes: Root hash of the tree
        
        Raises:
            MerkleTreeError: If data is empty
        """
        if not data:
            raise MerkleTreeError("Cannot build Merkle tree from empty data")
        
        # Initialize with leaf hashes
        self.tree = []
        leaf_hashes: List[bytes] = [self._hash(item) for item in data]
        self.leaf_count = len(leaf_hashes)
        
        # Add leaf level to tree
        self.tree.append(leaf_hashes[:])
        
        # Build tree bottom-up
        current_level = self._handle_odd_leaves(leaf_hashes)
        
        while len(current_level) > 1:
            next_level: List[bytes] = []
            
            # Hash pairs of nodes
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
                
                # Concatenate and hash
                combined = left + right
                parent_hash = self._hash(combined)
                next_level.append(parent_hash)
            
            # Handle odd number of nodes in next level
            next_level = self._handle_odd_leaves(next_level)
            self.tree.append(next_level)
            current_level = next_level
        
        # Root is the last element
        self.root = current_level[0] if current_level else b''
        return self.root
    
    def get_proof(self, leaf_index: int) -> List[bytes]:
        """
        Generate Merkle proof for leaf at given index.
        
        The proof contains all sibling hashes needed to reconstruct
        the root hash from the leaf. Proof size is O(log n).
        
        Args:
            leaf_index: Index of leaf in original data
        
        Returns:
            List[bytes]: Sibling hashes forming the proof path
        
        Raises:
            MerkleTreeError: If index is out of bounds or tree is empty
        """
        if not self.tree:
            raise MerkleTreeError("Merkle tree is empty")
        
        if leaf_index >= self.leaf_count:
            raise MerkleTreeError(
                f"Leaf index {leaf_index} out of bounds for tree with {self.leaf_count} leaves"
            )
        
        proof: List[bytes] = []
        current_index = leaf_index
        
        # Traverse from leaves to root
        for level_idx in range(len(self.tree) - 1):
            current_level = self.tree[level_idx]
            
            # Find sibling
            if current_index % 2 == 0:
                sibling_index = current_index + 1
            else:
                sibling_index = current_index - 1
            
            # Add sibling if it exists
            if sibling_index < len(current_level):
                proof.append(current_level[sibling_index])
            else:
                # If no sibling, use current node (handled by odd-leaf duplication)
                proof.append(current_level[current_index])
            
            # Move to parent level
            current_index = current_index // 2
        
        return proof
    
    def verify_proof(
        self,
        leaf_hash: bytes,
        proof: List[bytes],
        leaf_index: int,
        root: Optional[bytes] = None
    ) -> bool:
        """
        Verify Merkle proof without requiring full tree.
        
        Reconstructs root hash from leaf using proof and compares
        with expected root.
        
        Args:
            leaf_hash: Hash of the leaf to verify
            proof: Merkle proof path (siblings)
            leaf_index: Original index of leaf in tree
            root: Expected root hash (uses self.root if not provided)
        
        Returns:
            bool: True if proof is valid, False otherwise
        
        Raises:
            MerkleTreeError: If proof cannot be verified due to invalid structure
        """
        if root is None:
            root = self.root
        
        if not root:
            raise MerkleTreeError("No root hash to verify against")
        
        current_hash = leaf_hash
        current_index = leaf_index
        
        # Reconstruct root hash from leaf
        for sibling_hash in proof:
            # Determine if current hash is left or right child
            if current_index % 2 == 0:
                # Current is left child
                combined = current_hash + sibling_hash
            else:
                # Current is right child
                combined = sibling_hash + current_hash
            
            current_hash = self._hash(combined)
            current_index = current_index // 2
        
        return current_hash == root
    
    def get_root(self) -> bytes:
        """
        Get the root hash of the tree.
        
        Returns:
            bytes: Root hash, or empty bytes if tree is empty
        """
        return self.root
    
    def get_tree_height(self) -> int:
        """
        Get the height of the Merkle tree.
        
        Height is the number of levels from leaves to root.
        
        Returns:
            int: Height of tree (1 for single leaf, 0 for empty)
        """
        return len(self.tree) if self.tree else 0
    
    def get_proof_size(self, num_leaves: int) -> int:
        """
        Calculate the size of Merkle proofs for given number of leaves.
        
        Proof size is O(log n) where n is number of leaves.
        
        Args:
            num_leaves: Number of leaves in tree
        
        Returns:
            int: Expected number of hashes in proof (32 bytes each)
        """
        if num_leaves == 0:
            return 0
        
        import math
        return math.ceil(math.log2(num_leaves))
