"""
Block class for CryptoVault blockchain.
Implements blockchain block structure with Proof of Work and validation.
"""

import hashlib
import time
import json
from typing import Dict, Any, Optional, Tuple
from exceptions import BlockValidationError, ProofOfWorkError


class Block:
    """
    Represents a single block in the blockchain.
    
    Attributes:
        index (int): Block position in chain (0 for genesis)
        previous_hash (bytes): Hash of previous block (empty for genesis)
        merkle_root (bytes): Root hash of transaction Merkle tree
        timestamp (int): Unix timestamp when block was created
        nonce (int): Number used once for Proof of Work
        difficulty (int): Difficulty level for Proof of Work
        hash (bytes): SHA-256 hash of block header
        transactions (list): Raw transaction data for reference
    
    The block uses SHA-256 hashing and Proof of Work consensus.
    Block hash must be less than target determined by difficulty.
    """
    
    def __init__(
        self,
        index: int,
        previous_hash: bytes,
        merkle_root: bytes,
        difficulty: int = 4,
        timestamp: Optional[int] = None,
        nonce: int = 0,
        transactions: Optional[list] = None
    ) -> None:
        """
        Initialize a block.
        
        Args:
            index: Position in blockchain
            previous_hash: Hash of previous block
            merkle_root: Root hash of transaction Merkle tree
            difficulty: Difficulty level for PoW (default: 4)
            timestamp: Unix timestamp (uses current time if None)
            nonce: Proof of Work nonce (default: 0)
            transactions: Associated transactions for reference
        
        Raises:
            BlockValidationError: If parameters are invalid
        """
        if index < 0:
            raise BlockValidationError("Block index cannot be negative")
        
        if difficulty < 1 or difficulty > 32:
            raise BlockValidationError("Difficulty must be between 1 and 32")
        
        if not isinstance(previous_hash, bytes):
            raise BlockValidationError("previous_hash must be bytes")
        
        if not isinstance(merkle_root, bytes):
            raise BlockValidationError("merkle_root must be bytes")
        
        self.index: int = index
        self.previous_hash: bytes = previous_hash
        self.merkle_root: bytes = merkle_root
        self.timestamp: int = timestamp or int(time.time())
        self.nonce: int = nonce
        self.difficulty: int = difficulty
        self.hash: bytes = b''
        self.transactions: list = transactions or []
        
        # Calculate hash immediately
        self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> bytes:
        """
        Calculate SHA-256 hash of block header.
        
        Hashes: previous_hash + merkle_root + timestamp + nonce + difficulty
        Uses double SHA-256 (Bitcoin-style hashing).
        
        Returns:
            bytes: SHA-256 hash of block header
        """
        block_header = (
            self.previous_hash +
            self.merkle_root +
            self.timestamp.to_bytes(8, byteorder='big') +
            self.nonce.to_bytes(4, byteorder='big') +
            self.difficulty.to_bytes(1, byteorder='big')
        )
        
        # Double SHA-256 (Bitcoin style)
        first_hash = hashlib.sha256(block_header).digest()
        second_hash = hashlib.sha256(first_hash).digest()
        
        return second_hash
    
    def validate_pow(self) -> bool:
        """
        Validate Proof of Work.
        
        Checks that block hash is less than target determined by difficulty.
        Target = 2^(256 - difficulty*8)
        
        Returns:
            bool: True if PoW is valid, False otherwise
        
        Raises:
            ProofOfWorkError: If difficulty is invalid
        """
        if self.difficulty < 1 or self.difficulty > 32:
            raise ProofOfWorkError(f"Invalid difficulty: {self.difficulty}")
        
        # Calculate target: 2^(256 - difficulty*8)
        # Each difficulty level halves the target (adds one leading zero bit)
        target = 2 ** (256 - self.difficulty * 8)
        
        # Convert hash to integer for comparison
        hash_int = int.from_bytes(self.hash, byteorder='big')
        
        return hash_int < target
    
    def mine(self) -> Tuple[int, bytes]:
        """
        Mine the block by finding a valid nonce through Proof of Work.
        
        Iterates nonce values until block hash meets difficulty requirement.
        Updates block's nonce and hash when valid one is found.
        
        Returns:
            Tuple[int, bytes]: (nonce_found, block_hash)
        
        Raises:
            ProofOfWorkError: If unable to find valid nonce after 2^32 attempts
        """
        import time
        start_time = time.time()
        
        # Calculate target
        target = 2 ** (256 - self.difficulty * 8)
        
        # Try nonces until we find one that works
        max_nonce = 2 ** 32  # Practical limit for 32-bit nonce
        
        for nonce in range(max_nonce):
            self.nonce = nonce
            self.hash = self.calculate_hash()
            
            hash_int = int.from_bytes(self.hash, byteorder='big')
            if hash_int < target:
                elapsed = time.time() - start_time
                return nonce, self.hash
        
        raise ProofOfWorkError(
            f"Unable to find valid nonce for difficulty {self.difficulty} "
            f"after {max_nonce} attempts"
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert block to dictionary representation.
        
        Useful for serialization, storage, and transmission.
        Hashes and merkle_root are hex-encoded for JSON compatibility.
        
        Returns:
            Dict[str, Any]: Dictionary representation of block
        """
        return {
            'index': self.index,
            'previous_hash': self.previous_hash.hex(),
            'merkle_root': self.merkle_root.hex(),
            'timestamp': self.timestamp,
            'nonce': self.nonce,
            'difficulty': self.difficulty,
            'hash': self.hash.hex(),
            'transaction_count': len(self.transactions)
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        """
        Create block from dictionary representation.
        
        Reconstructs block from serialized data. Hash values are
        converted from hex strings back to bytes.
        
        Args:
            data: Dictionary with block data
        
        Returns:
            Block: Reconstructed block instance
        
        Raises:
            BlockValidationError: If data is invalid or incomplete
        """
        required_fields = [
            'index', 'previous_hash', 'merkle_root', 'timestamp',
            'nonce', 'difficulty', 'hash'
        ]
        
        missing = [f for f in required_fields if f not in data]
        if missing:
            raise BlockValidationError(
                f"Missing required fields in block data: {missing}"
            )
        
        try:
            block = cls(
                index=data['index'],
                previous_hash=bytes.fromhex(data['previous_hash']),
                merkle_root=bytes.fromhex(data['merkle_root']),
                difficulty=data['difficulty'],
                timestamp=data['timestamp'],
                nonce=data['nonce'],
                transactions=data.get('transactions', [])
            )
            
            # Verify hash matches
            loaded_hash = bytes.fromhex(data['hash'])
            if block.hash != loaded_hash:
                raise BlockValidationError(
                    "Loaded block hash does not match calculated hash"
                )
            
            return block
        
        except (ValueError, KeyError) as e:
            raise BlockValidationError(f"Error parsing block data: {str(e)}")
    
    def __repr__(self) -> str:
        """Return string representation of block."""
        return (
            f"Block(index={self.index}, "
            f"hash={self.hash.hex()[:16]}..., "
            f"timestamp={self.timestamp})"
        )
    
    def __eq__(self, other: Any) -> bool:
        """Check equality based on hash."""
        if not isinstance(other, Block):
            return False
        return self.hash == other.hash


# Type hint for clarity
from typing import Tuple
