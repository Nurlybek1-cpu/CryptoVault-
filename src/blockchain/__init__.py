"""
CryptoVault Blockchain Package.

Provides a complete blockchain implementation with Merkle trees, Proof of Work,
transaction management, and audit trail functionality.

Main Components:
    - BlockchainModule: Core blockchain state management
    - Block: Individual block structure with PoW validation
    - MerkleTree: Efficient transaction verification
    - Exceptions: Blockchain-specific error types

Usage:
    from blockchain import BlockchainModule, Block, MerkleTree
    
    # Initialize blockchain
    blockchain = BlockchainModule(difficulty=4)
    
    # Create genesis block
    blockchain.create_genesis_block()
    
    # Add transactions
    blockchain.add_transaction({
        'id': 'tx1',
        'timestamp': time.time(),
        'sender': 'alice',
        'recipient': 'bob',
        'amount': 10
    })
    
    # Mine block
    mined_block = blockchain.mine_block()
    
    # Verify chain
    is_valid = blockchain.validate_chain()
"""

import hashlib
import time
import json
import logging

from .block import Block
from .blockchain_module import BlockchainModule
from .merkle_tree import MerkleTree
from ..exceptions import (
    BlockchainError,
    BlockValidationError,
    MerkleTreeError,
    ProofOfWorkError,
    ChainReorganizationError,
    TransactionError,
    AuditTrailError
)

__version__ = "1.0.0"
__author__ = "CryptoVault Developers"
__all__ = [
    'BlockchainModule',
    'Block',
    'MerkleTree',
    'BlockchainError',
    'BlockValidationError',
    'MerkleTreeError',
    'ProofOfWorkError',
    'ChainReorganizationError',
    'TransactionError',
    'AuditTrailError'
]
