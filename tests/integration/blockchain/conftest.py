"""
Integration test fixtures for blockchain operations.
"""

import time
import pytest

from src.blockchain.blockchain_module import BlockchainModule
from src.blockchain.block import Block
from src.blockchain.merkle_tree import MerkleTree
from src.blockchain.chain_validator import ChainValidator
from src.blockchain.chain_reorganizer import ChainReorganizer


@pytest.fixture(scope="function")
def blockchain_module() -> BlockchainModule:
    """
    Initialize a BlockchainModule instance with low difficulty for testing.
    Each test gets a fresh instance.
    """
    return BlockchainModule(difficulty=2)


@pytest.fixture
def test_transactions() -> list:
    """
    Sample transactions used across integration tests.
    """
    return [
        {
            "id": "tx1",
            "sender": "alice",
            "recipient": "bob",
            "amount": 10,
            "timestamp": int(time.time()),
        },
        {
            "id": "tx2",
            "sender": "bob",
            "recipient": "carol",
            "amount": 5,
            "timestamp": int(time.time()) + 1,
        },
        {
            "id": "tx3",
            "sender": "carol",
            "recipient": "dave",
            "amount": 2,
            "timestamp": int(time.time()) + 2,
        },
        {
            "id": "tx4",
            "sender": "dave",
            "recipient": "eve",
            "amount": 3,
            "timestamp": int(time.time()) + 3,
        },
        {
            "id": "tx5",
            "sender": "eve",
            "recipient": "alice",
            "amount": 7,
            "timestamp": int(time.time()) + 4,
        },
    ]


@pytest.fixture
def large_transaction_set() -> list:
    """
    Generate a large set of transactions for merkle proof testing.
    """
    txs = []
    base_time = int(time.time())
    for i in range(10):
        txs.append({
            "id": f"tx_{i}",
            "sender": f"user_{i % 3}",
            "recipient": f"user_{(i + 1) % 3}",
            "amount": i + 1,
            "timestamp": base_time + i,
        })
    return txs


@pytest.fixture
def chain_validator() -> ChainValidator:
    """
    Provide a ChainValidator instance for integration tests.
    """
    return ChainValidator()


@pytest.fixture
def chain_reorganizer(chain_validator) -> ChainReorganizer:
    """
    Provide a ChainReorganizer instance for fork resolution tests.
    """
    return ChainReorganizer(chain_validator)


@pytest.fixture
def mined_blockchain(blockchain_module, test_transactions) -> BlockchainModule:
    """
    Create a blockchain with 3 mined blocks for testing chain operations.
    """
    # Add and mine first block
    for tx in test_transactions[:2]:
        blockchain_module.add_transaction(tx)
    blockchain_module.mine_block()

    # Add and mine second block
    for tx in test_transactions[2:4]:
        blockchain_module.add_transaction(tx)
    blockchain_module.mine_block()

    # Add and mine third block
    blockchain_module.add_transaction(test_transactions[4])
    blockchain_module.mine_block()

    return blockchain_module
