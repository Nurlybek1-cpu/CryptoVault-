import pytest

from src.blockchain.blockchain_module import BlockchainModule
from src.blockchain.block import Block


@pytest.fixture(scope="module")
def test_difficulty() -> int:
    # Low difficulty for fast tests
    return 2


@pytest.fixture(scope="module")
def blockchain_module(test_difficulty: int) -> BlockchainModule:
    """
    Initialize a BlockchainModule instance with low difficulty for testing.
    """
    return BlockchainModule(difficulty=test_difficulty)


@pytest.fixture
def test_transactions() -> list:
    """
    Sample transactions used across tests.
    """
    return [
        {
            "id": "tx1",
            "sender": "alice",
            "recipient": "bob",
            "amount": 10,
            "timestamp": 1703330400,
        },
        {
            "id": "tx2",
            "sender": "bob",
            "recipient": "carol",
            "amount": 5,
            "timestamp": 1703330500,
        },
        {
            "id": "tx3",
            "sender": "carol",
            "recipient": "dave",
            "amount": 2,
            "timestamp": 1703330600,
        },
    ]


@pytest.fixture
def fresh_blockchain(test_difficulty: int) -> BlockchainModule:
    """
    Provide a fresh blockchain instance for tests that mutate the chain.
    """
    return BlockchainModule(difficulty=test_difficulty)


@pytest.fixture
def valid_chain(fresh_blockchain: BlockchainModule, test_transactions: list) -> list[Block]:
    """
    Build a small valid chain with a few mined blocks.
    """
    # Add some transactions and mine a couple of blocks
    for tx in test_transactions:
        fresh_blockchain.add_transaction(tx)
    fresh_blockchain.mine_block()

    for tx in test_transactions:
        fresh_blockchain.add_transaction(tx)
    fresh_blockchain.mine_block()

    return list(fresh_blockchain.chain)


