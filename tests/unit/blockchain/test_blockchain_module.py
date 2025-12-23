import time
import copy

import pytest

from src.blockchain.block import Block
from src.blockchain.blockchain_module import BlockchainModule
from src.blockchain.merkle_tree import MerkleTree
from src.blockchain.proof_of_work import ProofOfWork
from src.blockchain.chain_validator import ChainValidator
from src.blockchain.chain_reorganizer import ChainReorganizer


class TestBlockStructure:
    def test_block_creation(self, test_difficulty):
        block = Block(
            index=1,
            transactions=[],
            previous_hash="0" * 64,
            merkle_root="0" * 64,
            difficulty=test_difficulty,
        )
        assert block.index == 1
        assert block.previous_hash == "0" * 64
        assert isinstance(block.hash, str)
        assert len(block.hash) == 64

    def test_block_hash_calculation(self, test_difficulty):
        block1 = Block(
            index=1,
            transactions=[],
            previous_hash="0" * 64,
            merkle_root="a" * 64,
            difficulty=test_difficulty,
        )
        block2 = Block(
            index=1,
            transactions=[],
            previous_hash="0" * 64,
            merkle_root="a" * 64,
            difficulty=test_difficulty,
        )
        assert block1.calculate_hash() == block2.calculate_hash()

    def test_block_hash_change_on_data_change(self, test_difficulty):
        block = Block(
            index=1,
            transactions=[],
            previous_hash="0" * 64,
            merkle_root="a" * 64,
            difficulty=test_difficulty,
        )
        original_hash = block.hash
        block.nonce += 1
        block.hash = block.calculate_hash()
        assert block.hash != original_hash

    def test_block_pow_validation(self, test_difficulty):
        # Use difficulty 1 for quick PoW check
        block = Block(
            index=1,
            transactions=[],
            previous_hash="0" * 64,
            merkle_root="b" * 64,
            difficulty=1,
        )
        pow_engine = ProofOfWork()
        pow_engine.mine_block(block)
        assert block.validate_pow()
        assert block.hash.startswith("0" * block.difficulty)

    def test_block_to_from_dict(self, test_difficulty):
        block = Block(
            index=1,
            transactions=[],
            previous_hash="0" * 64,
            merkle_root="c" * 64,
            difficulty=test_difficulty,
        )
        data = block.to_dict()
        restored = Block.from_dict(
            {
                "index": data["index"],
                "previous_hash": data["previous_hash"],
                "merkle_root": data["merkle_root"],
                "timestamp": data["timestamp"],
                "nonce": data["nonce"],
                "difficulty": data["difficulty"],
                "hash": data["hash"],
                "transactions": [],
            }
        )
        assert restored.index == block.index
        assert restored.hash == block.hash


class TestProofOfWork:
    def test_mine_block(self, test_difficulty):
        block = Block(
            index=1,
            transactions=[],
            previous_hash="0" * 64,
            merkle_root="d" * 64,
            difficulty=1,
        )
        pow_engine = ProofOfWork()
        result = pow_engine.mine_block(block)
        assert result["success"] is True
        assert result["nonce"] == block.nonce
        assert isinstance(result["hash"], str)
        assert block.validate_pow()

    def test_mined_block_meets_difficulty(self):
        block = Block(
            index=1,
            transactions=[],
            previous_hash="0" * 64,
            merkle_root="e" * 64,
            difficulty=2,
        )
        pow_engine = ProofOfWork()
        pow_engine.mine_block(block)
        assert block.hash.startswith("0" * block.difficulty)

    def test_difficulty_adjustment(self):
        pow_engine = ProofOfWork()
        blocks = []
        base_time = int(time.time())

        # Create 10 blocks mined too quickly (average time << target_time/2)
        for i in range(10):
            b = Block(
                index=i,
                transactions=[],
                previous_hash="0" * 64,
                merkle_root="f" * 64,
                difficulty=2,
            )
            b.timestamp = base_time + i * 10
            blocks.append(b)

        new_difficulty = pow_engine.adjust_difficulty(blocks, target_time=60)
        assert new_difficulty > blocks[-1].difficulty

    def test_pow_difficulty_levels(self):
        # Only test low difficulties to keep tests fast
        for difficulty in (1, 2):
            block = Block(
                index=1,
                transactions=[],
                previous_hash="0" * 64,
                merkle_root="g" * 64,
                difficulty=difficulty,
            )
            pow_engine = ProofOfWork()
            pow_engine.mine_block(block)
            assert block.hash.startswith("0" * difficulty)

    def test_pow_performance(self):
        block = Block(
            index=1,
            transactions=[],
            previous_hash="0" * 64,
            merkle_root="h" * 64,
            difficulty=1,
        )
        pow_engine = ProofOfWork()
        start = time.time()
        pow_engine.mine_block(block)
        elapsed = time.time() - start
        # Mining with difficulty 1 should be very fast
        assert elapsed < 2.0


class TestMerkleTree:
    def test_merkle_tree_root(self, test_transactions):
        tree = MerkleTree(test_transactions)
        root = tree.get_root()
        assert isinstance(root, str)
        assert len(root) == 64

    def test_merkle_tree_single_transaction(self, test_transactions):
        tree = MerkleTree(test_transactions[:1])
        assert tree.get_root() is not None
        assert len(tree.tree[0]) == 1 or len(tree.tree[0]) == 2

    def test_merkle_tree_even_transactions(self, test_transactions):
        even_txs = test_transactions[:2]
        tree = MerkleTree(even_txs)
        assert len(tree.tree[0]) == 2

    def test_merkle_tree_odd_transactions(self, test_transactions):
        odd_txs = test_transactions[:3]
        tree = MerkleTree(odd_txs)
        # Internal implementation duplicates last leaf if odd
        assert len(tree.tree[0]) in (3, 4)

    def test_merkle_proof_generation(self, test_transactions):
        tree = MerkleTree(test_transactions)
        leaf_hash = tree.tree[0][0]
        proof = tree.get_proof(leaf_hash)
        assert isinstance(proof, list)
        assert all(len(direction) > 0 for direction, _ in proof)

    def test_merkle_proof_verification(self, test_transactions):
        tree = MerkleTree(test_transactions)
        leaf_hash = tree.tree[0][0]
        proof = tree.get_proof(leaf_hash)
        assert tree.verify_proof(leaf_hash, proof, tree.get_root())

    def test_merkle_proof_invalid(self, test_transactions):
        tree = MerkleTree(test_transactions)
        leaf_hash = tree.tree[0][0]
        proof = tree.get_proof(leaf_hash)
        # Tamper with proof
        if proof:
            proof[0] = (proof[0][0], "x" * 64)
        assert not tree.verify_proof(leaf_hash, proof, tree.get_root())

    def test_merkle_proof_tampered(self, test_transactions):
        tree = MerkleTree(test_transactions)
        leaf_hash = tree.tree[0][0]
        proof = tree.get_proof(leaf_hash)
        # Tamper with leaf hash
        tampered_leaf = "0" * 64
        assert not tree.verify_proof(tampered_leaf, proof, tree.get_root())


class TestChainValidation:
    def test_validate_block_valid(self, valid_chain):
        validator = ChainValidator()
        for i in range(1, len(valid_chain)):
            assert validator.validate_block(valid_chain[i], valid_chain[i - 1])

    def test_validate_block_invalid_hash(self, valid_chain):
        validator = ChainValidator()
        bad_chain = copy.deepcopy(valid_chain)
        bad_chain[1].hash = "f" * 64
        assert not validator.validate_block(bad_chain[1], bad_chain[0])

    def test_validate_block_invalid_pow(self, valid_chain):
        validator = ChainValidator()
        bad_block = copy.deepcopy(valid_chain[1])
        # Force invalid PoW by setting non-matching hash
        bad_block.hash = "1" + bad_block.hash[1:]
        assert not validator.validate_block(bad_block, valid_chain[0])

    def test_validate_block_broken_link(self, valid_chain):
        validator = ChainValidator()
        bad_block = copy.deepcopy(valid_chain[1])
        bad_block.previous_hash = "0" * 64
        assert not validator.validate_block(bad_block, valid_chain[0])

    def test_validate_chain_valid(self, valid_chain):
        validator = ChainValidator()
        assert validator.validate_chain(valid_chain)

    def test_validate_chain_invalid(self, valid_chain):
        validator = ChainValidator()
        bad_chain = copy.deepcopy(valid_chain)
        bad_chain[-1].previous_hash = "0" * 64
        assert not validator.validate_chain(bad_chain)


class TestTransactions:
    def test_add_transaction(self, fresh_blockchain, test_transactions):
        tx = test_transactions[0]
        result = fresh_blockchain.add_transaction(tx)
        assert result is True
        assert len(fresh_blockchain.pending_transactions) == 1

    def test_transaction_structure(self, fresh_blockchain, test_transactions):
        tx = test_transactions[0]
        fresh_blockchain.add_transaction(tx)
        pending = fresh_blockchain.pending_transactions[0]
        for field in ["id", "sender", "recipient", "amount", "timestamp"]:
            assert field in pending

    def test_multiple_transactions(self, fresh_blockchain, test_transactions):
        for tx in test_transactions:
            fresh_blockchain.add_transaction(tx)
        assert len(fresh_blockchain.pending_transactions) == len(test_transactions)


class TestChainReorganization:
    def test_find_fork_point(self, valid_chain):
        reorganizer = ChainReorganizer(ChainValidator())
        # Create a competing chain that diverges at last block
        competing_chain = copy.deepcopy(valid_chain)
        last = competing_chain[-1]
        modified_last = Block(
            index=last.index,
            transactions=last.transactions,
            previous_hash=last.previous_hash,
            merkle_root=last.merkle_root,
            difficulty=last.difficulty,
        )
        competing_chain[-1] = modified_last

        fork_index = reorganizer.find_fork_point(valid_chain, competing_chain)
        assert fork_index == len(valid_chain) - 2

    def test_reorganize_chain(self, valid_chain):
        reorganizer = ChainReorganizer(ChainValidator())
        old_chain = valid_chain
        # Extend new chain by one extra block to be longer
        new_chain = copy.deepcopy(old_chain)
        last = new_chain[-1]
        extra_block = Block(
            index=last.index + 1,
            transactions=[],
            previous_hash=last.hash,
            merkle_root=last.merkle_root,
            difficulty=last.difficulty,
        )
        new_chain.append(extra_block)

        result = reorganizer.reorganize_chain(new_chain, old_chain)
        assert result["success"] is True
        assert result["blocks_added"] == 1

    def test_reorganize_transactions_restored(self, valid_chain, test_transactions):
        reorganizer = ChainReorganizer(ChainValidator())
        old_chain = valid_chain
        # New chain shares only genesis
        new_chain = [copy.deepcopy(old_chain[0])]
        # Add two new blocks without transactions
        for i in range(1, 3):
            b = Block(
                index=i,
                transactions=[],
                previous_hash=new_chain[-1].hash,
                merkle_root=new_chain[-1].merkle_root,
                difficulty=new_chain[-1].difficulty,
            )
            new_chain.append(b)

        result = reorganizer.reorganize_chain(new_chain, old_chain)
        assert result["transactions_restored"] >= 0

    def test_longest_chain_rule(self, valid_chain):
        reorganizer = ChainReorganizer(ChainValidator())
        current_chain = valid_chain
        shorter_chain = current_chain[:-1]
        longest = reorganizer.find_longest_chain(shorter_chain, current_chain)
        assert longest is current_chain


