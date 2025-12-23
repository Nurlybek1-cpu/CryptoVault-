"""
Main blockchain module for CryptoVault.
Implements blockchain state management, block validation, and chain operations.
"""

import hashlib
import json
import logging
import time
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

from src.blockchain.block import Block
from src.blockchain.merkle_tree import MerkleTree
from src.blockchain.proof_of_work import ProofOfWork
from src.blockchain.chain_validator import ChainValidator
from src.blockchain.chain_reorganizer import ChainReorganizer
from src.blockchain.transaction_verifier import TransactionVerifier
from src.exceptions import (
    BlockchainError, BlockValidationError, TransactionError,
    ChainReorganizationError, AuditTrailError, ProofOfWorkError
)


class BlockchainModule:
    """
    Core blockchain module for CryptoVault.
    
    Manages the blockchain state, including block chain, pending transactions,
    validation, and audit trail. Implements Proof of Work consensus and
    Merkle tree verification.
    
    Attributes:
        chain (List[Block]): List of blocks forming the blockchain
        pending_transactions (List[Dict]): Transactions waiting to be mined
        difficulty (int): Current difficulty level for PoW
        nonce_range (Tuple[int, int]): Min/max nonce values
        validator: Validator instance for transaction/signature verification
        logger: Logger instance for tracking operations
        audit_trail (Dict): Audit trail for entities and transactions
    """
    
    def __init__(
        self,
        difficulty: int = 4,
        nonce_range: Tuple[int, int] = (0, 2**32-1),
        validator = None,
        logger: Optional[logging.Logger] = None
    ) -> None:
        """
        Initialize blockchain module.
        
        Args:
            difficulty: Initial difficulty level (default: 4)
            nonce_range: Valid range for nonce values
            validator: Validator instance for transaction verification
            logger: Logger instance (creates default if None)
        
        Raises:
            BlockchainError: If difficulty or nonce_range is invalid
        """
        if difficulty < 1 or difficulty > 32:
            raise BlockchainError("Difficulty must be between 1 and 32")
        
        if nonce_range[0] < 0 or nonce_range[1] <= nonce_range[0]:
            raise BlockchainError("Invalid nonce range")
        
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict[str, Any]] = []
        self.difficulty: int = difficulty
        self.nonce_range: Tuple[int, int] = nonce_range
        self.tx_validator = validator
        self.validator = ChainValidator()
        self.tx_verifier = TransactionVerifier()
        self.chain_reorganizer = ChainReorganizer(self.validator)
        self.logger: logging.Logger = logger or self._setup_logger()
        self.pow = ProofOfWork()
        
        # Audit trail: entity_type -> entity_id -> list of transactions
        self.audit_trail: Dict[str, Dict[str, List[Dict]]] = defaultdict(lambda: defaultdict(list))
        
        self.logger.info(
            f"BlockchainModule initialized with difficulty={difficulty}, "
            f"nonce_range={nonce_range}"
        )

        # Initialize chain with genesis block
        self.genesis_block: Block = self.create_genesis_block()
    
    @staticmethod
    def _setup_logger() -> logging.Logger:
        """
        Set up default logger for blockchain operations.
        
        Returns:
            logging.Logger: Configured logger instance
        """
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def create_genesis_block(self) -> Block:
        """
        Create and mine the genesis block (index 0).
        """
        if self.chain:
            return self.chain[0]

        previous_hash = "0" * 64
        merkle_root = hashlib.sha256(b"").hexdigest()

        genesis_block = Block(
            index=0,
            transactions=[],
            previous_hash=previous_hash,
            merkle_root=merkle_root,
            difficulty=self.difficulty,
        )
        self.pow.mine_block(genesis_block)
        self.chain.append(genesis_block)
        self.logger.info(
            "Genesis block created: %s", genesis_block.hash[:16]
        )
        return genesis_block
    
    def add_transaction(
        self,
        transaction_dict: Dict[str, Any],
        sender_pubkey: Any = None,
    ) -> bool:
        """
        Add transaction to pending transactions pool.
        
        Validates transaction structure and optionally verifies signature
        if validator is available.
        
        Args:
            transaction_dict: Transaction data with fields like:
                - id: Unique transaction ID
                - timestamp: Transaction timestamp
                - sender: Sender entity identifier
                - recipient: Recipient entity identifier
                - amount: Transaction amount
                - signature: Transaction signature (optional)
                - metadata: Additional metadata (optional)
        
        Returns:
            bool: True if transaction added successfully
        
        Raises:
            TransactionError: If transaction is invalid
        """
        # Validate required fields
        required_fields = ['id', 'timestamp', 'sender', 'recipient', 'amount']
        missing_fields = [f for f in required_fields if f not in transaction_dict]
        
        if missing_fields:
            raise TransactionError(
                f"Transaction missing required fields: {missing_fields}"
            )
        # Basic amount check
        if transaction_dict['amount'] <= 0:
            raise TransactionError("Transaction amount must be positive")

        # Verify transaction signature if public key provided
        if sender_pubkey is not None:
            if not self.tx_verifier.validate_transaction(transaction_dict, sender_pubkey):
                raise TransactionError(
                    f"Transaction {transaction_dict.get('id')} failed ECDSA signature verification"
                )
        # Otherwise, fall back to external validator if configured
        elif self.tx_validator and not self.verify_transaction_signature(transaction_dict):
            raise TransactionError(
                f"Transaction {transaction_dict.get('id')} failed signature verification"
            )
        
        # Add to pending transactions
        self.pending_transactions.append(transaction_dict)
        
        self.logger.debug(
            f"Transaction {transaction_dict['id']} added to pending pool"
        )
        
        # Record in audit trail
        sender = transaction_dict.get('sender', 'unknown')
        self._record_audit_entry('transaction', sender, transaction_dict)
        
        return True
    
    def create_block(
        self,
        transactions: Optional[List[Dict[str, Any]]] = None,
        miner: str = "system"
    ) -> Dict[str, Any]:
        """
        Create a new block with given transactions.
        
        Does NOT automatically mine the block. Call mine_block() to
        perform Proof of Work.
        
        Args:
            transactions: Transactions to include. Uses pending if None.
            miner: Identifier of miner creating block
        
        Returns:
            Dict[str, Any]: Block information
        
        Raises:
            BlockchainError: If block creation fails
        """
        if transactions is None:
            if not self.pending_transactions:
                raise BlockchainError("No transactions available to create block")
            transactions = self.pending_transactions
            self.pending_transactions = []
        
        # Build Merkle tree from transaction hashes
        merkle_root = self.build_merkle_tree(transactions)
        
        # Get previous block hash
        if self.chain:
            previous_hash = self.chain[-1].hash
            index = len(self.chain)
        else:
            previous_hash = "0" * 64
            index = 0
        
        # Create block
        block = Block(
            index=index,
            transactions=transactions,
            previous_hash=previous_hash,
            merkle_root=merkle_root,
            difficulty=self.difficulty
        )
        
        self.logger.info(
            f"Block {index} created by miner '{miner}' "
            f"with {len(transactions)} transactions"
        )
        
        return block.to_dict()
    
    def mine_block(self) -> Dict[str, Any]:
        """
        Mine the next block from pending transactions.
        
        Performs Proof of Work on a new block until valid nonce is found.
        Adds mined block to chain if valid.
        
        Returns:
            Dict[str, Any]: Mined block data
        
        Raises:
            BlockchainError: If mining fails or block is invalid
        """
        if not self.pending_transactions:
            raise BlockchainError("No pending transactions to mine")
        
        try:
            # Get previous block hash
            if self.chain:
                previous_hash = self.chain[-1].hash
                index = len(self.chain)
            else:
                # Create genesis block first
                return self.create_genesis_block().to_dict()
            
            # Build Merkle tree
            merkle_root = self.build_merkle_tree(self.pending_transactions)
            
            # Create block
            block = Block(
                index=index,
                transactions=self.pending_transactions,
                previous_hash=previous_hash,
                merkle_root=merkle_root,
                difficulty=self.difficulty,
            )
            
            # Mine block
            start_time = time.time()
            mining_result = self.pow.mine_block(block)
            elapsed = time.time() - start_time
            
            # Validate before adding
            if not self.validate_block(block):
                raise BlockValidationError("Mined block failed validation")
            
            # Add to chain
            self.chain.append(block)
            cleared_txs = len(self.pending_transactions)
            self.pending_transactions = []
            
            self.logger.info(
                f"Block {block.index} mined successfully in {elapsed:.2f}s "
                f"with nonce={block.nonce}, hash={(block.hash or '')[:16]}..., "
                f"cleared {cleared_txs} transactions"
            )

            # Adjust difficulty based on recent blocks
            try:
                self.difficulty = self.pow.adjust_difficulty(self.chain)
            except Exception as e:
                self.logger.warning(f"Difficulty adjustment failed: {e}")
            
            return block.to_dict()
        
        except Exception as e:
            self.logger.error(f"Mining failed: {e}")
            raise BlockchainError(f"Block mining failed: {e}")
    
    def validate_block(self, block: Block) -> bool:
        """
        Validate a single block using chain validator and Merkle root check.
        """
        try:
            if not isinstance(block, Block):
                raise BlockValidationError("Invalid block type")

            if block.index < 0:
                raise BlockValidationError("Block index cannot be negative")

            # Validate against previous block if exists
            if block.index > 0 and len(self.chain) >= block.index:
                previous_block = self.chain[block.index - 1]
                if not self.validator.validate_block(block, previous_block):
                    raise BlockValidationError("Block failed structural validation")
            elif block.index == 0 and block.previous_hash != "0" * 64:
                raise BlockValidationError("Invalid genesis previous hash")

            # Validate Merkle root if transactions present
            if block.transactions:
                calculated_merkle = self.build_merkle_tree(block.transactions)
                if calculated_merkle != block.merkle_root:
                    raise BlockValidationError("Merkle root mismatch")

            self.logger.debug(f"Block {block.index} validation passed")
            return True

        except BlockValidationError as e:
            self.logger.warning(f"Block {block.index} validation failed: {e}")
            return False
    
    def validate_chain(self) -> bool:
        """
        Validate entire blockchain using the ChainValidator.
        """
        try:
            if not self.chain:
                return False

            if not self.validator.validate_chain(self.chain):
                raise BlockValidationError("Chain validation failed")

            self.logger.info(
                f"Chain validation passed for {len(self.chain)} blocks"
            )
            return True

        except BlockValidationError as e:
            self.logger.error(f"Chain validation failed: {e}")
            return False

    def is_chain_valid(self) -> Dict[str, Any]:
        """
        Return detailed chain validation result.
        """
        errors: List[str] = []
        if not self.chain:
            return {"valid": False, "blocks_validated": 0, "errors": ["Empty chain"]}

        # Check genesis
        genesis = self.chain[0]
        if genesis.index != 0:
            errors.append("Genesis index is not 0")
        if genesis.previous_hash != "0" * 64:
            errors.append("Genesis previous hash incorrect")

        blocks_validated = 0
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if not self.validator.validate_block(current_block, previous_block):
                errors.append(f"Block {i} failed validation")
            blocks_validated += 1

        return {
            "valid": len(errors) == 0,
            "blocks_validated": blocks_validated,
            "errors": errors,
        }

    def receive_chain(self, received_chain: List[Block]) -> Dict[str, Any]:
        """
        Handle a competing chain from another node and reorganize if needed.
        """
        result: Dict[str, Any] = {
            "success": False,
            "reason": "",
        }

        try:
            # Decide which chain should be adopted (longest valid rule)
            longest = self.chain_reorganizer.find_longest_chain(
                received_chain, self.chain
            )

            if longest is self.chain:
                result["reason"] = "Current chain is longer or preferred"
                return result

            # Perform reorganization
            reorg_info = self.chain_reorganizer.reorganize_chain(
                received_chain, self.chain
            )

            # Update local chain
            self.chain = received_chain

            # Restore rolled-back transactions to pending
            removed_txs = reorg_info.get("removed_transactions", [])
            self.pending_transactions.extend(removed_txs)

            result.update(reorg_info)
            result["success"] = True
            return result

        except ChainReorganizationError as e:
            self.logger.warning(f"Chain reorganization rejected: {e}")
            result["reason"] = str(e)
            return result
    
    def get_block(self, index: int) -> Dict[str, Any]:
        """
        Get block by index.
        
        Args:
            index: Block index in chain
        
        Returns:
            Dict[str, Any]: Block data
        
        Raises:
            BlockchainError: If block not found
        """
        if index < 0 or index >= len(self.chain):
            raise BlockchainError(
                f"Block {index} not found in chain of length {len(self.chain)}"
            )
        
        return self.chain[index].to_dict()
    
    def get_transaction_count(self) -> int:
        """
        Get total transaction count across all blocks.
        
        Returns:
            int: Total number of transactions in blockchain
        """
        return sum(len(block.transactions) for block in self.chain)
    
    def get_chain_length(self) -> int:
        """
        Get current blockchain length.
        
        Returns:
            int: Number of blocks in chain
        """
        return len(self.chain)
    
    def build_merkle_tree(self, transactions: List[Dict[str, Any]]) -> str:
        """
        Build Merkle tree from transactions and return root hash.
        """
        if not transactions:
            raise BlockchainError("Cannot build Merkle tree from empty transactions")

        try:
            merkle_tree = MerkleTree(transactions)
            root = merkle_tree.get_root()
            if root is None:
                raise BlockchainError("Merkle tree construction failed: empty root")
            return root
        except Exception as e:
            raise BlockchainError(f"Merkle tree construction failed: {e}")

    def get_merkle_proof(self, transaction_hash: str, block_index: int) -> List[tuple]:
        """
        Get Merkle proof for a transaction in a specific block.
        """
        block = self.get_block(block_index)
        tree = MerkleTree(block["transactions"])
        return tree.get_proof(transaction_hash)

    def verify_merkle_proof(
        self,
        transaction_hash: str,
        proof: List[tuple],
        merkle_root: str,
    ) -> bool:
        """
        Verify Merkle proof for a transaction.
        """
        try:
            temp_tree = MerkleTree([])
            return temp_tree.verify_proof(transaction_hash, proof, merkle_root)
        except Exception as e:
            self.logger.warning(f"Merkle proof verification failed: {e}")
            return False
    
    def verify_transaction_signature(self, transaction: Dict[str, Any]) -> bool:
        """
        Verify transaction signature.
        
        Uses validator if available, otherwise returns True.
        
        Args:
            transaction: Transaction dictionary
        
        Returns:
            bool: True if signature is valid or no validator available
        """
        if not self.tx_validator:
            return True
        
        if 'signature' not in transaction:
            return False
        
        try:
            return self.tx_validator.verify_signature(transaction)
        except Exception as e:
            self.logger.warning(
                f"Transaction {transaction.get('id')} signature verification failed: {e}"
            )
            return False
    
    def reorganize_chain(self, new_chain: List[Block]) -> bool:
        """
        Reorganize blockchain (chain reorg/fork resolution).
        
        Replaces current chain with new chain if new chain is valid and longer.
        Used for fork resolution and consensus updates.
        
        Args:
            new_chain: New blockchain to adopt
        
        Returns:
            bool: True if reorganization successful
        
        Raises:
            ChainReorganizationError: If new chain is invalid
        """
        try:
            if not new_chain:
                raise ChainReorganizationError("Cannot reorganize to empty chain")
            
            if len(new_chain) <= len(self.chain):
                raise ChainReorganizationError(
                    f"New chain ({len(new_chain)}) must be longer than current "
                    f"({len(self.chain)})"
                )
            
            # Validate new chain
            old_chain = self.chain[:]
            self.chain = new_chain
            
            if not self.validate_chain():
                self.chain = old_chain
                raise ChainReorganizationError("New chain failed validation")
            
            self.logger.info(
                f"Chain reorganized from {len(old_chain)} to {len(new_chain)} blocks"
            )
            return True
        
        except ChainReorganizationError as e:
            self.logger.error(f"Chain reorganization failed: {e}")
            raise
    
    def get_audit_trail(
        self,
        entity_type: str,
        entity_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get audit trail for an entity.
        
        Returns all transactions and events associated with an entity.
        
        Args:
            entity_type: Type of entity (e.g., 'transaction', 'block')
            entity_id: Identifier of entity
        
        Returns:
            List[Dict[str, Any]]: Audit entries for entity
        
        Raises:
            AuditTrailError: If entity not found
        """
        if entity_type not in self.audit_trail:
            raise AuditTrailError(f"No audit trail for entity type '{entity_type}'")
        
        if entity_id not in self.audit_trail[entity_type]:
            raise AuditTrailError(
                f"No audit trail found for {entity_type} '{entity_id}'"
            )
        
        return self.audit_trail[entity_type][entity_id]
    
    def _record_audit_entry(
        self,
        entity_type: str,
        entity_id: str,
        data: Dict[str, Any]
    ) -> None:
        """
        Record audit entry for an entity.
        
        Args:
            entity_type: Type of entity
            entity_id: Entity identifier
            data: Data to record
        """
        entry = {
            'timestamp': int(time.time()),
            'block_index': len(self.chain),
            'data': data
        }
        self.audit_trail[entity_type][entity_id].append(entry)
    
    def get_blockchain_stats(self) -> Dict[str, Any]:
        """
        Get blockchain statistics.
        
        Returns:
            Dict[str, Any]: Statistics including block count, transaction count, etc.
        """
        return {
            'block_count': len(self.chain),
            'transaction_count': self.get_transaction_count(),
            'pending_transaction_count': len(self.pending_transactions),
            'difficulty': self.difficulty,
            'chain_valid': self.validate_chain() if self.chain else True
        }