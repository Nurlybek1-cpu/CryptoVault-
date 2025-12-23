# Blockchain Integration Tests

Comprehensive integration tests for CryptoVault blockchain operations, covering complete end-to-end workflows.

## Overview

The integration test suite validates blockchain functionality across 8 major test classes with 23 test methods:

- **Mining workflows** (3 tests)
- **Chain growth and validation** (4 tests)
- **Merkle proof verification** (2 tests)
- **Tampering detection** (4 tests)
- **Chain reorganization/fork resolution** (3 tests)
- **Difficulty adjustment** (2 tests)
- **Audit trail** (3 tests)
- **End-to-end blockchain integration** (2 tests)

## Test Classes

### 1. TestCompleteMiningFlow (3 tests)

Tests the complete mining workflow from transaction pool to mined block.

**Tests:**
- `test_add_transactions_mine_block()` - Verify transactions are mined into blocks with correct merkle roots and PoW
- `test_mine_empty_pending_raises_error()` - Verify error handling when mining with no pending transactions
- `test_transaction_validation()` - Verify transaction validation during add_transaction

**Coverage:**
- ✅ Transaction addition to pending pool
- ✅ Block mining with transaction inclusion
- ✅ Merkle root correctness
- ✅ Proof of Work validation
- ✅ Error handling for invalid transactions

### 2. TestChainGrowth (4 tests)

Tests blockchain growth, chain linking, and state management.

**Tests:**
- `test_build_blockchain()` - Mine 5 blocks and verify chain length, block linking
- `test_chain_stats()` - Verify blockchain statistics tracking (block count, transaction count, difficulty)
- `test_get_block_by_index()` - Retrieve blocks by index with validation
- `test_transaction_count()` - Verify transaction counting across entire blockchain

**Coverage:**
- ✅ Chain length tracking
- ✅ Block linking and hash chains
- ✅ Block retrieval API
- ✅ Statistics accuracy
- ✅ Genesis block structure

### 3. TestMerkleProofVerification (2 tests)

Tests Merkle tree proof generation and verification for transaction inclusion proofs.

**Tests:**
- `test_merkle_proof_verification()` - Generate proof for specific transaction and verify validity/invalidity
- `test_merkle_proof_all_transactions()` - Verify proofs work across all transactions in a block

**Coverage:**
- ✅ Merkle proof generation
- ✅ Merkle proof verification (positive cases)
- ✅ Merkle proof rejection (negative cases)
- ✅ Transaction inclusion verification

### 4. TestTamperDetection (4 tests)

Tests detection of various tampering scenarios that violate blockchain integrity.

**Tests:**
- `test_detect_block_tampering()` - Detect transaction data modifications via merkle root mismatch
- `test_detect_hash_tampering()` - Detect block hash modifications breaking PoW
- `test_detect_previous_hash_tampering()` - Detect chain link breaking (previous_hash mismatch)
- `test_detect_nonce_tampering()` - Detect nonce modifications invalidating PoW

**Coverage:**
- ✅ Transaction tampering detection
- ✅ Hash tampering detection
- ✅ Chain linking verification
- ✅ Proof of Work validation
- ✅ Block integrity checks

### 5. TestChainReorganization (3 tests)

Tests fork resolution and chain reorganization logic (longest valid chain rule).

**Tests:**
- `test_chain_fork_resolution()` - Build two chains, fork, resolve to longest valid chain
- `test_reject_shorter_chain()` - Verify shorter chains are rejected
- `test_reject_invalid_chain()` - Verify invalid chains with broken links are rejected

**Coverage:**
- ✅ Chain fork detection
- ✅ Longest chain rule implementation
- ✅ Transaction restoration from removed blocks
- ✅ Invalid chain rejection
- ✅ Chain switch validation

### 6. TestDifficultyAdjustment (2 tests)

Tests difficulty adjustment mechanism based on mining speed.

**Tests:**
- `test_difficulty_increases_with_fast_mining()` - Verify difficulty adjusts as blocks are mined
- `test_difficulty_stays_valid()` - Verify difficulty remains within valid bounds (1-32)

**Coverage:**
- ✅ Difficulty calculation
- ✅ Difficulty boundary enforcement
- ✅ Difficulty state persistence

### 7. TestAuditTrail (3 tests)

Tests audit trail recording and retrieval for compliance and forensics.

**Tests:**
- `test_audit_trail_transaction_recording()` - Verify transactions are recorded in audit trail with timestamps
- `test_audit_trail_block_recording()` - Verify block mining recorded in audit trail
- `test_audit_trail_multiple_entities()` - Verify audit trail works with multiple entities

**Coverage:**
- ✅ Transaction audit recording
- ✅ Timestamp tracking
- ✅ Entity-specific audit queries
- ✅ Block index tracking

### 8. TestBlockchainIntegration (2 tests)

End-to-end integration tests for complete blockchain workflows.

**Tests:**
- `test_complete_workflow()` - Complete workflow: genesis → add txs → mine → validate
- `test_blockchain_persistence_simulation()` - Verify blockchain state maintained across operations

**Coverage:**
- ✅ Genesis block creation
- ✅ Transaction flow to mining
- ✅ Block persistence
- ✅ Chain validation
- ✅ State consistency

## Running Tests

### Run all blockchain integration tests
```bash
pytest tests/integration/test_blockchain_flow.py -v
```

### Run specific test class
```bash
pytest tests/integration/test_blockchain_flow.py::TestCompleteMiningFlow -v
```

### Run specific test
```bash
pytest tests/integration/test_blockchain_flow.py::TestCompleteMiningFlow::test_add_transactions_mine_block -v
```

### Run with coverage
```bash
pytest tests/integration/test_blockchain_flow.py --cov=src.blockchain --cov-report=html
```

### Run unit tests
```bash
pytest tests/unit/blockchain/ -v
```

## Test Fixtures

### blockchain_module
Fresh `BlockchainModule` instance with difficulty=2 for fast testing

### test_transactions
List of 5 sample transactions (alice→bob, bob→carol, etc.)

### large_transaction_set
Set of 10 transactions for merkle proof testing

### mined_blockchain
Pre-mined blockchain with 3 blocks (genesis + 3 mined blocks, 5 transactions total)

### chain_validator
`ChainValidator` instance for block/chain validation

### chain_reorganizer
`ChainReorganizer` instance for fork resolution testing

## Test Results

### Current Status: ✅ All 23 tests passing

```
tests/integration/test_blockchain_flow.py: 23 PASSED (0.40s)
tests/unit/blockchain/: 31 PASSED (0.10s)
```

## Coverage Summary

| Component | Tests | Coverage |
|-----------|-------|----------|
| Mining | 3 | Full mining workflow |
| Chain Growth | 4 | Block creation, linking, retrieval |
| Merkle Proofs | 2 | Proof generation and verification |
| Tampering Detection | 4 | All tampering types (tx, hash, links, nonce) |
| Fork Resolution | 3 | Chain reorg and validation |
| Difficulty | 2 | Adjustment bounds and persistence |
| Audit Trail | 3 | Recording and retrieval |
| Integration | 2 | End-to-end workflows |

## Key Test Scenarios

### Mining
- ✅ Add multiple transactions
- ✅ Mine block with transactions
- ✅ Verify merkle root correctness
- ✅ Verify Proof of Work validation
- ✅ Verify pending transactions cleared

### Chain Growth
- ✅ Mine sequential blocks
- ✅ Verify chain length growth
- ✅ Verify block linking
- ✅ Verify chain validation
- ✅ Track transaction counts

### Merkle Proofs
- ✅ Generate proofs for transactions
- ✅ Verify valid proofs pass
- ✅ Reject invalid proofs
- ✅ Handle all block sizes

### Tampering Detection
- ✅ Detect transaction modifications
- ✅ Detect hash changes
- ✅ Detect broken chain links
- ✅ Detect nonce tampering
- ✅ Report validation failures

### Fork Resolution
- ✅ Build competing chains
- ✅ Apply longest valid chain rule
- ✅ Restore rolled-back transactions
- ✅ Reject shorter chains
- ✅ Reject invalid chains

### Difficulty
- ✅ Adjust based on block times
- ✅ Maintain bounds (1-32)
- ✅ Persist across blocks

### Audit Trail
- ✅ Record all transactions
- ✅ Include timestamps
- ✅ Track block indices
- ✅ Support entity queries

## Performance

Tests run efficiently due to:
- Low difficulty (2) for fast mining
- Fresh blockchain instances per test
- Minimal transaction sets
- No external I/O or network calls

**Typical runtime:** ~0.4 seconds for all 23 integration tests

## References

- See [docs/testing_guide.md](../../docs/testing_guide.md) for general testing best practices
- See [src/blockchain/blockchain_module.py](../../src/blockchain/blockchain_module.py) for API documentation
- See [tests/unit/blockchain/test_blockchain_module.py](../unit/blockchain/test_blockchain_module.py) for unit tests

## Future Enhancements

- [ ] Performance benchmarking tests
- [ ] Multi-node consensus simulation
- [ ] Network partition handling
- [ ] Large-scale blockchain tests (1000+ blocks)
- [ ] Memory usage profiling
- [ ] Concurrent mining simulation
