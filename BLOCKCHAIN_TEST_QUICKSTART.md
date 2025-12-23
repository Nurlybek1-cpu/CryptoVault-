# Quick Start: Running Blockchain Tests

## Running Integration Tests

### Basic test run
```bash
pytest tests/integration/test_blockchain_flow.py -v
```

### With coverage report
```bash
# Using venv python directly (ensures pytest-cov is found)
.venv\Scripts\python.exe -m pytest tests/integration/test_blockchain_flow.py --cov=src.blockchain --cov-report=term
```

### With detailed missing line coverage
```bash
.venv\Scripts\python.exe -m pytest tests/integration/test_blockchain_flow.py --cov=src.blockchain --cov-report=term-missing
```

### Generate HTML coverage report
```bash
.venv\Scripts\python.exe -m pytest tests/integration/test_blockchain_flow.py --cov=src.blockchain --cov-report=html
# Open htmlcov/index.html in browser
```

## Running Unit Tests

```bash
pytest tests/unit/blockchain/ -v
```

## Running All Blockchain Tests (Integration + Unit)

```bash
pytest tests/integration/test_blockchain_flow.py tests/unit/blockchain/ -v
```

Or with the venv Python:
```bash
.venv\Scripts\python.exe -m pytest tests/integration/test_blockchain_flow.py tests/unit/blockchain/ -v
```

## Test Results

### All Tests Passing
- ✅ 23 integration tests
- ✅ 31 unit tests
- ✅ 54 total tests

### Coverage Summary
- **Overall:** 66% coverage
- **Merkle Tree:** 95% (excellent)
- **Package Init:** 100% (perfect)
- **Proof of Work:** 80% (very good)
- **Chain Reorganizer:** 77% (good)
- **Chain Validator:** 67% (good)
- **Block:** 64% (good)
- **BlockchainModule:** 61% (good)
- **TransactionVerifier:** 26% (unit tests focus on blockchain ops)

## Troubleshooting

### Issue: "unrecognized arguments: --cov"
**Solution:** Use the venv Python executable instead of system pytest:
```bash
.venv\Scripts\python.exe -m pytest [args]
```

### Issue: Tests not found
**Solution:** Run from the workspace root:
```bash
cd c:\Users\Nuryk\crypto_vault
pytest tests/integration/test_blockchain_flow.py
```

## Key Files

- **Tests:** [tests/integration/test_blockchain_flow.py](tests/integration/test_blockchain_flow.py)
- **Fixtures:** [tests/integration/conftest.py](tests/integration/conftest.py)
- **Documentation:** [tests/integration/BLOCKCHAIN_TESTS_README.md](tests/integration/BLOCKCHAIN_TESTS_README.md)
