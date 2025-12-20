# Testing Guide for CryptoVault

## Overview

This guide provides comprehensive documentation for testing the CryptoVault authentication module. It covers test structure, execution, coverage targets, and best practices for maintaining a robust test suite.

## Table of Contents

1. [Test Structure](#test-structure)
2. [Running Tests](#running-tests)
3. [Test Coverage](#test-coverage)
4. [Test Categories](#test-categories)
5. [Fixtures and Mocks](#fixtures-and-mocks)
6. [Best Practices](#best-practices)
7. [Common Patterns](#common-patterns)
8. [Debugging Tests](#debugging-tests)

## Test Structure

### Directory Layout

```
tests/
├── conftest.py              # Root-level pytest configuration
├── unit/
│   └── auth/
│       ├── conftest.py      # Auth module fixtures
│       └── test_auth_module.py  # Auth module tests
├── integration/             # Integration tests
├── security/                # Security-focused tests
└── performance/             # Performance tests
```

### Test File Organization

Tests are organized by module and functionality:

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions
- **Security Tests**: Test security properties and attack scenarios
- **Performance Tests**: Test performance characteristics

## Running Tests

### Basic Commands

```bash
# Run all tests
pytest

# Run tests with verbose output
pytest -v

# Run specific test file
pytest tests/unit/auth/test_auth_module.py

# Run specific test class
pytest tests/unit/auth/test_auth_module.py::TestPasswordValidator

# Run specific test method
pytest tests/unit/auth/test_auth_module.py::TestPasswordValidator::test_valid_password

# Run tests matching a pattern
pytest -k "password"

# Run tests with coverage
pytest --cov=src.auth tests/unit/auth/

# Run tests with coverage report
pytest --cov=src.auth --cov-report=html tests/unit/auth/
```

### Pytest Options

```bash
# Stop on first failure
pytest -x

# Run last failed tests only
pytest --lf

# Show local variables on failure
pytest -l

# Show print statements
pytest -s

# Run in parallel (requires pytest-xdist)
pytest -n auto
```

### Coverage Targets

Target coverage: **70%+ for authentication module**

```bash
# Generate coverage report
pytest --cov=src.auth --cov-report=term-missing tests/unit/auth/

# Generate HTML coverage report
pytest --cov=src.auth --cov-report=html tests/unit/auth/
# Open htmlcov/index.html in browser
```

## Test Coverage

### Coverage Goals

| Component | Target Coverage | Critical Paths |
|-----------|----------------|----------------|
| PasswordValidator | 85%+ | All validation rules |
| PasswordHasher | 80%+ | Hash/verify operations |
| AuthModule | 75%+ | Registration, login flows |
| TOTPManager | 80%+ | Setup, verification |
| BackupCodesManager | 80%+ | Generation, verification |
| RateLimiter | 75%+ | Rate limit logic |
| Session Management | 70%+ | Token generation, validation |

### Critical Test Scenarios

**Password Validation:**
- ✅ Strong passwords pass validation
- ✅ Weak passwords fail validation
- ✅ All character requirements enforced
- ✅ Sequential patterns rejected
- ✅ Username containment checked

**Password Hashing:**
- ✅ Same password produces different hashes (salts)
- ✅ Correct passwords verify successfully
- ✅ Incorrect passwords rejected
- ✅ Invalid hash formats handled gracefully

**Registration:**
- ✅ Valid users registered successfully
- ✅ Duplicate usernames rejected
- ✅ Weak passwords rejected
- ✅ TOTP secrets generated
- ✅ Backup codes generated
- ✅ Only hashes stored in database

**Login:**
- ✅ Valid credentials create sessions
- ✅ Invalid credentials rejected
- ✅ Failed attempts tracked
- ✅ Account lockout after 5 failures
- ✅ Rate limiting enforced
- ✅ TOTP required when enabled

**Security Properties:**
- ✅ Constant-time password comparison
- ✅ Constant-time backup code verification
- ✅ Session tokens are unique
- ✅ Backup codes single-use only
- ✅ Rate limits track per identifier

## Test Categories

### Unit Tests

Test individual components in isolation with mocked dependencies.

**Example:**
```python
def test_valid_password(self):
    validator = PasswordValidator()
    is_valid, error_msg = validator.validate("ValidPassword123!")
    assert is_valid is True
```

### Integration Tests

Test component interactions and end-to-end flows.

**Example:**
```python
def test_register_and_login_flow(self, auth_module, test_username, test_password):
    # Register
    result = auth_module.register(test_username, test_password)
    assert result["success"] is True
    
    # Login
    login_result = auth_module.login(test_username, test_password)
    assert login_result["success"] is True
```

### Security Tests

Test security properties and attack scenarios.

**Example:**
```python
def test_timing_attack_prevention(self, hasher):
    """Test that password verification uses constant-time comparison."""
    password = "TestPassword123!"
    hash = hasher.hash_password(password)
    
    # Both should take similar time
    correct_result = hasher.verify_password(password, hash)
    incorrect_result = hasher.verify_password("WrongPassword", hash)
    
    assert correct_result is True
    assert incorrect_result is False
```

## Fixtures and Mocks

### Available Fixtures

**test_username**: Valid test username (`"testuser123"`)

**test_password**: Valid strong password (`"ValidPassword123!"`)

**test_weak_password**: Weak password for negative tests (`"weak"`)

**mock_database**: Mock database connection with in-memory storage

**auth_module**: Initialized AuthModule instance with mocked database

### Using Fixtures

```python
def test_registration(self, auth_module, test_username, test_password):
    result = auth_module.register(test_username, test_password)
    assert result["success"] is True
```

### Mock Database

The mock database fixture provides:

- `execute()` method that simulates SQL queries
- `commit()` method for transactions
- In-memory storage for users and sessions
- Access to stored data via `_users_data` and `_sessions_data`

**Example:**
```python
def test_backup_codes_stored_hashed(self, auth_module, test_username, test_password, mock_database):
    result = auth_module.register(test_username, test_password)
    plaintext_codes = result["backup_codes"]
    
    # Access database data
    user_data = mock_database._users_data[test_username]
    stored_hashes = user_data[13].split(",")  # backup_codes_hash
    
    # Verify codes are hashed
    assert len(stored_hashes) == 10
    for code in plaintext_codes:
        assert code not in stored_hashes
```

## Best Practices

### Test Naming

- Use descriptive test names: `test_valid_password()` not `test_password()`
- Group related tests in classes: `TestPasswordValidator`, `TestLogin`
- Follow pattern: `test_<what>_<condition>_<expected_result>`

### Test Organization

- One assertion per test when possible
- Test one behavior per test method
- Group related tests in test classes
- Use fixtures for common setup

### Test Data

- Use fixtures for reusable test data
- Avoid hardcoded values when possible
- Use realistic but not real data
- Clean up test data after tests

### Assertions

- Use specific assertions: `assert is_valid is True` not `assert is_valid`
- Include descriptive error messages: `assert len(codes) == 10, "Expected 10 backup codes"`
- Test both positive and negative cases

### Mocking

- Mock external dependencies (database, network, file system)
- Don't mock the code under test
- Use appropriate mock types (MagicMock, Mock, patch)
- Verify mock calls when behavior matters

### Security Testing

- Test constant-time operations
- Test input validation
- Test error handling
- Test rate limiting
- Test account lockout
- Test session expiration

## Common Patterns

### Testing Exceptions

```python
def test_weak_password_raises_error(self, auth_module, test_username):
    with pytest.raises(PasswordStrengthError) as exc_info:
        auth_module.register(test_username, "weak")
    
    assert exc_info.value.error_code == "PASSWORD_WEAK"
```

### Testing Multiple Scenarios

```python
@pytest.mark.parametrize("username,expected_error", [
    ("user@name", "INVALID_USERNAME_FORMAT"),
    ("user name", "INVALID_USERNAME_FORMAT"),
    ("", "INVALID_USERNAME"),
])
def test_invalid_usernames(self, auth_module, username, expected_error, test_password):
    with pytest.raises(RegistrationError) as exc_info:
        auth_module.register(username, test_password)
    
    assert exc_info.value.error_code == expected_error
```

### Testing Time-Dependent Code

```python
@patch('time.time')
def test_session_expiration(self, mock_time, auth_module):
    # Set current time
    mock_time.return_value = 1000.0
    
    # Create session
    result = auth_module.login("user", "pass")
    
    # Advance time
    mock_time.return_value = 2000.0
    
    # Session should be expired
    # ... test expiration logic
```

### Testing Database Operations

```python
def test_user_stored_in_database(self, auth_module, test_username, test_password, mock_database):
    auth_module.register(test_username, test_password)
    
    # Verify database state
    assert test_username in mock_database._users_data
    user_data = mock_database._users_data[test_username]
    assert user_data[1] == test_username  # username field
```

## Debugging Tests

### Using pytest Debugging

```bash
# Drop into debugger on failure
pytest --pdb

# Drop into debugger at start of test
pytest --trace

# Show local variables on failure
pytest -l
```

### Print Statements

```python
def test_debug_example(self, auth_module):
    result = auth_module.register("user", "pass")
    print(f"Result: {result}")  # Use -s flag to see output
    assert result["success"] is True
```

### Using pytest fixtures for debugging

```python
@pytest.fixture
def debug_mode():
    import logging
    logging.basicConfig(level=logging.DEBUG)
    yield
    logging.basicConfig(level=logging.WARNING)
```

### Common Issues

**Tests failing intermittently:**
- Check for time-dependent code (use time mocking)
- Check for race conditions (use locks or sequential execution)
- Check for shared state between tests (use fixtures with proper cleanup)

**Mock not working:**
- Verify patch path matches import path
- Check mock is applied before code execution
- Verify mock return values are set correctly

**Database state issues:**
- Ensure database is reset between tests (use fixtures)
- Check transaction handling (commit/rollback)
- Verify mock database state matches expectations

## Continuous Integration

### CI Configuration

Tests should run in CI/CD pipeline:

```yaml
# Example GitHub Actions
- name: Run tests
  run: |
    pytest tests/unit/auth/ -v --cov=src.auth --cov-report=xml
    
- name: Check coverage
  run: |
    coverage report --fail-under=70
```

### Pre-commit Hooks

```bash
# Run tests before commit
pytest tests/unit/auth/ --quick  # Fast subset of tests

# Run full test suite on push
pytest tests/ -v --cov=src
```

## Test Maintenance

### Adding New Tests

1. Identify component to test
2. Determine test category (unit/integration/security)
3. Create test class or add to existing
4. Write test with clear name and assertions
5. Run tests and verify coverage
6. Update this guide if needed

### Refactoring Tests

- Keep tests focused on behavior, not implementation
- Update tests when interfaces change
- Remove obsolete tests
- Consolidate duplicate tests

### Test Performance

- Use fast mocks instead of real dependencies
- Avoid unnecessary database operations
- Use parametrize for similar tests
- Run unit tests separately from integration tests

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Pytest Fixtures](https://docs.pytest.org/en/stable/fixture.html)
- [Pytest Mocking](https://docs.pytest.org/en/stable/monkeypatch.html)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
- [Testing Best Practices](https://docs.python-guide.org/writing/tests/)

## Conclusion

This testing guide provides the foundation for maintaining a robust test suite for the CryptoVault authentication module. Follow these practices to ensure code quality, security, and maintainability.

**Remember:**
- Write tests first when possible (TDD)
- Aim for high coverage of critical paths
- Test security properties explicitly
- Keep tests fast and reliable
- Update tests when code changes

