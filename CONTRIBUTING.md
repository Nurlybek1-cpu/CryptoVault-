# Contributing to CryptoVault

Thank you for contributing to CryptoVault! This document provides guidelines for contributing.

## Code of Conduct

- Be respectful and inclusive
- Respect others' opinions and expertise
- Report inappropriate behavior to: conduct@cryptovault.dev

## How to Contribute

### 1. Fork and Clone

```bash
# Fork on GitHub, then clone your fork
git clone https://github.com/your-username/cryptovault.git
cd cryptovault
```

### 2. Create Feature Branch

```bash
# Create descriptive branch name
git checkout -b feature/add-quantum-resistant-crypto
```

### 3. Make Changes

```bash
# Install development dependencies
make install-dev

# Make your changes
# ... edit files ...

# Run tests
make test

# Check code quality
make check
```

### 4. Commit and Push

```bash
# Follow commit message format
git commit -m "feat: add quantum-resistant algorithms"
git push origin feature/add-quantum-resistant-crypto
```

### 5. Create Pull Request

- Go to GitHub and create pull request
- Fill in the PR template
- Link any related issues

## Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation only
- **style**: Code style changes (formatting, missing semicolons, etc)
- **refactor**: Code refactoring without feature/fix changes
- **perf**: Performance improvement
- **test**: Adding or updating tests
- **chore**: Build system, dependencies, etc
- **security**: Security-related changes

### Scope

- auth
- file-encryption
- blockchain
- messaging
- ledger
- docs
- ci

### Examples

```
feat(auth): add biometric authentication support
fix(file-encryption): resolve AES-GCM nonce collision
docs(security): update threat model documentation
test(blockchain): add merkle proof validation tests
security(auth): implement rate limiting on password reset
```

## Code Style

### PEP 8 Compliance

```bash
# Check style
flake8 src/

# Auto-format code
black src/
```

### Type Hints

All functions must have type hints:

```python
def encrypt_file(
    self,
    filepath: str,
    password: str,
    cipher_type: str = "AES-256-GCM"
) -> Dict[str, Any]:
    """Encrypt a file with password-derived key.
    
    Args:
        filepath: Path to file to encrypt
        password: Password for key derivation
        cipher_type: Encryption algorithm (default: AES-256-GCM)
    
    Returns:
        Dictionary with encryption result
    
    Raises:
        FileNotFoundError: If file does not exist
        PasswordValidationError: If password is invalid
    """
```

### Docstrings

Use Google-style docstrings on all public methods:

```python
def verify_password(self, password: str, hash: str) -> bool:
    """Verify password against hash using constant-time comparison.
    
    Args:
        password: Plain text password to verify
        hash: Hash from hash_password() to verify against
    
    Returns:
        True if password matches hash, False otherwise
    
    Raises:
        ValueError: If password or hash is invalid
    """
```

## Testing Requirements

### Minimum Coverage

- Overall: 70%+
- Critical paths: 90%+
- New code: 80%+

### Test File Structure

```python
import pytest
from src.auth.password_hasher import PasswordHasher

class TestPasswordHasher:
    """Test suite for PasswordHasher."""
    
    @pytest.fixture
    def hasher(self):
        """Initialize hasher."""
        return PasswordHasher()
    
    def test_hash_password(self, hasher):
        """Test password hashing produces valid hash."""
        hash = hasher.hash_password("TestPassword123!")
        assert hash is not None
        assert len(hash) > 0
        assert "$argon2id" in hash
    
    def test_verify_password(self, hasher):
        """Test password verification works."""
        password = "TestPassword123!"
        hash = hasher.hash_password(password)
        assert hasher.verify_password(password, hash) is True
    
    def test_wrong_password_fails(self, hasher):
        """Test wrong password fails verification."""
        hash = hasher.hash_password("CorrectPassword")
        assert hasher.verify_password("WrongPassword", hash) is False
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test class
pytest tests/unit/auth/test_password_hasher.py::TestPasswordHasher -v

# Run with markers
pytest -m "security" tests/
```

## Security Contributions

If you're adding security features:

1. **Document the threat model** - Explain what you're protecting against
2. **Provide proof of concept** - Show how the feature prevents attacks
3. **Include security tests** - Test attack scenarios, not just happy path
4. **Review NIST standards** - Ensure compliance with cryptographic standards
5. **Get security review** - Request review from security team

### Security Checklist

- [ ] Uses NIST-approved algorithms only
- [ ] Implements proper key sizes (256-bit minimum)
- [ ] Uses constant-time comparisons for sensitive data
- [ ] Never logs secrets (passwords, tokens, keys)
- [ ] Includes comprehensive error handling
- [ ] Has security-focused tests
- [ ] Documented threat model
- [ ] Peer reviewed by security expert

## Documentation

### When to Update Docs

- **Always**: When adding/changing public API
- **Always**: When changing security properties
- **Always**: When adding new module or feature
- **When relevant**: Code style, algorithms, architecture changes

### Documentation Format

```markdown
# Feature Name

## Overview
High-level description of feature.

## Use Cases
When and why to use this feature.

## API Reference
Complete API documentation with examples.

## Security Considerations
Threat model, mitigations, limitations.

## Performance
Benchmarks, optimization tips.

## Examples
Copy-paste ready code examples.
```

## Review Process

### What to Expect

1. **Automated Checks** (GitHub Actions)
   - Tests pass
   - Coverage >= 70%
   - Code quality checks pass

2. **Code Review** (1-2 reviewers)
   - Security review
   - Code style check
   - Documentation review

3. **Approval** (Maintainer)
   - Final verification
   - Merge to main

### Addressing Review Comments

```bash
# Make requested changes
# Commit with fixup message
git commit --amend

# Force push to PR branch
git push origin feature/name -f

# Don't create new commits for review feedback
# Instead, amend your existing commits
```

## Release Process

Releases follow Semantic Versioning: MAJOR.MINOR.PATCH

- **MAJOR**: Breaking API changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

## Getting Help

- **Questions**: Create discussion on GitHub
- **Issues**: Create issue with reproduction steps
- **Security**: Email security@cryptovault.dev

## Recognition

Contributors will be recognized:

- Mentioned in CHANGELOG.md
- Listed in README.md (with permission)
- Credited in release notes
- Listed on project website

## License

By contributing, you agree that your contributions are licensed under the MIT License.

---

Thank you for making CryptoVault more secure! 🔐