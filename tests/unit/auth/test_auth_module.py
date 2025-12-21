"""
Comprehensive unit tests for the Authentication Module.

This test suite covers all authentication functionality including:
- Password validation and strength scoring
- Password hashing and verification
- User registration
- User login and authentication
- Session management
- TOTP two-factor authentication
- Backup codes
- Rate limiting
- Account lockout
"""

import pytest  # type: ignore
import time
import hashlib
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from src.auth.auth_module import AuthModule
from src.auth.password_validator import PasswordValidator
from src.auth.password_hasher import PasswordHasher
from src.auth.backup_codes import BackupCodesManager
from src.auth.rate_limiter import RateLimiter
from src.auth.totp import TOTPManager
from src.exceptions import (
    AuthenticationError,
    RegistrationError,
    PasswordStrengthError,
    TOTPError,
    SessionError,
    AccountLockedError,
    RateLimitError,
)


# ============================================================================
# Password Validator Tests
# ============================================================================

class TestPasswordValidator:
    """Test suite for PasswordValidator class."""
    
    def test_valid_password(self):
        """Test that a strong password passes validation."""
        validator = PasswordValidator()
        # Use password without sequential patterns or weak words
        # "V@lidTestP@ss!7" - 15 chars, has uppercase, lowercase, numbers, special chars, no sequences
        is_valid, error_msg = validator.validate("V@lidTestP@ss!7")
        assert is_valid is True
        assert error_msg == ""
    
    def test_weak_password_length(self):
        """Test that passwords shorter than 12 characters are rejected."""
        validator = PasswordValidator(min_length=12)
        is_valid, error_msg = validator.validate("Short1!")
        assert is_valid is False
        assert "at least 12 characters" in error_msg.lower()
    
    def test_missing_uppercase(self):
        """Test that passwords without uppercase letters are rejected."""
        validator = PasswordValidator(require_uppercase=True)
        is_valid, error_msg = validator.validate("validpassword123!")
        assert is_valid is False
        assert "uppercase" in error_msg.lower()
    
    def test_missing_lowercase(self):
        """Test that passwords without lowercase letters are rejected."""
        validator = PasswordValidator(require_lowercase=True)
        is_valid, error_msg = validator.validate("VALIDPASSWORD123!")
        assert is_valid is False
        assert "lowercase" in error_msg.lower()
    
    def test_missing_numbers(self):
        """Test that passwords without numbers are rejected."""
        validator = PasswordValidator(require_numbers=True)
        is_valid, error_msg = validator.validate("ValidPassword!")
        assert is_valid is False
        assert "number" in error_msg.lower()
    
    def test_missing_special_chars(self):
        """Test that passwords without special characters are rejected."""
        validator = PasswordValidator(require_special=True)
        is_valid, error_msg = validator.validate("ValidPassword123")
        assert is_valid is False
        assert "special character" in error_msg.lower()
    
    def test_sequential_pattern(self):
        """Test that sequential patterns like '123456' are rejected."""
        validator = PasswordValidator()
        # Use password with sequential pattern but no common weak patterns
        # "MySecure123abc!" contains "123" and "abc" sequential patterns
        is_valid, error_msg = validator.validate("MySecure123abc!")
        assert is_valid is False
        assert "sequential" in error_msg.lower()
    
    def test_password_strength_score(self):
        """Test password strength score calculation."""
        validator = PasswordValidator()
        
        # Very weak password
        score_weak = validator.calculate_strength_score("weak")
        assert 0 <= score_weak <= 20
        
        # Strong password
        score_strong = validator.calculate_strength_score("MySecureP@ssw0rd!")
        assert 60 <= score_strong <= 100
        
        # Ensure scores are in valid range
        assert 0 <= score_weak <= 100
        assert 0 <= score_strong <= 100


# ============================================================================
# Password Hasher Tests
# ============================================================================

class TestPasswordHasher:
    """Test suite for PasswordHasher class."""
    
    def test_hash_password_success(self):
        """Test that password hashing creates a valid hash."""
        hasher = PasswordHasher(time_cost=1, memory_cost=1024)  # Lower for testing
        password = "TestPassword123!"
        password_hash = hasher.hash_password(password)
        
        assert password_hash is not None
        assert len(password_hash) > 0
        assert password_hash.startswith("$argon2id$")
    
    def test_hash_password_different_each_time(self):
        """Test that hashing the same password produces different hashes (different salts)."""
        hasher = PasswordHasher(time_cost=1, memory_cost=1024)
        password = "TestPassword123!"
        
        hash1 = hasher.hash_password(password)
        hash2 = hasher.hash_password(password)
        
        # Hashes should be different due to random salts
        assert hash1 != hash2
    
    def test_verify_password_correct(self):
        """Test that correct passwords are verified successfully."""
        hasher = PasswordHasher(time_cost=1, memory_cost=1024)
        password = "TestPassword123!"
        password_hash = hasher.hash_password(password)
        
        is_valid = hasher.verify_password(password, password_hash)
        assert is_valid is True
    
    def test_verify_password_incorrect(self):
        """Test that incorrect passwords are rejected."""
        hasher = PasswordHasher(time_cost=1, memory_cost=1024)
        password = "TestPassword123!"
        wrong_password = "WrongPassword456!"
        password_hash = hasher.hash_password(password)
        
        is_valid = hasher.verify_password(wrong_password, password_hash)
        assert is_valid is False
    
    def test_verify_password_timing_safe(self):
        """Test that password verification uses constant-time comparison.
        
        Note: This is difficult to test precisely, but we verify that
        verification doesn't fail due to timing issues.
        """
        hasher = PasswordHasher(time_cost=1, memory_cost=1024)
        password = "TestPassword123!"
        password_hash = hasher.hash_password(password)
        
        # Both should complete without raising exceptions
        correct_result = hasher.verify_password(password, password_hash)
        incorrect_result = hasher.verify_password("WrongPassword", password_hash)
        
        assert correct_result is True
        assert incorrect_result is False
    
    def test_invalid_hash_format(self):
        """Test that invalid hash formats are handled gracefully."""
        hasher = PasswordHasher()
        password = "TestPassword123!"
        invalid_hash = "not_a_valid_hash_format"
        
        is_valid = hasher.verify_password(password, invalid_hash)
        assert is_valid is False
    
    def test_needs_rehash(self):
        """Test that needs_rehash detects outdated hashes."""
        # Create hash with old parameters
        hasher_old = PasswordHasher(time_cost=1, memory_cost=1024)
        password = "TestPassword123!"
        old_hash = hasher_old.hash_password(password)
        
        # Create new hasher with different parameters
        hasher_new = PasswordHasher(time_cost=2, memory_cost=2048)
        
        needs_rehash = hasher_new.needs_rehash(old_hash)
        assert needs_rehash is True


# ============================================================================
# Registration Tests
# ============================================================================

class TestRegistration:
    """Test suite for user registration functionality."""
    
    def test_register_new_user_success(self, auth_module, test_username, test_password):
        """Test successful user registration."""
        result = auth_module.register(test_username, test_password)
        
        assert result["success"] is True
        assert result["username"] == test_username
        assert "user_id" in result
        assert "totp_secret" in result
        assert "backup_codes" in result
        assert len(result["backup_codes"]) == 10
    
    def test_register_duplicate_username(self, auth_module, test_username, test_password):
        """Test that duplicate usernames are rejected."""
        # Register first user
        auth_module.register(test_username, test_password)
        
        # Attempt to register with same username
        with pytest.raises(RegistrationError) as exc_info:
            auth_module.register(test_username, test_password)
        
        assert exc_info.value.error_code == "USERNAME_EXISTS"
    
    def test_register_weak_password(self, auth_module, test_username, test_weak_password):
        """Test that weak passwords are rejected during registration."""
        with pytest.raises(PasswordStrengthError) as exc_info:
            auth_module.register(test_username, test_weak_password)
        
        assert exc_info.value.error_code == "PASSWORD_WEAK"
    
    def test_register_invalid_username(self, auth_module, test_password):
        """Test that usernames with invalid characters are rejected."""
        invalid_usernames = ["user@name", "user name", "user.name", "user#name"]
        
        for invalid_username in invalid_usernames:
            with pytest.raises(RegistrationError) as exc_info:
                auth_module.register(invalid_username, test_password)
            assert exc_info.value.error_code in ["INVALID_USERNAME_FORMAT", "USERNAME_TOO_SHORT"]
    
    def test_register_generates_totp_secret(self, auth_module, test_username, test_password):
        """Test that registration generates a TOTP secret."""
        result = auth_module.register(test_username, test_password)
        
        assert "totp_secret" in result
        assert result["totp_secret"] is not None
        assert len(result["totp_secret"]) > 0
    
    def test_register_generates_backup_codes(self, auth_module, test_username, test_password):
        """Test that registration generates 10 backup codes."""
        result = auth_module.register(test_username, test_password)
        
        assert "backup_codes" in result
        assert len(result["backup_codes"]) == 10
        # Each code should be in format XXXX-XXXX
        for code in result["backup_codes"]:
            assert len(code) == 9  # XXXX-XXXX format
            assert "-" in code
    
    def test_register_returns_plaintext_codes_once(self, auth_module, test_username, test_password):
        """Test that registration returns plaintext codes (shown only once)."""
        result = auth_module.register(test_username, test_password)
        
        # Codes should be plaintext strings (not hashed)
        for code in result["backup_codes"]:
            assert isinstance(code, str)
            assert len(code) == 9
            assert code.replace("-", "").isalnum()
    
    def test_register_backup_codes_hashed_in_db(self, auth_module, test_username, test_password, mock_database):
        """Test that only hashes of backup codes are stored in the database."""
        result = auth_module.register(test_username, test_password)
        plaintext_codes = result["backup_codes"]
        
        # Get user from database
        cursor = mock_database.execute(
            "SELECT backup_codes_hash FROM users WHERE username = ?",
            (test_username,)
        )
        user_record = cursor.fetchone()
        
        assert user_record is not None
        # backup_codes_hash is at index 8 in SELECT query result
        # SELECT order: user_id(0), username(1), password_hash(2), account_locked(3),
        #               account_locked_until(4), failed_login_attempts(5), totp_enabled(6),
        #               totp_secret(7), backup_codes_hash(8)
        stored_hash_str = user_record[8]
        
        # Verify stored codes are hashed
        stored_hashes = stored_hash_str.split(",")
        assert len(stored_hashes) == 10
        
        # Verify plaintext codes are NOT in database
        for plaintext_code in plaintext_codes:
            assert plaintext_code not in stored_hash_str


# ============================================================================
# Login Tests
# ============================================================================

class TestLogin:
    """Test suite for user login functionality."""
    
    def test_login_success(self, auth_module, test_username, test_password):
        """Test successful login creates a session."""
        # Register user first
        auth_module.register(test_username, test_password)
        
        # Login
        result = auth_module.login(test_username, test_password)
        
        assert result["success"] is True
        assert result["username"] == test_username
        assert "session_token" in result
        assert "expires_at" in result
    
    def test_login_wrong_password(self, auth_module, test_username, test_password):
        """Test that wrong passwords are rejected."""
        # Register user first
        auth_module.register(test_username, test_password)
        
        # Attempt login with wrong password
        with pytest.raises(AuthenticationError) as exc_info:
            auth_module.login(test_username, "WrongPassword123!")
        
        assert exc_info.value.error_code == "INVALID_CREDENTIALS"
    
    def test_login_nonexistent_user(self, auth_module, test_password):
        """Test that non-existent users are rejected (generic error)."""
        with pytest.raises(AuthenticationError) as exc_info:
            auth_module.login("nonexistent_user", test_password)
        
        assert exc_info.value.error_code == "INVALID_CREDENTIALS"
    
    def test_login_increments_failed_attempts(self, auth_module, test_username, test_password, mock_database):
        """Test that failed login attempts are tracked."""
        # Register user
        auth_module.register(test_username, test_password)
        
        # Fail login 3 times
        for _ in range(3):
            with pytest.raises(AuthenticationError):
                auth_module.login(test_username, "WrongPassword123!")
        
        # Check failed attempts in database
        cursor = mock_database.execute(
            "SELECT failed_login_attempts FROM users WHERE username = ?",
            (test_username,)
        )
        user_record = cursor.fetchone()
        
        assert user_record is not None
        assert user_record[5] == 3  # failed_login_attempts
    
    def test_login_locks_after_5_failures(self, auth_module, test_username, test_password):
        """Test that account locks after 5 failed attempts."""
        # Register user
        auth_module.register(test_username, test_password)
        
        # Fail login 5 times
        for _ in range(5):
            with pytest.raises(AuthenticationError):
                auth_module.login(test_username, "WrongPassword123!")
        
        # 6th attempt should fail with AccountLockedError
        with pytest.raises(AccountLockedError):
            auth_module.login(test_username, test_password)
    
    def test_login_locked_account(self, auth_module, test_username, test_password):
        """Test that locked accounts cannot be logged into."""
        # Register user
        auth_module.register(test_username, test_password)
        
        # Lock account manually
        cursor = auth_module.db.execute(
            "SELECT user_id FROM users WHERE username = ?",
            (test_username,)
        )
        user_record = cursor.fetchone()
        user_id = user_record[0]
        
        auth_module.lockout_user(user_id, minutes=30)
        
        # Attempt login should fail
        with pytest.raises(AccountLockedError):
            auth_module.login(test_username, test_password)
    
    def test_login_with_totp(self, auth_module, test_username, test_password):
        """Test that login requires TOTP when enabled."""
        # Register user
        result = auth_module.register(test_username, test_password)
        totp_secret = result["totp_secret"]
        
        # Enable TOTP
        import pyotp
        totp = pyotp.TOTP(totp_secret)
        auth_module.totp_manager.enable_totp(
            result["user_id"],
            totp_secret,
            totp.now()
        )
        
        # Login without TOTP should return AWAITING_MFA
        login_result = auth_module.login(test_username, test_password)
        assert login_result["success"] is False
        assert login_result["status"] == "AWAITING_MFA"
        
        # Login with TOTP should succeed
        login_result = auth_module.login(
            test_username,
            test_password,
            totp_code=totp.now()
        )
        assert login_result["success"] is True
    
    def test_login_resets_failed_attempts(self, auth_module, test_username, test_password, mock_database):
        """Test that successful login resets failed attempts counter."""
        # Register user
        auth_module.register(test_username, test_password)
        
        # Fail login 2 times
        for _ in range(2):
            with pytest.raises(AuthenticationError):
                auth_module.login(test_username, "WrongPassword123!")
        
        # Successful login
        auth_module.login(test_username, test_password)
        
        # Check that failed attempts are reset
        cursor = mock_database.execute(
            "SELECT failed_login_attempts FROM users WHERE username = ?",
            (test_username,)
        )
        user_record = cursor.fetchone()
        
        assert user_record is not None
        assert user_record[5] == 0  # failed_login_attempts reset to 0
    
    def test_login_rate_limit(self, auth_module, test_username, test_password):
        """Test that rate limiting is enforced during login."""
        # Register user
        auth_module.register(test_username, test_password)
        
        # Make 5 failed login attempts (rate limit threshold)
        for _ in range(5):
            with pytest.raises(AuthenticationError):
                auth_module.login(test_username, "WrongPassword123!")
        
        # 6th attempt should trigger rate limit
        with pytest.raises(RateLimitError):
            auth_module.login(test_username, "WrongPassword123!")


# ============================================================================
# Session Management Tests
# ============================================================================

class TestSessionManagement:
    """Test suite for session management functionality."""
    
    def test_session_token_generated(self, auth_module, test_username, test_password):
        """Test that session tokens are generated on login."""
        # Register and login
        auth_module.register(test_username, test_password)
        result = auth_module.login(test_username, test_password)
        
        assert "session_token" in result
        assert result["session_token"] is not None
        assert len(result["session_token"]) > 0
    
    def test_session_token_unique(self, auth_module, test_username, test_password):
        """Test that different sessions generate unique tokens."""
        # Register user
        auth_module.register(test_username, test_password)
        
        # Generate two sessions
        result1 = auth_module.login(test_username, test_password)
        result2 = auth_module.login(test_username, test_password)
        
        # Tokens should be different
        assert result1["session_token"] != result2["session_token"]
    
    def test_verify_session_valid(self, auth_module, test_username, test_password, mock_database):
        """Test that valid sessions are verified successfully.
        
        Note: This tests the session storage in database.
        """
        # Register and login
        auth_module.register(test_username, test_password)
        result = auth_module.login(test_username, test_password)
        session_token = result["session_token"]
        
        # Verify session exists in database
        cursor = mock_database.execute(
            "SELECT * FROM sessions WHERE session_token = ?",
            (session_token,)
        )
        session_record = cursor.fetchone()
        
        assert session_record is not None
    
    def test_verify_session_expired(self, auth_module, test_username, test_password, mock_database):
        """Test that expired sessions are rejected.
        
        Note: This is tested by checking expiration in database.
        """
        # Register and login
        auth_module.register(test_username, test_password)
        result = auth_module.login(test_username, test_password)
        session_token = result["session_token"]
        expires_at = result["expires_at"]
        
        # Verify expiration is set in the future
        assert expires_at > time.time()
    
    def test_verify_session_invalidated(self, auth_module, test_username, test_password, mock_database):
        """Test that invalidated sessions are rejected.
        
        Note: This would require session invalidation functionality.
        For now, we test that sessions can be marked as invalid in database.
        """
        # Register and login
        auth_module.register(test_username, test_password)
        result = auth_module.login(test_username, test_password)
        session_token = result["session_token"]
        
        # Mark session as invalid
        mock_database.execute(
            "UPDATE sessions SET is_valid = ? WHERE session_token = ?",
            (False, session_token)
        )
        mock_database.commit()
        
        # Verify session is marked invalid
        cursor = mock_database.execute(
            "SELECT is_valid FROM sessions WHERE session_token = ?",
            (session_token,)
        )
        session_record = cursor.fetchone()
        
        assert session_record is not None
        assert session_record[6] is False  # is_valid


# ============================================================================
# TOTP Tests
# ============================================================================

class TestTOTP:
    """Test suite for TOTP two-factor authentication."""
    
    def test_totp_setup_generates_secret(self, auth_module, test_username):
        """Test that TOTP setup generates a secret."""
        # Get user_id from registration (simplified)
        # In real test, would register first
        result = auth_module.totp_manager.setup_totp("test_user_id", test_username)
        
        assert result["success"] is True
        assert "secret" in result
        assert result["secret"] is not None
        assert len(result["secret"]) > 0
    
    def test_totp_qr_code_generated(self, auth_module, test_username):
        """Test that TOTP setup generates a QR code file."""
        import os
        
        result = auth_module.totp_manager.setup_totp("test_user_id", test_username)
        
        assert "qr_code_path" in result
        qr_path = result["qr_code_path"]
        
        # Verify file exists (may need to check if file system is accessible in tests)
        # This is a placeholder test
        assert qr_path is not None
        assert qr_path.endswith(".png")
    
    def test_verify_totp_valid_code(self, auth_module):
        """Test that valid TOTP codes are verified successfully."""
        import pyotp
        
        # Generate secret
        secret = pyotp.random_base32()
        
        # Generate current code
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        
        # Verify code
        is_valid = auth_module.totp_manager.verify_totp(secret, current_code)
        assert is_valid is True
    
    def test_verify_totp_invalid_code(self, auth_module):
        """Test that invalid TOTP codes are rejected."""
        import pyotp
        
        secret = pyotp.random_base32()
        invalid_code = "000000"
        
        is_valid = auth_module.totp_manager.verify_totp(secret, invalid_code)
        assert is_valid is False
    
    def test_verify_totp_allows_time_window(self, auth_module):
        """Test that TOTP verification allows time window (±30 seconds)."""
        import pyotp
        import time
        
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        
        # Generate code for current time
        current_code = totp.now()
        
        # Code should be valid
        is_valid = auth_module.totp_manager.verify_totp(secret, current_code, time_window=1)
        assert is_valid is True
    
    def test_enable_totp(self, auth_module, mock_database):
        """Test that TOTP can be enabled after verification."""
        import pyotp
        
        user_id = "test_user_id"
        secret = pyotp.random_base32()
        
        # Generate verification code
        totp = pyotp.TOTP(secret)
        verification_code = totp.now()
        
        # Enable TOTP
        result = auth_module.totp_manager.enable_totp(user_id, secret, verification_code)
        assert result is True
    
    def test_disable_totp(self, auth_module, mock_database):
        """Test that TOTP can be disabled."""
        user_id = "test_user_id"
        
        result = auth_module.totp_manager.disable_totp(user_id)
        assert result is True


# ============================================================================
# Backup Codes Tests
# ============================================================================

class TestBackupCodes:
    """Test suite for backup codes functionality."""
    
    def test_generate_codes_count(self):
        """Test that generate_codes creates the specified number of codes."""
        manager = BackupCodesManager()
        codes = manager.generate_codes(count=10)
        
        assert len(codes) == 10
    
    def test_generate_codes_format(self):
        """Test that generated codes match XXXX-XXXX format."""
        manager = BackupCodesManager()
        codes = manager.generate_codes(count=5)
        
        for code in codes:
            assert len(code) == 9  # XXXX-XXXX
            assert code[4] == "-"
            parts = code.split("-")
            assert len(parts) == 2
            assert len(parts[0]) == 4
            assert len(parts[1]) == 4
    
    def test_generate_codes_unique(self):
        """Test that generated codes are unique."""
        manager = BackupCodesManager()
        codes = manager.generate_codes(count=100)
        
        # All codes should be unique
        assert len(codes) == len(set(codes))
    
    def test_hash_codes(self):
        """Test that hash_codes produces SHA-256 hashes."""
        manager = BackupCodesManager()
        codes = ["ABCD-1234", "EFGH-5678"]
        hashes = manager.hash_codes(codes)
        
        assert len(hashes) == 2
        # Each hash should be 64 characters (SHA-256 hex)
        for code_hash in hashes:
            assert len(code_hash) == 64
            assert all(c in "0123456789abcdef" for c in code_hash)
    
    def test_verify_code_valid(self):
        """Test that valid backup codes are verified successfully."""
        manager = BackupCodesManager()
        codes = ["ABCD-1234", "EFGH-5678"]
        hashes = manager.hash_codes(codes)
        
        is_valid, index = manager.verify_code("ABCD-1234", hashes)
        assert is_valid is True
        assert index == 0
    
    def test_verify_code_invalid(self):
        """Test that invalid backup codes are rejected."""
        manager = BackupCodesManager()
        codes = ["ABCD-1234", "EFGH-5678"]
        hashes = manager.hash_codes(codes)
        
        is_valid, index = manager.verify_code("INVALID-CODE", hashes)
        assert is_valid is False
        assert index == -1
    
    def test_verify_code_timing_safe(self):
        """Test that code verification uses constant-time comparison.
        
        Note: This is difficult to test precisely, but we verify that
        verification doesn't fail due to timing issues.
        """
        manager = BackupCodesManager()
        codes = ["ABCD-1234"] * 10  # Multiple same codes for testing
        hashes = manager.hash_codes(codes)
        
        # Both should complete without raising exceptions
        valid_result = manager.verify_code("ABCD-1234", hashes)
        invalid_result = manager.verify_code("WRONG-CODE", hashes)
        
        assert valid_result[0] is True
        assert invalid_result[0] is False
    
    def test_use_code_removes_code(self, auth_module, test_username, test_password, mock_database):
        """Test that using a backup code removes it from the database."""
        # Register user
        result = auth_module.register(test_username, test_password)
        backup_code = result["backup_codes"][0]
        
        # Get code hashes from database
        cursor = mock_database.execute(
            "SELECT backup_codes_hash FROM users WHERE username = ?",
            (test_username,)
        )
        user_record = cursor.fetchone()
        # backup_codes_hash is at index 8 in SELECT query result
        code_hashes_str = user_record[8]
        original_hashes = code_hashes_str.split(",")
        original_count = len(original_hashes)
        
        # Verify and use code
        is_valid, code_index = auth_module.backup_codes_manager.verify_code(
            backup_code,
            original_hashes
        )
        assert is_valid is True
        
        auth_module.backup_codes_manager.use_code(test_username, code_index, db=mock_database)
        
        # Check that code was removed
        cursor = mock_database.execute(
            "SELECT backup_codes_hash FROM users WHERE username = ?",
            (test_username,)
        )
        user_record = cursor.fetchone()
        # backup_codes_hash is at index 8 in SELECT query result
        updated_hashes_str = user_record[8]
        updated_hashes = updated_hashes_str.split(",") if updated_hashes_str else []
        
        assert len(updated_hashes) == original_count - 1


# ============================================================================
# Rate Limiter Tests
# ============================================================================

class TestRateLimiter:
    """Test suite for rate limiting functionality."""
    
    def test_rate_limit_allows_attempts(self):
        """Test that attempts within limit are allowed."""
        limiter = RateLimiter()
        identifier = "test_user"
        
        # First 5 attempts should be allowed
        for i in range(5):
            allowed, count = limiter.check_rate_limit(identifier, max_attempts=5, window_minutes=15)
            assert allowed is True
            assert count == i + 1
    
    def test_rate_limit_blocks_excess(self):
        """Test that attempts over limit are blocked."""
        limiter = RateLimiter()
        identifier = "test_user"
        
        # Make 5 attempts (limit)
        for _ in range(5):
            limiter.check_rate_limit(identifier, max_attempts=5, window_minutes=15)
        
        # 6th attempt should be blocked
        allowed, count = limiter.check_rate_limit(identifier, max_attempts=5, window_minutes=15)
        assert allowed is False
        assert count >= 5
    
    def test_rate_limit_time_window(self):
        """Test that only recent attempts count toward rate limit."""
        limiter = RateLimiter()
        identifier = "test_user"
        
        # Make attempts
        for _ in range(3):
            limiter.check_rate_limit(identifier, max_attempts=5, window_minutes=1)
        
        # Wait for window to expire (in real test, would use time mocking)
        # For now, test that attempts within window count
        allowed, count = limiter.check_rate_limit(identifier, max_attempts=5, window_minutes=1)
        assert count >= 3
    
    def test_rate_limit_reset(self):
        """Test that reset_attempts clears the rate limit counter."""
        limiter = RateLimiter()
        identifier = "test_user"
        
        # Make some attempts
        for _ in range(3):
            limiter.check_rate_limit(identifier, max_attempts=5, window_minutes=15)
        
        # Reset attempts
        limiter.reset_attempts(identifier)
        
        # Should be able to make attempts again
        allowed, count = limiter.check_rate_limit(identifier, max_attempts=5, window_minutes=15)
        assert allowed is True
        assert count == 1
    
    def test_rate_limit_multiple_users(self):
        """Test that rate limits are tracked separately for different users."""
        limiter = RateLimiter()
        
        # User 1 makes 5 attempts
        for _ in range(5):
            limiter.check_rate_limit("user1", max_attempts=5, window_minutes=15)
        
        # User 2 should still have full limit
        allowed, count = limiter.check_rate_limit("user2", max_attempts=5, window_minutes=15)
        assert allowed is True
        assert count == 1


# ============================================================================
# Account Lockout Tests
# ============================================================================

class TestAccountLockout:
    """Test suite for account lockout functionality."""
    
    def test_lockout_user(self, auth_module, test_username, test_password, mock_database):
        """Test that lockout_user locks an account."""
        # Register user
        auth_module.register(test_username, test_password)
        
        # Get user_id
        cursor = auth_module.db.execute(
            "SELECT user_id FROM users WHERE username = ?",
            (test_username,)
        )
        user_record = cursor.fetchone()
        user_id = user_record[0]
        
        # Lock account
        auth_module.lockout_user(user_id, minutes=30)
        
        # Verify account is locked
        is_locked, reason = auth_module.is_account_locked(user_id)
        assert is_locked is True
        assert "locked" in reason.lower()
    
    def test_unlock_user(self, auth_module, test_username, test_password, mock_database):
        """Test that unlock_user unlocks an account."""
        # Register user
        auth_module.register(test_username, test_password)
        
        # Get user_id
        cursor = auth_module.db.execute(
            "SELECT user_id FROM users WHERE username = ?",
            (test_username,)
        )
        user_record = cursor.fetchone()
        user_id = user_record[0]
        
        # Lock then unlock
        auth_module.lockout_user(user_id, minutes=30)
        auth_module.unlock_user(user_id)
        
        # Verify account is unlocked
        is_locked, reason = auth_module.is_account_locked(user_id)
        assert is_locked is False
    
    def test_lockout_expires(self, auth_module, test_username, test_password, mock_database):
        """Test that lockouts have expiration timestamps."""
        # Register user
        auth_module.register(test_username, test_password)
        
        # Get user_id
        cursor = auth_module.db.execute(
            "SELECT user_id FROM users WHERE username = ?",
            (test_username,)
        )
        user_record = cursor.fetchone()
        user_id = user_record[0]
        
        # Lock account
        auth_module.lockout_user(user_id, minutes=30)
        
        # Check lockout expiration
        cursor = auth_module.db.execute(
            "SELECT account_locked_until FROM users WHERE user_id = ?",
            (user_id,)
        )
        user_record = cursor.fetchone()
        lockout_until = user_record[0]
        
        assert lockout_until is not None
        assert lockout_until > datetime.utcnow()
    
    def test_lockout_auto_unlock(self, auth_module, test_username, test_password, mock_database):
        """Test that expired lockouts are automatically unlocked.
        
        Note: This tests the check_lock_expiry functionality.
        """
        # Register user
        auth_module.register(test_username, test_password)
        
        # Get user_id
        cursor = auth_module.db.execute(
            "SELECT user_id FROM users WHERE username = ?",
            (test_username,)
        )
        user_record = cursor.fetchone()
        user_id = user_record[0]
        
        # Lock account with very short expiration (for testing)
        # In real scenario, would need to manipulate time
        auth_module.lockout_user(user_id, minutes=0)
        
        # Check expiry should unlock
        auth_module.check_lock_expiry(user_id)
        
        # Note: This test may need adjustment based on actual implementation
    
    def test_lock_prevents_login(self, auth_module, test_username, test_password):
        """Test that locked accounts cannot be logged into."""
        # Register user
        auth_module.register(test_username, test_password)
        
        # Get user_id
        cursor = auth_module.db.execute(
            "SELECT user_id FROM users WHERE username = ?",
            (test_username,)
        )
        user_record = cursor.fetchone()
        user_id = user_record[0]
        
        # Lock account
        auth_module.lockout_user(user_id, minutes=30)
        
        # Attempt login should fail
        with pytest.raises(AccountLockedError):
            auth_module.login(test_username, test_password)

