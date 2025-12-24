"""
Custom exceptions for CryptoVault authentication and security operations.

This module defines all custom exception classes used throughout the
CryptoVault application for handling authentication, registration, password
validation, TOTP verification, session management, and account security.
"""


class AuthenticationError(Exception):
    """
    Base exception for authentication-related errors.
    
    Raised when authentication operations fail, such as invalid credentials,
    expired tokens, or authentication system failures.
    
    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
    """

    def __init__(self, message: str, error_code: str | None = None) -> None:
        """
        Initialize AuthenticationError.
        
        Args:
            message: Error message describing what went wrong
            error_code: Optional error code for error categorization
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class RegistrationError(AuthenticationError):
    """
    Exception raised during user registration failures.
    
    Raised when user registration cannot be completed due to validation
    errors, duplicate usernames, or system constraints.
    
    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
        field: Optional field name that caused the error
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            field: str | None = None
    ) -> None:
        """
        Initialize RegistrationError.
        
        Args:
            message: Error message describing the registration failure
            error_code: Optional error code for error categorization
            field: Optional field name that caused the error
        """
        super().__init__(message, error_code)
        self.field = field


class PasswordStrengthError(AuthenticationError):
    """
    Exception raised when password does not meet strength requirements.
    
    Raised during password validation when a password fails to meet
    minimum security requirements such as length, character variety,
    or pattern restrictions.
    
    Attributes:
        message: Human-readable error message describing the failure
        error_code: Optional error code for error categorization
        failed_checks: List of validation checks that failed
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            failed_checks: list[str] | None = None
    ) -> None:
        """
        Initialize PasswordStrengthError.
        
        Args:
            message: Error message describing the password strength issue
            error_code: Optional error code for error categorization
            failed_checks: List of validation checks that failed
        """
        super().__init__(message, error_code)
        self.failed_checks = failed_checks or []


class TOTPError(AuthenticationError):
    """
    Exception raised during TOTP (Time-Based One-Time Password) operations.
    
    Raised when TOTP code generation, verification, or setup fails.
    This includes invalid codes, expired codes, or TOTP configuration errors.
    
    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
        remaining_attempts: Optional number of remaining verification attempts
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            remaining_attempts: int | None = None
    ) -> None:
        """
        Initialize TOTPError.
        
        Args:
            message: Error message describing the TOTP failure
            error_code: Optional error code for error categorization
            remaining_attempts: Optional number of remaining attempts
        """
        super().__init__(message, error_code)
        self.remaining_attempts = remaining_attempts


class SessionError(AuthenticationError):
    """
    Exception raised during session management operations.
    
    Raised when session token generation, validation, or management fails.
    This includes invalid tokens, expired sessions, or session system errors.
    
    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
        session_id: Optional session identifier related to the error
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            session_id: str | None = None
    ) -> None:
        """
        Initialize SessionError.
        
        Args:
            message: Error message describing the session error
            error_code: Optional error code for error categorization
            session_id: Optional session identifier related to the error
        """
        super().__init__(message, error_code)
        self.session_id = session_id


class AccountLockedError(AuthenticationError):
    """
    Exception raised when attempting to access a locked account.
    
    Raised when authentication is attempted on an account that has been
    locked due to security reasons, such as too many failed login attempts
    or administrative action.
    
    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
        lockout_until: Optional timestamp when the account will be unlocked
        reason: Optional reason for the account lockout
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            lockout_until: float | None = None,
            reason: str | None = None
    ) -> None:
        """
        Initialize AccountLockedError.
        
        Args:
            message: Error message describing the account lockout
            error_code: Optional error code for error categorization
            lockout_until: Optional timestamp when account will be unlocked
            reason: Optional reason for the account lockout
        """
        super().__init__(message, error_code)
        self.lockout_until = lockout_until
        self.reason = reason


class RateLimitError(AuthenticationError):
    """
    Exception raised when rate limiting is triggered.
    
    Raised when too many requests are made within a time window, indicating
    potential abuse or brute-force attacks. Used to protect authentication
    endpoints and sensitive operations.
    
    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
        retry_after: Optional seconds to wait before retrying
        limit: Optional rate limit that was exceeded
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            retry_after: float | None = None,
            limit: int | None = None
    ) -> None:
        """
        Initialize RateLimitError.
        
        Args:
            message: Error message describing the rate limit violation
            error_code: Optional error code for error categorization
            retry_after: Optional seconds to wait before retrying
            limit: Optional rate limit that was exceeded
        """
        super().__init__(message, error_code)
        self.retry_after = retry_after
        self.limit = limit


class PasswordResetError(AuthenticationError):
    """
    Exception raised during password reset operations.
    
    Raised when password reset operations fail, such as invalid or expired
    reset tokens, or when reset token verification fails.
    
    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
        token_id: Optional reset token identifier related to the error
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            token_id: str | None = None
    ) -> None:
        """
        Initialize PasswordResetError.
        
        Args:
            message: Error message describing the password reset failure
            error_code: Optional error code for error categorization
            token_id: Optional reset token identifier related to the error
        """
        super().__init__(message, error_code)
        self.token_id = token_id


"""
Blockchain module exceptions for CryptoVault.
Provides custom exception classes for blockchain operations and validation.
"""


class BlockchainError(Exception):
    """Base exception for blockchain-related errors."""
    pass


class BlockValidationError(BlockchainError):
    """Raised when block validation fails."""
    pass


class MerkleTreeError(BlockchainError):
    """Raised when Merkle tree operations fail."""
    pass


class ProofOfWorkError(BlockchainError):
    """Raised when Proof of Work validation fails."""
    pass


class ChainReorganizationError(BlockchainError):
    """Raised when chain reorganization fails."""
    pass


class TransactionError(BlockchainError):
    """Raised when transaction validation fails."""
    pass


class AuditTrailError(BlockchainError):
    """Raised when audit trail operations fail."""
    pass


# Start Module 2
class MessagingError(Exception):
    """Base class for messaging exceptions."""
    pass


class KeyExchangeError(MessagingError):
    """Raised when ECDH key exchange fails."""
    pass


class EncryptionError(MessagingError):
    """Raised when message encryption/decryption fails."""
    pass


class SignatureError(MessagingError):
    """Raised when signing a message fails."""
    pass


class MessageVerificationError(MessagingError):
    """Raised when message signature verification fails."""
    pass


class GroupMessagingError(MessagingError):
    """Raised when group messaging operations fail."""
    pass
# End Module 2

# ============================================================================
# File Encryption Module Exceptions
# ============================================================================

class FileEncryptionError(Exception):
    """
    Base exception for file encryption operations.

    Raised when file encryption or decryption fails due to algorithm
    errors, I/O issues, or other cryptographic failures.

    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
        filepath: Optional path to the file that caused the error
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            filepath: str | None = None,
    ) -> None:
        """
        Initialize FileEncryptionError.

        Args:
            message: Error message describing what went wrong
            error_code: Optional error code for error categorization
            filepath: Optional path to the file that caused the error
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.filepath = filepath


class KeyDerivationError(FileEncryptionError):
    """
    Exception raised when key derivation fails.

    Raised when PBKDF2, Argon2, or other key derivation functions
    fail due to invalid parameters or system errors.

    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
        algorithm: Key derivation algorithm that failed
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            algorithm: str | None = None,
    ) -> None:
        """
        Initialize KeyDerivationError.

        Args:
            message: Error message describing the derivation failure
            error_code: Optional error code for error categorization
            algorithm: Key derivation algorithm that failed
        """
        super().__init__(message, error_code)
        self.algorithm = algorithm


class FileIntegrityError(FileEncryptionError):
    """
    Exception raised when file integrity verification fails.

    Raised when hash computation fails or when integrity checks
    cannot be performed due to I/O or algorithm errors.

    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
        filepath: Path to the file with integrity issues
        expected_hash: Expected hash value
        actual_hash: Actual computed hash value
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            filepath: str | None = None,
            expected_hash: str | None = None,
            actual_hash: str | None = None,
    ) -> None:
        """
        Initialize FileIntegrityError.

        Args:
            message: Error message describing the integrity failure
            error_code: Optional error code for error categorization
            filepath: Path to the file with integrity issues
            expected_hash: Expected hash value
            actual_hash: Actual computed hash value
        """
        super().__init__(message, error_code, filepath)
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash


class FileTamperingDetected(FileEncryptionError):
    """
    Exception raised when file tampering is detected.

    Raised when authentication tag verification fails or when
    HMAC verification indicates the file has been modified.
    This is a security-critical exception.

    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
        filepath: Path to the tampered file
        detection_method: Method that detected tampering (e.g., "HMAC", "GCM_TAG")
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            filepath: str | None = None,
            detection_method: str | None = None,
    ) -> None:
        """
        Initialize FileTamperingDetected.

        Args:
            message: Error message describing the tampering detection
            error_code: Optional error code for error categorization
            filepath: Path to the tampered file
            detection_method: Method that detected tampering
        """
        super().__init__(message, error_code, filepath)
        self.detection_method = detection_method


class FileDecodingError(FileEncryptionError):
    """
    Exception raised when encrypted file decoding fails.

    Raised when the encrypted file format is invalid or cannot
    be parsed, such as missing headers or corrupted metadata.

    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
        filepath: Path to the file with decoding issues
        expected_format: Expected file format
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            filepath: str | None = None,
            expected_format: str | None = None,
    ) -> None:
        """
        Initialize FileDecodingError.

        Args:
            message: Error message describing the decoding failure
            error_code: Optional error code for error categorization
            filepath: Path to the file with decoding issues
            expected_format: Expected file format
        """
        super().__init__(message, error_code, filepath)
        self.expected_format = expected_format


class MetadataEncryptionError(FileEncryptionError):
    """
    Exception raised when metadata encryption/decryption fails.

    Raised when file metadata cannot be encrypted or decrypted,
    such as header encryption failures or corrupted metadata blocks.

    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
        file_id: File identifier with metadata issues
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            file_id: str | None = None,
    ) -> None:
        """
        Initialize MetadataEncryptionError.

        Args:
            message: Error message describing the metadata failure
            error_code: Optional error code for error categorization
            file_id: File identifier with metadata issues
        """
        super().__init__(message, error_code)
        self.file_id = file_id


class FileStreamingError(FileEncryptionError):
    """
    Exception raised during streaming file operations.

    Raised when streaming read/write operations fail due to
    I/O errors, buffer issues, or interrupted operations.

    Attributes:
        message: Human-readable error message
        error_code: Optional error code for programmatic handling
        filepath: Path to the file with streaming issues
        bytes_processed: Number of bytes processed before failure
    """

    def __init__(
            self,
            message: str,
            error_code: str | None = None,
            filepath: str | None = None,
            bytes_processed: int | None = None,
    ) -> None:
        """
        Initialize FileStreamingError.

        Args:
            message: Error message describing the streaming failure
            error_code: Optional error code for error categorization
            filepath: Path to the file with streaming issues
            bytes_processed: Number of bytes processed before failure
        """
        super().__init__(message, error_code, filepath)
        self.bytes_processed = bytes_processed
