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

