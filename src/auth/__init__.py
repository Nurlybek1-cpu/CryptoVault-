"""
Authentication module for CryptoVault.

This package provides authentication functionality including user registration,
login, password validation, TOTP-based multi-factor authentication, session
management, and account security features.
"""

from src.auth.auth_module import AuthModule
from src.auth.backup_codes import BackupCodesManager
from src.auth.password_validator import PasswordValidator
from src.auth.rate_limiter import RateLimiter
from src.auth.session_manager import SessionManager
from src.auth.totp import TOTPManager

__all__ = [
    'AuthModule',
    'BackupCodesManager',
    'PasswordValidator',
    'RateLimiter',
    'SessionManager',
    'TOTPManager',
]

