"""
Authentication module for CryptoVault.

This package provides authentication functionality including user registration,
login, password validation, TOTP-based multi-factor authentication, session
management, and account security features.
"""

from src.auth.auth_module import AuthModule
from src.auth.backup_codes import BackupCodesManager
from src.auth.password_validator import PasswordValidator

__all__ = [
    'AuthModule',
    'BackupCodesManager',
    'PasswordValidator',
]

