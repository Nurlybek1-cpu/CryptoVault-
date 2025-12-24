"""
File Encryption Module for CryptoVault.

This module provides comprehensive file encryption capabilities including:
- AES-256-GCM and ChaCha20-Poly1305 encryption
- Secure key derivation (PBKDF2, Argon2)
- File integrity verification
- Streaming file operations

Usage:
    from src.file_encryption import FileEncryptionModule, KeyDerivation, FileOperations
    
    # Initialize module
    encryption_module = FileEncryptionModule(user_id="user123")
    
    # Encrypt a file
    result = encryption_module.encrypt_file("document.pdf", password="secure_password")
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from src.file_encryption.file_encryption_module import FileEncryptionModule
from src.file_encryption.key_derivation import KeyDerivation
from src.file_encryption.file_operations import FileOperations

__all__ = [
    "FileEncryptionModule",
    "KeyDerivation",
    "FileOperations",
    "AESGCM",
    "ChaCha20Poly1305",
]