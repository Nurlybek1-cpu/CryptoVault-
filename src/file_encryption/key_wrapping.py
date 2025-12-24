"""
AES Key Wrap utilities (RFC 3394) for wrapping file encryption keys (FEKs)
with a master key (KEK).

Provides deterministic, integrity-protecting wrapping using AES-KW.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.keywrap import (
    aes_key_wrap,
    aes_key_unwrap,
    InvalidUnwrap,
)
from cryptography.hazmat.backends import default_backend

from src.exceptions import KeyDecodingError


class KeyWrapper:
    """Wrap and unwrap FEKs using AES Key Wrap (RFC 3394).

    Master key must be 32 bytes (AES-256). FEK typically 32 bytes.
    """

    def encrypt_key_with_master_key(self, fek: bytes, master_key: bytes) -> bytes:
        if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != 32:
            raise ValueError("master_key must be 32 bytes for AES-256")
        if not isinstance(fek, (bytes, bytearray)):
            raise ValueError("fek must be bytes")

        # aes_key_wrap returns wrapped key (len = len(fek) + 8)
        wrapped = aes_key_wrap(wrapping_key=master_key, key_to_wrap=fek, backend=default_backend())
        return wrapped

    def decrypt_key_with_master_key(self, wrapped_fek: bytes, master_key: bytes) -> bytes:
        if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != 32:
            raise ValueError("master_key must be 32 bytes for AES-256")
        try:
            fek = aes_key_unwrap(wrapping_key=master_key, wrapped_key=wrapped_fek, backend=default_backend())
            return fek
        except InvalidUnwrap as exc:
            raise KeyDecodingError("Failed to unwrap key - wrong master key or corrupted wrapped key") from exc
        except Exception as exc:
            raise KeyDecodingError("Failed to unwrap key") from exc

    def rotate_file_key(self, old_wrapped_fek: bytes, old_master_key: bytes, new_master_key: bytes) -> bytes:
        # Unwrap with old master key, then wrap with new master key
        fek = self.decrypt_key_with_master_key(old_wrapped_fek, old_master_key)
        new_wrapped = self.encrypt_key_with_master_key(fek, new_master_key)
        return new_wrapped
