"""
File integrity utilities: SHA-256 hashing and HMAC-SHA256 authenticity.

Provides streaming, memory-efficient functions to compute file hashes
and HMACs and to verify integrity/authenticity.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from src.exceptions import FileIntegrityError, FileTamperingDetected


CHUNK_SIZE: Final[int] = 8192


class FileIntegrity:
    def __init__(self) -> None:
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def calculate_file_hash(self, filepath: str, algorithm: str = "sha256") -> str:
        if algorithm.lower() != "sha256":
            raise ValueError("Only sha256 is supported")

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        try:
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    digest.update(chunk)
        except FileNotFoundError:
            raise
        except Exception as exc:
            self._logger.exception("Failed to compute file hash")
            raise FileIntegrityError("Failed to compute file hash") from exc

        return digest.finalize().hex()

    def calculate_file_hmac(self, filepath: str, key: bytes, algorithm: str = "sha256") -> str:
        if algorithm.lower() != "sha256":
            raise ValueError("Only sha256 is supported for HMAC")

        try:
            h = hmac.new(key, digestmod=hashlib.sha256)
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    h.update(chunk)
        except FileNotFoundError:
            raise
        except Exception as exc:
            self._logger.exception("Failed to compute file HMAC")
            raise FileIntegrityError("Failed to compute file HMAC") from exc

        return h.hexdigest()

    def verify_file_integrity(self, original_filepath: str, backup_hash: str) -> bool:
        current_hash = self.calculate_file_hash(original_filepath)
        if current_hash == backup_hash:
            return True
        self._logger.warning("File integrity mismatch for %s", original_filepath)
        return False

    def verify_file_authenticity(self, filepath: str, expected_hmac: str, key: bytes) -> bool:
        current_hmac = self.calculate_file_hmac(filepath, key)
        if hmac.compare_digest(current_hmac, expected_hmac):
            return True
        self._logger.warning("File authenticity HMAC mismatch for %s", filepath)
        return False
