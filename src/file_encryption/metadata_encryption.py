"""
Metadata Encryption Module - Secure filename and metadata protection.

This module provides encrypted storage and retrieval of file metadata
including filename, file size, MIME type, and creation timestamp.
All metadata is encrypted with AES-256-GCM to protect sensitive
information from filesystem inspection.

Features:
- AES-256-GCM encryption for metadata confidentiality
- Per-metadata random nonce (12 bytes)
- HMAC-based authentication of encrypted metadata
- Serialization via JSON with base64 encoding
- Metadata hash for tampering detection
- Timestamps for created_at tracking

Security Notes:
- Filename is encrypted and hidden from filesystem
- MIME type is hidden (cannot infer file content type)
- File size is encrypted (cannot infer file importance)
- Only owner with master key can decrypt metadata
- Auth tag validates metadata integrity and prevents tampering
- Metadata hash provides additional tamper detection

Storage Patterns:
- Flat: encrypted_files/file_id.enc + file_id.meta
- Hierarchical: file_id/data.enc + file_id/metadata.enc

References:
- docs/algorithms/aes_gcm.md
- docs/examples/metadata_encryption.md
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes


@dataclass
class EncryptedMetadata:
    """
    Container for encrypted metadata components.

    Attributes:
        encrypted_metadata: Base64-encoded AES-GCM ciphertext
        nonce: Base64-encoded random nonce (12 bytes)
        metadata_hash: SHA-256 hash of original metadata dict (hex)
    """
    encrypted_metadata: str  # base64-encoded
    nonce: str  # base64-encoded
    metadata_hash: str  # hexadecimal SHA-256


class MetadataEncryption:
    """
    Encrypts and decrypts file metadata using AES-256-GCM.

    Provides confidential and authenticated storage of file metadata
    including filename, file size, MIME type, and timestamps.
    Hides sensitive information from filesystem inspection while
    providing integrity protection against tampering.

    Example:
        >>> meta_enc = MetadataEncryption()
        >>> encrypted = meta_enc.encrypt_metadata(
        ...     "document.pdf", 50000, "application/pdf", master_key
        ... )
        >>> metadata = meta_enc.decrypt_metadata(encrypted, master_key)
        >>> print(metadata["filename"])  # "document.pdf"
    """

    def __init__(self) -> None:
        """
        Initialize MetadataEncryption.

        No parameters needed; uses standard cryptography.io libraries.
        """
        self._logger: logging.Logger = logging.getLogger(
            f"{__name__}.{self.__class__.__name__}"
        )
        self._logger.info("MetadataEncryption initialized")

    def encrypt_metadata(
            self,
            original_filename: str,
            file_size: int,
            mime_type: str,
            master_key: bytes,
            additional_data: dict | None = None,
    ) -> dict:
        """
        Encrypt file metadata using AES-256-GCM.

        Encrypts filename, file size, MIME type, and creation timestamp.
        Returns base64-encoded ciphertext, nonce, and metadata hash.

        Args:
            original_filename: Original filename (e.g., "document.pdf")
            file_size: File size in bytes
            mime_type: MIME type (e.g., "application/pdf")
            master_key: 32-byte (256-bit) AES key
            additional_data: Optional dict of additional metadata fields

        Returns:
            dict: Encrypted metadata container with:
                - encrypted_metadata: Base64-encoded AES-GCM ciphertext
                - nonce: Base64-encoded random nonce (12 bytes)
                - metadata_hash: SHA-256 hash of plaintext metadata

        Raises:
            ValueError: If master_key is not 32 bytes or parameters invalid
            MetadataEncryptionError: If encryption fails

        Example:
            >>> encrypted = meta_enc.encrypt_metadata(
            ...     "secret.docx", 15000, "application/vnd.ms-word", key
            ... )
            >>> print(f"Hash: {encrypted['metadata_hash']}")
        """
        if not original_filename:
            raise ValueError("original_filename is required")

        if not isinstance(file_size, int) or file_size < 0:
            raise ValueError("file_size must be a non-negative integer")

        if not mime_type:
            raise ValueError("mime_type is required")

        if len(master_key) != 32:
            raise ValueError("master_key must be 32 bytes (256 bits)")

        try:
            # Create metadata dictionary
            metadata = {
                "filename": original_filename,
                "file_size": file_size,
                "mime_type": mime_type,
                "created_at": datetime.utcnow().isoformat(),
            }

            # Include additional metadata fields if provided
            if additional_data:
                metadata.update(additional_data)

            # Serialize metadata to JSON bytes
            metadata_bytes = json.dumps(metadata, default=str).encode("utf-8")

            # Generate random nonce (12 bytes for AES-GCM)
            nonce = os.urandom(12)

            # Create AES-GCM cipher
            cipher = AESGCM(master_key)

            # Encrypt metadata with authentication
            # aad=None means no additional authenticated data
            encrypted_metadata_bytes = cipher.encrypt(nonce, metadata_bytes, None)

            # Compute SHA-256 hash of plaintext metadata
            metadata_hash = hashlib.sha256(metadata_bytes).hexdigest()

            self._logger.debug(
                "Metadata encrypted",
                extra={
                    "filename": original_filename,
                    "file_size": file_size,
                    "mime_type": mime_type,
                    "ciphertext_length": len(encrypted_metadata_bytes),
                }
            )

            return {
                "encrypted_metadata": base64.b64encode(encrypted_metadata_bytes).decode("utf-8"),
                "nonce": base64.b64encode(nonce).decode("utf-8"),
                "metadata_hash": metadata_hash,
            }

        except Exception as exc:
            self._logger.exception("Failed to encrypt metadata")
            raise

    def decrypt_metadata(
            self,
            encrypted_metadata_dict: dict,
            master_key: bytes,
    ) -> dict:
        """
        Decrypt file metadata using AES-256-GCM.

        Decrypts the encrypted metadata, verifies authentication tag,
        and validates metadata hash to ensure no tampering.

        Args:
            encrypted_metadata_dict: Dict with encrypted_metadata, nonce, metadata_hash
            master_key: 32-byte (256-bit) AES key

        Returns:
            dict: Plaintext metadata containing:
                - filename: Original filename
                - file_size: File size in bytes
                - mime_type: MIME type
                - created_at: ISO timestamp of creation
                - ... any additional fields included in encryption

        Raises:
            ValueError: If keys missing or master_key invalid
            MetadataEncryptionError: If decryption fails or auth fails
            MetadataTamperingError: If hash validation fails

        Example:
            >>> metadata = meta_enc.decrypt_metadata(encrypted, key)
            >>> print(metadata["filename"])  # "secret.docx"
        """
        if not encrypted_metadata_dict:
            raise ValueError("encrypted_metadata_dict is required")

        if len(master_key) != 32:
            raise ValueError("master_key must be 32 bytes (256 bits)")

        try:
            # Extract and decode components
            encrypted_bytes = base64.b64decode(
                encrypted_metadata_dict["encrypted_metadata"]
            )
            nonce = base64.b64decode(encrypted_metadata_dict["nonce"])
            expected_hash = encrypted_metadata_dict["metadata_hash"]

            # Create AES-GCM cipher
            cipher = AESGCM(master_key)

            # Decrypt metadata (verifies auth tag automatically)
            # InvalidTag exception raised if auth fails
            plaintext_bytes = cipher.decrypt(nonce, encrypted_bytes, None)

            # Parse JSON metadata
            metadata = json.loads(plaintext_bytes.decode("utf-8"))

            # Validate hash to ensure metadata hasn't been tampered with
            computed_hash = hashlib.sha256(plaintext_bytes).hexdigest()
            if computed_hash != expected_hash:
                raise ValueError(
                    f"Metadata hash mismatch: expected {expected_hash}, "
                    f"got {computed_hash}. Possible tampering detected."
                )

            self._logger.debug(
                "Metadata decrypted successfully",
                extra={
                    "filename": metadata.get("filename"),
                    "file_size": metadata.get("file_size"),
                    "mime_type": metadata.get("mime_type"),
                }
            )

            return metadata

        except ValueError:
            raise
        except Exception as exc:
            self._logger.exception("Failed to decrypt metadata")
            raise

    def validate_metadata_hash(
            self,
            metadata: dict,
            expected_hash: str,
    ) -> bool:
        """
        Validate metadata hash to detect tampering.

        Verifies that the metadata has not been modified since encryption
        by comparing computed hash with expected hash.

        Args:
            metadata: Plaintext metadata dictionary
            expected_hash: Expected SHA-256 hash (hexadecimal)

        Returns:
            bool: True if hash matches, False otherwise

        Example:
            >>> is_valid = meta_enc.validate_metadata_hash(metadata, stored_hash)
        """
        metadata_bytes = json.dumps(metadata, default=str).encode("utf-8")
        computed_hash = hashlib.sha256(metadata_bytes).hexdigest()
        return computed_hash == expected_hash

    def get_metadata_summary(self, metadata: dict) -> str:
        """
        Get a human-readable summary of metadata.

        Useful for logging and debugging (only call on decrypted metadata).

        Args:
            metadata: Plaintext metadata dictionary

        Returns:
            str: Summary string with filename, size, and type

        Example:
            >>> summary = meta_enc.get_metadata_summary(metadata)
            >>> print(summary)  # "document.pdf (15000 bytes, application/pdf)"
        """
        filename = metadata.get("filename", "unknown")
        file_size = metadata.get("file_size", 0)
        mime_type = metadata.get("mime_type", "unknown")
        return f"{filename} ({file_size} bytes, {mime_type})"
