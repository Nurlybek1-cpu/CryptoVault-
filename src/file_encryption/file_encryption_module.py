"""
File Encryption Module - Core Implementation.

This module provides the main FileEncryptionModule class for encrypting and
decrypting files with authenticated encryption (AES-256-GCM, ChaCha20-Poly1305).

Features:
- Master key derivation from password using PBKDF2/Argon2
- File Encryption Key (FEK) generation and encryption
- File integrity verification using SHA-256 and HMAC
- Metadata encryption for secure file headers
- File sharing via public key cryptography

Security Notes:
- AES-256 requires 32-byte (256-bit) keys
- ChaCha20 nonces are 12 bytes
- PBKDF2 uses minimum 100,000 iterations (OWASP recommendation)
- All key material is cryptographically random
- File contents are NEVER logged

References:
- docs/algorithms/pbkdf2.md
- docs/algorithms/aes_gcm.md
"""

from __future__ import annotations

import logging
import os
import base64
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Generator

if TYPE_CHECKING:
    pass

from src.file_encryption.key_derivation import KeyDerivation
from src.exceptions import KeyDerivationError
from src.file_encryption.file_encryptor import FileEncryptor
from src.file_encryption.key_wrapping import KeyWrapper
from src.exceptions import KeyDecodingError
from src.file_encryption.file_integrity import FileIntegrity
from src.exceptions import FileIntegrityError, FileTamperingDetected
from src.file_encryption.file_sharing import FileSharing
from src.file_encryption.metadata_encryption import MetadataEncryption


@dataclass
class EncryptionConfig:
    """
    Configuration for file encryption parameters.

    Attributes:
        default_cipher: Default cipher algorithm (AES-256-GCM or ChaCha20-Poly1305)
        pbkdf2_iterations: Number of PBKDF2 iterations (min 100,000 per OWASP)
        salt_length: Length of salt in bytes (32 bytes recommended)
        key_length: Length of encryption key in bytes (32 for AES-256)
        nonce_length: Length of nonce in bytes (12 for AES-GCM/ChaCha20)
        chunk_size: Size of chunks for streaming encryption
        tag_length: Length of authentication tag in bytes (16 for full security)
    """
    default_cipher: str = "AES-256-GCM"
    pbkdf2_iterations: int = 100_000
    salt_length: int = 32
    key_length: int = 32  # 256 bits for AES-256
    nonce_length: int = 12  # 96 bits recommended for AES-GCM
    chunk_size: int = 65536  # 64 KB chunks
    tag_length: int = 16  # 128 bits for full authentication security


@dataclass
class EncryptionStatistics:
    """
    Statistics for encryption operations.

    Attributes:
        files_encrypted: Total number of files encrypted
        files_decrypted: Total number of files decrypted
        bytes_encrypted: Total bytes encrypted
        bytes_decrypted: Total bytes decrypted
        integrity_checks_passed: Number of successful integrity checks
        integrity_checks_failed: Number of failed integrity checks
        last_operation_time: Timestamp of the last operation
    """
    files_encrypted: int = 0
    files_decrypted: int = 0
    bytes_encrypted: int = 0
    bytes_decrypted: int = 0
    integrity_checks_passed: int = 0
    integrity_checks_failed: int = 0
    last_operation_time: datetime | None = None


@dataclass
class FileMetadata:
    """
    Encrypted file metadata structure.

    Attributes:
        file_id: Unique identifier for the file
        original_filename: Original name of the file
        original_size: Original file size in bytes
        encrypted_size: Encrypted file size in bytes
        cipher_type: Encryption algorithm used
        created_at: Timestamp when file was encrypted
        salt: Salt used for key derivation
        nonce: Nonce used for encryption
        hmac_signature: HMAC signature for file authenticity
        file_hash: SHA-256 hash of original file
    """
    file_id: str
    original_filename: str
    original_size: int
    encrypted_size: int = 0
    cipher_type: str = "AES-256-GCM"
    created_at: datetime = field(default_factory=datetime.utcnow)
    salt: bytes = b""
    nonce: bytes = b""
    hmac_signature: str = ""
    file_hash: str = ""


class FileEncryptionModule:
    """
    Core file encryption module for CryptoVault.

    Provides secure file encryption/decryption with authenticated encryption,
    key management, integrity verification, and audit trail capabilities.

    Features:
        - AES-256-GCM and ChaCha20-Poly1305 encryption
        - PBKDF2/Argon2 key derivation
        - File integrity verification (SHA-256, HMAC)
        - Encrypted metadata storage
        - File sharing with public key cryptography
        - Comprehensive logging (no file content logged)

    Attributes:
        user_id: User identifier for audit trail
        config: Encryption configuration parameters
        statistics: Encryption operation statistics

    Example:
        >>> module = FileEncryptionModule(user_id="user123")
        >>> result = module.encrypt_file("document.pdf", "strong_password")
        >>> print(result["file_id"])
    """

    # Supported cipher algorithms
    SUPPORTED_CIPHERS = frozenset({"AES-256-GCM", "ChaCha20-Poly1305"})

    def __init__(
            self,
            user_id: str,
            config: EncryptionConfig | None = None,
    ) -> None:
        """
        Initialize the FileEncryptionModule.

        Args:
            user_id: User identifier for audit trail and logging
            config: Optional encryption configuration; uses defaults if not provided

        Raises:
            ValueError: If user_id is empty or None
        """
        if not user_id:
            raise ValueError("user_id is required for audit trail")

        self._user_id: str = user_id
        self._config: EncryptionConfig = config or EncryptionConfig()
        self._statistics: EncryptionStatistics = EncryptionStatistics()

        # Master key cache: stores encrypted keys in memory
        # Key: key_id (str), Value: encrypted_key (bytes)
        self._master_key_cache: dict[str, bytes] = {}

        # File metadata storage: stores metadata for encrypted files
        # Key: file_id (str), Value: FileMetadata
        self._file_metadata_storage: dict[str, FileMetadata] = {}

        # Initialize logger - no file content should ever be logged
        self._logger: logging.Logger = logging.getLogger(
            f"{__name__}.{self.__class__.__name__}"
        )
        # Key derivation utility
        self.key_derivation = KeyDerivation()
        # File encryptor for streaming operations
        self.file_encryptor = FileEncryptor()
        # Key wrapper (AES-KW) for wrapping FEKs with master key
        self.key_wrapper = KeyWrapper()
        # File integrity utilities
        self.file_integrity = FileIntegrity()
        # File sharing utilities (RSA-OAEP for FEK sharing)
        self.file_sharing = FileSharing(user_id=user_id)
        # Metadata encryption utilities (AES-GCM for filename/metadata)
        self.metadata_encryption = MetadataEncryption()
        self._logger.info(
            "FileEncryptionModule initialized",
            extra={
                "user_id": self._user_id,
                "cipher": self._config.default_cipher,
            }
        )

    @property
    def user_id(self) -> str:
        """Get the user ID for audit trail."""
        return self._user_id

    @property
    def config(self) -> EncryptionConfig:
        """Get the encryption configuration."""
        return self._config

    @property
    def statistics(self) -> EncryptionStatistics:
        """Get encryption operation statistics."""
        return self._statistics

    def encrypt_file(
            self,
            filepath: str,
            password: str,
            cipher_type: str = "AES-256-GCM",
    ) -> dict:
        """
        Encrypt a file with authenticated encryption and metadata protection.

        Complete workflow:
        1. Derive master key from password using PBKDF2
        2. Generate random File Encryption Key (FEK)
        3. Encrypt file content with FEK using AES-256-GCM (streaming)
        4. Encrypt metadata (filename, size, MIME type) with master key
        5. Wrap FEK with master key using AES-KW
        6. Compute file integrity hash and HMAC
        7. Return encrypted file path and metadata

        Args:
            filepath: Path to the file to encrypt
            password: Password for key derivation (PBKDF2)
            cipher_type: Encryption algorithm ("AES-256-GCM" or "ChaCha20-Poly1305")

        Returns:
            dict: Encryption result containing:
                - file_id: Unique identifier for encrypted file
                - encrypted_filepath: Path to encrypted file
                - original_filename: Original filename (for reference)
                - original_size: Original file size in bytes
                - encrypted_size: Encrypted file size in bytes
                - cipher_type: Algorithm used for encryption
                - master_key_salt: Salt for PBKDF2 key derivation
                - encrypted_fek: Wrapped FEK (AES-KW encrypted with master key)
                - encrypted_metadata: Encrypted filename/size/mime metadata
                - file_hash: SHA-256 hash of original file
                - file_hmac: HMAC-SHA256 of original file
                - created_at: Timestamp of encryption

        Raises:
            FileEncryptionError: If encryption fails
            KeyDerivationError: If key derivation fails
            FileNotFoundError: If input file does not exist
            ValueError: If cipher_type is not supported

        Example:
            >>> result = module.encrypt_file("document.pdf", "password123")
            >>> print(f"File ID: {result['file_id']}")
            >>> print(f"Encrypted: {result['encrypted_filepath']}")
        """
        if not filepath:
            raise ValueError("filepath is required")

        if not password:
            raise ValueError("password is required")

        if cipher_type not in self.SUPPORTED_CIPHERS:
            raise ValueError(f"Unsupported cipher: {cipher_type}")

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        try:
            # Get original file info
            original_filename = os.path.basename(filepath)
            original_size = os.path.getsize(filepath)
            mime_type = "application/octet-stream"  # Default; could be detected

            # Derive master key from password
            master_key, salt = self.derive_master_key(password)

            # Encrypt file metadata (filename hidden)
            encrypted_metadata = self.encrypt_file_metadata(
                original_filename=original_filename,
                file_size=original_size,
                mime_type=mime_type,
                master_key=master_key,
            )

            # Encrypt file content (FileEncryptor creates and manages FEK internally)
            file_id = f"file_{int(datetime.utcnow().timestamp() * 1000000)}"
            encrypted_filepath = os.path.join(
                os.path.dirname(filepath),
                f"{file_id}.enc"
            )

            encryption_result = self.file_encryptor.encrypt_file_streaming(
                input_path=filepath,
                output_path=encrypted_filepath,
                master_key=master_key,
                cipher_type=cipher_type,
            )

            # Extract FEK from encryption result (FileEncryptor created it)
            encrypted_fek_b64 = encryption_result["encrypted_fek"]
            encrypted_fek = base64.b64decode(encrypted_fek_b64)

            # Compute file integrity metrics
            original_file_hash = self.get_file_integrity_hash(filepath)
            file_hmac = self.get_file_authenticity_hmac(filepath, master_key)

            # Update statistics
            self._statistics.files_encrypted += 1
            self._statistics.bytes_encrypted += original_size
            self._statistics.last_operation_time = datetime.utcnow()

            result = {
                "file_id": file_id,
                "encrypted_filepath": encrypted_filepath,
                "original_filename": original_filename,
                "original_size": original_size,
                "encrypted_size": encryption_result.get("file_size_encrypted", 0),
                "cipher_type": cipher_type,
                "master_key_salt": base64.b64encode(salt).decode("utf-8"),
                "encrypted_fek": encrypted_fek_b64,
                "encrypted_metadata": encrypted_metadata,
                "file_hash": original_file_hash,
                "file_hmac": file_hmac,
                "created_at": datetime.utcnow().isoformat(),
            }

            self._logger.info(
                "File encrypted successfully",
                extra={
                    "file_id": file_id,
                    "filename": original_filename,
                    "size": original_size,
                    "encrypted_size": result["encrypted_size"],
                }
            )

            return result

        except (FileNotFoundError, ValueError):
            raise
        except Exception as exc:
            self._logger.exception("Failed to encrypt file")
            raise

    def decrypt_file(
            self,
            encrypted_filepath: str,
            password: str,
            encryption_result: dict,
    ) -> dict:
        """
        Decrypt an encrypted file and restore metadata.

        Complete workflow:
        1. Decode salt from encryption result
        2. Derive master key from password using PBKDF2 (with salt)
        3. Decrypt metadata to verify key and retrieve filename
        4. Unwrap FEK using master key (AES-KW)
        5. Decrypt file content with FEK
        6. Verify file integrity (hash and HMAC)
        7. Restore original filename (optional)

        Args:
            encrypted_filepath: Path to the encrypted file
            password: Password for key derivation (must match encryption)
            encryption_result: Dict returned from encrypt_file() containing:
                - master_key_salt: Salt for PBKDF2
                - encrypted_fek: Wrapped FEK
                - encrypted_metadata: Encrypted filename/size/mime
                - file_hash: Original file SHA-256 hash
                - file_hmac: Original file HMAC-SHA256

        Returns:
            dict: Decryption result containing:
                - decrypted_filepath: Path to decrypted file
                - original_filename: Restored original filename
                - file_hash: SHA-256 hash of decrypted file
                - file_hmac: HMAC-SHA256 of decrypted file
                - integrity_verified: Boolean indicating hash match
                - authenticity_verified: Boolean indicating HMAC match
                - created_at: Timestamp of decryption

        Raises:
            FileEncryptionError: If decryption fails
            FileTamperingDetected: If file integrity check fails
            FileDecodingError: If file format is invalid
            FileNotFoundError: If encrypted file does not exist
            ValueError: If encryption_result missing required fields

        Example:
            >>> result = module.decrypt_file(
            ...     "file_123.enc", "password123", encryption_result
            ... )
            >>> print(f"Decrypted: {result['decrypted_filepath']}")
        """
        if not encrypted_filepath:
            raise ValueError("encrypted_filepath is required")

        if not password:
            raise ValueError("password is required")

        if not encryption_result:
            raise ValueError("encryption_result dict is required")

        if not os.path.exists(encrypted_filepath):
            raise FileNotFoundError(f"Encrypted file not found: {encrypted_filepath}")

        try:
            # Extract encryption parameters
            salt = base64.b64decode(encryption_result["master_key_salt"])
            encrypted_fek_b64 = encryption_result["encrypted_fek"]
            encrypted_metadata = encryption_result["encrypted_metadata"]
            expected_file_hash = encryption_result["file_hash"]
            expected_file_hmac = encryption_result["file_hmac"]

            # Decode wrapped FEK
            encrypted_fek = base64.b64decode(encrypted_fek_b64)

            # Derive master key from password (with same salt)
            master_key = self.key_derivation.pbkdf2_derive(
                password=password,
                salt=salt,
                iterations=self._config.pbkdf2_iterations,
                dklen=self._config.key_length,
            )

            # Decrypt metadata to verify key and get original filename
            metadata = self.decrypt_file_metadata(encrypted_metadata, master_key)
            original_filename = metadata["filename"]

            # Decrypt file content using FileEncryptor
            # (FileEncryptor internally unwraps the FEK from the header)
            file_id = os.path.splitext(os.path.basename(encrypted_filepath))[0]
            decrypted_filepath = os.path.join(
                os.path.dirname(encrypted_filepath),
                original_filename,
            )

            decryption_result = self.file_encryptor.decrypt_file_streaming(
                encrypted_path=encrypted_filepath,
                output_path=decrypted_filepath,
                master_key=master_key,
            )

            # Verify file integrity
            decrypted_file_hash = self.get_file_integrity_hash(decrypted_filepath)
            decrypted_file_hmac = self.get_file_authenticity_hmac(
                decrypted_filepath, master_key
            )

            integrity_verified = decrypted_file_hash == expected_file_hash
            authenticity_verified = decrypted_file_hmac == expected_file_hmac

            if not integrity_verified:
                raise FileTamperingDetected(
                    f"File integrity check failed: hash mismatch",
                    filepath=decrypted_filepath
                )

            if not authenticity_verified:
                raise FileTamperingDetected(
                    f"File authenticity check failed: HMAC mismatch",
                    filepath=decrypted_filepath
                )

            # Update statistics
            self._statistics.files_decrypted += 1
            self._statistics.bytes_decrypted += os.path.getsize(decrypted_filepath)
            self._statistics.integrity_checks_passed += 1
            self._statistics.last_operation_time = datetime.utcnow()

            result = {
                "decrypted_filepath": decrypted_filepath,
                "original_filename": original_filename,
                "file_hash": decrypted_file_hash,
                "file_hmac": decrypted_file_hmac,
                "integrity_verified": integrity_verified,
                "authenticity_verified": authenticity_verified,
                "created_at": datetime.utcnow().isoformat(),
            }

            self._logger.info(
                "File decrypted successfully",
                extra={
                    "file_id": file_id,
                    "filename": original_filename,
                    "integrity_verified": integrity_verified,
                    "authenticity_verified": authenticity_verified,
                }
            )

            return result

        except (ValueError, FileNotFoundError, FileTamperingDetected):
            raise
        except Exception as exc:
            self._logger.exception("Failed to decrypt file")
            raise


    def verify_file_integrity(
            self,
            filepath: str,
            expected_hash: str,
    ) -> bool:
        """
        Verify file integrity using SHA-256 hash comparison.

        Computes the SHA-256 hash of the file and compares it with
        the expected hash to verify file integrity.

        Args:
            filepath: Path to the file to verify
            expected_hash: Expected SHA-256 hash in hexadecimal format

        Returns:
            bool: True if hashes match, False otherwise

        Raises:
            FileIntegrityError: If hash computation fails
            FileNotFoundError: If the file does not exist

        Example:
            >>> is_valid = module.verify_file_integrity("file.txt", "abc123...")
            >>> print(f"File integrity: {'valid' if is_valid else 'invalid'}")
        """
        raise NotImplementedError("Implementation pending")

    def derive_master_key(
            self,
            password: str,
            salt: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """
        Derive a master key from password using PBKDF2.

        Derives a cryptographic key from the password using PBKDF2-HMAC-SHA256
        with the configured number of iterations (minimum 100,000).

        Args:
            password: Password to derive key from
            salt: Optional salt; generates random 32-byte salt if not provided

        Returns:
            tuple[bytes, bytes]: (derived_key, salt) where:
                - derived_key: 32-byte (256-bit) derived key
                - salt: 32-byte salt used for derivation

        Raises:
            KeyDerivationError: If key derivation fails
            ValueError: If password is empty

        Example:
            >>> key, salt = module.derive_master_key("password123")
            >>> print(f"Key length: {len(key)} bytes")
        """
        if not password:
            raise ValueError("password is required for key derivation")

        # Generate salt if not provided
        if salt is None:
            salt = self.key_derivation.generate_random_salt(self._config.salt_length)

        # Derive master key using PBKDF2
        try:
            master_key = self.key_derivation.pbkdf2_derive(
                password=password,
                salt=salt,
                iterations=self._config.pbkdf2_iterations,
                dklen=self._config.key_length,
            )
        except Exception as exc:
            self._logger.exception("Failed to derive master key")
            raise KeyDerivationError("Failed to derive master key") from exc

        # Validate derived key strength
        if not self.key_derivation.validate_key_strength(master_key):
            raise KeyDerivationError("Derived key has invalid length or strength")

        self._logger.info(f"Master key derived for user {self._user_id}")

        return master_key, salt

    def generate_file_encryption_key(self) -> bytes:
        """
        Generate a random File Encryption Key (FEK).

        Generates a cryptographically random 32-byte key for file encryption.
        Each file should have a unique FEK wrapped by the master key.

        Returns:
            bytes: 32-byte (256-bit) random encryption key

        Raises:
            FileEncryptionError: If random number generation fails

        Example:
            >>> fek = module.generate_file_encryption_key()
            >>> print(f"FEK length: {len(fek)} bytes")
        """
        try:
            return os.urandom(self._config.key_length)
        except Exception as exc:
            self._logger.exception("Failed to generate FEK")
            raise

    def encrypt_file_encryption_key(
            self,
            fek: bytes,
            master_key: bytes,
    ) -> bytes:
        """
        Encrypt the File Encryption Key (FEK) with the master key.

        Wraps the FEK using AES-256-GCM with the master key, providing
        confidentiality and authenticity protection for the key.

        Args:
            fek: 32-byte File Encryption Key to encrypt
            master_key: 32-byte master key for encryption

        Returns:
            bytes: Encrypted FEK (nonce + ciphertext + tag)

        Raises:
            FileEncryptionError: If encryption fails
            ValueError: If key sizes are incorrect

        Example:
            >>> encrypted_fek = module.encrypt_file_encryption_key(fek, master_key)
        """
        try:
            wrapped = self.key_wrapper.encrypt_key_with_master_key(fek, master_key)
            return wrapped
        except Exception as exc:
            self._logger.exception("Failed to wrap FEK")
            raise

    def decrypt_file_encryption_key(
            self,
            encrypted_fek: bytes,
            master_key: bytes,
    ) -> bytes:
        """
        Decrypt the File Encryption Key (FEK) with the master key.

        Unwraps the encrypted FEK using AES-256-GCM with the master key.
        Verifies authenticity before returning the decrypted key.

        Args:
            encrypted_fek: Encrypted FEK (nonce + ciphertext + tag)
            master_key: 32-byte master key for decryption

        Returns:
            bytes: 32-byte decrypted File Encryption Key

        Raises:
            FileEncryptionError: If decryption fails
            FileTamperingDetected: If FEK authentication fails

        Example:
            >>> fek = module.decrypt_file_encryption_key(encrypted_fek, master_key)
        """
        try:
            fek = self.key_wrapper.decrypt_key_with_master_key(encrypted_fek, master_key)
            return fek
        except KeyDecodingError:
            # propagate as-is
            raise
        except Exception as exc:
            self._logger.exception("Failed to unwrap FEK")
            raise

    def get_file_integrity_hash(self, filepath: str) -> str:
        """
        Compute SHA-256 hash of a file.

        Reads the file in chunks and computes its SHA-256 hash.
        Suitable for large files without loading entirely into memory.

        Args:
            filepath: Path to the file to hash

        Returns:
            str: Hexadecimal SHA-256 hash of the file

        Raises:
            FileIntegrityError: If hash computation fails
            FileNotFoundError: If the file does not exist

        Example:
            >>> hash_value = module.get_file_integrity_hash("document.pdf")
            >>> print(f"SHA-256: {hash_value}")
        """
        try:
            return self.file_integrity.calculate_file_hash(filepath)
        except FileIntegrityError:
            raise
        except Exception:
            self._logger.exception("Failed to get file integrity hash")
            raise

    def get_file_authenticity_hmac(self, filepath: str, key: bytes) -> str:
        """
        Compute HMAC-SHA256 of a file for authenticity.

        Reads the file in chunks and computes the HMAC using the provided key.

        Args:
            filepath: Path to the file to compute HMAC for
            key: Key bytes to use for HMAC computation

        Returns:
            str: Hexadecimal HMAC-SHA256 of the file

        Raises:
            FileIntegrityError: If HMAC computation fails
            FileNotFoundError: If the file does not exist

        Example:
            >>> hmac_value = module.get_file_authenticity_hmac("file.enc", key)
        """
        try:
            return self.file_integrity.calculate_file_hmac(filepath, key)
        except FileIntegrityError:
            raise
        except Exception:
            self._logger.exception("Failed to compute file HMAC")
            raise

    def verify_file_integrity(self, filepath: str, expected_hash: str) -> bool:
        try:
            return self.file_integrity.verify_file_integrity(filepath, expected_hash)
        except FileIntegrityError:
            raise
        except Exception:
            self._logger.exception("Failed to verify file integrity")
            raise

    def verify_file_authenticity(self, filepath: str, expected_hmac: str, key: bytes) -> bool:
        try:
            ok = self.file_integrity.verify_file_authenticity(filepath, expected_hmac, key)
            if not ok:
                raise FileTamperingDetected("File authenticity HMAC verification failed", filepath=filepath)
            return True
        except FileTamperingDetected:
            raise
        except FileIntegrityError:
            raise
        except Exception:
            self._logger.exception("Failed to verify file authenticity")
            raise

    def encrypt_file_metadata(
            self,
            original_filename: str,
            file_size: int,
            mime_type: str,
            master_key: bytes,
            additional_data: dict | None = None,
    ) -> dict:
        """
        Encrypt file metadata (filename, size, MIME type).

        Encrypts sensitive metadata using AES-256-GCM with the master key.
        Returns encrypted metadata with nonce and hash for integrity verification.

        Args:
            original_filename: Original filename (e.g., "document.pdf")
            file_size: File size in bytes
            mime_type: MIME type (e.g., "application/pdf")
            master_key: 32-byte (256-bit) master key
            additional_data: Optional additional metadata fields

        Returns:
            dict: Encrypted metadata container with:
                - encrypted_metadata: Base64-encoded AES-GCM ciphertext
                - nonce: Base64-encoded random nonce
                - metadata_hash: SHA-256 hash of plaintext metadata

        Raises:
            ValueError: If parameters invalid or key incorrect size
            MetadataEncryptionError: If encryption fails

        Example:
            >>> encrypted_meta = module.encrypt_file_metadata(
            ...     "secret.pdf", 50000, "application/pdf", master_key
            ... )
            >>> print(f"Hash: {encrypted_meta['metadata_hash']}")
        """
        try:
            encrypted_meta = self.metadata_encryption.encrypt_metadata(
                original_filename=original_filename,
                file_size=file_size,
                mime_type=mime_type,
                master_key=master_key,
                additional_data=additional_data,
            )
            self._logger.info(
                "File metadata encrypted",
                extra={
                    "filename": original_filename,
                    "file_size": file_size,
                    "mime_type": mime_type,
                }
            )
            return encrypted_meta
        except Exception as exc:
            self._logger.exception("Failed to encrypt file metadata")
            raise

    def decrypt_file_metadata(
            self,
            encrypted_metadata_dict: dict,
            master_key: bytes,
    ) -> dict:
        """
        Decrypt file metadata.

        Decrypts encrypted metadata, verifies authentication tag and hash,
        and returns plaintext metadata dictionary.

        Args:
            encrypted_metadata_dict: Dict with encrypted_metadata, nonce, metadata_hash
            master_key: 32-byte (256-bit) master key

        Returns:
            dict: Plaintext metadata containing:
                - filename: Original filename
                - file_size: File size in bytes
                - mime_type: MIME type
                - created_at: ISO timestamp of creation
                - ... any additional fields

        Raises:
            ValueError: If parameters invalid or key incorrect size
            MetadataEncryptionError: If decryption fails
            MetadataTamperingError: If hash validation fails

        Example:
            >>> metadata = module.decrypt_file_metadata(encrypted_meta, master_key)
            >>> print(metadata["filename"])  # "secret.pdf"
        """
        try:
            metadata = self.metadata_encryption.decrypt_metadata(
                encrypted_metadata_dict=encrypted_metadata_dict,
                master_key=master_key,
            )
            self._logger.info(
                "File metadata decrypted",
                extra={
                    "filename": metadata.get("filename"),
                    "file_size": metadata.get("file_size"),
                }
            )
            return metadata
        except Exception as exc:
            self._logger.exception("Failed to decrypt file metadata")
            raise

    def setup_file_sharing(
            self,
            file_id: str,
            encrypted_fek: bytes,
            recipient_pubkey,
            recipient_id: str,
            expiry_days: int | None = None,
    ) -> dict:
        """
        Set up file sharing with a recipient using public key cryptography.

        Encrypts the File Encryption Key for the recipient using their
        public key (RSA-OAEP), enabling secure file sharing without password
        exchange. Only the recipient with the corresponding private key can
        decrypt the FEK and access the shared file.

        Args:
            file_id: Unique identifier of the file being shared
            encrypted_fek: Wrapped FEK bytes to encrypt for recipient
            recipient_pubkey: Recipient's RSA public key
            recipient_id: User ID of the recipient
            expiry_days: Optional days until share expires (None for permanent)

        Returns:
            dict: Share record containing:
                - share_id: Unique identifier for this share
                - file_id: File identifier
                - owner_id: Owner's user ID
                - recipient_id: Recipient's user ID
                - encrypted_fek: Base64-encoded RSA-encrypted FEK
                - shared_at: Timestamp of share creation
                - expiry: Optional expiry date
                - revoked: Access revocation status

        Raises:
            FileEncryptionError: If key encryption fails
            ValueError: If file_id not found or pubkey invalid

        Example:
            >>> result = module.setup_file_sharing(
            ...     "file123", fek_bytes, recipient_key, "bob", expiry_days=7
            ... )
            >>> print(result["share_id"])
        """
        try:
            share = self.file_sharing.share_file_with_recipient(
                file_id=file_id,
                encrypted_fek=encrypted_fek,
                recipient_pubkey=recipient_pubkey,
                recipient_id=recipient_id,
                expiry_days=expiry_days
            )
            self._logger.info(
                "File sharing setup completed",
                extra={
                    "file_id": file_id,
                    "recipient_id": recipient_id,
                    "share_id": share["share_id"]
                }
            )
            return share
        except Exception as exc:
            self._logger.exception("Failed to setup file sharing")
            raise


    def receive_shared_file(
            self,
            share_record: dict,
            private_key,
    ) -> bytes:
        """
        Decrypt shared file FEK using recipient's private key.

        Decrypts the FEK that was encrypted with the recipient's public key.
        Verifies that the share is active (not revoked and not expired).

        Args:
            share_record: Share record dict containing encrypted FEK and metadata
            private_key: Recipient's RSA private key

        Returns:
            bytes: Decrypted File Encryption Key (32 bytes)

        Raises:
            ValueError: If share is revoked, expired, or invalid
            KeyDecodingError: If FEK decryption fails

        Example:
            >>> fek = module.receive_shared_file(share_record, bob_private_key)
            >>> print(f"FEK length: {len(fek)} bytes")
        """
        try:
            fek = self.file_sharing.receive_shared_file(share_record, private_key)
            self._logger.info(
                "Shared file received and decrypted",
                extra={
                    "file_id": share_record.get("file_id"),
                    "fek_length": len(fek)
                }
            )
            return fek
        except Exception as exc:
            self._logger.exception("Failed to receive shared file")
            raise

    def revoke_file_access(
            self,
            file_id: str,
            recipient_id: str,
    ) -> bool:
        """
        Revoke access to a shared file for a specific recipient.

        Marks the share record as revoked. The recipient can no longer
        decrypt the FEK using the revoked share record.

        Args:
            file_id: Identifier of the file
            recipient_id: User ID of the recipient whose access to revoke

        Returns:
            bool: True if access revoked successfully, False if share not found

        Example:
            >>> success = module.revoke_file_access("file123", "bob")
            >>> print(f"Access revoked: {success}")
        """
        try:
            success = self.file_sharing.revoke_file_access(file_id, recipient_id)
            if success:
                self._logger.info(
                    "File access revoked",
                    extra={"file_id": file_id, "recipient_id": recipient_id}
                )
            else:
                self._logger.warning(
                    "No active share found to revoke",
                    extra={"file_id": file_id, "recipient_id": recipient_id}
                )
            return success
        except Exception as exc:
            self._logger.exception("Failed to revoke file access")
            raise

    def get_file_shares(self, file_id: str) -> list[dict]:
        """
        Get all active shares for a file.

        Returns a list of all active (not revoked) shares for the specified file.

        Args:
            file_id: Identifier of the file

        Returns:
            list[dict]: List of share records with recipient info

        Example:
            >>> shares = module.get_file_shares("file123")
            >>> print(f"Recipients: {[s['recipient_id'] for s in shares]}")
        """
        try:
            return self.file_sharing.get_file_shares(file_id)
        except Exception as exc:
            self._logger.exception("Failed to get file shares")
            raise

    def get_user_shared_files(self) -> list[dict]:
        """
        Get all files shared by this user.

        Returns a list of all files that this user (the owner) has shared.

        Returns:
            list[dict]: List of shared file information with recipients

        Example:
            >>> shared = module.get_user_shared_files()
            >>> for f in shared:
            ...     print(f"File {f['file_id']} recipients: {f['recipients']}")
        """
        try:
            return self.file_sharing.get_user_shared_files()
        except Exception as exc:
            self._logger.exception("Failed to get user shared files")
            raise

        """
        Create encrypted metadata structure for a file.

        Generates the cryptographic components needed for metadata
        encryption including nonce, key derivation parameters, etc.

        Returns:
            dict: Metadata encryption components containing:
                - nonce: Random nonce for metadata encryption
                - salt: Salt for key derivation
                - key_id: Identifier for the metadata key
                - algorithm: Algorithm used for metadata encryption

        Raises:
            MetadataEncryptionError: If metadata creation fails

        Example:
            >>> metadata_enc = module.create_metadata_encryption()
        """
        raise NotImplementedError("Implementation pending")

    def get_file_metadata(self, file_id: str) -> dict:
        """
        Retrieve metadata for an encrypted file.

        Returns the stored metadata for the specified encrypted file,
        including encryption parameters and file information.

        Args:
            file_id: Unique identifier of the encrypted file

        Returns:
            dict: File metadata containing:
                - file_id: File identifier
                - original_filename: Original file name
                - original_size: Original file size
                - encrypted_size: Encrypted file size
                - cipher_type: Encryption algorithm used
                - created_at: Encryption timestamp
                - file_hash: SHA-256 hash of original file

        Raises:
            FileEncryptionError: If file_id not found

        Example:
            >>> metadata = module.get_file_metadata("file123")
            >>> print(metadata["original_filename"])
        """
        raise NotImplementedError("Implementation pending")