"""
Unit tests for File Encryption Module.

Comprehensive test suite covering:
- Key derivation (PBKDF2)
- File encryption/decryption (AES-256-GCM)
- Key wrapping/unwrapping (AES-KW)
- File integrity & authenticity (SHA-256, HMAC)
- File sharing (RSA-OAEP)
- Metadata encryption (AES-GCM)
"""

import os
import time
import pytest
import tempfile
from cryptography.hazmat.primitives.asymmetric import rsa

from src.file_encryption.file_encryption_module import FileEncryptionModule
from src.file_encryption.key_derivation import KeyDerivation
from src.file_encryption.file_encryptor import FileEncryptor
from src.file_encryption.key_wrapping import KeyWrapper
from src.file_encryption.file_integrity import FileIntegrity
from src.file_encryption.file_sharing import FileSharing
from src.file_encryption.metadata_encryption import MetadataEncryption
from src.exceptions import KeyDerivationError, FileTamperingDetected, FileIntegrityError


class TestKeyDerivation:
    """Tests for PBKDF2 key derivation."""

    def test_pbkdf2_creates_32_byte_key(self, key_derivation, test_password, salt):
        """Test that PBKDF2 creates a 32-byte key."""
        key = key_derivation.pbkdf2_derive(test_password, salt)
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_pbkdf2_deterministic(self, key_derivation, test_password, salt):
        """Test that same password+salt produces same key."""
        key1 = key_derivation.pbkdf2_derive(test_password, salt)
        key2 = key_derivation.pbkdf2_derive(test_password, salt)
        assert key1 == key2

    def test_pbkdf2_different_salt_different_key(self, key_derivation, test_password):
        """Test that different salts produce different keys."""
        salt1 = os.urandom(32)
        salt2 = os.urandom(32)
        
        key1 = key_derivation.pbkdf2_derive(test_password, salt1)
        key2 = key_derivation.pbkdf2_derive(test_password, salt2)
        
        assert key1 != key2

    def test_pbkdf2_different_password_different_key(self, key_derivation, salt):
        """Test that different passwords produce different keys."""
        password1 = "Password123!"
        password2 = "DifferentPassword456!"
        
        key1 = key_derivation.pbkdf2_derive(password1, salt)
        key2 = key_derivation.pbkdf2_derive(password2, salt)
        
        assert key1 != key2

    def test_pbkdf2_custom_iterations(self, key_derivation, test_password, salt):
        """Test PBKDF2 with custom iterations (must be >= 100000)."""
        key = key_derivation.pbkdf2_derive(
            test_password, salt, iterations=150000, dklen=32
        )
        assert len(key) == 32

    def test_generate_random_salt(self, key_derivation):
        """Test salt generation produces random 32-byte values."""
        salt1 = key_derivation.generate_random_salt()
        salt2 = key_derivation.generate_random_salt()
        
        assert len(salt1) == 32
        assert len(salt2) == 32
        assert salt1 != salt2

    def test_validate_key_strength(self, key_derivation):
        """Test key strength validation."""
        strong_key = os.urandom(32)
        weak_key = b"short"
        
        assert key_derivation.validate_key_strength(strong_key) is True
        assert key_derivation.validate_key_strength(weak_key) is False

    def test_pbkdf2_performance(self, key_derivation, test_password, salt):
        """Test that PBKDF2 derivation completes in reasonable time."""
        start = time.time()
        key = key_derivation.pbkdf2_derive(test_password, salt, iterations=100000)
        elapsed = time.time() - start
        
        # Should complete in < 1 second (typically ~100-200ms)
        assert elapsed < 1.0
        assert len(key) == 32

    def test_pbkdf2_empty_password_fails(self, key_derivation, salt):
        """Test that empty password raises error."""
        with pytest.raises(Exception):
            key_derivation.pbkdf2_derive("", salt)


class TestFileEncryption:
    """Tests for file encryption functionality."""

    def test_encrypt_file_success(self, file_encryption_module, test_file, cleanup_files):
        """Test successful file encryption."""
        password = "TestPassword123!"
        
        result = file_encryption_module.encrypt_file(test_file, password)
        
        assert result is not None
        assert "file_id" in result
        assert "encrypted_filepath" in result
        assert os.path.exists(result["encrypted_filepath"])
        
        cleanup_files.append(result["encrypted_filepath"])

    def test_encrypt_file_creates_metadata(self, file_encryption_module, test_file, cleanup_files):
        """Test that encryption creates encrypted metadata."""
        password = "TestPassword123!"
        
        result = file_encryption_module.encrypt_file(test_file, password)
        
        assert "encrypted_metadata" in result
        assert "nonce" in result["encrypted_metadata"]
        assert "encrypted_metadata" in result["encrypted_metadata"]
        assert "metadata_hash" in result["encrypted_metadata"]
        
        cleanup_files.append(result["encrypted_filepath"])

    def test_encrypt_file_wraps_fek(self, file_encryption_module, test_file, cleanup_files):
        """Test that encryption wraps FEK."""
        password = "TestPassword123!"
        
        result = file_encryption_module.encrypt_file(test_file, password)
        
        assert "encrypted_fek" in result
        assert isinstance(result["encrypted_fek"], str)  # base64-encoded
        
        cleanup_files.append(result["encrypted_filepath"])

    def test_encrypt_file_generates_unique_nonces(self, file_encryption_module, test_file, cleanup_files):
        """Test that each encryption uses unique nonce."""
        password = "TestPassword123!"
        
        result1 = file_encryption_module.encrypt_file(test_file, password)
        result2 = file_encryption_module.encrypt_file(test_file, password)
        
        # Extract nonces from metadata
        nonce1 = result1["encrypted_metadata"]["nonce"]
        nonce2 = result2["encrypted_metadata"]["nonce"]
        
        # Nonces should be different
        assert nonce1 != nonce2
        
        cleanup_files.append(result1["encrypted_filepath"])
        cleanup_files.append(result2["encrypted_filepath"])

    def test_encrypt_file_computes_hash(self, file_encryption_module, test_file, cleanup_files):
        """Test that encryption computes file hash."""
        password = "TestPassword123!"
        
        result = file_encryption_module.encrypt_file(test_file, password)
        
        assert "file_hash" in result
        assert isinstance(result["file_hash"], str)
        assert len(result["file_hash"]) == 64  # SHA-256 hex string
        
        cleanup_files.append(result["encrypted_filepath"])

    def test_encrypt_file_with_large_file(self, file_encryption_module, test_large_file, cleanup_files):
        """Test encryption of large files (streaming)."""
        password = "TestPassword123!"
        
        result = file_encryption_module.encrypt_file(test_large_file, password)
        
        assert result is not None
        assert os.path.getsize(result["encrypted_filepath"]) > 0
        
        cleanup_files.append(result["encrypted_filepath"])

    def test_encrypt_file_missing_file_raises_error(self, file_encryption_module):
        """Test that encrypting non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            file_encryption_module.encrypt_file("/nonexistent/file.txt", "password")

    def test_encrypt_file_empty_password_raises_error(self, file_encryption_module, test_file):
        """Test that empty password raises ValueError."""
        with pytest.raises(ValueError):
            file_encryption_module.encrypt_file(test_file, "")


class TestFileDecryption:
    """Tests for file decryption functionality."""

    def test_decrypt_file_success(self, file_encryption_module, test_file, cleanup_files):
        """Test successful file decryption."""
        password = "TestPassword123!"
        
        # Encrypt
        enc_result = file_encryption_module.encrypt_file(test_file, password)
        enc_file = enc_result["encrypted_filepath"]
        
        # Decrypt
        dec_result = file_encryption_module.decrypt_file(enc_file, password, enc_result)
        
        assert dec_result is not None
        assert "decrypted_filepath" in dec_result
        assert os.path.exists(dec_result["decrypted_filepath"])
        assert dec_result["integrity_verified"] is True
        
        cleanup_files.append(enc_file)
        cleanup_files.append(dec_result["decrypted_filepath"])

    def test_decrypt_file_restores_filename(self, file_encryption_module, test_file, cleanup_files):
        """Test that decryption restores original filename."""
        password = "TestPassword123!"
        original_filename = os.path.basename(test_file)
        
        # Encrypt
        enc_result = file_encryption_module.encrypt_file(test_file, password)
        enc_file = enc_result["encrypted_filepath"]
        
        # Decrypt
        dec_result = file_encryption_module.decrypt_file(enc_file, password, enc_result)
        
        assert dec_result["original_filename"] == original_filename
        
        cleanup_files.append(enc_file)
        cleanup_files.append(dec_result["decrypted_filepath"])

    def test_decrypt_file_roundtrip(self, file_encryption_module, test_file, cleanup_files):
        """Test encrypt-decrypt roundtrip preserves content."""
        password = "TestPassword123!"
        
        # Read original content
        with open(test_file, 'rb') as f:
            original_content = f.read()
        
        # Encrypt
        enc_result = file_encryption_module.encrypt_file(test_file, password)
        enc_file = enc_result["encrypted_filepath"]
        
        # Decrypt
        dec_result = file_encryption_module.decrypt_file(enc_file, password, enc_result)
        dec_file = dec_result["decrypted_filepath"]
        
        # Read decrypted content
        with open(dec_file, 'rb') as f:
            decrypted_content = f.read()
        
        # Content should match
        assert original_content == decrypted_content
        
        cleanup_files.append(enc_file)
        cleanup_files.append(dec_file)

    def test_decrypt_file_wrong_password_fails(self, file_encryption_module, test_file, cleanup_files):
        """Test that decryption with wrong password fails."""
        correct_password = "TestPassword123!"
        wrong_password = "WrongPassword456!"
        
        # Encrypt
        enc_result = file_encryption_module.encrypt_file(test_file, correct_password)
        enc_file = enc_result["encrypted_filepath"]
        
        # Decrypt with wrong password
        with pytest.raises((ValueError, Exception)):
            file_encryption_module.decrypt_file(enc_file, wrong_password, enc_result)
        
        cleanup_files.append(enc_file)

    def test_decrypt_file_missing_file_raises_error(self, file_encryption_module):
        """Test that decrypting non-existent file raises FileNotFoundError."""
        dummy_result = {
            "master_key_salt": "dummy",
            "encrypted_fek": "dummy",
            "encrypted_metadata": {},
            "file_hash": "dummy",
            "file_hmac": "dummy"
        }
        with pytest.raises(FileNotFoundError):
            file_encryption_module.decrypt_file("/nonexistent/file.enc", "password", dummy_result)

    def test_decrypt_file_detects_tampering(self, file_encryption_module, test_file, cleanup_files):
        """Test that tampering detection works."""
        password = "TestPassword123!"
        
        # Encrypt
        enc_result = file_encryption_module.encrypt_file(test_file, password)
        enc_file = enc_result["encrypted_filepath"]
        
        # Tamper with encrypted file
        with open(enc_file, 'r+b') as f:
            f.seek(1100)  # Past header
            f.write(b'tampered')
        
        # Attempt to decrypt - should fail due to integrity check
        with pytest.raises(FileIntegrityError):
            file_encryption_module.decrypt_file(enc_file, password, enc_result)
        
        cleanup_files.append(enc_file)

    def test_decrypt_file_with_large_file(self, file_encryption_module, test_large_file, cleanup_files):
        """Test decryption of large files (streaming)."""
        password = "TestPassword123!"
        
        # Encrypt
        enc_result = file_encryption_module.encrypt_file(test_large_file, password)
        enc_file = enc_result["encrypted_filepath"]
        
        # Decrypt
        dec_result = file_encryption_module.decrypt_file(enc_file, password, enc_result)
        
        # Verify integrity
        assert dec_result["integrity_verified"] is True
        assert dec_result["authenticity_verified"] is True
        
        cleanup_files.append(enc_file)
        cleanup_files.append(dec_result["decrypted_filepath"])


class TestKeyWrapping:
    """Tests for FEK key wrapping/unwrapping."""

    def test_wrap_key_success(self, key_wrapper=None, file_encryption_key=None, master_key=None):
        """Test successful key wrapping."""
        if key_wrapper is None:
            key_wrapper = KeyWrapper()
        if file_encryption_key is None:
            file_encryption_key = os.urandom(32)
        if master_key is None:
            master_key = os.urandom(32)
        
        wrapped = key_wrapper.encrypt_key_with_master_key(file_encryption_key, master_key)
        
        assert wrapped is not None
        assert isinstance(wrapped, bytes)
        assert len(wrapped) > 0

    def test_unwrap_key_success(self):
        """Test successful key unwrapping."""
        key_wrapper = KeyWrapper()
        fek = os.urandom(32)
        master_key = os.urandom(32)
        
        wrapped = key_wrapper.encrypt_key_with_master_key(fek, master_key)
        unwrapped = key_wrapper.decrypt_key_with_master_key(wrapped, master_key)
        
        assert unwrapped == fek

    def test_unwrap_wrong_key_fails(self):
        """Test that unwrapping with wrong key fails."""
        key_wrapper = KeyWrapper()
        fek = os.urandom(32)
        correct_key = os.urandom(32)
        wrong_key = os.urandom(32)
        
        wrapped = key_wrapper.encrypt_key_with_master_key(fek, correct_key)
        
        with pytest.raises(Exception):
            key_wrapper.decrypt_key_with_master_key(wrapped, wrong_key)

    def test_key_wrapping_roundtrip(self):
        """Test wrap-unwrap roundtrip."""
        key_wrapper = KeyWrapper()
        original_fek = os.urandom(32)
        master_key = os.urandom(32)
        
        wrapped = key_wrapper.encrypt_key_with_master_key(original_fek, master_key)
        unwrapped = key_wrapper.decrypt_key_with_master_key(wrapped, master_key)
        
        assert unwrapped == original_fek


class TestFileIntegrity:
    """Tests for file integrity and authenticity."""

    def test_calculate_file_hash(self, test_file):
        """Test file hash calculation."""
        file_integrity = FileIntegrity()
        
        hash1 = file_integrity.calculate_file_hash(test_file)
        
        assert hash1 is not None
        assert isinstance(hash1, str)
        assert len(hash1) == 64  # SHA-256 hex string

    def test_file_hash_deterministic(self, test_file):
        """Test that hashing same file produces same hash."""
        file_integrity = FileIntegrity()
        
        hash1 = file_integrity.calculate_file_hash(test_file)
        hash2 = file_integrity.calculate_file_hash(test_file)
        
        assert hash1 == hash2

    def test_file_hash_changes_on_modification(self, test_file_with_content, test_file_content):
        """Test that hash changes when file is modified."""
        file_integrity = FileIntegrity()
        
        # Calculate initial hash
        hash1 = file_integrity.calculate_file_hash(test_file_with_content)
        
        # Modify file
        with open(test_file_with_content, 'a') as f:
            f.write("modified content")
        
        # Calculate new hash
        hash2 = file_integrity.calculate_file_hash(test_file_with_content)
        
        # Hashes should differ
        assert hash1 != hash2

    def test_calculate_file_hmac(self, test_file):
        """Test file HMAC calculation."""
        file_integrity = FileIntegrity()
        key = os.urandom(32)
        
        hmac = file_integrity.calculate_file_hmac(test_file, key)
        
        assert hmac is not None
        assert isinstance(hmac, str)
        assert len(hmac) == 64  # HMAC-SHA256 hex string

    def test_file_hmac_deterministic(self, test_file):
        """Test that HMAC with same key produces same value."""
        file_integrity = FileIntegrity()
        key = os.urandom(32)
        
        hmac1 = file_integrity.calculate_file_hmac(test_file, key)
        hmac2 = file_integrity.calculate_file_hmac(test_file, key)
        
        assert hmac1 == hmac2

    def test_file_hmac_different_keys_different_values(self, test_file):
        """Test that different keys produce different HMACs."""
        file_integrity = FileIntegrity()
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        
        hmac1 = file_integrity.calculate_file_hmac(test_file, key1)
        hmac2 = file_integrity.calculate_file_hmac(test_file, key2)
        
        assert hmac1 != hmac2

    def test_verify_file_integrity_success(self, test_file):
        """Test successful integrity verification."""
        file_integrity = FileIntegrity()
        
        expected_hash = file_integrity.calculate_file_hash(test_file)
        is_valid = file_integrity.verify_file_integrity(test_file, expected_hash)
        
        assert is_valid is True

    def test_verify_file_integrity_failure(self, test_file):
        """Test integrity verification failure."""
        file_integrity = FileIntegrity()
        
        wrong_hash = "0" * 64  # Invalid hash
        is_valid = file_integrity.verify_file_integrity(test_file, wrong_hash)
        
        assert is_valid is False

    def test_verify_file_authenticity_success(self, test_file):
        """Test successful authenticity verification."""
        file_integrity = FileIntegrity()
        key = os.urandom(32)
        
        expected_hmac = file_integrity.calculate_file_hmac(test_file, key)
        is_authentic = file_integrity.verify_file_authenticity(test_file, expected_hmac, key)
        
        assert is_authentic is True

    def test_verify_file_authenticity_failure_wrong_hmac(self, test_file):
        """Test authenticity verification failure with wrong HMAC."""
        file_integrity = FileIntegrity()
        key = os.urandom(32)
        
        wrong_hmac = "0" * 64  # Invalid HMAC
        is_authentic = file_integrity.verify_file_authenticity(test_file, wrong_hmac, key)
        
        assert is_authentic is False


class TestMetadataEncryption:
    """Tests for metadata encryption."""

    def test_encrypt_metadata_success(self):
        """Test successful metadata encryption."""
        meta_enc = MetadataEncryption()
        master_key = os.urandom(32)
        
        result = meta_enc.encrypt_metadata(
            "test.pdf", 5000, "application/pdf", master_key
        )
        
        assert "encrypted_metadata" in result
        assert "nonce" in result
        assert "metadata_hash" in result

    def test_decrypt_metadata_success(self):
        """Test successful metadata decryption."""
        meta_enc = MetadataEncryption()
        master_key = os.urandom(32)
        
        encrypted = meta_enc.encrypt_metadata(
            "test.pdf", 5000, "application/pdf", master_key
        )
        decrypted = meta_enc.decrypt_metadata(encrypted, master_key)
        
        assert decrypted["filename"] == "test.pdf"
        assert decrypted["file_size"] == 5000
        assert decrypted["mime_type"] == "application/pdf"

    def test_metadata_encrypt_decrypt_roundtrip(self):
        """Test metadata roundtrip."""
        meta_enc = MetadataEncryption()
        master_key = os.urandom(32)
        
        original_filename = "document.docx"
        original_size = 50000
        original_mime = "application/vnd.openxmlformats"
        
        encrypted = meta_enc.encrypt_metadata(
            original_filename, original_size, original_mime, master_key
        )
        decrypted = meta_enc.decrypt_metadata(encrypted, master_key)
        
        assert decrypted["filename"] == original_filename
        assert decrypted["file_size"] == original_size
        assert decrypted["mime_type"] == original_mime

    def test_metadata_hash_validates(self):
        """Test metadata hash validation."""
        meta_enc = MetadataEncryption()
        master_key = os.urandom(32)
        
        encrypted = meta_enc.encrypt_metadata(
            "test.pdf", 5000, "application/pdf", master_key
        )
        decrypted = meta_enc.decrypt_metadata(encrypted, master_key)
        
        is_valid = meta_enc.validate_metadata_hash(
            decrypted, encrypted["metadata_hash"]
        )
        assert is_valid is True

    def test_metadata_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        meta_enc = MetadataEncryption()
        correct_key = os.urandom(32)
        wrong_key = os.urandom(32)
        
        encrypted = meta_enc.encrypt_metadata(
            "test.pdf", 5000, "application/pdf", correct_key
        )
        
        with pytest.raises(Exception):
            meta_enc.decrypt_metadata(encrypted, wrong_key)


class TestFileSharing:
    """Tests for file sharing functionality."""

    def test_share_file_with_recipient(self):
        """Test sharing file with recipient."""
        sharing = FileSharing(user_id="alice")
        fek = os.urandom(32)
        master_key = os.urandom(32)
        
        # Generate RSA keys
        recipient_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        recipient_public = recipient_private.public_key()
        
        share = sharing.share_file_with_recipient(
            file_id="file123",
            encrypted_fek=fek,
            recipient_pubkey=recipient_public,
            recipient_id="bob"
        )
        
        assert share is not None
        assert share["file_id"] == "file123"
        assert share["recipient_id"] == "bob"
        assert "encrypted_fek" in share

    def test_receive_shared_file(self):
        """Test recipient receiving shared file."""
        sharing = FileSharing(user_id="alice")
        fek = os.urandom(32)
        
        # Generate RSA keys
        recipient_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        recipient_public = recipient_private.public_key()
        
        # Share file
        share = sharing.share_file_with_recipient(
            file_id="file123",
            encrypted_fek=fek,
            recipient_pubkey=recipient_public,
            recipient_id="bob"
        )
        
        # Recipient receives shared file
        received_fek = sharing.receive_shared_file(share, recipient_private)
        
        assert received_fek == fek

    def test_revoke_file_access(self):
        """Test access revocation."""
        sharing = FileSharing(user_id="alice")
        fek = os.urandom(32)
        
        # Generate RSA keys
        recipient_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        recipient_public = recipient_private.public_key()
        
        # Share file
        sharing.share_file_with_recipient(
            file_id="file123",
            encrypted_fek=fek,
            recipient_pubkey=recipient_public,
            recipient_id="bob"
        )
        
        # Revoke access
        revoked = sharing.revoke_file_access("file123", "bob")
        assert revoked is True
        
        # Verify access is revoked
        shares = sharing.get_file_shares("file123")
        assert len(shares) == 0

    def test_get_file_shares(self):
        """Test retrieving file shares."""
        sharing = FileSharing(user_id="alice")
        fek = os.urandom(32)
        
        # Generate RSA keys
        recipient_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        recipient_public = recipient_private.public_key()
        
        # Share file with two recipients
        sharing.share_file_with_recipient(
            file_id="file123",
            encrypted_fek=fek,
            recipient_pubkey=recipient_public,
            recipient_id="bob"
        )
        sharing.share_file_with_recipient(
            file_id="file123",
            encrypted_fek=fek,
            recipient_pubkey=recipient_public,
            recipient_id="charlie"
        )
        
        shares = sharing.get_file_shares("file123")
        assert len(shares) == 2


class TestEncryptionStatistics:
    """Tests for encryption statistics tracking."""

    def test_statistics_updated_after_encryption(self, file_encryption_module, test_file, cleanup_files):
        """Test that statistics are updated after encryption."""
        initial_count = file_encryption_module.statistics.files_encrypted
        
        result = file_encryption_module.encrypt_file(test_file, "password")
        
        assert file_encryption_module.statistics.files_encrypted == initial_count + 1
        
        cleanup_files.append(result["encrypted_filepath"])

    def test_statistics_updated_after_decryption(self, file_encryption_module, test_file, cleanup_files):
        """Test that statistics are updated after decryption."""
        # Encrypt
        enc_result = file_encryption_module.encrypt_file(test_file, "password")
        enc_file = enc_result["encrypted_filepath"]
        
        initial_count = file_encryption_module.statistics.files_decrypted
        
        # Decrypt
        dec_result = file_encryption_module.decrypt_file(enc_file, "password", enc_result)
        
        assert file_encryption_module.statistics.files_decrypted == initial_count + 1
        assert file_encryption_module.statistics.integrity_checks_passed > 0
        
        cleanup_files.append(enc_file)
        cleanup_files.append(dec_result["decrypted_filepath"])


class TestErrorHandling:
    """Tests for error handling."""

    def test_encrypt_file_with_unsupported_cipher(self, file_encryption_module, test_file):
        """Test error handling for unsupported cipher."""
        with pytest.raises(ValueError):
            file_encryption_module.encrypt_file(
                test_file, "password", cipher_type="UnsupportedCipher"
            )

    def test_decrypt_with_missing_encryption_result(self, file_encryption_module, test_file):
        """Test error handling when encryption_result is missing."""
        with pytest.raises(ValueError):
            file_encryption_module.decrypt_file(test_file, "password", None)

    def test_metadata_encryption_with_invalid_key_size(self):
        """Test error handling for invalid key size."""
        meta_enc = MetadataEncryption()
        invalid_key = os.urandom(16)  # Should be 32
        
        with pytest.raises(ValueError):
            meta_enc.encrypt_metadata("file.txt", 100, "text/plain", invalid_key)
