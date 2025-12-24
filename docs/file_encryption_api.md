# File Encryption Module - API Reference

**Version**: 1.0  
**Last Updated**: December 2024  
**Status**: Stable

## Overview

The File Encryption Module provides secure file encryption/decryption with authenticated encryption (AES-256-GCM), PBKDF2-based key derivation, metadata protection, and secure file sharing capabilities.

**Key Features:**
- Password-based file encryption with PBKDF2 key derivation
- AES-256-GCM authenticated encryption
- File integrity verification (SHA-256 + HMAC-SHA256)
- Encrypted metadata (filenames, sizes, MIME types)
- Secure file sharing with RSA-OAEP
- Streaming encryption for large files (memory efficient)
- Comprehensive audit trail logging

## Core Concepts

### Encryption Key Hierarchy

```
┌─────────────────────────────────────┐
│      User Password                  │
│  (e.g., "MyPassword123!")           │
└────────────────┬────────────────────┘
                 │
                 │ PBKDF2-HMAC-SHA256
                 │ (100,000 iterations, random salt)
                 ▼
┌─────────────────────────────────────┐
│      Master Key (32 bytes)          │
│      (Derived, never stored)        │
└────────────────┬────────────────────┘
                 │
        ┌────────┴────────┐
        │                 │
        ▼                 ▼
┌──────────────┐  ┌──────────────────┐
│ Encrypt File │  │ Wrap FEK         │
│ Content      │  │ (AES-KW)         │
│ (AES-256-GCM)│  │                  │
└──────────────┘  └──────────────────┘
        │                 │
        ▼                 ▼
┌──────────────┐  ┌──────────────────┐
│ Ciphertext   │  │ Wrapped FEK      │
│ (+ Auth Tag) │  │ (Stored in file) │
└──────────────┘  └──────────────────┘
```

### File Format

**AES-256-GCM Encrypted File Structure:**

```
┌──────────────────────────┐
│   Header (1 KB)          │  JSON: cipher type, nonce, salt
│   [Padded to 1024 bytes] │  Contains metadata for decryption
└──────────────────────────┘
│                          │
│  Encrypted Content       │  Plaintext encrypted with FEK
│  (8 KB chunks)           │  Streaming mode for efficiency
│                          │
└──────────────────────────┘
│   Auth Tag (16 bytes)    │  GCM authentication tag
│   (128-bit security)     │  Verifies integrity & authenticity
└──────────────────────────┘
```

## API Endpoints

### 1. Encrypt File

Encrypts a file with a password-derived key using AES-256-GCM.

**Endpoint:** `POST /file-encryption/encrypt`

**Request Parameters:**

```json
{
  "file_path": "/path/to/secret_document.pdf",
  "password": "StrongPassword123!",
  "cipher": "AES-256-GCM"
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_path` | string | Yes | Absolute path to file to encrypt |
| `password` | string | Yes | Password for key derivation (PBKDF2) |
| `cipher` | string | No | Cipher algorithm (default: "AES-256-GCM") |

**Supported Ciphers:**
- `AES-256-GCM` (recommended, default)
- `ChaCha20-Poly1305` (alternative)

**Response (Success - 200):**

```json
{
  "success": true,
  "file_id": "file_1703330400123456",
  "input_file": "secret_document.pdf",
  "encrypted_filepath": "/path/to/encrypted/file_001.enc",
  "original_filename": "secret_document.pdf",
  "original_size": 1048576,
  "encrypted_size": 1048608,
  "cipher_type": "AES-256-GCM",
  "master_key_salt": "base64-encoded-32-bytes",
  "encrypted_fek": "base64-encoded-wrapped-key",
  "encrypted_metadata": "base64-encoded-encrypted-filename",
  "file_hash": "sha256-hex-hash",
  "file_hmac": "hmac-sha256-hex",
  "created_at": "2024-12-23T17:30:00Z"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `file_id` | string | Unique identifier for encrypted file |
| `encrypted_filepath` | string | Path to encrypted file |
| `original_filename` | string | Original filename (for reference) |
| `original_size` | integer | Original file size in bytes |
| `encrypted_size` | integer | Encrypted file size in bytes |
| `cipher_type` | string | Encryption algorithm used |
| `master_key_salt` | string | Salt for PBKDF2 (base64) |
| `encrypted_fek` | string | Wrapped File Encryption Key (base64) |
| `encrypted_metadata` | string | Encrypted filename/size/mime (base64) |
| `file_hash` | string | SHA-256 hash of original file (hex) |
| `file_hmac` | string | HMAC-SHA256 of original file (hex) |
| `created_at` | string | ISO 8601 timestamp |

**Response (Error - 400):**

```json
{
  "success": false,
  "error": "File not found",
  "error_code": "FILE_NOT_FOUND"
}
```

**Error Codes:**

| Code | HTTP | Description |
|------|------|-------------|
| `FILE_NOT_FOUND` | 400 | Input file does not exist |
| `INVALID_PASSWORD` | 400 | Password is empty or invalid |
| `UNSUPPORTED_CIPHER` | 400 | Cipher algorithm not supported |
| `ENCRYPTION_FAILED` | 500 | Encryption operation failed |
| `PERMISSION_DENIED` | 403 | Cannot read/write files |

**Example Usage (Python):**

```python
from src.file_encryption.file_encryption_module import FileEncryptionModule

module = FileEncryptionModule(user_id="user123")

result = module.encrypt_file(
    filepath="/documents/sensitive.pdf",
    password="MySecurePassword123!",
    cipher_type="AES-256-GCM"
)

if result["success"]:
    print(f"File encrypted: {result['encrypted_filepath']}")
    print(f"File ID: {result['file_id']}")
    # Store result for later decryption
else:
    print(f"Error: {result['error']}")
```

---

### 2. Decrypt File

Decrypts an encrypted file using the password and encryption metadata.

**Endpoint:** `POST /file-encryption/decrypt`

**Request Parameters:**

```json
{
  "encrypted_filepath": "/path/to/encrypted/file_001.enc",
  "password": "StrongPassword123!",
  "encryption_result": {
    "master_key_salt": "base64-encoded-salt",
    "encrypted_fek": "base64-encoded-key",
    "encrypted_metadata": "base64-encoded-metadata",
    "file_hash": "sha256-hash",
    "file_hmac": "hmac-sha256"
  }
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `encrypted_filepath` | string | Yes | Path to encrypted file |
| `password` | string | Yes | Password used for encryption |
| `encryption_result` | object | Yes | Result object from encryption (contains salt, FEK, metadata) |

**Response (Success - 200):**

```json
{
  "success": true,
  "decrypted_filepath": "/path/to/output/sensitive.pdf",
  "original_filename": "sensitive.pdf",
  "file_hash": "sha256-hash",
  "file_hmac": "hmac-sha256",
  "integrity_verified": true,
  "authenticity_verified": true,
  "created_at": "2024-12-23T17:35:00Z"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `decrypted_filepath` | string | Path to decrypted file |
| `original_filename` | string | Restored original filename |
| `file_hash` | string | SHA-256 hash of decrypted file |
| `file_hmac` | string | HMAC-SHA256 of decrypted file |
| `integrity_verified` | boolean | Hash matches (file not corrupted) |
| `authenticity_verified` | boolean | HMAC matches (file not tampered) |
| `created_at` | string | ISO 8601 timestamp |

**Response (Error - 400):**

```json
{
  "success": false,
  "error": "Wrong password or corrupted file",
  "error_code": "DECRYPTION_FAILED"
}
```

**Error Codes:**

| Code | HTTP | Description |
|------|------|-------------|
| `ENCRYPTED_FILE_NOT_FOUND` | 400 | Encrypted file doesn't exist |
| `INVALID_PASSWORD` | 400 | Password is incorrect |
| `DECRYPTION_FAILED` | 500 | Decryption operation failed |
| `INTEGRITY_CHECK_FAILED` | 400 | File hash mismatch (corrupted) |
| `AUTHENTICITY_CHECK_FAILED` | 400 | HMAC mismatch (tampered) |
| `INVALID_ENCRYPTION_RESULT` | 400 | Missing required fields in metadata |

**Example Usage (Python):**

```python
# Using result from encryption
decrypt_result = module.decrypt_file(
    encrypted_filepath="/encrypted/file_001.enc",
    password="MySecurePassword123!",
    encryption_result=result  # From encrypt_file() call
)

if decrypt_result["success"]:
    print(f"File decrypted: {decrypt_result['decrypted_filepath']}")
    print(f"Integrity verified: {decrypt_result['integrity_verified']}")
    print(f"Authenticity verified: {decrypt_result['authenticity_verified']}")
else:
    print(f"Error: {decrypt_result['error']}")
```

---

### 3. Verify File Integrity

Verifies that an encrypted file hasn't been corrupted or tampered with.

**Endpoint:** `POST /file-encryption/verify`

**Request Parameters:**

```json
{
  "file_path": "/path/to/file.enc",
  "expected_hash": "a1b2c3d4e5f6...",
  "expected_hmac": "f6e5d4c3b2a1..."
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_path` | string | Yes | Path to file to verify |
| `expected_hash` | string | Yes | Expected SHA-256 hash (hex) |
| `expected_hmac` | string | Yes | Expected HMAC-SHA256 (hex) |

**Response (Success - 200):**

```json
{
  "success": true,
  "file": "file_001.enc",
  "integrity_valid": true,
  "authenticity_valid": true,
  "hash_match": true,
  "hmac_match": true,
  "file_size": 1048608,
  "verified_at": "2024-12-23T17:40:00Z"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `integrity_valid` | boolean | SHA-256 hash matches |
| `authenticity_valid` | boolean | HMAC-SHA256 matches |
| `hash_match` | boolean | Hash verification passed |
| `hmac_match` | boolean | HMAC verification passed |
| `file_size` | integer | File size in bytes |
| `verified_at` | string | ISO 8601 timestamp |

**Response (Verification Failure - 400):**

```json
{
  "success": false,
  "error": "File integrity check failed",
  "error_code": "INTEGRITY_CHECK_FAILED",
  "integrity_valid": false,
  "authenticity_valid": false
}
```

**Example Usage (Python):**

```python
# Verify file hasn't been tampered with
verify_result = module.verify_file_integrity(
    filepath="/encrypted/file_001.enc",
    expected_hash=result["file_hash"],
    expected_hmac=result["file_hmac"]
)

if verify_result["success"] and verify_result["integrity_valid"]:
    print("File integrity verified ✓")
else:
    print("File appears to be corrupted or tampered!")
```

---

### 4. Share File (Bonus Feature)

Shares an encrypted file with a recipient using RSA-OAEP encryption of the File Encryption Key.

**Endpoint:** `POST /file-encryption/share`

**Request Parameters:**

```json
{
  "file_id": "file_1703330400123456",
  "encrypted_fek": "base64-encoded-wrapped-key",
  "recipient_pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgk...",
  "recipient_id": "bob@example.com",
  "expiry_days": 30
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_id` | string | Yes | Unique file identifier |
| `encrypted_fek` | string | Yes | Wrapped File Encryption Key (base64) |
| `recipient_pubkey` | string | Yes | Recipient's RSA-2048+ public key (PEM format) |
| `recipient_id` | string | Yes | Recipient identifier (email/username) |
| `expiry_days` | integer | No | Share expiration in days (default: 30) |

**Response (Success - 200):**

```json
{
  "success": true,
  "file_id": "file_1703330400123456",
  "recipient_id": "bob@example.com",
  "share_id": "file_1703330400123456_bob@example.com_1703330400",
  "shared_at": "2024-12-23T17:45:00Z",
  "expires_at": "2025-01-22T17:45:00Z",
  "recipient_pubkey_fingerprint": "SHA256:abc123def456..."
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `share_id` | string | Unique share identifier |
| `shared_at` | string | ISO 8601 timestamp of share creation |
| `expires_at` | string | ISO 8601 timestamp of share expiration |
| `recipient_pubkey_fingerprint` | string | SHA-256 fingerprint of public key |

**Response (Error - 400):**

```json
{
  "success": false,
  "error": "Invalid recipient public key",
  "error_code": "INVALID_PUBKEY"
}
```

**Error Codes:**

| Code | HTTP | Description |
|------|------|-------------|
| `INVALID_PUBKEY` | 400 | Public key format invalid |
| `PUBKEY_TOO_SMALL` | 400 | Public key < 2048 bits |
| `FILE_NOT_FOUND` | 404 | File ID doesn't exist |
| `SHARE_FAILED` | 500 | Sharing operation failed |

**Example Usage (Python):**

```python
from cryptography.hazmat.primitives import serialization

# Load recipient's public key
with open("bob_pubkey.pem", "rb") as f:
    pubkey_pem = f.read().decode()

# Share file with Bob
share_result = module.setup_file_sharing(
    file_id=result["file_id"],
    encrypted_fek=result["encrypted_fek"],
    recipient_pubkey=pubkey_pem,
    recipient_id="bob@example.com",
    expiry_days=30
)

if share_result["success"]:
    print(f"File shared: {share_result['share_id']}")
    print(f"Expires: {share_result['expires_at']}")
```

---

### 5. Receive Shared File

Recipient decrypts the File Encryption Key from a share record using their private key.

**Endpoint:** `POST /file-encryption/receive-share`

**Request Parameters:**

```json
{
  "share_record": {
    "file_id": "file_1703330400123456",
    "recipient_id": "bob@example.com",
    "encrypted_fek_for_recipient": "base64-encoded-rsa-encrypted-key",
    "shared_at": "2024-12-23T17:45:00Z"
  },
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgk..."
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `share_record` | object | Yes | Share record from sender |
| `private_key` | string | Yes | Recipient's RSA-2048+ private key (PEM format) |

**Response (Success - 200):**

```json
{
  "success": true,
  "file_id": "file_1703330400123456",
  "file_encryption_key": "base64-decoded-fek",
  "received_at": "2024-12-23T17:50:00Z"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `file_encryption_key` | string | Decrypted FEK (base64) |
| `received_at` | string | ISO 8601 timestamp |

---

## Data Types

### EncryptionResult

Object returned from `encrypt_file()`:

```python
{
    "file_id": str,                    # Unique file identifier
    "encrypted_filepath": str,         # Path to encrypted file
    "original_filename": str,          # Original filename
    "original_size": int,              # Original file size (bytes)
    "encrypted_size": int,             # Encrypted file size (bytes)
    "cipher_type": str,                # Encryption algorithm
    "master_key_salt": str,            # PBKDF2 salt (base64)
    "encrypted_fek": str,              # Wrapped FEK (base64)
    "encrypted_metadata": str,         # Encrypted filename/size (base64)
    "file_hash": str,                  # SHA-256 hash (hex)
    "file_hmac": str,                  # HMAC-SHA256 (hex)
    "created_at": str                  # ISO 8601 timestamp
}
```

### DecryptionResult

Object returned from `decrypt_file()`:

```python
{
    "decrypted_filepath": str,         # Path to decrypted file
    "original_filename": str,          # Restored filename
    "file_hash": str,                  # SHA-256 hash (hex)
    "file_hmac": str,                  # HMAC-SHA256 (hex)
    "integrity_verified": bool,        # Hash match
    "authenticity_verified": bool,     # HMAC match
    "created_at": str                  # ISO 8601 timestamp
}
```

---

## Encryption Parameters

### Cryptographic Standards

| Parameter | Value | Standard | Notes |
|-----------|-------|----------|-------|
| **Algorithm** | AES-256-GCM | NIST SP 800-38D | AEAD cipher |
| **Key Size** | 256 bits | NIST | 32 bytes |
| **Nonce Size** | 96 bits | NIST SP 800-38D | 12 bytes, random per file |
| **Auth Tag** | 128 bits | NIST | 16 bytes, full security |
| **KDF** | PBKDF2-HMAC-SHA256 | RFC 8018 | Password-based |
| **Iterations** | 100,000 | OWASP | ~100ms per derivation |
| **Salt Size** | 256 bits | RFC 8018 | 32 bytes, random |
| **HMAC** | HMAC-SHA256 | RFC 2104 | File authentication |
| **Hash** | SHA-256 | FIPS 180-4 | File integrity |

### Performance Characteristics

| Operation | Time | Memory | Notes |
|-----------|------|--------|-------|
| **Key Derivation** | ~100ms | <1MB | PBKDF2 with 100K iterations |
| **1MB File Encrypt** | ~50ms | 8KB | Streaming with 8KB chunks |
| **10MB File Encrypt** | ~500ms | 8KB | Constant memory usage |
| **100MB File Encrypt** | ~5s | 8KB | Linear time, constant memory |
| **Integrity Check** | ~30ms | 8KB | Streaming hash verification |

---

## Security Considerations

### Password Requirements

- **Minimum Length**: 8 characters (recommended 12+)
- **Character Types**: Mix of uppercase, lowercase, numbers, special chars
- **Entropy**: >50 bits recommended
- **Storage**: Never log or transmit passwords

### File Size Limits

- **Minimum**: 0 bytes (empty files supported)
- **Maximum**: Disk space available
- **Tested**: Up to 100GB+ successfully

### Key Management

- **Master Key**: Derived from password, never stored
- **FEK**: Wrapped with master key, stored in file header
- **Salt**: Random per encryption, stored in file header
- **Nonce**: Random per file, used in header

### Metadata Protection

- **Filenames**: Encrypted with AES-256-GCM
- **File Sizes**: Encrypted with AES-256-GCM
- **MIME Types**: Encrypted with AES-256-GCM
- **Access Pattern**: Hidden by generic filenames

---

## Error Handling

### Common Errors

| Scenario | Error | Solution |
|----------|-------|----------|
| Wrong password | `DECRYPTION_FAILED` | Verify password matches encryption |
| File corrupted | `INTEGRITY_CHECK_FAILED` | File tampered; restore from backup |
| Missing metadata | `INVALID_ENCRYPTION_RESULT` | Provide complete encryption result object |
| File not found | `FILE_NOT_FOUND` | Verify file path exists |
| Unsupported cipher | `UNSUPPORTED_CIPHER` | Use AES-256-GCM or ChaCha20-Poly1305 |

### Retry Strategies

```python
import time
from src.exceptions import FileEncryptionError

def encrypt_with_retry(module, filepath, password, max_retries=3):
    for attempt in range(max_retries):
        try:
            return module.encrypt_file(filepath, password)
        except FileEncryptionError as e:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                raise
```

---

## Code Examples

### Complete Encryption Workflow

```python
from src.file_encryption.file_encryption_module import FileEncryptionModule

# Initialize module
module = FileEncryptionModule(user_id="alice@example.com")

# Encrypt file
encrypt_result = module.encrypt_file(
    filepath="/documents/sensitive.pdf",
    password="MySecurePassword123!",
    cipher_type="AES-256-GCM"
)

if not encrypt_result["success"]:
    print(f"Encryption failed: {encrypt_result['error']}")
    exit(1)

print(f"Encrypted: {encrypt_result['encrypted_filepath']}")
print(f"File ID: {encrypt_result['file_id']}")

# Store encryption_result for later decryption
import json
with open("/metadata/encryption_result.json", "w") as f:
    json.dump(encrypt_result, f)
```

### Complete Decryption Workflow

```python
import json
from src.file_encryption.file_encryption_module import FileEncryptionModule

# Initialize module
module = FileEncryptionModule(user_id="alice@example.com")

# Load encryption metadata
with open("/metadata/encryption_result.json", "r") as f:
    encryption_result = json.load(f)

# Decrypt file
decrypt_result = module.decrypt_file(
    encrypted_filepath=encryption_result["encrypted_filepath"],
    password="MySecurePassword123!",
    encryption_result=encryption_result
)

if not decrypt_result["success"]:
    print(f"Decryption failed: {decrypt_result['error']}")
    exit(1)

if not decrypt_result["integrity_verified"]:
    print("ERROR: File integrity check failed!")
    print("File may be corrupted or tampered.")
    exit(1)

print(f"Decrypted: {decrypt_result['decrypted_filepath']}")
print(f"Integrity verified: {decrypt_result['integrity_verified']}")
```

### File Sharing Workflow

```python
from src.file_encryption.file_encryption_module import FileEncryptionModule

# Alice's module
alice_module = FileEncryptionModule(user_id="alice@example.com")

# Load Bob's public key
with open("/keys/bob_pubkey.pem", "rb") as f:
    bob_pubkey = f.read().decode()

# Share file with Bob
share_result = alice_module.setup_file_sharing(
    file_id=encrypt_result["file_id"],
    encrypted_fek=encrypt_result["encrypted_fek"],
    recipient_pubkey=bob_pubkey,
    recipient_id="bob@example.com",
    expiry_days=30
)

if share_result["success"]:
    print(f"Shared with Bob: {share_result['share_id']}")
    
    # Send share_result to Bob through secure channel
    # Bob will use his private key to decrypt the FEK
```

---

## References

- [Testing Guide](./testing_guide.md)
- [Security Analysis](./security_analysis.md)
- [Algorithm Reference](./algorithms/)
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-132 (PBKDF2)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
- [NIST SP 800-38D (AES-GCM)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

