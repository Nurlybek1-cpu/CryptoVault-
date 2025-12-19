# AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)

## Overview

**AES-GCM** is an authenticated encryption algorithm that combines the AES block cipher in Counter (CTR) mode with the Galois Message Authentication Code (GMAC). It provides both **confidentiality** (encryption) and **authenticity** (integrity) in a single, efficient operation.

## Purpose

- **Authenticated Encryption**: Encrypt and authenticate data simultaneously
- **Integrity Protection**: Detect tampering or modification
- **Additional Authenticated Data (AAD)**: Authenticate metadata without encryption
- **High Performance**: Hardware acceleration available on modern CPUs

## Algorithm Specification

### Key Components

1. **AES Block Cipher**: 128/192/256-bit key
2. **Counter Mode (CTR)**: Turns block cipher into stream cipher
3. **Galois Field Multiplication**: For authentication (GMAC)
4. **Nonce/IV**: 96-bit initialization vector (12 bytes recommended)
5. **Authentication Tag**: 128-bit MAC (can be truncated to 96/64 bits)

### Parameters

| Parameter | Description | Recommended Size |
|-----------|-------------|------------------|
| **Key** | AES encryption key | 256 bits (32 bytes) |
| **Nonce** | Initialization vector | 96 bits (12 bytes) |
| **Plaintext** | Data to encrypt | Variable |
| **AAD** | Additional authenticated data | Variable (optional) |
| **Tag** | Authentication tag | 128 bits (16 bytes) |

## How AES-GCM Works

### Encryption Process

**Input**: 
- Key K (256 bits)
- Nonce N (96 bits)
- Plaintext P (variable length)
- AAD A (optional)

**Output**:
- Ciphertext C (same length as P)
- Authentication Tag T (128 bits)

**Steps**:

1. **Initialize Counter**:
   ```
   Counter = Nonce || 0x00000001
   (96-bit nonce + 32-bit counter starting at 1)
   ```

2. **Generate Authentication Key**:
   ```
   H = AES_K(0^128)  // Encrypt 128 zero bits
   ```

3. **Encrypt Plaintext (CTR Mode)**:
   ```
   For each 128-bit block i:
       Counter_i = Nonce || i
       Keystream_i = AES_K(Counter_i)
       C_i = P_i ⊕ Keystream_i
   ```

4. **Compute Authentication Tag (GMAC)**:
   ```
   GHASH = Galois_field_multiplication(AAD, C, H)
   Tag = GHASH ⊕ AES_K(Nonce || 0x00000001)
   ```

5. **Output**: (Nonce, Ciphertext, Tag)

### Decryption Process

**Input**:
- Key K
- Nonce N
- Ciphertext C
- Tag T_received
- AAD A

**Steps**:

1. **Recompute Authentication Tag**:
   ```
   T_computed = GMAC(AAD, C, H, Nonce)
   ```

2. **Verify Tag**:
   ```
   if T_computed ≠ T_received:
       REJECT (authentication failed)
       return ERROR
   ```

3. **Decrypt Ciphertext**:
   ```
   For each block i:
       Counter_i = Nonce || i
       Keystream_i = AES_K(Counter_i)
       P_i = C_i ⊕ Keystream_i
   ```

4. **Output**: Plaintext P (if authentication succeeds)

## Implementation Example

### Python Implementation

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class AESGCMCipher:
    def __init__(self, key=None):
        """Initialize AES-GCM with key"""
        if key is None:
            # Generate random 256-bit key
            key = AESGCM.generate_key(bit_length=256)
        self.key = key
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext, aad=b''):
        """Encrypt with AES-GCM"""
        # Generate random 96-bit nonce
        nonce = os.urandom(12)

        # Encrypt and authenticate
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, aad)

        # Return nonce + ciphertext (tag is appended by library)
        return nonce + ciphertext

    def decrypt(self, encrypted_data, aad=b''):
        """Decrypt with AES-GCM"""
        # Extract nonce (first 12 bytes)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        try:
            # Decrypt and verify
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, aad)
            return plaintext
        except Exception:
            raise ValueError("Authentication failed! Data tampered.")

# Usage Example
cipher = AESGCMCipher()

# Encrypt
message = b"Confidential message"
aad = b"user_id=12345"  # Authenticated but not encrypted
encrypted = cipher.encrypt(message, aad)
print(f"Encrypted ({len(encrypted)} bytes): {encrypted.hex()[:64]}...")

# Decrypt
decrypted = cipher.decrypt(encrypted, aad)
print(f"Decrypted: {decrypted.decode()}")

# Tampering detection
try:
    tampered = encrypted[:-1] + b'ÿ'  # Modify last byte
    cipher.decrypt(tampered, aad)
except ValueError as e:
    print(f"Tampering detected: {e}")
```

### Low-Level Implementation

```python
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

def gcm_encrypt(key, nonce, plaintext, aad=b''):
    """
    Manual AES-GCM encryption

    Args:
        key: 32-byte AES-256 key
        nonce: 12-byte nonce
        plaintext: data to encrypt
        aad: additional authenticated data

    Returns:
        (ciphertext, tag)
    """
    # Create AES cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Add AAD
    if aad:
        cipher.update(aad)

    # Encrypt
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return ciphertext, tag

def gcm_decrypt(key, nonce, ciphertext, tag, aad=b''):
    """
    Manual AES-GCM decryption

    Raises:
        ValueError: If authentication fails
    """
    # Create AES cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Add AAD
    if aad:
        cipher.update(aad)

    # Decrypt and verify
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext

# Example
key = os.urandom(32)
nonce = os.urandom(12)
plaintext = b"Secret data"
aad = b"metadata: file_id=42"

ciphertext, tag = gcm_encrypt(key, nonce, plaintext, aad)
decrypted = gcm_decrypt(key, nonce, ciphertext, tag, aad)

assert decrypted == plaintext
```

### Node.js Implementation

```javascript
const crypto = require('crypto');

class AESGCMCipher {
    constructor(key) {
        // Generate 256-bit key if not provided
        this.key = key || crypto.randomBytes(32);
    }

    encrypt(plaintext, aad = Buffer.alloc(0)) {
        // Generate random nonce
        const nonce = crypto.randomBytes(12);

        // Create cipher
        const cipher = crypto.createCipheriv('aes-256-gcm', this.key, nonce);

        // Set AAD
        if (aad.length > 0) {
            cipher.setAAD(aad);
        }

        // Encrypt
        let encrypted = cipher.update(plaintext);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        // Get authentication tag
        const tag = cipher.getAuthTag();

        // Return nonce + encrypted + tag
        return Buffer.concat([nonce, encrypted, tag]);
    }

    decrypt(encryptedData, aad = Buffer.alloc(0)) {
        // Extract components
        const nonce = encryptedData.slice(0, 12);
        const tag = encryptedData.slice(-16);
        const ciphertext = encryptedData.slice(12, -16);

        // Create decipher
        const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, nonce);

        // Set AAD and tag
        if (aad.length > 0) {
            decipher.setAAD(aad);
        }
        decipher.setAuthTag(tag);

        // Decrypt
        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return decrypted;
    }
}

// Usage
const cipher = new AESGCMCipher();
const encrypted = cipher.encrypt(Buffer.from('Hello World'));
const decrypted = cipher.decrypt(encrypted);
console.log(decrypted.toString()); // "Hello World"
```

## Security Considerations

### Strengths

1. **Authenticated Encryption**: Single operation for encryption + integrity
2. **Parallelizable**: Can encrypt/decrypt blocks in parallel
3. **Hardware Acceleration**: Intel AES-NI + PCLMULQDQ instructions
4. **Nonce Misuse Resistance**: Better than CBC (but still critical)
5. **Standardized**: NIST SP 800-38D, RFC 5288, TLS 1.3

### Critical Requirements

**1. Nonce Uniqueness**

⚠️ **NEVER REUSE (KEY, NONCE) PAIR**

```python
# WRONG - Catastrophic failure
nonce = b' ' * 12  # Fixed nonce
cipher.encrypt(message1, nonce)  # 
cipher.encrypt(message2, nonce)  # DISASTER!

# CORRECT - Random or counter-based nonce
nonce = os.urandom(12)  # Random
# OR
nonce = counter.to_bytes(12, 'big')  # Counter
```

**Why**: Nonce reuse leaks XOR of plaintexts and destroys authentication

**2. Tag Verification**

```python
def decrypt_safely(encrypted_data, key, aad):
    """Always verify tag before returning plaintext"""
    try:
        plaintext = decrypt_and_verify(encrypted_data, key, aad)
        return plaintext
    except AuthenticationError:
        # DO NOT return partial plaintext
        return None
```

**3. Key Management**

- **Key Size**: Use AES-256 (32 bytes) for maximum security
- **Key Derivation**: Use HKDF/PBKDF2 if deriving from password
- **Key Rotation**: Limit encryptions per key (2^32 max recommended)

### Vulnerabilities

| Attack | Mitigation |
|--------|------------|
| **Nonce Reuse** | Use random nonces or counters |
| **Forbidden Attack** | Limit messages encrypted per key |
| **Tag Truncation** | Always use 128-bit tags (never truncate) |
| **AAD Manipulation** | Include all metadata in AAD |

## Performance

### Benchmarks (Software)

| Key Size | Throughput | Latency |
|----------|------------|---------|
| AES-128-GCM | ~1-2 GB/s | ~1 μs/block |
| AES-256-GCM | ~0.8-1.5 GB/s | ~1.2 μs/block |

### Hardware Acceleration

Modern CPUs with AES-NI + PCLMULQDQ:
- **Throughput**: 5-10 GB/s
- **Latency**: ~100 ns/block

```python
# Enable hardware acceleration (automatic in most libraries)
from cryptography.hazmat.backends import default_backend
backend = default_backend()
# Automatically uses AES-NI if available
```

## Real-World Applications

### TLS 1.3

```python
# TLS 1.3 cipher suite
TLS_AES_256_GCM_SHA384 = {
    'encryption': 'AES-256-GCM',
    'key_size': 256,
    'nonce': 'TLS_sequence_number',
    'aad': 'TLS_record_header'
}
```

### File Encryption

```python
def encrypt_file(input_file, output_file, key):
    """Encrypt file with AES-GCM"""
    cipher = AESGCMCipher(key)

    with open(input_file, 'rb') as f_in:
        data = f_in.read()

    # Use filename as AAD
    aad = os.path.basename(input_file).encode()
    encrypted = cipher.encrypt(data, aad)

    with open(output_file, 'wb') as f_out:
        f_out.write(encrypted)
```

### Database Encryption

```python
class EncryptedDatabase:
    def __init__(self, key):
        self.cipher = AESGCMCipher(key)

    def encrypt_field(self, value, record_id):
        """Encrypt database field"""
        # Use record_id as AAD for integrity
        aad = f"record_id={record_id}".encode()
        return self.cipher.encrypt(value.encode(), aad)

    def decrypt_field(self, encrypted, record_id):
        aad = f"record_id={record_id}".encode()
        return self.cipher.decrypt(encrypted, aad).decode()
```

## AES-GCM vs Alternatives

| Algorithm | Speed | Security | Parallelizable | Use Case |
|-----------|-------|----------|----------------|----------|
| **AES-GCM** | Very Fast | Excellent | Yes | TLS, VPN, Disk |
| **ChaCha20-Poly1305** | Fast | Excellent | Yes | Mobile, IoT |
| **AES-CBC-HMAC** | Slow | Good | No (CBC) | Legacy |
| **AES-CCM** | Medium | Good | No | Constrained |

## Best Practices

1. ✅ **Use 96-bit (12-byte) nonces** for optimal performance
2. ✅ **Generate random nonces** with CSPRNG
3. ✅ **Always verify tags** before using decrypted data
4. ✅ **Include all metadata in AAD** (user IDs, timestamps, etc.)
5. ✅ **Use 128-bit authentication tags** (never truncate)
6. ✅ **Limit encryptions per key** to 2^32 operations
7. ✅ **Use AES-256** for maximum security
8. ❌ **Never reuse nonces** with the same key
9. ❌ **Never decrypt without verifying** the tag first

## Conclusion

AES-GCM is the **gold standard** for authenticated encryption in modern cryptography. It provides:

- **Security**: Confidentiality + integrity in one operation
- **Performance**: Hardware acceleration on modern CPUs
- **Simplicity**: Single API call for encrypt + authenticate
- **Standardization**: Widely supported (TLS 1.3, IPsec, HTTP/3)

**Use AES-GCM for**:
- TLS/SSL connections
- VPN tunnels (WireGuard, IPsec)
- Database encryption
- File encryption
- API request/response encryption

**Critical**: Proper nonce management is essential. Use random nonces or counters, never reuse.
