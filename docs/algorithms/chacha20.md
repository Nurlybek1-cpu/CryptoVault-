# ChaCha20-Poly1305

## Overview

**ChaCha20-Poly1305** is an authenticated encryption algorithm that combines the **ChaCha20** stream cipher with the **Poly1305** message authentication code (MAC). It provides both confidentiality and integrity and is specifically designed for high performance on software platforms without hardware AES acceleration.

## Purpose

- **Authenticated Encryption**: Encrypt and authenticate data in one operation
- **Software Performance**: Fast on CPUs without AES-NI
- **Mobile/IoT Optimized**: Excellent for ARM processors
- **Constant-Time**: Resistant to timing attacks
- **Applications**: TLS 1.3, WireGuard VPN, SSH, Signal

## Algorithm Specification

### Key Components

1. **ChaCha20**: 256-bit key stream cipher
2. **Poly1305**: 128-bit authentication tag (MAC)
3. **Nonce**: 96-bit initialization vector
4. **Counter**: 32-bit block counter

### Parameters

| Parameter | Size | Description |
|-----------|------|-------------|
| **Key** | 256 bits (32 bytes) | Encryption key |
| **Nonce** | 96 bits (12 bytes) | Initialization vector |
| **Counter** | 32 bits | Block counter (starts at 1) |
| **Tag** | 128 bits (16 bytes) | Authentication tag |

## ChaCha20 Stream Cipher

### Core Operation

ChaCha20 operates on a 512-bit (64-byte) state matrix:

```
Initial State (16 x 32-bit words):
┌────────────────────────────────────────┐
│ "expa"  "nd 3"  "2-by"  "te k" │  Constants
│  Key0   Key1    Key2    Key3   │  256-bit key
│  Key4   Key5    Key6    Key7   │
│  Counter Nonce0  Nonce1  Nonce2 │  Counter + Nonce
└────────────────────────────────────────┘
```

### Quarter Round

The basic operation is the "quarter round":

```
QUARTERROUND(a, b, c, d):
    a += b;  d ^= a;  d <<<= 16;
    c += d;  b ^= c;  b <<<= 12;
    a += b;  d ^= a;  d <<<= 8;
    c += d;  b ^= c;  b <<<= 7;
```

### ChaCha20 Block Function

```python
def chacha20_block(key, counter, nonce):
    """
    Generate one 64-byte ChaCha20 keystream block

    Args:
        key: 32-byte key
        counter: 4-byte counter
        nonce: 12-byte nonce

    Returns:
        64-byte keystream block
    """
    # Initialize state
    state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,  # "expand 32-byte k"
        key[0:4],   key[4:8],   key[8:12],  key[12:16],
        key[16:20], key[20:24], key[24:28], key[28:32],
        counter,    nonce[0:4], nonce[4:8], nonce[8:12]
    ]

    working_state = state.copy()

    # 20 rounds (10 double-rounds)
    for i in range(10):
        # Column rounds
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)

        # Diagonal rounds
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)

    # Add original state
    output = [a + b for a, b in zip(state, working_state)]

    return serialize_to_bytes(output)
```

### Encryption Process

```
Keystream Generation:
For each 64-byte block i:
    keystream_i = ChaCha20_Block(key, counter + i, nonce)

Encryption:
For each byte:
    ciphertext[i] = plaintext[i] ⊕ keystream[i]
```

## Poly1305 MAC

### Mathematical Foundation

Poly1305 evaluates a polynomial in GF(2^130 - 5):

```
MAC = ((m[0] · r^n + m[1] · r^(n-1) + ... + m[n-1] · r + s) mod (2^130 - 5)
```

Where:
- `r`: 128-bit key (derived from first 32 bytes of ChaCha20 keystream)
- `s`: 128-bit key (next 16 bytes)
- `m[i]`: Message blocks

### Tag Computation

```python
def poly1305(message, key):
    """
    Compute Poly1305 MAC

    Args:
        message: data to authenticate
        key: 32-byte key (r || s)

    Returns:
        16-byte tag
    """
    # Extract r and s
    r = clamp(key[:16])  # Clamp certain bits
    s = key[16:32]

    # Split message into 16-byte blocks
    blocks = split_into_blocks(message, 16)

    # Polynomial evaluation
    accumulator = 0
    p = (1 << 130) - 5  # Prime modulus

    for block in blocks:
        # Add 0x01 byte to each block
        n = int.from_bytes(block + b'', 'little')
        accumulator = ((accumulator + n) * r) % p

    # Add s
    tag = (accumulator + int.from_bytes(s, 'little')) % (2**128)

    return tag.to_bytes(16, 'little')
```

## ChaCha20-Poly1305 AEAD

### Encryption Process

**Input**:
- Key (32 bytes)
- Nonce (12 bytes)
- Plaintext (variable)
- AAD (optional)

**Steps**:

1. **Generate Poly1305 Key**:
   ```
   poly1305_key = ChaCha20_Block(key, counter=0, nonce)[:32]
   ```

2. **Encrypt Plaintext**:
   ```
   For block i (starting at counter=1):
       keystream = ChaCha20_Block(key, counter=i, nonce)
       ciphertext[i] = plaintext[i] ⊕ keystream
   ```

3. **Construct MAC Input**:
   ```
   mac_data = AAD || pad16(AAD) || 
              Ciphertext || pad16(Ciphertext) ||
              len(AAD) || len(Ciphertext)
   ```

4. **Compute Tag**:
   ```
   tag = Poly1305(mac_data, poly1305_key)
   ```

5. **Output**: (Ciphertext, Tag)

### Decryption Process

1. **Regenerate Poly1305 Key**: Same as encryption
2. **Verify Tag**: Recompute and compare with received tag
3. **Decrypt**: If tag valid, XOR ciphertext with keystream
4. **Output**: Plaintext (or ERROR if tag invalid)

## Implementation Example

### Python Implementation

```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

class ChaCha20Poly1305Cipher:
    def __init__(self, key=None):
        """Initialize ChaCha20-Poly1305"""
        if key is None:
            key = ChaCha20Poly1305.generate_key()
        self.key = key
        self.cipher = ChaCha20Poly1305(self.key)

    def encrypt(self, plaintext, aad=b''):
        """Encrypt with ChaCha20-Poly1305"""
        # Generate random 96-bit nonce
        nonce = os.urandom(12)

        # Encrypt and authenticate
        ciphertext = self.cipher.encrypt(nonce, plaintext, aad)

        # Return nonce + ciphertext + tag (tag appended by library)
        return nonce + ciphertext

    def decrypt(self, encrypted_data, aad=b''):
        """Decrypt with ChaCha20-Poly1305"""
        # Extract nonce
        nonce = encrypted_data[:12]
        ciphertext_and_tag = encrypted_data[12:]

        try:
            # Decrypt and verify
            plaintext = self.cipher.decrypt(nonce, ciphertext_and_tag, aad)
            return plaintext
        except Exception:
            raise ValueError("Authentication failed!")

# Usage Example
cipher = ChaCha20Poly1305Cipher()

message = b"Secure communication with ChaCha20-Poly1305"
aad = b"timestamp=2025-12-20"

# Encrypt
encrypted = cipher.encrypt(message, aad)
print(f"Encrypted: {len(encrypted)} bytes")

# Decrypt
decrypted = cipher.decrypt(encrypted, aad)
print(f"Decrypted: {decrypted.decode()}")

# Tampering detection
try:
    tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 0xFF])
    cipher.decrypt(tampered, aad)
except ValueError as e:
    print(f"Tampering detected: {e}")
```

### Node.js Implementation

```javascript
const crypto = require('crypto');

class ChaCha20Poly1305Cipher {
    constructor(key) {
        this.key = key || crypto.randomBytes(32);
    }

    encrypt(plaintext, aad = Buffer.alloc(0)) {
        const nonce = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv(
            'chacha20-poly1305', 
            this.key, 
            nonce,
            { authTagLength: 16 }
        );

        if (aad.length > 0) {
            cipher.setAAD(aad);
        }

        let encrypted = cipher.update(plaintext);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const tag = cipher.getAuthTag();

        return Buffer.concat([nonce, encrypted, tag]);
    }

    decrypt(encryptedData, aad = Buffer.alloc(0)) {
        const nonce = encryptedData.slice(0, 12);
        const tag = encryptedData.slice(-16);
        const ciphertext = encryptedData.slice(12, -16);

        const decipher = crypto.createDecipheriv(
            'chacha20-poly1305',
            this.key,
            nonce,
            { authTagLength: 16 }
        );

        if (aad.length > 0) {
            decipher.setAAD(aad);
        }
        decipher.setAuthTag(tag);

        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return decrypted;
    }
}

// Usage
const cipher = new ChaCha20Poly1305Cipher();
const encrypted = cipher.encrypt(Buffer.from('Hello ChaCha20!'));
const decrypted = cipher.decrypt(encrypted);
console.log(decrypted.toString());
```

## Security Considerations

### Strengths

1. **Constant-Time**: No table lookups, resistant to cache-timing attacks
2. **Fast on Software**: No hardware acceleration needed
3. **Well-Analyzed**: Extensively reviewed by cryptographers
4. **Nonce-Misuse Resistance**: Better than some alternatives
5. **Parallelizable**: Both encryption and authentication

### Security Requirements

**1. Nonce Uniqueness**

⚠️ **Critical**: Never reuse nonce with same key

```python
# CORRECT - Random nonce
nonce = os.urandom(12)

# CORRECT - Counter-based
nonce = counter.to_bytes(12, 'big')
counter += 1

# WRONG - Fixed nonce
nonce = b'\x00' * 12  # NEVER DO THIS
```

**2. Key Management**

- Use CSPRNG for key generation
- Limit messages per key: 2^64 max (practically unlimited)
- Rotate keys periodically

**3. Tag Verification**

Always verify tag before returning plaintext:

```python
def secure_decrypt(encrypted, key):
    try:
        plaintext = decrypt_and_verify(encrypted, key)
        return plaintext
    except:
        # DO NOT return partial data
        return None
```

## Performance Comparison

### Software Performance (No AES-NI)

| Algorithm | Throughput | Use Case |
|-----------|------------|----------|
| **ChaCha20-Poly1305** | ~1-2 GB/s | Mobile, IoT, ARM |
| **AES-128-GCM** | ~200 MB/s | When no AES-NI |
| **AES-256-GCM** | ~150 MB/s | When no AES-NI |

### With Hardware Acceleration

| Algorithm | Throughput | Platform |
|-----------|------------|----------|
| **ChaCha20-Poly1305** | ~1-2 GB/s | All platforms |
| **AES-256-GCM** | ~5-10 GB/s | Intel/AMD with AES-NI |

**Conclusion**: ChaCha20-Poly1305 is faster on mobile/IoT devices without AES-NI

## Real-World Applications

### TLS 1.3

```python
# TLS 1.3 cipher suite
TLS_CHACHA20_POLY1305_SHA256 = {
    'cipher': 'ChaCha20-Poly1305',
    'key_size': 256,
    'hash': 'SHA-256',
    'usage': 'Preferred for mobile'
}
```

### WireGuard VPN

```python
class WireGuardEncryption:
    def __init__(self, shared_secret):
        # Derive encryption key
        self.key = HKDF-SHA256(shared_secret, info=b'wireguard-enc')
        self.cipher = ChaCha20Poly1305Cipher(self.key)

    def encrypt_packet(self, packet, counter):
        # Use counter as part of nonce
        nonce = counter.to_bytes(12, 'big')
        return self.cipher.encrypt(packet, nonce)
```

### Signal Protocol

ChaCha20-Poly1305 is used for message encryption in Signal messaging app.

## ChaCha20-Poly1305 vs AES-GCM

| Feature | ChaCha20-Poly1305 | AES-GCM |
|---------|-------------------|---------|
| **Software Speed** | Very Fast | Medium (without AES-NI) |
| **Hardware Speed** | Fast | Very Fast (with AES-NI) |
| **Cache-Timing** | Immune | Vulnerable (without AES-NI) |
| **Mobile/IoT** | Excellent | Good |
| **Standardization** | RFC 8439, TLS 1.3 | NIST, TLS 1.2/1.3 |
| **Key Size** | 256-bit only | 128/192/256-bit |

**Recommendation**:
- **Mobile/IoT**: ChaCha20-Poly1305
- **Server with AES-NI**: AES-256-GCM
- **General Purpose**: ChaCha20-Poly1305 (simpler, safer)

## Best Practices

1. ✅ **Use 96-bit (12-byte) nonces** (RFC 8439 standard)
2. ✅ **Generate random nonces** with CSPRNG
3. ✅ **Never reuse nonces** with the same key
4. ✅ **Always verify tags** before using decrypted data
5. ✅ **Use for mobile/IoT** where AES-NI unavailable
6. ✅ **Prefer over AES-GCM** when in doubt (simpler, safer)
7. ❌ **Don't truncate tags** (always use full 128-bit)

## Conclusion

ChaCha20-Poly1305 is a modern, efficient authenticated encryption algorithm ideal for:

- **Mobile Applications**: Fast on ARM processors
- **IoT Devices**: No hardware requirements
- **VPNs**: WireGuard uses exclusively
- **TLS 1.3**: Recommended cipher suite
- **Secure Messaging**: Signal, WhatsApp

**Key Advantages**:
- Constant-time (immune to cache-timing attacks)
- Fast on all platforms
- Simple implementation
- Well-standardized (RFC 8439)

**Use ChaCha20-Poly1305 when**:
- Targeting mobile/ARM devices
- AES hardware acceleration unavailable
- Want constant-time security
- Prefer simplicity over maximum performance
