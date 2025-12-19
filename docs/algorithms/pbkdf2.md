# PBKDF2 (Password-Based Key Derivation Function 2)

## Overview

**PBKDF2** (Password-Based Key Derivation Function 2) is a key derivation function designed to derive cryptographic keys from passwords. It applies a pseudorandom function (typically HMAC) repeatedly to slow down brute-force attacks, making it computationally expensive to crack passwords.

## Purpose

- **Password Hashing**: Securely store passwords
- **Key Derivation**: Generate encryption keys from passwords
- **Key Stretching**: Slow down brute-force attacks
- **Salt Support**: Prevent rainbow table attacks

## Algorithm Specification

### Parameters

| Parameter | Description | Recommended Value |
|-----------|-------------|-------------------|
| **Password** | User password | Variable |
| **Salt** | Random data | 16+ bytes |
| **Iterations (c)** | Number of rounds | 100,000-600,000+ |
| **dkLen** | Derived key length | 32 bytes (256 bits) |
| **PRF** | Pseudorandom function | HMAC-SHA256 |

### Mathematical Formula

```
DK = PBKDF2(PRF, Password, Salt, c, dkLen)
```

Where:
- **PRF**: Pseudorandom function (e.g., HMAC-SHA-256)
- **Password**: Master password
- **Salt**: Cryptographic salt (prevents rainbow tables)
- **c**: Iteration count
- **dkLen**: Desired key length in bytes

### Detailed Algorithm

```
T_1 = F(Password, Salt, c, 1)
T_2 = F(Password, Salt, c, 2)
...
T_n = F(Password, Salt, c, n)

DK = T_1 || T_2 || ... || T_n
(truncate to dkLen bytes)

Where F is defined as:
F(Password, Salt, c, i) = U_1 ⊕ U_2 ⊕ ... ⊕ U_c

U_1 = PRF(Password, Salt || INT(i))
U_2 = PRF(Password, U_1)
U_3 = PRF(Password, U_2)
...
U_c = PRF(Password, U_{c-1})
```

## How PBKDF2 Works

### Step-by-Step Process

**1. Initialization**
```python
password = "user_password"
salt = os.urandom(16)  # 16 random bytes
iterations = 100000
dkLen = 32  # 256-bit key
```

**2. PRF Function (HMAC-SHA256)**
```python
def PRF(password, data):
    return HMAC-SHA256(key=password, data=data)
```

**3. Iteration Process**
```python
For block i:
    U_1 = HMAC-SHA256(password, salt || i)
    U_2 = HMAC-SHA256(password, U_1)
    U_3 = HMAC-SHA256(password, U_2)
    ...
    U_c = HMAC-SHA256(password, U_{c-1})

    T_i = U_1 ⊕ U_2 ⊕ ... ⊕ U_c
```

**4. Final Key**
```python
derived_key = T_1 || T_2 || ... (truncated to dkLen)
```

## Implementation Example

### Python Implementation

```python
import hashlib
import hmac
import os

def pbkdf2_hmac_sha256(password, salt, iterations, dklen):
    """
    PBKDF2 implementation using HMAC-SHA256

    Args:
        password: Password (bytes or str)
        salt: Salt (bytes)
        iterations: Iteration count
        dklen: Desired key length in bytes

    Returns:
        Derived key (bytes)
    """
    if isinstance(password, str):
        password = password.encode('utf-8')

    # Calculate number of blocks needed
    hlen = 32  # SHA-256 output length
    num_blocks = (dklen + hlen - 1) // hlen

    dk = b''

    for block_number in range(1, num_blocks + 1):
        # U_1 = PRF(password, salt || block_number)
        U = hmac.new(password, salt + block_number.to_bytes(4, 'big'), 
                     hashlib.sha256).digest()
        T = U

        # U_2 through U_c
        for _ in range(iterations - 1):
            U = hmac.new(password, U, hashlib.sha256).digest()
            # XOR with accumulated value
            T = bytes(a ^ b for a, b in zip(T, U))

        dk += T

    # Truncate to desired length
    return dk[:dklen]

# Usage Example
password = "MySecurePassword123"
salt = os.urandom(16)
iterations = 100000
dklen = 32

derived_key = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
print(f"Derived key: {derived_key.hex()}")
```

### Using Standard Library

```python
import hashlib
import os

class PBKDF2PasswordHasher:
    def __init__(self, iterations=100000):
        self.iterations = iterations

    def hash_password(self, password, salt=None):
        """Hash password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)

        if isinstance(password, str):
            password = password.encode('utf-8')

        # Derive key using PBKDF2-HMAC-SHA256
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password,
            salt,
            self.iterations,
            dklen=32
        )

        # Return salt + key for storage
        return salt + key

    def verify_password(self, password, stored_hash):
        """Verify password against stored hash"""
        # Extract salt (first 16 bytes)
        salt = stored_hash[:16]
        stored_key = stored_hash[16:]

        # Hash provided password with same salt
        if isinstance(password, str):
            password = password.encode('utf-8')

        derived_key = hashlib.pbkdf2_hmac(
            'sha256',
            password,
            salt,
            self.iterations,
            dklen=32
        )

        # Constant-time comparison
        return hmac.compare_digest(derived_key, stored_key)

# Usage
hasher = PBKDF2PasswordHasher(iterations=100000)

# Hash password
password = "UserPassword123!"
hashed = hasher.hash_password(password)
print(f"Stored hash (hex): {hashed.hex()}")

# Verify password
is_valid = hasher.verify_password("UserPassword123!", hashed)
print(f"Password valid: {is_valid}")

# Wrong password
is_valid_wrong = hasher.verify_password("WrongPassword", hashed)
print(f"Wrong password valid: {is_valid_wrong}")
```

### Node.js Implementation

```javascript
const crypto = require('crypto');

class PBKDF2Hasher {
    constructor(iterations = 100000) {
        this.iterations = iterations;
        this.keylen = 32;
        this.digest = 'sha256';
    }

    hashPassword(password, callback) {
        // Generate random salt
        crypto.randomBytes(16, (err, salt) => {
            if (err) return callback(err);

            // Derive key
            crypto.pbkdf2(
                password,
                salt,
                this.iterations,
                this.keylen,
                this.digest,
                (err, derivedKey) => {
                    if (err) return callback(err);

                    // Concatenate salt + key
                    const hash = Buffer.concat([salt, derivedKey]);
                    callback(null, hash);
                }
            );
        });
    }

    verifyPassword(password, storedHash, callback) {
        // Extract salt
        const salt = storedHash.slice(0, 16);
        const storedKey = storedHash.slice(16);

        // Derive key with same salt
        crypto.pbkdf2(
            password,
            salt,
            this.iterations,
            this.keylen,
            this.digest,
            (err, derivedKey) => {
                if (err) return callback(err);

                // Constant-time comparison
                const valid = crypto.timingSafeEqual(derivedKey, storedKey);
                callback(null, valid);
            }
        );
    }
}

// Usage
const hasher = new PBKDF2Hasher(100000);

hasher.hashPassword('MyPassword123', (err, hash) => {
    console.log('Hashed:', hash.toString('hex'));

    // Verify
    hasher.verifyPassword('MyPassword123', hash, (err, valid) => {
        console.log('Valid:', valid);  // true
    });
});
```

## Security Considerations

### Iteration Count

**Recommended values (as of 2025)**:

| Use Case | Minimum | Recommended |
|----------|---------|-------------|
| **Password Storage** | 100,000 | 200,000-600,000 |
| **Key Derivation** | 100,000 | 200,000+ |
| **Legacy Support** | 10,000 | Upgrade ASAP |

**Calculation**: Target ~100ms computation time on your server

```python
import time

def benchmark_iterations():
    """Find appropriate iteration count"""
    password = b"test_password"
    salt = os.urandom(16)

    for iterations in [10000, 50000, 100000, 200000, 500000]:
        start = time.time()
        hashlib.pbkdf2_hmac('sha256', password, salt, iterations, 32)
        elapsed = time.time() - start
        print(f"{iterations:7d} iterations: {elapsed*1000:.2f} ms")

benchmark_iterations()
```

### Salt Requirements

1. **Size**: Minimum 16 bytes (128 bits)
2. **Randomness**: Use CSPRNG (os.urandom, crypto.randomBytes)
3. **Uniqueness**: Different salt for each password
4. **Storage**: Store salt alongside hashed password

```python
# CORRECT
salt = os.urandom(16)  # Random salt

# WRONG
salt = b'fixed_salt'  # Never use fixed salt
```

### Common Vulnerabilities

| Vulnerability | Impact | Mitigation |
|---------------|--------|------------|
| **Low Iterations** | Fast brute-force | Use 100,000+ |
| **No Salt** | Rainbow tables | Always use random salt |
| **Fixed Salt** | Pre-computation | Unique salt per password |
| **Weak PRF** | Faster attacks | Use HMAC-SHA256+ |
| **Timing Attacks** | Password leak | Constant-time comparison |

## Performance Characteristics

### Computational Cost

```
Time ≈ iterations × (HMAC_time)
Memory ≈ O(1) - constant memory usage
```

**Example** (on modern CPU):
- 100,000 iterations: ~100 ms
- 200,000 iterations: ~200 ms
- 500,000 iterations: ~500 ms

### PBKDF2 vs Alternatives

| Algorithm | Memory | Speed | GPU Resistance | Recommendation |
|-----------|--------|-------|----------------|----------------|
| **PBKDF2** | Low | Fast | Moderate | Legacy/compatibility |
| **bcrypt** | Low | Medium | Good | Acceptable |
| **scrypt** | High | Slow | Excellent | Good choice |
| **Argon2id** | High | Slow | Excellent | **Best choice** |

**Conclusion**: PBKDF2 is acceptable but **Argon2id is recommended** for new applications.

## Real-World Applications

### Password Storage

```python
class UserPasswordManager:
    def __init__(self):
        self.hasher = PBKDF2PasswordHasher(iterations=100000)

    def register_user(self, username, password):
        """Register new user"""
        hashed_password = self.hasher.hash_password(password)
        # Store in database
        db.save_user(username, hashed_password)

    def authenticate_user(self, username, password):
        """Authenticate user"""
        stored_hash = db.get_user_hash(username)
        return self.hasher.verify_password(password, stored_hash)
```

### Encryption Key Derivation

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_with_password(plaintext, password):
    """Encrypt data using password-derived key"""
    # Generate salt
    salt = os.urandom(16)

    # Derive encryption key
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 
                               iterations=100000, dklen=32)

    # Encrypt
    cipher = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, plaintext, None)

    # Return salt + nonce + ciphertext
    return salt + nonce + ciphertext

def decrypt_with_password(encrypted_data, password):
    """Decrypt data using password-derived key"""
    # Extract components
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]

    # Derive same key
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt,
                               iterations=100000, dklen=32)

    # Decrypt
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, ciphertext, None)
```

### Database Encryption

```python
class EncryptedDatabase:
    def __init__(self, master_password):
        # Derive database encryption key from password
        self.salt = os.urandom(16)
        self.encryption_key = hashlib.pbkdf2_hmac(
            'sha256',
            master_password.encode(),
            self.salt,
            iterations=200000,
            dklen=32
        )
        self.cipher = AESGCM(self.encryption_key)
```

## Migration from PBKDF2

### Upgrading to Argon2

```python
class HybridPasswordHasher:
    def __init__(self):
        self.pbkdf2_hasher = PBKDF2PasswordHasher()
        self.argon2_hasher = Argon2Hasher()

    def verify_and_upgrade(self, username, password, stored_hash):
        """Verify with PBKDF2 and upgrade to Argon2"""
        # Check hash type (first byte as marker)
        if stored_hash[0:1] == b'':  # PBKDF2
            if self.pbkdf2_hasher.verify_password(password, stored_hash[1:]):
                # Upgrade to Argon2
                new_hash = b'' + self.argon2_hasher.hash_password(password)
                db.update_user_hash(username, new_hash)
                return True
        elif stored_hash[0:1] == b'':  # Argon2
            return self.argon2_hasher.verify_password(password, stored_hash[1:])
        return False
```

## Best Practices

1. ✅ **Use 100,000+ iterations** (200,000+ recommended)
2. ✅ **Generate random salt** (16+ bytes) for each password
3. ✅ **Use HMAC-SHA256 or SHA512** as PRF
4. ✅ **Store salt alongside hash** (salt is not secret)
5. ✅ **Use constant-time comparison** (hmac.compare_digest)
6. ✅ **Consider migrating to Argon2id** for new applications
7. ❌ **Never use fixed/shared salt**
8. ❌ **Never use low iteration counts** (<10,000)
9. ❌ **Don't use for frequent operations** (use session tokens)

## Conclusion

PBKDF2 is a **widely-supported, battle-tested** key derivation function suitable for:

- **Password Storage**: When Argon2 unavailable
- **Key Derivation**: Generating encryption keys from passwords
- **Legacy Systems**: Compatibility with older systems
- **Compliance**: FIPS 140-2 approved

**However**:
- **For new applications**: Use **Argon2id** instead
- **For existing PBKDF2**: Use 200,000+ iterations with SHA-256

**Key Takeaway**: PBKDF2 is acceptable but not optimal. Migrate to Argon2id when possible.
