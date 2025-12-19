# Argon2 Password Hashing Algorithm

## Overview

**Argon2** is a modern password-hashing function that won the Password Hashing Competition in 2015. It is specifically designed to resist GPU cracking attacks, side-channel attacks, and provides the highest level of security for password storage.

## Purpose

- **Password Storage**: Most secure password hashing
- **Memory-Hard**: Resistant to GPU/ASIC attacks
- **Key Derivation**: Generate keys from passwords
- **Configurable**: Adjustable time, memory, and parallelism
- **Applications**: Authentication systems, encryption key derivation

## Algorithm Variants

Argon2 has **three variants**:

| Variant | Optimization | Use Case | Security |
|---------|--------------|----------|----------|
| **Argon2d** | Data-dependent | Cryptocurrencies | Max GPU resistance, vulnerable to side-channels |
| **Argon2i** | Data-independent | Password hashing | Side-channel resistant, slower |
| **Argon2id** | Hybrid | **Recommended** | Best of both worlds |

**Recommendation**: Use **Argon2id** for all password hashing applications.

## Algorithm Specification

### Parameters

| Parameter | Symbol | Description | Recommended |
|-----------|--------|-------------|-------------|
| **Password** | P | User password | Variable |
| **Salt** | S | Random salt | 16 bytes |
| **Iterations** | t | Time cost | 2-3 |
| **Memory** | m | Memory cost (KB) | 64 MB (65536 KB) |
| **Parallelism** | p | Threads | 4 |
| **Tag Length** | τ | Output length | 32 bytes |

### Memory Cost Calculation

```
Memory Usage = m KB = m × 1024 bytes
Example: m = 65536 → 64 MB
```

### Mathematical Foundation

Argon2 operates in three phases:

1. **Initialization**: Setup memory blocks
2. **Processing**: Fill memory with pseudorandom data
3. **Finalization**: Compress memory to output hash

```
Hash = Argon2(P, S, t, m, p, τ)
```

## How Argon2 Works

### Step-by-Step Process

**1. Initialization**
```
H₀ = Blake2b(P || S || t || m || p || τ)
B = ⌈m / (4p)⌉  // Blocks per lane
```

**2. Memory Allocation**
```
Allocate m KB of memory arranged in:
- p lanes (parallel processing)
- B blocks per lane
- Each block = 1024 bytes
```

**3. Memory Filling (Argon2id)**

For Argon2id:
- **First half passes**: Data-independent (like Argon2i)
- **Second half passes**: Data-dependent (like Argon2d)

```
For each pass (0 to t-1):
    For each lane (0 to p-1):
        For each block in lane:
            Compute block using:
            - Previous block
            - Reference block (depends on variant)
            - Compression function
```

**4. Finalization**
```
XOR final blocks from all lanes
Hash = Blake2b(XORed_blocks)
Truncate to τ bytes
```

### Block Computation

```
Block[i] = G(Block[i-1], Block[ref])

Where:
- G: Compression function (Blake2b-based)
- ref: Reference block index (variant-specific)
```

## Implementation Example

### Python Implementation (using argon2-cffi)

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os

class Argon2PasswordManager:
    def __init__(self, time_cost=2, memory_cost=65536, parallelism=4):
        """
        Initialize Argon2id password hasher

        Args:
            time_cost: Number of iterations (2-3 recommended)
            memory_cost: Memory in KB (65536 = 64 MB recommended)
            parallelism: Number of parallel threads (4 recommended)
        """
        self.hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID  # Argon2id
        )

    def hash_password(self, password):
        """Hash password using Argon2id"""
        return self.hasher.hash(password)

    def verify_password(self, hashed, password):
        """Verify password against Argon2id hash"""
        try:
            self.hasher.verify(hashed, password)
            return True
        except VerifyMismatchError:
            return False

    def check_needs_rehash(self, hashed):
        """Check if hash needs upgrade (parameters changed)"""
        return self.hasher.check_needs_rehash(hashed)

# Usage Example
manager = Argon2PasswordManager()

# Hash password
password = "SecurePassword123!"
hashed = manager.hash_password(password)
print(f"Hashed: {hashed}")

# Verify password
is_valid = manager.verify_password(hashed, password)
print(f"Password valid: {is_valid}")

# Wrong password
is_valid_wrong = manager.verify_password(hashed, "WrongPassword")
print(f"Wrong password valid: {is_valid_wrong}")

# Check if rehash needed
needs_rehash = manager.check_needs_rehash(hashed)
print(f"Needs rehash: {needs_rehash}")
```

### Manual Implementation Concept

```python
import hashlib
import os

class Argon2Simple:
    def __init__(self, time_cost=2, memory_cost=1024, parallelism=1):
        """Simplified Argon2 (educational purposes only)"""
        self.t = time_cost
        self.m = memory_cost  # in KB
        self.p = parallelism

    def hash(self, password, salt=None):
        """Simplified Argon2 hash"""
        if salt is None:
            salt = os.urandom(16)

        # 1. Initial hash H₀
        H0 = hashlib.blake2b(
            password.encode() + salt + 
            self.t.to_bytes(4, 'little') +
            self.m.to_bytes(4, 'little') +
            self.p.to_bytes(4, 'little'),
            digest_size=64
        ).digest()

        # 2. Allocate memory (simplified)
        num_blocks = self.m // self.p
        memory = []

        # 3. Fill memory (simplified single-threaded)
        for i in range(num_blocks):
            if i == 0:
                block = hashlib.blake2b(H0 + i.to_bytes(4, 'little')).digest()
            else:
                # Mix previous block
                block = hashlib.blake2b(memory[i-1] + i.to_bytes(4, 'little')).digest()
            memory.append(block)

        # 4. Finalization
        final = memory[-1]
        for _ in range(self.t - 1):
            final = hashlib.blake2b(final).digest()

        return salt + final[:32]

# Educational example (use argon2-cffi in production!)
hasher = Argon2Simple(time_cost=2, memory_cost=1024)
hashed = hasher.hash("password")
print(f"Simplified Argon2: {hashed.hex()}")
```

### Node.js Implementation

```javascript
const argon2 = require('argon2');

class Argon2Manager {
    constructor(options = {}) {
        this.options = {
            type: argon2.argon2id,  // Argon2id variant
            memoryCost: options.memoryCost || 65536,  // 64 MB
            timeCost: options.timeCost || 2,
            parallelism: options.parallelism || 4,
            hashLength: 32,
            saltLength: 16
        };
    }

    async hashPassword(password) {
        return await argon2.hash(password, this.options);
    }

    async verifyPassword(hash, password) {
        try {
            return await argon2.verify(hash, password);
        } catch (err) {
            return false;
        }
    }

    async needsRehash(hash) {
        return argon2.needsRehash(hash, this.options);
    }
}

// Usage
const manager = new Argon2Manager();

(async () => {
    // Hash
    const hash = await manager.hashPassword('MyPassword123');
    console.log('Hash:', hash);

    // Verify
    const valid = await manager.verifyPassword(hash, 'MyPassword123');
    console.log('Valid:', valid);  // true

    const invalid = await manager.verifyPassword(hash, 'WrongPassword');
    console.log('Invalid:', invalid);  // false
})();
```

## Security Considerations

### Parameter Selection

**Memory Cost (m)**:
- **Minimum**: 19456 KB (19 MB)
- **Recommended**: 65536 KB (64 MB)
- **High Security**: 262144 KB (256 MB)

**Time Cost (t)**:
- **Minimum**: 1
- **Recommended**: 2-3
- **High Security**: 4+

**Parallelism (p)**:
- **Recommended**: 4 (number of CPU cores)
- **Trade-off**: More threads = faster but less memory-hard

### Tuning for Your System

```python
import time
from argon2 import PasswordHasher

def benchmark_argon2(time_cost, memory_cost, parallelism):
    """Benchmark Argon2 parameters"""
    hasher = PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism
    )

    start = time.time()
    hasher.hash("test_password")
    elapsed = time.time() - start

    print(f"t={time_cost}, m={memory_cost}KB, p={parallelism}: {elapsed*1000:.0f}ms")
    return elapsed

# Find parameters that take ~500ms
for time_cost in [1, 2, 3, 4]:
    for memory_cost in [32768, 65536, 131072]:  # 32MB, 64MB, 128MB
        benchmark_argon2(time_cost, memory_cost, 4)
```

**Target**: 500ms - 1000ms per hash on your server

### Security Guarantees

1. **Memory-Hardness**: Attacker must use same amount of RAM
2. **Time-Hardness**: Multiple iterations slow down attacks
3. **Side-Channel Resistance**: Argon2i/Argon2id variants
4. **GPU Resistance**: Memory requirements make GPUs ineffective
5. **ASIC Resistance**: Custom hardware provides little advantage

### Attack Resistance

| Attack Type | PBKDF2 | bcrypt | scrypt | Argon2id |
|-------------|--------|--------|--------|----------|
| **GPU Attacks** | Low | Medium | High | **Highest** |
| **ASIC Attacks** | Low | Medium | High | **Highest** |
| **Side-Channel** | Medium | Medium | Medium | **High** |
| **Parallel** | Weak | Medium | Good | **Best** |

## Performance Comparison

### Hash Time (t=2, m=64MB, p=4)

| Algorithm | Time | Memory | GPU Speedup |
|-----------|------|--------|-------------|
| **Argon2id** | ~500ms | 64 MB | **1-2x** (minimal) |
| **scrypt** | ~500ms | 64 MB | 10-100x |
| **bcrypt** | ~500ms | <1 MB | 100-1000x |
| **PBKDF2** | ~500ms | <1 KB | 1000-10000x |

**Conclusion**: Argon2id provides best resistance to parallel cracking

## Real-World Applications

### User Registration

```python
class UserAuthSystem:
    def __init__(self):
        self.hasher = Argon2PasswordManager(
            time_cost=2,
            memory_cost=65536,  # 64 MB
            parallelism=4
        )

    def register_user(self, username, password):
        """Register new user with Argon2id"""
        # Validate password strength first
        if not self.is_strong_password(password):
            raise ValueError("Password too weak")

        # Hash password
        hashed = self.hasher.hash_password(password)

        # Store in database
        db.insert_user(username, hashed)

    def authenticate_user(self, username, password):
        """Authenticate user"""
        stored_hash = db.get_user_hash(username)

        if self.hasher.verify_password(stored_hash, password):
            # Check if rehash needed (parameter upgrade)
            if self.hasher.check_needs_rehash(stored_hash):
                new_hash = self.hasher.hash_password(password)
                db.update_user_hash(username, new_hash)
            return True
        return False
```

### Key Derivation

```python
from argon2 import low_level

def derive_encryption_key(password, salt=None):
    """Derive 256-bit encryption key from password"""
    if salt is None:
        salt = os.urandom(16)

    # Derive key using Argon2id
    key = low_level.hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=65536,  # 64 MB
        parallelism=4,
        hash_len=32,  # 256-bit key
        type=low_level.Type.ID
    )

    return key, salt
```

## Migration Guide

### Upgrading from PBKDF2/bcrypt

```python
class HybridHasher:
    def __init__(self):
        self.argon2 = Argon2PasswordManager()
        self.pbkdf2 = PBKDF2PasswordManager()

    def verify_and_upgrade(self, username, password, stored_hash):
        """Verify password and upgrade to Argon2"""
        # Detect hash type by prefix
        if stored_hash.startswith('$argon2'):
            # Already Argon2
            return self.argon2.verify_password(stored_hash, password)

        elif stored_hash.startswith('$pbkdf2'):
            # Verify with PBKDF2
            if self.pbkdf2.verify_password(stored_hash, password):
                # Upgrade to Argon2
                new_hash = self.argon2.hash_password(password)
                db.update_user_hash(username, new_hash)
                return True

        return False
```

## Best Practices

1. ✅ **Use Argon2id variant** (best balance)
2. ✅ **Set memory cost to 64MB+** (65536 KB minimum)
3. ✅ **Use time cost of 2-3** (balance security/performance)
4. ✅ **Set parallelism to CPU core count** (typically 4)
5. ✅ **Generate random 16-byte salt** per password
6. ✅ **Target 500-1000ms** hash time on your server
7. ✅ **Upgrade parameters periodically** as hardware improves
8. ✅ **Use constant-time verification**
9. ❌ **Don't use Argon2d** for password hashing (side-channel vulnerable)
10. ❌ **Don't set memory too low** (<19MB)

## Argon2 vs Other Algorithms

### When to Use Argon2

✅ **Use Argon2id for**:
- New password hashing systems
- Maximum security requirements
- Protecting high-value accounts
- Compliance with modern standards

✅ **Use PBKDF2 for**:
- Legacy system compatibility
- FIPS 140-2 compliance required
- Extremely constrained memory

✅ **Use bcrypt for**:
- Migration not feasible
- Moderate security acceptable

## Conclusion

Argon2 is the **state-of-the-art** password hashing algorithm and should be used for all new applications:

**Advantages**:
- Winner of Password Hashing Competition (2015)
- Maximum resistance to GPU/ASIC cracking
- Configurable memory, time, and parallelism
- Resistant to side-channel attacks (Argon2i/Argon2id)
- Recommended by OWASP, NIST

**Key Configuration**:
```
Variant: Argon2id
Time Cost: 2-3
Memory: 64-256 MB
Parallelism: 4
Salt: 16 bytes (random)
Output: 32 bytes
```

**Use Argon2id for maximum security in modern authentication systems!**
