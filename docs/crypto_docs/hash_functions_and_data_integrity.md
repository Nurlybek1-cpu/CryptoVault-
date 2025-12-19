---
theme: default
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Lecture 6: Hash Functions and Data Integrity
  MAT364 - Cryptography Course
drawings:
  persist: false
transition: slide-left
title: Hash Functions and Data Integrity
css: unocss
---

<style>
.slidev-layout {
  font-size: 0.9rem;
  max-height: 100vh;
  overflow-y: auto;
}

.slidev-layout h1 { font-size: 2rem; margin-bottom: 1rem; }
.slidev-layout h2 { font-size: 1.5rem; margin-bottom: 0.8rem; }
.slidev-layout h3 { font-size: 1.2rem; margin-bottom: 0.6rem; }
.slidev-layout pre { font-size: 0.75rem; max-height: 18rem; overflow-y: auto; margin: 0.5rem 0; }
.slidev-layout code { font-size: 0.8rem; }
.slidev-layout .grid { gap: 1rem; }
.slidev-layout .grid > div { min-height: 0; }
.slidev-layout ul, .slidev-layout ol { margin: 0.5rem 0; padding-left: 1.2rem; }
.slidev-layout li { margin: 0.2rem 0; line-height: 1.4; }

@media (max-width: 768px) {
  .slidev-layout { font-size: 0.8rem; }
  .slidev-layout h1 { font-size: 1.6rem; }
  .slidev-layout h2 { font-size: 1.3rem; }
  .slidev-layout h3 { font-size: 1.1rem; }
  .slidev-layout pre { font-size: 0.7rem; max-height: 15rem; }
}
</style>

# Hash Functions and Data Integrity
## MAT364 - Cryptography Course

**Instructor:** Adil Akhmetov  
**University:** SDU  
**Week 6**

<div class="pt-6">
  <span @click="$slidev.nav.next" class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Press Space for next page →
  </span>
</div>

---
layout: default
---

# What Are Cryptographic Hash Functions?

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Definition
**Hash function** maps input of arbitrary length to a fixed-length output (digest).

## Core Properties
- **Preimage resistance**: Given h, hard to find m such that H(m) = h
- **Second-preimage resistance**: For given m, hard to find m' ≠ m with H(m') = H(m)
- **Collision resistance**: Hard to find any m, m' with H(m) = H(m')
- **Avalanche effect**: Small input change → large output change

</div>

<div>

## Cryptographic vs Non-cryptographic
- Cryptographic: SHA-256, SHA-3, BLAKE2/BLAKE3
- Non-cryptographic: CRC32, Adler32 (checksums only)

## Use Cases
- Data integrity and file verification
- Digital signatures and certificates
- Password storage and KDFs
- Blockchain and Merkle trees

</div>

</div>

<div class="mt-4 p-3 bg-blue-100 rounded-lg text-sm">
<strong>Key idea:</strong> Hashes ensure integrity; paired with keys (HMAC) they ensure authenticity.
</div>

---
layout: default
---

# Hash Families and Constructions

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Common Algorithms
- **MD5** (128-bit) — broken (collisions practical)
- **SHA-1** (160-bit) — deprecated (chosen-prefix collisions)
- **SHA-2** (224/256/384/512) — widely used, secure
- **SHA-3/Keccak** — sponge construction, secure
- **BLAKE2/BLAKE3** — fast modern alternatives

## Security Levels
- n-bit hash ≈ **birthday bound** 2^(n/2) for collisions
- Choose 256-bit hashes for modern security margins

</div>

<div>

## Constructions
- **Merkle–Damgård** (MD5, SHA-1, SHA-2)
  - Iterative compression; length-extension caveat
- **Sponge** (Keccak/SHA-3)
  - Absorb-squeeze model; resistant to length-extension

## Length-Extension Attacks
- If API exposes raw H(m) with MD construction, attacker may compute H(m || x)
- Use **HMAC** or SHA-3 to avoid this

</div>

</div>

---
layout: two-cols
---

# Hashing in Practice

## Python Examples
```python
import hashlib

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

print(sha256_hex(b"hello"))
```

:::right::

## JavaScript (Node.js)
```javascript
import { createHash } from 'crypto'

export function sha256Hex(input) {
  return createHash('sha256').update(input).digest('hex')
}

console.log(sha256Hex('hello'))
```

---
layout: default
---

# Message Authentication: HMAC

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Why HMAC?
- Hash alone gives integrity, not authenticity
- **HMAC(K, m)** uses a secret key K to prevent forgeries
- Secure even if underlying hash has length-extension

## Properties
- Deterministic and fast
- Resistant to length-extension
- Standardized (RFC 2104)

</div>

<div>

## Example (Python)
```python
import hmac, hashlib

def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()

print(hmac_sha256_hex(b'secret', b'hello'))
```

## Typical Uses
- API request signing
- Token validation
- Secure cookies and sessions

</div>

</div>

<div class="mt-4 p-3 bg-green-100 rounded-lg text-sm">
<strong>Best practice:</strong> Prefer HMAC over raw hashes for authenticity; include nonces/timestamps to prevent replay.
</div>

---
layout: default
---

# Password Storage and KDFs

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Goals
- Slow down brute-force and credential stuffing
- Use **salt** to prevent rainbow tables
- Optionally use **pepper** stored separately

## Options
- PBKDF2 (widely supported)
- bcrypt (adaptive, 60-char hashes)
- scrypt (memory-hard)
- Argon2id (modern recommendation)

</div>

<div>

## PBKDF2 Example (Python)
```python
import os, hashlib

def hash_password(password: str, rounds: int = 200_000) -> bytes:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, rounds, dklen=32)
    return salt + key

def verify_password(password: str, stored: bytes, rounds: int = 200_000) -> bool:
    salt, key = stored[:16], stored[16:]
    candidate = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, rounds, dklen=32)
    return hmac.compare_digest(candidate, key)
```

## Guidance
- Target ≥100ms per hash on server
- Unique random salt per password
- Use constant-time compare

</div>

</div>

---
layout: default
---

# Data Integrity in Systems

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Common Patterns
- File integrity: publish SHA-256 sums
- Package managers: signed manifests (hash + signature)
- Backups: deduplication via chunk hashes
- Databases: row/version checksums

## Merkle Trees
- Each leaf is a hash of data block
- Internal nodes hash children
- **Merkle root** authenticates entire dataset
- Used in blockchains and git

</div>

<div>

## Example: Merkle Root
```python
import hashlib

def h(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def merkle_root(leaves: list[bytes]) -> bytes:
    level = [h(x) for x in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate last
        level = [h(level[i] + level[i+1]) for i in range(0, len(level), 2)]
    return level[0]
```

## Applications
- Blockchain transaction inclusion proofs
- Large-file integrity with partial verification

</div>

</div>

---
layout: default
---

# Security and Attacks

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Threats
- Collision attacks (birthday bound)
- Length-extension (MD construction)
- Timing side-channels in comparisons
- Poor randomness for salts/keys

## Mitigations
- Use modern hashes (SHA-256/3, BLAKE2/3)
- HMAC or SHA-3 to avoid extension
- Constant-time comparisons
- CSPRNG for salts/keys

</div>

<div>

## Birthday Paradox (Quick Math)
Let output size be n bits. Collision work ≈ 2^(n/2).

Examples:
- 128-bit hash → ~2^64 work (insufficient long-term)
- 256-bit hash → ~2^128 work (modern standard)

## When to Use What
- Integrity only: SHA-256
- Integrity + authenticity: HMAC-SHA-256
- Passwords: bcrypt/scrypt/Argon2id

</div>

</div>

---
layout: default
---

# 🎯 Student Task: Verify Integrity

<div class="p-4 bg-gradient-to-r from-amber-50 to-yellow-50 rounded-lg border-2 border-amber-300">

## Task
1. Compute SHA-256 of a file you choose
2. Tamper with one byte and recompute
3. Explain observed avalanche effect
4. Create HMAC over the file using a secret key

### Deliverables
- Original and modified hashes
- HMAC value and key length used
- Short paragraph on integrity vs authenticity

</div>

---
layout: default
---

# ✅ Solution Sketch

<div class="p-4 bg-gradient-to-r from-green-50 to-blue-50 rounded-lg border-2 border-green-300">

## Expected Outcomes
- Modified file hash is completely different
- HMAC changes when key or data changes
- Explanation distinguishes integrity (hash) vs authenticity (HMAC)

## Example Commands (bash)
```bash
shasum -a 256 myfile.bin
python - <<'PY'
import hmac, hashlib
key=b'secretkey'; data=b'example'
print(hmac.new(key, data, hashlib.sha256).hexdigest())
PY
```

</div>

---
layout: default
---

# Real-World Applications

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Where Hashes Power Systems
- **Git** object IDs (SHA-1/SHA-256)
- **TLS** cert chains and signatures
- **Package registries** (npm, PyPI) integrity
- **Blockchain** linking and Merkle proofs

</div>

<div>

## Best Practices Recap
- Prefer SHA-256/3 or BLAKE2/3
- Use HMAC for MACs; avoid raw-hash MACs
- Never store plain passwords; use KDFs
- Document and publish expected hashes

</div>

</div>

---
layout: end
---

# Questions?

<div class="pt-6">
  <span class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Let's discuss hash functions! 💬
  </span>
</div>

<div class="mt-4 text-sm text-gray-600">
<p><strong>Next Week:</strong> We will dive deep into RSA and asymmetric cryptography details.</p>
<p><strong>Assignment:</strong> Build a small tool to compute file hashes and HMACs.</p>
</div>


