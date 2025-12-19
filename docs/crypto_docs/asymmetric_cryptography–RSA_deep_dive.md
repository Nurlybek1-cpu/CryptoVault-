---
theme: default
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Lecture 7: Asymmetric Cryptography – RSA Deep Dive
  MAT364 - Cryptography Course
drawings:
  persist: false
transition: slide-left
title: Asymmetric Cryptography – RSA Deep Dive
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

# Asymmetric Cryptography – RSA Deep Dive
## MAT364 - Cryptography Course

**Instructor:** Adil Akhmetov  
**University:** SDU  
**Week 7**

<div class="pt-6">
  <span @click="$slidev.nav.next" class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Press Space for next page →
  </span>
</div>

---
layout: default
---

# RSA Refresher and Overview

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Core Idea
- Key pair: **Public (n, e)** and **Private (n, d)**
- Security: Hardness of factoring n = p × q
- Operations: c = m^e mod n; m = c^d mod n

## Where We Go Deeper Today
- Number theory foundations
- Secure key generation
- Padding (OAEP/PSS)
- Attacks and defenses

</div>

<div>

## Parameters
- n = p × q (1024/2048/3072/4096-bit)
- e: public exponent (use 65537)
- d: modular inverse of e mod φ(n)

## Performance
- Use **CRT** to speed up decryption/signing
- Avoid side-channel leaks (constant-time code)

</div>

</div>

---
layout: section
---

# Number Theory for RSA

---
layout: two-cols
---

# Modular Arithmetic Essentials

## Concepts
- φ(n) = (p-1)(q-1)
- Modular inverse: d ≡ e^{-1} (mod φ(n))
- Euler's theorem: a^{φ(n)} ≡ 1 (mod n) for gcd(a, n) = 1

```python
from math import gcd

def egcd(a: int, b: int):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError('inverse does not exist')
    return x % m
```

:::right::

## CRT Optimization
- Compute modulo p and q separately
- Recombine using CRT to speed up 3–4×

```python
def rsa_decrypt_crt(c: int, p: int, q: int, d: int) -> int:
    n = p * q
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = modinv(q, p)
    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    h = (qinv * (m1 - m2)) % p
    return (m2 + h * q) % n
```

---
layout: default
---

# Secure Key Generation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Steps
1. Generate random large primes p, q
2. n = p × q; φ(n) = (p-1)(q-1)
3. Choose e = 65537
4. Compute d = e^{-1} mod φ(n)
5. Validate (gcd(e, φ(n)) = 1, key tests)

## Pitfalls
- p and q too close → Fermat factorization
- Reused primes → catastrophic compromise
- Weak RNG → predictable keys
- Small d (Wiener's attack)

</div>

<div>

## Toy Implementation (Educational)
```python
import secrets

def generate_prime(bits: int) -> int:
    # Placeholder primality; use robust tests (e.g., Miller–Rabin) in practice
    def is_probable_prime(n: int) -> bool:
        if n % 2 == 0: return False
        # ... omitted: implement Miller–Rabin rounds ...
        return True
    while True:
        candidate = secrets.randbits(bits) | 1 | (1 << (bits - 1))
        if is_probable_prime(candidate):
            return candidate

def generate_rsa(bits: int = 2048):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)
    return (n, e), (n, d), (p, q)
```

## Best Practice
- Use vetted libraries for production keygen

</div>

</div>

---
layout: default
---

# Padding and Safe RSA

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Why Padding?
- Textbook RSA is deterministic and malleable
- Enables chosen-ciphertext attacks
- Use standardized padding: **OAEP** (encryption), **PSS** (signatures)

## Encryption (OAEP)
- Randomized mask generation (MGF1)
- Semantic security under RSA assumption

</div>

<div>

## Python `cryptography` Example
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

ciphertext = public_key.encrypt(
    b"secret",
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)

plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)
```

## Signatures (PSS)
- Probabilistic padding; mitigates forgery structures

</div>

</div>

---
layout: default
---

# Attacks and Defenses

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Classical Attacks
- **Small e broadcast (Håstad)**: same message, different moduli
- **Padding oracles (Bleichenbacher)**: PKCS#1 v1.5
- **Wiener's attack**: small private exponent d
- **Fault/side-channel**: timing, power, cache

## Mitigations
- Use OAEP/PSS; avoid PKCS#1 v1.5
- Constant-time implementations and blinding
- Robust key sizes (≥2048-bit)
- Side-channel hardening

</div>

<div>

## RSA Blinding (Concept)
- Multiply ciphertext by r^e mod n before decrypt
- Remove r after exponentiation
- Breaks timing correlation with input

## Do/Don't
- Do: authenticate ciphertexts (KEM + DEM)
- Don't: encrypt raw data with textbook RSA

</div>

</div>

---
layout: two-cols
---

# Practical RSA (Toy)

## Minimal Demo (Educational Only)
```python
def rsa_encrypt_int(m: int, pub: tuple[int,int]) -> int:
    n, e = pub
    if m >= n:
        raise ValueError('message too large')
    return pow(m, e, n)

def rsa_decrypt_int(c: int, priv: tuple[int,int]) -> int:
    n, d = priv
    return pow(c, d, n)
```

:::right::

## With Encoding
```python
def to_int(msg: bytes) -> int:
    return int.from_bytes(msg, 'big')

def from_int(m: int) -> bytes:
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, 'big')

# Always use OAEP/PSS with real libraries in practice
```

---
layout: default
---

# 🎯 Student Task: Modular Inverse and CRT

<div class="p-4 bg-gradient-to-r from-amber-50 to-yellow-50 rounded-lg border-2 border-amber-300">

## Task A: Modular Inverse
Given e = 17 and φ(n) = 3120, compute d such that e·d ≡ 1 (mod 3120).

## Task B: CRT Speedup
Given p = 61, q = 53, n = 3233, d = 2753, and c = 2790, compute m using CRT steps (dp, dq, qinv).

### Deliverables
- Value of d
- Step-by-step CRT recombination

</div>

---
layout: default
---

# ✅ Solution Sketch

<div class="p-4 bg-gradient-to-r from-green-50 to-blue-50 rounded-lg border-2 border-green-300">

## Task A
- d = 2753 (since 17 × 2753 = 46801 ≡ 1 (mod 3120))

## Task B (Outline)
1. dp = d mod (p-1) = 2753 mod 60 = 53
2. dq = d mod (q-1) = 2753 mod 52 = 49
3. qinv = q^{-1} mod p = 53^{-1} mod 61 = 38
4. m1 = c^{dp} mod p; m2 = c^{dq} mod q
5. h = (qinv × (m1 - m2)) mod p
6. m = m2 + h × q (mod n)

</div>

---
layout: default
---

# Real-World RSA

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Usage Patterns
- TLS key exchange (historically); modern TLS prefers ECDHE
- Code signing and package signing
- Document signing (PDF, XMLDSig)
- PKI and certificates (X.509)

</div>

<div>

## Best Practices Recap
- Use 2048–3072-bit keys (or ECC alternative)
- OAEP for encryption, PSS for signatures
- e = 65537; enforce key validation
- Prefer ECDHE for key exchange, RSA for signatures

</div>

</div>

---
layout: end
---

# Questions?

<div class="pt-6">
  <span class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Let's discuss RSA in depth! 💬
  </span>
</div>

<div class="mt-4 text-sm text-gray-600">
<p><strong>Next Week:</strong> We'll study key exchange protocols in practice (DH, ECDH, authenticated key exchange).</p>
<p><strong>Assignment:</strong> Implement RSA with OAEP/PSS using a standard library, and measure CRT speedups.</p>
</div>


