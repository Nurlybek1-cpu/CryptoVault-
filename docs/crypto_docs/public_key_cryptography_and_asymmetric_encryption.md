---
theme: default
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Lecture 5: Public Key Cryptography and Asymmetric Encryption
  MAT364 - Cryptography Course
drawings:
  persist: false
transition: slide-left
title: Public Key Cryptography and Asymmetric Encryption
css: unocss
---

<style>
.slidev-layout {
  font-size: 0.9rem;
  max-height: 100vh;
  overflow-y: auto;
}

.slidev-layout h1 {
  font-size: 2rem;
  margin-bottom: 1rem;
}

.slidev-layout h2 {
  font-size: 1.5rem;
  margin-bottom: 0.8rem;
}

.slidev-layout h3 {
  font-size: 1.2rem;
  margin-bottom: 0.6rem;
}

.slidev-layout pre {
  font-size: 0.75rem;
  max-height: 18rem;
  overflow-y: auto;
  margin: 0.5rem 0;
}

.slidev-layout code {
  font-size: 0.8rem;
}

.slidev-layout .grid {
  gap: 1rem;
}

.slidev-layout .grid > div {
  min-height: 0;
}

.slidev-layout ul, .slidev-layout ol {
  margin: 0.5rem 0;
  padding-left: 1.2rem;
}

.slidev-layout li {
  margin: 0.2rem 0;
  line-height: 1.4;
}

/* Responsive adjustments */
@media (max-width: 768px) {
  .slidev-layout {
    font-size: 0.8rem;
  }
  
  .slidev-layout h1 {
    font-size: 1.6rem;
  }
  
  .slidev-layout h2 {
    font-size: 1.3rem;
  }
  
  .slidev-layout h3 {
    font-size: 1.1rem;
  }
  
  .slidev-layout pre {
    font-size: 0.7rem;
    max-height: 15rem;
  }
}
</style>

# Public Key Cryptography and Asymmetric Encryption
## MAT364 - Cryptography Course

**Instructor:** Adil Akhmetov  
**University:** SDU  
**Week 5**

<div class="pt-6">
  <span @click="$slidev.nav.next" class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Press Space for next page →
  </span>
</div>

---
layout: default
---

# What is Public Key Cryptography?

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, x: -50, rotateY: -10 }"
     :enter="{ opacity: 1, x: 0, rotateY: 0, transition: { duration: 800, delay: 200, type: 'spring' } }">

## Definition
**Public key cryptography** uses two different but mathematically related keys - a public key and a private key.

<v-clicks>

## Key Characteristics
- **Asymmetric** - Different keys for encryption/decryption
- **Public key** - Can be shared openly
- **Private key** - Must be kept secret
- **Mathematical relationship** - Keys are related but one cannot be derived from the other

</v-clicks>

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, x: 50, rotateY: 10 }"
     :enter="{ opacity: 1, x: 0, rotateY: 0, transition: { duration: 800, delay: 400, type: 'spring' } }">

## How It Works
<v-clicks>

- **Encryption** - Use recipient's public key
- **Decryption** - Use your own private key
- **Digital signatures** - Sign with private key, verify with public key
- **Key exchange** - Establish shared secrets securely

</v-clicks>

## Advantages
<v-clicks>

- **Solves key distribution** - No need to share secret keys
- **Digital signatures** - Authentication and non-repudiation
- **Scalable** - Works with many users
- **Enables secure communication** - Even with strangers

</v-clicks>

</div>

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20, scale: 0.9 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 600, delay: 600, type: 'spring' } }"
     class="mt-4 p-3 bg-blue-100 rounded-lg text-sm">
<strong>Revolutionary:</strong> Public key cryptography solved the key distribution problem that had plagued cryptography for centuries!
</div>

---
layout: default
---

# The Key Distribution Problem

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Symmetric Cryptography Problem
<v-clicks>

- **Both parties** need the same secret key
- **How to share** the key securely?
- **Chicken and egg** - Need secure channel to share key
- **Doesn't scale** - n(n-1)/2 keys for n users

</v-clicks>

## Example: 1000 Users
<v-clicks>

- **Symmetric:** Need 499,500 different keys
- **Public key:** Each user has 1 key pair = 1000 keys total
- **Key management** nightmare vs. simple solution

</v-clicks>

</div>

<div>

## Public Key Solution
<v-clicks>

- **Publish public keys** - Put them on websites, directories
- **Keep private keys** - Never share them
- **Anyone can encrypt** - Using your public key
- **Only you can decrypt** - Using your private key

</v-clicks>

## Real-World Analogy
<v-clicks>

- **Public key** = Your mailbox (anyone can put mail in)
- **Private key** = Your mailbox key (only you can open it)
- **Encryption** = Putting mail in someone's mailbox
- **Decryption** = Opening your own mailbox

</v-clicks>

</div>

</div>

---
layout: section
---

# RSA Algorithm

---
layout: default
---

# RSA: The First Public Key Algorithm

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## History
<v-clicks>

- **1977** - Rivest, Shamir, Adleman (RSA)
- **First practical** public key system
- **Based on** integer factorization
- **Still widely used** today

</v-clicks>

## Key Generation
<v-clicks>

1. **Choose two primes** p and q
2. **Calculate n** = p × q
3. **Calculate φ(n)** = (p-1)(q-1)
4. **Choose e** such that gcd(e, φ(n)) = 1
5. **Calculate d** such that e × d ≡ 1 (mod φ(n))

</v-clicks>

</div>

<div>

## Keys
<v-clicks>

- **Public key:** (n, e)
- **Private key:** (n, d)
- **n:** Modulus (product of two primes)
- **e:** Public exponent (usually 65537)
- **d:** Private exponent (calculated)

</v-clicks>

## Security
<v-clicks>

- **Based on** difficulty of factoring large numbers
- **Breaking RSA** = Factoring n into p and q
- **Current recommendation:** 2048-bit keys minimum
- **Quantum threat:** Shor's algorithm can break RSA

</v-clicks>

</div>

</div>

---
layout: default
---

# RSA Encryption and Decryption

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Encryption
<v-clicks>

**Formula:** c = m^e (mod n)

- **m:** Plaintext message (as integer)
- **e:** Public exponent
- **n:** Modulus
- **c:** Ciphertext

</v-clicks>

## Example
<v-clicks>

```
p = 61, q = 53
n = 61 × 53 = 3233
φ(n) = 60 × 52 = 3120
e = 17 (chosen)
d = 2753 (calculated)

Public key: (3233, 17)
Private key: (3233, 2753)

Message: m = 65
Encrypt: c = 65^17 mod 3233 = 2790
```

</v-clicks>

</div>

<div>

## Decryption
<v-clicks>

**Formula:** m = c^d (mod n)

- **c:** Ciphertext
- **d:** Private exponent
- **n:** Modulus
- **m:** Original plaintext

</v-clicks>

## Verification
<v-clicks>

```
Decrypt: m = 2790^2753 mod 3233 = 65 ✓
```

</v-clicks>

## Implementation
```python
def rsa_encrypt(message, public_key):
    n, e = public_key
    return pow(message, e, n)

def rsa_decrypt(ciphertext, private_key):
    n, d = private_key
    return pow(ciphertext, d, n)
```

</div>

</div>

---
layout: default
---

# 🎯 Student Task: RSA Key Generation

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-yellow-50 to-orange-50 rounded-lg border-2 border-yellow-300">

## Task: Generate RSA Keys

<v-clicks>

**Given:**
- p = 7, q = 11
- e = 3

**Your Task:**
1. Calculate n = p × q
2. Calculate φ(n) = (p-1)(q-1)
3. Verify that gcd(e, φ(n)) = 1
4. Calculate d such that e × d ≡ 1 (mod φ(n))
5. What are the public and private keys?

**Hint:** Use extended Euclidean algorithm for step 4

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 2000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center text-sm text-gray-600">
<strong>Work through this step by step!</strong>
</div>
</div>

</div>

---
layout: default
---

# ✅ Solution: RSA Key Generation

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-green-50 to-blue-50 rounded-lg border-2 border-green-300">

## Step-by-Step Solution

<v-clicks>

**Step 1:** n = p × q = 7 × 11 = 77

**Step 2:** φ(n) = (p-1)(q-1) = 6 × 10 = 60

**Step 3:** gcd(3, 60) = 3 ≠ 1 ❌

**Problem:** e = 3 is not coprime with φ(n) = 60

**Solution:** Choose a different e

**Let e = 7:** gcd(7, 60) = 1 ✓

**Step 4:** Find d such that 7 × d ≡ 1 (mod 60)

Using extended Euclidean algorithm: d = 43

**Verification:** 7 × 43 = 301 ≡ 1 (mod 60) ✓

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 3000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center">
<strong class="text-green-600">Keys:</strong><br>
<strong>Public:</strong> (77, 7)<br>
<strong>Private:</strong> (77, 43)
</div>
</div>

</div>

---
layout: section
---

# Elliptic Curve Cryptography

---
layout: default
---

# What are Elliptic Curves?

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Mathematical Definition
<v-clicks>

**General form:** y² = x³ + ax + b

- **a, b:** Curve parameters
- **Points (x,y)** that satisfy the equation
- **Special point O** - point at infinity
- **Group operation** - point addition

</v-clicks>

## Example: y² = x³ - x + 1
<v-clicks>

```
Points on curve:
(0,1), (0,-1), (1,1), (1,-1), (2,2.65), (2,-2.65), ...
```

</v-clicks>

</div>

<div>

## Why Elliptic Curves?
<v-clicks>

- **Smaller keys** - 256-bit ECC = 3072-bit RSA security
- **Faster operations** - More efficient than RSA
- **Less memory** - Smaller key storage
- **Mobile friendly** - Better for constrained devices

</v-clicks>

## Security
<v-clicks>

- **Based on** discrete logarithm problem
- **Harder to break** than RSA for same security level
- **Quantum resistant** - No known quantum algorithm
- **Future-proof** - Will remain secure longer

</v-clicks>

</div>

</div>

---
layout: default
---

# Elliptic Curve Operations

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Point Addition
<v-clicks>

**Rule:** P + Q = R

- **P, Q:** Points on curve
- **R:** Result point
- **Geometric:** Draw line through P and Q, find third intersection
- **Algebraic:** Use formulas for coordinates

</v-clicks>

## Point Doubling
<v-clicks>

**Rule:** 2P = P + P

- **P:** Point on curve
- **Geometric:** Draw tangent at P, find second intersection
- **Special case** of point addition

</v-clicks>

</div>

<div>

## Scalar Multiplication
<v-clicks>

**Rule:** kP = P + P + ... + P (k times)

- **k:** Integer (scalar)
- **P:** Point on curve
- **Result:** Another point on curve
- **Used for** key generation and encryption

</v-clicks>

## Implementation
```python
def point_add(P, Q, a, p):
    """Add two points on elliptic curve"""
    if P == O: return Q
    if Q == O: return P
    if P == Q: return point_double(P, a, p)
    
    x1, y1 = P
    x2, y2 = Q
    
    if x1 == x2 and y1 != y2:
        return O  # Point at infinity
    
    # Calculate slope
    if x1 != x2:
        s = (y2 - y1) * pow(x2 - x1, -1, p) % p
    else:
        s = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    
    # Calculate result point
    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    
    return (x3, y3)
```

</div>

</div>

---
layout: section
---

# Digital Signatures

---
layout: default
---

# What are Digital Signatures?

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Purpose
<v-clicks>

- **Authentication** - Prove who sent the message
- **Integrity** - Ensure message wasn't modified
- **Non-repudiation** - Sender cannot deny sending
- **Legal validity** - Equivalent to handwritten signature

</v-clicks>

## How They Work
<v-clicks>

1. **Hash the message** - Create message digest
2. **Sign the hash** - Use private key
3. **Send message + signature** - Both together
4. **Verify signature** - Use public key

</v-clicks>

</div>

<div>

## Properties
<v-clicks>

- **Unforgeable** - Only private key holder can sign
- **Verifiable** - Anyone can verify with public key
- **Non-reusable** - Each message has unique signature
- **Non-deniable** - Cannot claim signature is fake

</v-clicks>

## Real-World Uses
<v-clicks>

- **Software distribution** - Verify authenticity
- **Email security** - PGP, S/MIME
- **Blockchain** - Transaction authentication
- **Legal documents** - Electronic contracts

</v-clicks>

</div>

</div>

---
layout: default
---

# RSA Digital Signatures

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Signing Process
<v-clicks>

1. **Hash message:** h = H(m)
2. **Sign hash:** s = h^d (mod n)
3. **Send:** (message, signature)

</v-clicks>

## Verification Process
<v-clicks>

1. **Hash message:** h = H(m)
2. **Verify signature:** h' = s^e (mod n)
3. **Compare:** h == h' ✓

</v-clicks>

</div>

<div>

## Implementation
```python
import hashlib

def rsa_sign(message, private_key):
    """Sign message using RSA"""
    n, d = private_key
    
    # Hash the message
    message_hash = int(hashlib.sha256(message).hexdigest(), 16)
    
    # Sign the hash
    signature = pow(message_hash, d, n)
    
    return signature

def rsa_verify(message, signature, public_key):
    """Verify RSA signature"""
    n, e = public_key
    
    # Hash the message
    message_hash = int(hashlib.sha256(message).hexdigest(), 16)
    
    # Verify signature
    recovered_hash = pow(signature, e, n)
    
    return message_hash == recovered_hash
```

</div>

</div>

---
layout: section
---

# Key Exchange Protocols

---
layout: default
---

# Diffie-Hellman Key Exchange

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## The Problem
<v-clicks>

- **Two parties** want to establish shared secret
- **No secure channel** available
- **Eavesdropper** can see all communication
- **Solution:** Use public key cryptography

</v-clicks>

## How It Works
<v-clicks>

1. **Alice and Bob** agree on public parameters (p, g)
2. **Alice** chooses private key a, sends g^a (mod p)
3. **Bob** chooses private key b, sends g^b (mod p)
4. **Both calculate** shared secret: g^(ab) (mod p)

</v-clicks>

</div>

<div>

## Security
<v-clicks>

- **Eavesdropper** sees g^a and g^b
- **Cannot calculate** g^(ab) without a or b
- **Based on** discrete logarithm problem
- **Man-in-the-middle** attacks possible

</v-clicks>

## Example
<v-clicks>

```
p = 23, g = 5
Alice: a = 6, sends 5^6 mod 23 = 8
Bob: b = 15, sends 5^15 mod 23 = 19
Shared secret: 8^15 mod 23 = 19^6 mod 23 = 2
```

</v-clicks>

## Implementation
```python
def diffie_hellman(p, g, private_key):
    """Diffie-Hellman key exchange"""
    return pow(g, private_key, p)

def shared_secret(other_public, private_key, p):
    """Calculate shared secret"""
    return pow(other_public, private_key, p)
```

</div>

</div>

---
layout: default
---

# Elliptic Curve Diffie-Hellman (ECDH)

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Why ECDH?
<v-clicks>

- **Smaller keys** - 256-bit ECC = 3072-bit RSA
- **Faster** - More efficient than regular DH
- **Mobile friendly** - Better for constrained devices
- **Same security** - Equivalent to DH but smaller

</v-clicks>

## How It Works
<v-clicks>

1. **Agree on curve** and base point G
2. **Alice** chooses private key a, sends aG
3. **Bob** chooses private key b, sends bG
4. **Shared secret** = abG = baG

</v-clicks>

</div>

<div>

## Implementation
```python
def ecdh_key_exchange(private_key, other_public, curve):
    """ECDH key exchange"""
    # Calculate shared secret
    shared_point = scalar_multiply(private_key, other_public, curve)
    
    # Extract x-coordinate as shared secret
    shared_secret = shared_point[0]
    
    return shared_secret

def ecdh_public_key(private_key, base_point, curve):
    """Generate ECDH public key"""
    return scalar_multiply(private_key, base_point, curve)
```

</div>

</div>

---
layout: section
---

# Practical Implementation

---
layout: default
---

# Complete RSA Implementation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Key Generation
```python
import random
from math import gcd

def generate_rsa_keys(bit_length=2048):
    """Generate RSA key pair"""
    # Generate two large primes
    p = generate_prime(bit_length // 2)
    q = generate_prime(bit_length // 2)
    
    # Calculate n and φ(n)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Choose public exponent
    e = 65537  # Common choice
    
    # Calculate private exponent
    d = mod_inverse(e, phi_n)
    
    return (n, e), (n, d)

def generate_prime(bit_length):
    """Generate random prime number"""
    while True:
        candidate = random.getrandbits(bit_length)
        if is_prime(candidate):
            return candidate
```

</div>

<div>

## Encryption/Decryption
```python
def rsa_encrypt(message, public_key):
    """RSA encryption"""
    n, e = public_key
    
    # Convert message to integer
    if isinstance(message, str):
        message = message.encode()
    
    # Convert to integer
    m = int.from_bytes(message, 'big')
    
    # Encrypt
    c = pow(m, e, n)
    
    return c

def rsa_decrypt(ciphertext, private_key):
    """RSA decryption"""
    n, d = private_key
    
    # Decrypt
    m = pow(ciphertext, d, n)
    
    # Convert back to bytes
    message = m.to_bytes((m.bit_length() + 7) // 8, 'big')
    
    return message
```

</div>

</div>

---
layout: default
---

# Security Considerations

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## RSA Security
<v-clicks>

- **Key size** - Use at least 2048 bits
- **Prime generation** - Use cryptographically secure random
- **Padding** - Use OAEP padding, not PKCS#1 v1.5
- **Timing attacks** - Use constant-time implementations

</v-clicks>

## Common Attacks
<v-clicks>

- **Factorization** - Breaking n into p and q
- **Timing attacks** - Measuring execution time
- **Side-channel** - Power analysis, cache attacks
- **Padding oracle** - Exploiting padding errors

</v-clicks>

</div>

<div>

## Best Practices
<v-clicks>

- **Use established libraries** - Don't implement from scratch
- **Keep keys secure** - Store private keys safely
- **Rotate keys** - Change keys regularly
- **Use hybrid systems** - RSA for key exchange, AES for data

</v-clicks>

## Real-World Usage
<v-clicks>

- **TLS/SSL** - Web security
- **Email encryption** - PGP, S/MIME
- **Digital certificates** - PKI infrastructure
- **Blockchain** - Bitcoin, Ethereum

</v-clicks>

</div>

</div>

---
layout: default
---

# 🎯 Student Task: Implement RSA

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-indigo-50 to-purple-50 rounded-lg border-2 border-indigo-300">

## Task: Complete RSA Implementation

<v-clicks>

**Requirements:**
1. **Generate RSA keys** (small primes for testing)
2. **Implement encryption/decryption**
3. **Add digital signature** functionality
4. **Test with sample messages**
5. **Handle edge cases** (message too large, etc.)

**Bonus:**
- Add padding schemes
- Implement key validation
- Add performance testing
- Create interactive demo

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 2000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center text-sm text-gray-600">
<strong>Focus on understanding the mathematics behind RSA!</strong>
</div>
</div>

</div>

---
layout: default
---

# Common Vulnerabilities

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Implementation Errors
<v-clicks>

- **❌ Weak random** - Predictable primes
- **❌ Small key sizes** - Easy to factor
- **❌ No padding** - Vulnerable to attacks
- **❌ Timing attacks** - Leak information

</v-clicks>

## Protocol Issues
<v-clicks>

- **❌ Key reuse** - Same key for different purposes
- **❌ Weak parameters** - Small primes, bad curves
- **❌ No authentication** - Man-in-the-middle attacks
- **❌ Side channels** - Power, timing, cache attacks

</v-clicks>

</div>

<div>

## Best Practices
<v-clicks>

- **✅ Use established libraries** - Tested implementations
- **✅ Proper key sizes** - 2048+ bits for RSA
- **✅ Secure random** - Cryptographically secure PRNG
- **✅ Constant time** - Prevent timing attacks

</v-clicks>

## Modern Alternatives
<v-clicks>

- **Elliptic curves** - Smaller keys, faster
- **Post-quantum** - Quantum-resistant algorithms
- **Hybrid systems** - Best of both worlds
- **Hardware security** - HSM, TPM

</v-clicks>

</div>

</div>

---
layout: default
---

# Real-World Applications

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Web Security
<v-clicks>

- **HTTPS** - TLS/SSL certificates
- **Email security** - S/MIME, PGP
- **VPN** - IPsec, OpenVPN
- **SSH** - Secure shell connections

</v-clicks>

## Blockchain
<v-clicks>

- **Bitcoin** - ECDSA signatures
- **Ethereum** - ECDSA + ECDH
- **Smart contracts** - Cryptographic verification
- **Digital wallets** - Key management

</v-clicks>

</div>

<div>

## Enterprise
<v-clicks>

- **PKI** - Public Key Infrastructure
- **Digital certificates** - X.509 standard
- **Code signing** - Software authenticity
- **Document signing** - PDF, Office documents

</v-clicks>

## Future Trends
<v-clicks>

- **Post-quantum crypto** - Quantum-resistant algorithms
- **Homomorphic encryption** - Compute on encrypted data
- **Zero-knowledge proofs** - Prove without revealing
- **Multi-party computation** - Secure collaborative computing

</v-clicks>

</div>

</div>

---
layout: end
---

# Questions?

<div class="pt-6">
  <span class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Let's discuss public key cryptography! 💬
  </span>
</div>

<div class="mt-4 text-sm text-gray-600">
<p><strong>Next Week:</strong> We'll explore hash functions and learn about SHA, MD5, and their applications!</p>
<p><strong>Assignment:</strong> Implement RSA and ECDH to understand asymmetric cryptography!</p>
</div>
