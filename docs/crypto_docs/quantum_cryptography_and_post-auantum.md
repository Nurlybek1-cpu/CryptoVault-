---
theme: default
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Lecture 13: Quantum Cryptography and Post-Quantum
  MAT364 - Cryptography Course
drawings:
  persist: false
transition: slide-left
title: Quantum Cryptography and Post-Quantum
css: unocss
---

<style>
.slidev-layout {
  font-size: 0.94rem;
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
  .slidev-layout { font-size: 0.85rem; }
  .slidev-layout h1 { font-size: 1.6rem; }
  .slidev-layout h2 { font-size: 1.3rem; }
  .slidev-layout h3 { font-size: 1.1rem; }
  .slidev-layout pre { font-size: 0.7rem; max-height: 16rem; }
}
</style>

# Quantum Cryptography and Post-Quantum
## MAT364 - Cryptography Course

**Instructor:** Adil Akhmetov  
**University:** SDU  
**Week 13**

<div class="pt-6">
  <span @click="$slidev.nav.next" class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Press Space for next page →
  </span>
</div>

---
layout: default
---

# Week 13 Focus

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Motivation
- Quantum computers threaten current cryptographic systems
- Shor's algorithm breaks RSA and ECDSA
- Need quantum-resistant alternatives
- Quantum key distribution offers provable security

## Learning Outcomes
1. Understand quantum computing threats to cryptography
2. Explain quantum key distribution (QKD) principles
3. Identify post-quantum cryptographic algorithms
4. Evaluate migration strategies for post-quantum security

</div>

<div>

## Agenda
- Quantum computing fundamentals and threats
- Quantum key distribution (BB84 protocol)
- Post-quantum cryptography families
- NIST PQC standardization
- Migration planning and hybrid approaches
- Lab: Implement a post-quantum signature scheme

</div>

</div>

---
layout: section
---

# The Quantum Threat

---
layout: default
---

# Why Quantum Computing Matters

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## The Threat Timeline
- **Current:** Classical computers (limited threat)
- **5-10 years:** Small-scale quantum computers
- **10-30 years:** Cryptographically relevant quantum computers
- **"Harvest now, decrypt later"** attacks already happening

## Algorithms at Risk
- **RSA** - Factoring problem (Shor's algorithm)
- **ECDSA/ECDH** - Discrete log problem (Shor's algorithm)
- **Diffie-Hellman** - Discrete log problem
- **Symmetric crypto** - Grover's algorithm (halves key size)

</div>

<div>

## Shor's Algorithm Impact
```
Classical: Factor 2048-bit RSA
- Best algorithm: ~10^20 years
- Requires: Classical supercomputer

Quantum: Factor 2048-bit RSA
- Shor's algorithm: ~hours/days
- Requires: ~4000 logical qubits
```

## Grover's Algorithm Impact
- **AES-128** → equivalent to AES-64 security
- **AES-256** → equivalent to AES-128 security
- **Solution:** Use AES-256 for post-quantum security

</div>

</div>

<div class="mt-4 p-3 bg-red-50 rounded-lg text-sm">
<strong>Critical:</strong> Data encrypted today with RSA/ECDSA may be decrypted in 10-20 years. Start planning migration now!
</div>

---
layout: default
---

# Quantum Computing Basics

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Qubits vs Bits
- **Classical bit:** 0 or 1
- **Quantum bit (qubit):** Superposition of 0 and 1
- **Entanglement:** Qubits can be correlated
- **Measurement:** Collapses superposition to 0 or 1

## Quantum Gates
- **Hadamard:** Creates superposition
- **CNOT:** Creates entanglement
- **Phase gates:** Manipulate quantum phases
- **Measurement:** Extract classical information

</div>

<div>

## Quantum Advantage
- **Parallelism:** Process many states simultaneously
- **Interference:** Amplify correct answers
- **Entanglement:** Correlate distant qubits
- **Limitations:** Measurement destroys superposition

## Current State
- **IBM:** 100+ qubit processors
- **Google:** Quantum supremacy demonstrated
- **Challenges:** Error rates, decoherence, scaling
- **Timeline:** Cryptographically relevant QC in 10-30 years

</div>

</div>

---
layout: default
---

# Video: Introduction to Quantum Computing

<div class="flex items-center justify-center">
  <iframe 
    width="560" 
    height="315" 
    src="https://www.youtube.com/embed/JhHMJCUmq28" 
    title="Quantum Computing Explained" 
    frameborder="0" 
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" 
    allowfullscreen
    class="rounded-lg">
  </iframe>
</div>

<div class="mt-4 text-sm text-gray-600 text-center">
<strong>Source:</strong> <a href="https://www.youtube.com/watch?v=JhHMJCUmq28" target="_blank">Veritasium - Quantum Computing Explained</a>
</div>

---
layout: section
---

# Quantum Key Distribution (QKD)

---
layout: default
---

# BB84 Protocol

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Protocol Overview
**BB84 (Bennett & Brassard, 1984):**
- First practical quantum key distribution
- Uses quantum properties for security
- Provably secure against eavesdropping
- No computational assumptions

## Quantum States
- **Basis 0 (Z):** |0⟩, |1⟩
- **Basis 1 (X):** |+⟩ = (|0⟩ + |1⟩)/√2, |-⟩ = (|0⟩ - |1⟩)/√2
- **Random basis choice** for each qubit
- **Measurement** in wrong basis gives random result

</div>

<div>

## Protocol Steps
1. **Alice** sends qubits in random bases
2. **Bob** measures in random bases
3. **Public discussion:** Compare bases (not results)
4. **Key extraction:** Keep bits where bases matched
5. **Error checking:** Detect eavesdropping
6. **Privacy amplification:** Remove leaked information

## Security Guarantee
- **Eavesdropping detection:** Any measurement disturbs qubits
- **Information-theoretic security:** No computational assumptions
- **Perfect secrecy:** Even with unlimited computational power

</div>

</div>

---
layout: default
---

# BB84 Implementation Example

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Simplified Python Simulation
```python
import random
import numpy as np

class BB84Protocol:
    def __init__(self):
        self.bases = ['Z', 'X']  # Two measurement bases
        
    def alice_prepare_qubit(self, bit, basis):
        """Alice prepares a qubit"""
        # In real QKD, this would be a physical qubit
        # Here we simulate with classical representation
        return {
            'bit': bit,
            'basis': basis
        }
    
    def bob_measure(self, qubit, basis):
        """Bob measures the qubit"""
        if qubit['basis'] == basis:
            # Same basis: measurement is correct
            return qubit['bit']
        else:
            # Different basis: random result
            return random.randint(0, 1)
    
    def generate_key(self, length=100):
        """Generate shared key using BB84"""
        # Alice's random bits and bases
        alice_bits = [random.randint(0, 1) for _ in range(length)]
        alice_bases = [random.choice(self.bases) for _ in range(length)]
        
        # Bob's random bases
        bob_bases = [random.choice(self.bases) for _ in range(length)]
        
        # Prepare and measure qubits
        matching_bases = []
        shared_key = []
        
        for i in range(length):
            qubit = self.alice_prepare_qubit(alice_bits[i], alice_bases[i])
            bob_result = self.bob_measure(qubit, bob_bases[i])
            
            if alice_bases[i] == bob_bases[i]:
                matching_bases.append(i)
                shared_key.append(bob_result)
        
        return shared_key, matching_bases
```

</div>

<div>

## Error Detection
```python
def error_detection(self, key1, key2, sample_size=10):
    """Detect errors (eavesdropping)"""
    # Compare random sample of bits
    sample_indices = random.sample(
        range(min(len(key1), len(key2))), 
        sample_size
    )
    
    errors = 0
    for idx in sample_indices:
        if key1[idx] != key2[idx]:
            errors += 1
    
    error_rate = errors / sample_size
    return error_rate < 0.1  # Threshold for acceptable errors

# Usage
bb84 = BB84Protocol()
key, indices = bb84.generate_key(1000)

# Public discussion (simulated)
# Alice and Bob compare bases publicly
# Keep only matching basis bits
print(f"Shared key length: {len(key)}")
print(f"Key bits: {key[:20]}...")
```

## Real-World QKD
- **Distance limits:** ~200km over fiber, longer with repeaters
- **Rate limits:** ~Mbps key generation
- **Cost:** Expensive equipment
- **Applications:** High-security government, finance

</div>

</div>

---
layout: default
---

# Video: Quantum Key Distribution Explained

<div class="flex items-center justify-center">
  <iframe 
    width="560" 
    height="315" 
    src="https://www.youtube.com/embed/R0SOqLwLOR0" 
    title="Quantum Key Distribution" 
    frameborder="0" 
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" 
    allowfullscreen
    class="rounded-lg">
  </iframe>
</div>

<div class="mt-4 text-sm text-gray-600 text-center">
<strong>Source:</strong> <a href="https://www.youtube.com/watch?v=R0SOqLwLOR0" target="_blank">Quantum Key Distribution</a>
</div>

---
layout: section
---

# Post-Quantum Cryptography

---
layout: default
---

# Post-Quantum Algorithm Families

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Lattice-Based
- **Security:** Shortest Vector Problem (SVP)
- **Examples:** CRYSTALS-Kyber, CRYSTALS-Dilithium, Falcon
- **Pros:** Fast, versatile (encryption, signatures, KEM)
- **Cons:** Large public keys/signatures

## Hash-Based
- **Security:** One-way hash functions
- **Examples:** SPHINCS+, XMSS, LMS
- **Pros:** Mature, conservative security
- **Cons:** Large signatures, stateful schemes

</div>

<div>

## Code-Based
- **Security:** Decoding random linear codes
- **Examples:** Classic McEliece, BIKE
- **Pros:** Long history, well-studied
- **Cons:** Large public keys

## Multivariate
- **Security:** Solving systems of multivariate equations
- **Examples:** Rainbow (broken), GeMSS
- **Pros:** Fast verification
- **Cons:** Large keys, less mature

</div>

</div>

<div class="mt-4 p-3 bg-blue-50 rounded-lg text-sm">
<strong>NIST PQC Standardization:</strong> Selected CRYSTALS-Kyber (KEM) and CRYSTALS-Dilithium, FALCON, SPHINCS+ (signatures) in 2024.
</div>

---
layout: default
---

# NIST Post-Quantum Cryptography Standardization

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Timeline
- **2016:** Call for proposals
- **2017:** 69 submissions received
- **2019-2020:** Round 2 and 3 evaluations
- **2022:** Finalists selected
- **2024:** Standards published (FIPS 203, 204, 205)

## Selected Algorithms

**Key Encapsulation (KEM):**
- **CRYSTALS-Kyber** - Primary standard
- **Alternatives:** BIKE, HQC, SIKE (withdrawn)

**Digital Signatures:**
- **CRYSTALS-Dilithium** - Primary standard
- **FALCON** - For small signatures
- **SPHINCS+** - Hash-based backup

</div>

<div>

## Algorithm Comparison

| Algorithm | Type | Key Size | Signature Size | Security Level |
|-----------|------|----------|----------------|----------------|
| Kyber-768 | KEM | 1,568 B | - | Level 3 |
| Dilithium-3 | Signature | 1,952 B | 3,293 B | Level 3 |
| Falcon-512 | Signature | 897 B | 666 B | Level 1 |
| SPHINCS+-256f | Signature | 64 B | 49,856 B | Level 5 |

## Migration Priority
1. **High:** TLS, VPN, email encryption
2. **Medium:** Code signing, document signing
3. **Low:** Internal systems, short-lived keys

</div>

</div>

---
layout: default
---

# CRYSTALS-Kyber (KEM)

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Overview
- **Type:** Lattice-based key encapsulation
- **Security:** Module-LWE problem
- **Standard:** FIPS 203
- **Use case:** Replace RSA/ECDH key exchange

## Key Generation
```python
# Conceptual implementation
class KyberKEM:
    def __init__(self, security_level=3):
        # security_level: 1, 3, or 5
        self.n = 256  # Polynomial degree
        self.q = 3329  # Modulus
        self.k = {1: 2, 3: 3, 5: 4}[security_level]
    
    def keygen(self):
        """Generate key pair"""
        # Generate matrix A (public parameter)
        A = self.generate_matrix()
        
        # Generate secret vector s
        s = self.sample_secret()
        
        # Generate error vector e
        e = self.sample_error()
        
        # Compute public key: t = A*s + e
        t = self.matrix_vector_mult(A, s) + e
        
        return (t, A), s  # (public_key, secret_key)
```

</div>

<div>

## Encapsulation & Decapsulation
```python
    def encapsulate(self, public_key):
        """Encapsulate shared secret"""
        t, A = public_key
        
        # Generate random vector
        m = self.sample_message()
        
        # Generate error vectors
        r, e1, e2 = self.sample_errors()
        
        # Compute ciphertext
        u = A.T * r + e1
        v = t.T * r + e2 + self.encode(m)
        
        # Derive shared secret
        K = self.hash(m, u, v)
        
        return (u, v), K  # (ciphertext, shared_secret)
    
    def decapsulate(self, ciphertext, secret_key):
        """Decapsulate shared secret"""
        u, v = ciphertext
        s = secret_key
        
        # Decode message
        m = self.decode(v - s.T * u)
        
        # Re-derive shared secret
        K = self.hash(m, u, v)
        
        return K
```

## Real Implementation
- Use **liboqs** or **pqcrypto** libraries
- Never implement from scratch for production
- Follow NIST specifications exactly

</div>

</div>

---
layout: default
---

# CRYSTALS-Dilithium (Signatures)

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Overview
- **Type:** Lattice-based digital signature
- **Security:** Module-LWE and Module-SIS
- **Standard:** FIPS 204
- **Use case:** Replace RSA/ECDSA signatures

## Key Generation
```python
class DilithiumSignature:
    def __init__(self, security_level=3):
        self.n = 256  # Polynomial degree
        self.q = 8380417  # Modulus
        self.k = {1: 4, 3: 6, 5: 8}[security_level]
        self.l = {1: 4, 3: 5, 5: 7}[security_level]
    
    def keygen(self):
        """Generate signing key pair"""
        # Generate matrix A
        A = self.generate_matrix()
        
        # Generate secret vectors
        s1 = self.sample_secret_vector(self.l)
        s2 = self.sample_secret_vector(self.k)
        
        # Compute public key: t = A*s1 + s2
        t = self.matrix_vector_mult(A, s1) + s2
        t1 = self.high_bits(t)
        
        return (A, t1), (s1, s2, t)  # (public_key, secret_key)
```

</div>

<div>

## Signing & Verification
```python
    def sign(self, message, secret_key):
        """Sign message"""
        A, t1 = self.public_key
        s1, s2, t = secret_key
        
        # Generate random vector
        y = self.sample_y()
        
        # Compute challenge
        w1 = self.low_bits(A * y)
        c = self.hash(message, w1)
        
        # Compute signature
        z = y + c * s1
        h = self.make_hint(-c * t, w1 - c * s2)
        
        return (c, z, h)  # signature
    
    def verify(self, message, signature, public_key):
        """Verify signature"""
        c, z, h = signature
        A, t1 = public_key
        
        # Recompute challenge
        w1_prime = self.use_hint(h, A * z - c * 2^k * t1)
        c_prime = self.hash(message, w1_prime)
        
        return c == c_prime and self.check_norm(z)
```

</div>

</div>

---
layout: default
---

# Video: Post-Quantum Cryptography Overview

<div class="flex items-center justify-center">
  <iframe 
    width="560" 
    height="315" 
    src="https://www.youtube.com/embed/vTSbeL0q530" 
    title="Post-Quantum Cryptography" 
    frameborder="0" 
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" 
    allowfullscreen
    class="rounded-lg">
  </iframe>
</div>

<div class="mt-4 text-sm text-gray-600 text-center">
<strong>Source:</strong> <a href="https://www.youtube.com/watch?v=vTSbeL0q530" target="_blank">Understanding Post-Quantum Cryptography</a>
</div>

---
layout: section
---

# Practical Implementation

---
layout: default
---

# Using Post-Quantum Libraries

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## liboqs (C/C++)
```python
# Python bindings for liboqs
from oqs import KeyEncapsulation, Signature

# Key Encapsulation (Kyber)
kem = KeyEncapsulation('Kyber768')
public_key, secret_key = kem.generate_keypair()

# Encapsulate
ciphertext, shared_secret = kem.encapsulate(public_key)

# Decapsulate
shared_secret2 = kem.decapsulate(ciphertext, secret_key)
assert shared_secret == shared_secret2

# Digital Signature (Dilithium)
sig = Signature('Dilithium3')
public_key, secret_key = sig.generate_keypair()

# Sign
message = b"Hello, post-quantum world!"
signature = sig.sign(message, secret_key)

# Verify
is_valid = sig.verify(message, signature, public_key)
print(f"Signature valid: {is_valid}")
```

</div>

<div>

## Python cryptography Library
```python
from cryptography.hazmat.primitives.asymmetric import kyber, dilithium
from cryptography.hazmat.primitives import serialization

# Kyber KEM
private_key = kyber.generate_private_key(kyber.Kyber768)
public_key = private_key.public_key()

# Encapsulate
ciphertext, shared_secret = public_key.encapsulate()

# Decapsulate
shared_secret2 = private_key.decapsulate(ciphertext)

# Dilithium Signature
private_key = dilithium.generate_private_key(dilithium.Dilithium3)
public_key = private_key.public_key()

# Sign
message = b"Secure message"
signature = private_key.sign(message)

# Verify
public_key.verify(signature, message)
```

## Installation
```bash
# Install liboqs Python bindings
pip install oqs

# Or use cryptography library (when available)
pip install cryptography
```

</div>

</div>

---
layout: default
---

# Hybrid Approaches

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Why Hybrid?
- **Transition period:** Support both classical and PQ
- **Backward compatibility:** Works with existing systems
- **Risk mitigation:** If one breaks, other still works
- **Gradual migration:** Phase out classical over time

## Hybrid TLS
```
TLS 1.3 with hybrid key exchange:
- ECDHE (X25519) + Kyber-768
- Both keys exchanged
- Shared secret = KDF(ECDHE_secret || Kyber_secret)
- Secure if either algorithm is secure
```

</div>

<div>

## Implementation Example
```python
from cryptography.hazmat.primitives.asymmetric import x25519, kyber
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def hybrid_key_exchange():
    # Classical: X25519
    x25519_private = x25519.X25519PrivateKey.generate()
    x25519_public = x25519_private.public_key()
    
    # Post-quantum: Kyber
    kyber_private = kyber.generate_private_key(kyber.Kyber768)
    kyber_public = kyber_private.public_key()
    
    # Exchange public keys (simulated)
    # ... network exchange ...
    
    # Compute shared secrets
    x25519_secret = x25519_private.exchange(peer_x25519_public)
    kyber_ciphertext, kyber_secret = peer_kyber_public.encapsulate()
    
    # Combine secrets
    combined_secret = x25519_secret + kyber_secret
    
    # Derive final key
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'hybrid-tls-key'
    )
    final_key = kdf.derive(combined_secret)
    
    return final_key
```

</div>

</div>

---
layout: section
---

# Migration Strategy

---
layout: default
---

# Migration Planning

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Phase 1: Assessment (Now)
- **Inventory:** List all cryptographic systems
- **Risk analysis:** Identify critical data
- **Dependencies:** Map crypto library usage
- **Timeline:** Estimate migration effort

## Phase 2: Hybrid Deployment (1-2 years)
- **Enable hybrid:** Support both classical and PQ
- **Test thoroughly:** Validate PQ implementations
- **Monitor performance:** Measure overhead
- **Update standards:** Revise security policies

</div>

<div>

## Phase 3: Full Migration (3-5 years)
- **Remove classical:** Phase out old algorithms
- **Update protocols:** TLS, SSH, etc.
- **Train staff:** Update documentation
- **Audit compliance:** Verify PQ adoption

## Phase 4: Post-Migration (Ongoing)
- **Monitor standards:** Watch for new attacks
- **Update algorithms:** Migrate to newer PQ schemes
- **Maintain hybrid:** Keep flexibility

</div>

</div>

<div class="mt-4 p-3 bg-yellow-50 rounded-lg text-sm">
<strong>Timeline:</strong> Start planning now! Full migration may take 5-10 years, but critical systems should be hybrid-ready within 2-3 years.
</div>

---
layout: default
---

# Migration Checklist

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Technical Tasks
- [ ] Audit all cryptographic systems
- [ ] Identify RSA/ECDSA usage
- [ ] Test PQ libraries in dev environment
- [ ] Implement hybrid key exchange
- [ ] Update TLS configurations
- [ ] Modify certificate infrastructure
- [ ] Update code signing workflows
- [ ] Test performance impact

</div>

<div>

## Organizational Tasks
- [ ] Train development teams
- [ ] Update security policies
- [ ] Revise compliance documentation
- [ ] Plan budget for migration
- [ ] Coordinate with vendors
- [ ] Establish testing procedures
- [ ] Create rollback plans
- [ ] Monitor industry standards

</div>

</div>

## Performance Considerations

| Metric | Classical | Post-Quantum | Impact |
|--------|-----------|--------------|--------|
| Key Exchange | ~1ms | ~2-5ms | 2-5x slower |
| Signature Size | 64-256 B | 666-50k B | 10-200x larger |
| Public Key Size | 32-256 B | 800-2k B | 10-30x larger |
| CPU Usage | Baseline | +20-50% | Moderate increase |

---
layout: section
---

# Lab: Post-Quantum Implementation

---
layout: default
---

# 🎯 Student Lab Assignment

<div class="p-4 bg-gradient-to-r from-slate-50 to-indigo-50 rounded-lg border border-indigo-200">

## Scenario
You need to implement a post-quantum secure messaging system that can replace an existing RSA-based system.

## Tasks
1. Install and test `liboqs` Python bindings (or similar library)
2. Implement Kyber key exchange between two parties
3. Implement Dilithium signatures for message authentication
4. Create a hybrid system that supports both classical (X25519) and post-quantum (Kyber) key exchange
5. Measure and compare performance (key generation, encryption, signing times)

### Deliverables
- Working code demonstrating PQ key exchange and signatures
- Performance comparison table (classical vs PQ vs hybrid)
- Short report on migration challenges and recommendations

</div>

---
layout: default
---

# ✅ Solution Outline

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Implementation Structure
```python
from oqs import KeyEncapsulation, Signature
import json
import time

class PostQuantumMessaging:
    def __init__(self):
        # Initialize KEM and signature schemes
        self.kem = KeyEncapsulation('Kyber768')
        self.sig = Signature('Dilithium3')
        
        # Generate keys
        self.kem_pub, self.kem_priv = self.kem.generate_keypair()
        self.sig_pub, self.sig_priv = self.sig.generate_keypair()
    
    def send_message(self, message, recipient_kem_pub):
        # Encapsulate shared secret
        ciphertext, shared_secret = recipient_kem_pub.encapsulate()
        
        # Encrypt message (simplified - use AES in practice)
        encrypted = self.encrypt(message, shared_secret)
        
        # Sign encrypted message
        signature = self.sig.sign(encrypted, self.sig_priv)
        
        return {
            'ciphertext': ciphertext.hex(),
            'encrypted': encrypted.hex(),
            'signature': signature.hex(),
            'public_key': self.sig_pub.hex()
        }
```

</div>

<div>

## Performance Benchmarking
```python
def benchmark_pq_algorithms():
    results = {}
    
    # Benchmark Kyber
    kem = KeyEncapsulation('Kyber768')
    start = time.time()
    pub, priv = kem.generate_keypair()
    results['kyber_keygen'] = time.time() - start
    
    start = time.time()
    ct, ss = kem.encapsulate(pub)
    results['kyber_encaps'] = time.time() - start
    
    start = time.time()
    ss2 = kem.decapsulate(ct, priv)
    results['kyber_decaps'] = time.time() - start
    
    # Benchmark Dilithium
    sig = Signature('Dilithium3')
    start = time.time()
    pub, priv = sig.generate_keypair()
    results['dilithium_keygen'] = time.time() - start
    
    message = b"test message" * 100
    start = time.time()
    signature = sig.sign(message, priv)
    results['dilithium_sign'] = time.time() - start
    
    start = time.time()
    valid = sig.verify(message, signature, pub)
    results['dilithium_verify'] = time.time() - start
    
    return results
```

</div>

</div>

---
layout: section
---

# Challenges and Considerations

---
layout: default
---

# Post-Quantum Challenges

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Technical Challenges
- **Large key/signature sizes:** Bandwidth and storage impact
- **Performance overhead:** Slower than classical crypto
- **Library maturity:** Fewer implementations available
- **Standardization:** Still evolving (NIST PQC Round 4)
- **Interoperability:** Need compatible implementations

## Implementation Risks
- **Side-channel attacks:** New attack vectors
- **Implementation bugs:** Less battle-tested code
- **Algorithm selection:** Risk of choosing broken algorithm
- **Migration complexity:** Large codebase changes

</div>

<div>

## Operational Challenges
- **Cost:** Hardware/software upgrades
- **Training:** Staff education required
- **Vendor support:** Limited PQ support
- **Compliance:** Regulatory approval needed
- **Timeline:** Long migration periods

## Best Practices
- **Use hybrid approach:** Deploy both classical and PQ
- **Follow standards:** Use NIST-approved algorithms
- **Test thoroughly:** Extensive testing before deployment
- **Monitor research:** Stay updated on PQ developments
- **Plan ahead:** Start migration planning early

</div>

</div>

---
layout: default
---

# Video: The Future of Cryptography

<div class="flex items-center justify-center">
  <iframe 
    width="560" 
    height="315" 
    src="https://www.youtube.com/embed/lvTqbM5Dq4Q" 
    title="Future of Cryptography" 
    frameborder="0" 
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" 
    allowfullscreen
    class="rounded-lg">
  </iframe>
</div>

<div class="mt-4 text-sm text-gray-600 text-center">
<strong>Source:</strong> <a href="https://www.youtube.com/watch?v=lvTqbM5Dq4Q" target="_blank">MinutePhysics - How Quantum Computers Break Encryption | Shor's Algorithm Explained</a>
</div>

---
layout: default
---

# Summary

- **Quantum computers** threaten current cryptographic systems (RSA, ECDSA)
- **Quantum key distribution** offers provable security but has practical limitations
- **Post-quantum cryptography** provides quantum-resistant alternatives
- **NIST standards** (Kyber, Dilithium, Falcon, SPHINCS+) are now available
- **Hybrid approaches** enable gradual migration while maintaining security
- **Migration planning** should start now for critical systems

<div class="mt-4 text-sm text-gray-600">
<p><strong>Next Week:</strong> Practical projects and final project presentations.</p>
<p><strong>Assignment:</strong> Complete the post-quantum lab and submit performance analysis report.</p>
</div>

---
layout: end
---

# Questions?

<div class="pt-6">
  <span class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Thanks for exploring quantum and post-quantum cryptography! ⚛️🔐
  </span>
</div>

