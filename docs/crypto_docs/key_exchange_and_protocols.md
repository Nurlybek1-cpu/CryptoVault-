---
theme: default
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Lecture 8: Key Exchange and Protocols
  MAT364 - Cryptography Course
drawings:
  persist: false
transition: slide-left
title: Key Exchange and Protocols
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

# Key Exchange and Protocols
## MAT364 - Cryptography Course

**Instructor:** Adil Akhmetov  
**University:** SDU  
**Week 8**

<div class="pt-6">
  <span @click="$slidev.nav.next" class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Press Space for next page →
  </span>
</div>

---
layout: default
---

# The Key Exchange Problem

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## The Challenge
- **Alice and Bob** want to communicate securely
- **No pre-shared secret** exists
- **Eve eavesdrops** on all communication
- **How to establish** shared secret key?

## Before Public Key Crypto
- **Courier delivery** - Slow and expensive
- **Pre-shared keys** - Doesn't scale
- **Trusted third party** - Single point of failure
- **Physical meeting** - Not always possible

</div>

<div>

## The Breakthrough
**Diffie-Hellman (1976):**
- First practical key exchange protocol
- Based on discrete logarithm problem
- Allows secure key establishment over insecure channel
- Foundation for modern cryptography

## Real-World Importance
- **TLS/SSL** - Secure web browsing
- **VPN** - Secure remote access
- **SSH** - Secure shell connections
- **Signal/WhatsApp** - Secure messaging

</div>

</div>

<div class="mt-4 p-3 bg-blue-100 rounded-lg text-sm">
<strong>Key insight:</strong> Key exchange enables secure communication without pre-shared secrets!
</div>

---
layout: section
---

# Diffie-Hellman Key Exchange

---
layout: default
---

# Diffie-Hellman Protocol

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## How It Works
1. **Public parameters:** prime p and generator g
2. **Alice's secret:** random a, sends A = g^a mod p
3. **Bob's secret:** random b, sends B = g^b mod p
4. **Shared secret:** Both compute s = g^(ab) mod p

## Mathematical Foundation
- **Discrete log problem:** Given g, p, and g^a, hard to find a
- **Diffie-Hellman problem:** Given g^a and g^b, hard to find g^(ab)
- **Security:** Relies on hardness of these problems

</div>

<div>

## Example
```python
# Public parameters
p = 23  # Prime modulus
g = 5   # Generator

# Alice's side
a = 6  # Alice's secret
A = pow(g, a, p)  # A = 5^6 mod 23 = 8

# Bob's side
b = 15  # Bob's secret
B = pow(g, b, p)  # B = 5^15 mod 23 = 19

# Shared secret computation
# Alice computes: s = B^a mod p = 19^6 mod 23 = 2
s_alice = pow(B, a, p)

# Bob computes: s = A^b mod p = 8^15 mod 23 = 2
s_bob = pow(A, b, p)

print(f"Shared secret: {s_alice} = {s_bob}")
```

</div>

</div>

---
layout: default
---

# DH Implementation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Complete Implementation
```python
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

class DiffieHellmanKeyExchange:
    def __init__(self, key_size=2048):
        # Generate parameters (usually pre-shared)
        self.parameters = dh.generate_parameters(
            generator=2,
            key_size=key_size
        )
        
        # Generate private key
        self.private_key = self.parameters.generate_private_key()
        
        # Get public key
        self.public_key = self.private_key.public_key()
    
    def get_public_bytes(self):
        """Serialize public key for transmission"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def compute_shared_secret(self, peer_public_bytes):
        """Compute shared secret from peer's public key"""
        peer_public_key = serialization.load_pem_public_key(
            peer_public_bytes
        )
        shared_key = self.private_key.exchange(peer_public_key)
        return shared_key
```

</div>

<div>

## Usage Example
```python
# Alice's side
alice = DiffieHellmanKeyExchange()
alice_public = alice.get_public_bytes()

# Bob's side
bob = DiffieHellmanKeyExchange()
bob_public = bob.get_public_bytes()

# Exchange public keys (over insecure channel)
# ...

# Compute shared secrets
alice_shared = alice.compute_shared_secret(bob_public)
bob_shared = bob.compute_shared_secret(alice_public)

# Verify they match
assert alice_shared == bob_shared
print(f"Shared secret established: {alice_shared.hex()[:32]}...")

# Derive symmetric keys from shared secret
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def derive_key(shared_secret, info=b''):
    """Derive symmetric key from shared secret"""
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    )
    return kdf.derive(shared_secret)

encryption_key = derive_key(alice_shared, b'encryption')
```

</div>

</div>

---
layout: default
---

# Man-in-the-Middle Attack

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## The Attack
**Eve intercepts and modifies:**
1. Alice sends A → Eve intercepts, sends E₁
2. Bob sends B → Eve intercepts, sends E₂
3. Alice thinks she's talking to Bob (key K₁)
4. Bob thinks he's talking to Alice (key K₂)
5. Eve can decrypt, read, re-encrypt all messages

## Why It Works
- **No authentication** in basic DH
- **Eve controls** the channel
- **Alice and Bob** can't detect the attack
- **Need authentication** to prevent this

</div>

<div>

## Attack Diagram
```
Alice          Eve           Bob
  |             |             |
  |-- A -->     |             |
  |             |-- E1 -->    |
  |             |             |
  |             |     <-- B --|
  |     <-- E2 -|             |
  |             |             |
K1 = E2^a     K1 = A^e1      K2 = E1^b
              K2 = B^e2
```

## Solution: Authenticated DH
- **Sign** public keys with private key
- **Verify signatures** before computing shared secret
- **Use certificates** to bind identity to public key
- **Station-to-Station** protocol
- **TLS handshake** includes authentication

</div>

</div>

<div class="mt-4 p-3 bg-red-100 rounded-lg text-sm">
<strong>Warning:</strong> Never use unauthenticated DH in production! Always combine with authentication.
</div>

---
layout: default
---

# 🎯 Student Task: DH Key Exchange

<div class="p-4 bg-gradient-to-r from-amber-50 to-yellow-50 rounded-lg border-2 border-amber-300">

## Task: Manual DH Calculation
Given public parameters:
- p = 71 (prime)
- g = 7 (generator)
- Alice's secret: a = 5
- Bob's secret: b = 12

**Your tasks:**
1. Calculate Alice's public value A = g^a mod p
2. Calculate Bob's public value B = g^b mod p
3. Calculate shared secret from Alice's perspective: s = B^a mod p
4. Calculate shared secret from Bob's perspective: s = A^b mod p
5. Verify they match

**Bonus:** Explain why Eve can't compute the shared secret even though she sees A and B.

</div>

---
layout: default
---

# ✅ Solution: DH Calculation

<div class="p-4 bg-gradient-to-r from-green-50 to-blue-50 rounded-lg border-2 border-green-300">

## Step-by-Step Solution

**Given:** p = 71, g = 7, a = 5, b = 12

**Step 1:** Alice's public value
```
A = g^a mod p = 7^5 mod 71 = 16807 mod 71 = 51
```

**Step 2:** Bob's public value
```
B = g^b mod p = 7^12 mod 71 = 13841287201 mod 71 = 4
```

**Step 3:** Alice computes shared secret
```
s = B^a mod p = 4^5 mod 71 = 1024 mod 71 = 30
```

**Step 4:** Bob computes shared secret
```
s = A^b mod p = 51^12 mod 71 = 30
```

**Bonus answer:** Eve sees A=51 and B=4, but computing g^(ab) from g^a and g^b is the Diffie-Hellman problem, which is computationally hard.

</div>

---
layout: section
---

# Elliptic Curve Diffie-Hellman (ECDH)

---
layout: default
---

# ECDH Overview

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Why ECDH?
- **Smaller keys** - 256-bit ECC ≈ 3072-bit RSA
- **Faster** - More efficient operations
- **Lower bandwidth** - Smaller key transmission
- **Mobile-friendly** - Less computation/storage

## How It Works
1. **Agree on curve** and base point G
2. **Alice:** secret a, public A = aG
3. **Bob:** secret b, public B = bG
4. **Shared secret:** S = aB = bA = abG

</div>

<div>

## Implementation
```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class ECDHKeyExchange:
    def __init__(self):
        # Generate private key on secp256r1 curve
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
    
    def get_public_bytes(self):
        """Get public key for transmission"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def compute_shared_secret(self, peer_public_bytes):
        """Compute ECDH shared secret"""
        peer_public = serialization.load_pem_public_key(
            peer_public_bytes
        )
        shared_key = self.private_key.exchange(
            ec.ECDH(), peer_public
        )
        
        # Derive key using HKDF
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        )
        return kdf.derive(shared_key)
```

</div>

</div>

---
layout: section
---

# TLS Handshake Protocol

---
layout: default
---

# TLS 1.3 Handshake

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Handshake Flow
**ClientHello:**
- Supported cipher suites
- Key share (ECDHE public key)
- Supported groups (curves)

**ServerHello:**
- Selected cipher suite
- Key share (server's public key)
- Server certificate

**Key Derivation:**
- Both compute shared secret
- Derive encryption keys
- Start encrypted communication

</div>

<div>

## Simplified Implementation
```python
class TLSHandshake:
    def __init__(self, is_server=False):
        self.is_server = is_server
        self.ecdh = ECDHKeyExchange()
        self.cipher_suites = [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256'
        ]
    
    def create_client_hello(self):
        """Create ClientHello message"""
        return {
            'version': 'TLS 1.3',
            'cipher_suites': self.cipher_suites,
            'key_share': self.ecdh.get_public_bytes(),
            'supported_groups': ['secp256r1', 'x25519']
        }
    
    def process_server_hello(self, server_hello):
        """Process ServerHello and establish keys"""
        peer_public = server_hello['key_share']
        shared_secret = self.ecdh.compute_shared_secret(peer_public)
        
        # Derive handshake and application keys
        handshake_key = self.derive_key(shared_secret, b'handshake')
        app_key = self.derive_key(shared_secret, b'application')
        
        return handshake_key, app_key
```

</div>

</div>

---
layout: default
---

# Perfect Forward Secrecy (PFS)

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## What is PFS?
- **Ephemeral keys** for each session
- **Past sessions** remain secure even if long-term key compromised
- **No single key** can decrypt all past traffic
- **Essential** for long-term security

## Without PFS
- RSA key exchange: same key encrypts many sessions
- If private key leaked → all past traffic decryptable
- "Decrypt all historical traffic" attack

</div>

<div>

## With PFS (DHE/ECDHE)
- **New ephemeral key** for each session
- **Session keys** discarded after use
- **Past sessions** remain secure
- **TLS 1.3** mandates PFS

## Implementation
```python
class PFSSession:
    def __init__(self):
        # Generate ephemeral key pair
        self.ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    
    def start_session(self, peer_public):
        """Start new session with PFS"""
        # Compute session key
        session_key = self.ephemeral_key.exchange(
            ec.ECDH(), peer_public
        )
        
        # Immediately discard private key after use
        self.ephemeral_key = None
        
        return self.derive_session_keys(session_key)
    
    def derive_session_keys(self, shared_secret):
        """Derive encryption and MAC keys"""
        # Use HKDF to derive separate keys
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'encryption'
        ).derive(shared_secret)
        
        mac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'mac'
        ).derive(shared_secret)
        
        return encryption_key, mac_key
```

</div>

</div>

---
layout: section
---

# Authenticated Key Exchange

---
layout: default
---

# Station-to-Station (STS) Protocol

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Protocol Flow
1. **Alice → Bob:** g^a
2. **Bob → Alice:** g^b, Sig_B(g^a, g^b)
3. **Alice → Bob:** Sig_A(g^a, g^b)
4. **Both verify** signatures with certificates
5. **Compute** shared secret

## Security Properties
- **Authentication** - Both parties verified
- **Key confirmation** - Both know they have same key
- **Perfect forward secrecy** - Ephemeral keys
- **Prevents MITM** - Signatures bind identity

</div>

<div>

## Implementation Sketch
```python
class STSProtocol:
    def __init__(self, private_key, certificate):
        self.private_key = private_key  # Long-term signing key
        self.certificate = certificate
        self.dh = DiffieHellmanKeyExchange()
    
    def initiate(self):
        """Initiator sends DH public value"""
        return self.dh.get_public_bytes()
    
    def respond(self, initiator_public):
        """Responder sends DH public + signature"""
        my_public = self.dh.get_public_bytes()
        
        # Sign both public values
        signature = self.private_key.sign(
            initiator_public + my_public,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return my_public, signature, self.certificate
    
    def verify_and_finish(self, peer_public, signature, cert):
        """Verify signature and compute shared secret"""
        my_public = self.dh.get_public_bytes()
        
        # Verify signature
        public_key = cert.public_key()
        public_key.verify(
            signature,
            my_public + peer_public,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Compute shared secret
        return self.dh.compute_shared_secret(peer_public)
```

</div>

</div>

---
layout: default
---

# Signal Protocol (Double Ratchet)

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Key Features
- **End-to-end encryption** for messaging
- **Perfect forward secrecy** for every message
- **Future secrecy** - Compromise doesn't affect future
- **Used by** Signal, WhatsApp, Facebook Messenger

## Ratchets
**DH Ratchet:**
- New ECDH key pair for each message exchange
- Provides forward secrecy

**Symmetric Ratchet:**
- Derives new keys from previous keys
- KDF chain for message keys

</div>

<div>

## Simplified Concept
```python
class DoubleRatchet:
    def __init__(self):
        self.dh_key = ec.generate_private_key(ec.SECP256R1())
        self.root_key = None
        self.chain_key = None
        self.message_number = 0
    
    def dh_ratchet(self, peer_public):
        """Perform DH ratchet step"""
        # Compute new shared secret
        dh_output = self.dh_key.exchange(ec.ECDH(), peer_public)
        
        # Derive new root and chain keys
        self.root_key, self.chain_key = self.kdf_rk(
            self.root_key, dh_output
        )
        
        # Generate new DH key pair
        self.dh_key = ec.generate_private_key(ec.SECP256R1())
        self.message_number = 0
    
    def symmetric_ratchet(self):
        """Derive next message key"""
        message_key, self.chain_key = self.kdf_ck(self.chain_key)
        self.message_number += 1
        return message_key
    
    def encrypt_message(self, plaintext):
        """Encrypt message with current keys"""
        message_key = self.symmetric_ratchet()
        
        # Encrypt with message key (AES-256-GCM)
        cipher = Cipher(
            algorithms.AES(message_key),
            modes.GCM(os.urandom(12))
        )
        # ... encryption logic ...
```

</div>

</div>

---
layout: default
---

# Key Derivation Functions (KDFs)

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Purpose
- **Transform** shared secret into usable keys
- **Expand** short secret into multiple keys
- **Extract** entropy from non-uniform sources
- **Domain separation** - Different keys for different purposes

## HKDF (HMAC-based KDF)
- **Extract:** Extract fixed-length key from source
- **Expand:** Expand key to desired length
- **Standard:** RFC 5869

</div>

<div>

## Implementation
```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_keys(shared_secret, salt=None):
    """Derive multiple keys from shared secret"""
    
    # Extract phase
    kdf_extract = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'master'
    )
    master_key = kdf_extract.derive(shared_secret)
    
    # Expand phase for different purposes
    def expand_key(info, length=32):
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info
        )
        return kdf.derive(master_key)
    
    return {
        'encryption_key': expand_key(b'encryption'),
        'mac_key': expand_key(b'mac'),
        'iv': expand_key(b'iv', 16)
    }

# Usage
shared_secret = os.urandom(32)
keys = derive_keys(shared_secret)
```

</div>

</div>

---
layout: default
---

# 🎯 Student Task: Protocol Analysis

<div class="p-4 bg-gradient-to-r from-indigo-50 to-purple-50 rounded-lg border-2 border-indigo-300">

## Task: Design Secure Protocol

**Scenario:** Alice and Bob want to establish a secure channel for exchanging messages.

**Requirements:**
1. Mutual authentication (both verify each other's identity)
2. Perfect forward secrecy
3. Resistance to man-in-the-middle attacks
4. Efficient for mobile devices

**Your task:**
1. Choose key exchange method (DH or ECDH)
2. Design authentication mechanism
3. Specify key derivation process
4. Describe message encryption scheme
5. Identify potential vulnerabilities

**Deliverable:** Protocol description with security analysis

</div>

---
layout: default
---

# ✅ Solution: Protocol Design

<div class="p-4 bg-gradient-to-r from-green-50 to-emerald-50 rounded-lg border-2 border-green-300">

## Recommended Solution

**Protocol: Authenticated ECDHE with Certificates**

1. **Key Exchange:** ECDHE (secp256r1 or X25519)
2. **Authentication:** Digital signatures (ECDSA)
3. **Key Derivation:** HKDF-SHA256
4. **Encryption:** AES-256-GCM

**Flow:**
```
Alice → Bob: A = aG, Cert_A
Bob → Alice: B = bG, Cert_B, Sig_B(A || B)
Alice → Bob: Sig_A(A || B)
Both: Verify certs and signatures, compute K = abG
Both: Derive keys = HKDF(K, "encryption" || "mac")
```

**Security:**
- ECDHE provides PFS
- Certificates prevent MITM
- Signatures bind identity to session
- Efficient for mobile (small keys)

</div>

---
layout: default
---

# Real-World Protocols

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## TLS 1.3
- **Mandatory PFS** (DHE/ECDHE only)
- **1-RTT** handshake
- **0-RTT** resumption (with replay risk)
- **Simplified** cipher suites

## SSH (Secure Shell)
- **Key exchange:** DH group exchange
- **Authentication:** Public key, password, certificates
- **Channel security:** Separate keys for each direction
- **Applications:** Remote login, file transfer

</div>

<div>

## WireGuard VPN
- **Modern** cryptographic primitives
- **Simple** protocol design
- **Fast** performance
- **Noise Protocol** framework

## IPsec
- **IKEv2** key exchange
- **ESP/AH** protocols
- **SA (Security Association)** establishment
- **VPN** and network-level security

</div>

</div>

---
layout: default
---

# Best Practices

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Protocol Design
- **Use established protocols** (TLS, Signal)
- **Avoid custom protocols** unless expert
- **Get security review** before deployment
- **Follow standards** (NIST, IETF RFCs)

## Implementation
- **Use vetted libraries** (OpenSSL, cryptography)
- **Validate all inputs** and certificates
- **Implement timeouts** and limits
- **Test edge cases** thoroughly

</div>

<div>

## Security Considerations
- **Always authenticate** key exchange
- **Use perfect forward secrecy**
- **Derive keys properly** (HKDF)
- **Check certificate validity**
- **Implement revocation** checking

## Common Mistakes
- ❌ Unauthenticated DH
- ❌ Reusing ephemeral keys
- ❌ Weak random number generation
- ❌ Missing certificate validation
- ❌ Poor error handling

</div>

</div>

---
layout: end
---

# Questions?

<div class="pt-6">
  <span class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Let's discuss key exchange protocols! 💬
  </span>
</div>

<div class="mt-4 text-sm text-gray-600">
<p><strong>Next Week:</strong> We'll explore digital signatures and their applications in detail.</p>
<p><strong>Assignment:</strong> Implement ECDH key exchange with proper key derivation.</p>
</div>

