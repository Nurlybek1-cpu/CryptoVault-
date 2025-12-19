---
theme: default
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Lecture 9: Digital Signatures
  MAT364 - Cryptography Course
drawings:
  persist: false
transition: slide-left
title: Digital Signatures
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

# Digital Signatures
## MAT364 - Cryptography Course

**Instructor:** Adil Akhmetov  
**University:** SDU  
**Week 9**

<div class="pt-6">
  <span @click="$slidev.nav.next" class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Press Space for next page →
  </span>
</div>

---
layout: default
---

# What Are Digital Signatures?

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Purpose
- **Authenticity**: Proves who created the message
- **Integrity**: Detects any tampering
- **Non-repudiation**: Signer cannot deny the signature

## High-Level Flow
1. Compute hash of message m → h = H(m)
2. Sign h with private key → σ
3. Verify with public key: Verify(m, σ) → true/false

</div>

<div>

## Building Blocks
- Cryptographic hash (e.g., SHA-256)
- Asymmetric keys (RSA, ECDSA, Ed25519)
- Secure padding or deterministic nonce generation

## Real-World Uses
- Software/code signing
- TLS certificates and OCSP
- Package registries (npm, PyPI)
- Documents and PDFs

</div>

</div>

<div class="mt-4 p-3 bg-blue-100 rounded-lg text-sm">
<strong>Key idea:</strong> Sign the hash, not the raw message; verify with the corresponding public key.
</div>

---
layout: section
---

# RSA-PSS Signatures

---
layout: default
---

# RSA-PSS: Secure Padding for Signatures

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Why PSS?
- Textbook RSA signatures are malleable and insecure
- **PSS (Probabilistic Signature Scheme)** provides provable security
- Random salt per signature → protects against structure-based attacks

## Guidance
- Use 2048–3072-bit RSA keys
- Hash: SHA-256 or stronger
- Public exponent e = 65537

</div>

<div>

## Python Example (`cryptography`)
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Key generation
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

message = b"Approve PR #42"

# Sign (RSA-PSS)
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Verify
public_key.verify(
    signature,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

</div>

</div>

---
layout: section
---

# ECDSA and Ed25519

---
layout: default
---

# ECDSA: Elliptic Curve Signatures

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Concepts
- Works over elliptic curves (e.g., secp256r1)
- Requires a fresh, uniformly random nonce k for each signature
- If k repeats or leaks → private key recovery

## Deterministic k (RFC 6979)
- Derive k from (privkey, H(m)) via HMAC-DRBG
- Avoids bad RNG failures

## Security
- Comparable security to RSA with much smaller keys
- Widely used in TLS, JWT libraries, blockchain systems

</div>

<div>

## Python Example (ECDSA)
```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()
msg = b"pay 10.00 USD"

signature = private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
public_key.verify(signature, msg, ec.ECDSA(hashes.SHA256()))
```

## Ed25519 (EdDSA)
- Twisted Edwards curve; deterministic and fast
- Safer API: no need to manage nonces

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

sk = ed25519.Ed25519PrivateKey.generate()
pk = sk.public_key()
sig = sk.sign(b"hello")
pk.verify(sig, b"hello")
```

</div>

</div>

---
layout: default
---

# Hash-Then-Sign and Pitfalls

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Correct Pattern
1. Canonicalize/serialize the message
2. Compute h = H(m)
3. Sign h using the scheme’s API (or pass m if API handles hashing)

## Do/Don't
- Do: include domain separation/context strings
- Do: sign exactly what you intend to verify
- Don't: sign non-canonical JSON or ambiguous encodings
- Don't: mix encodings (UTF-8 vs UTF-16) without care

</div>

<div>

## Common Vulnerabilities
- Nonce reuse in ECDSA (leaks private key)
- Using raw RSA (no PSS) → forgery
- Malleable or ambiguous message formats
- Ignoring verification errors or exceptions

## Mitigations
- Prefer Ed25519 or ECDSA with RFC 6979
- Use RSA-PSS for RSA signatures
- Define a canonical serialization (e.g., CBOR/JSON canonical)

</div>

</div>

---
layout: default
---

# 🎯 Student Task: Verify and Break

<div class="p-4 bg-gradient-to-r from-amber-50 to-yellow-50 rounded-lg border-2 border-amber-300">

## Part A: Verify a Signature
Given `message = "invoice #1234: 250 USD"`, generate an Ed25519 key pair, sign the message, and verify it.

## Part B: Spot the Bug
Consider ECDSA signing that uses a fixed `k = 42` for all messages. Explain how an attacker recovers the private key from two signatures over different messages.

### Deliverables
- Ed25519 signature (hex) and verification result
- Short explanation of the ECDSA nonce reuse attack

</div>

---
layout: default
---

# ✅ Solution Sketch

<div class="p-4 bg-gradient-to-r from-green-50 to-blue-50 rounded-lg border-2 border-green-300">

## Part A (Ed25519)
```python
from cryptography.hazmat.primitives.asymmetric import ed25519

msg = b"invoice #1234: 250 USD"
sk = ed25519.Ed25519PrivateKey.generate()
pk = sk.public_key()
sig = sk.sign(msg)

try:
    pk.verify(sig, msg)
    print("valid")
except Exception:
    print("invalid")
```

## Part B (Nonce Reuse in ECDSA)
If the same nonce k is reused for two signatures (r, s1) on m1 and (r, s2) on m2 over the same key,
then an attacker computes k = (H(m1) - H(m2)) / (s1 - s2) mod n and recovers the private key d from
the signature equation. Hence, k must be unique and unpredictable (or derived deterministically per RFC 6979).

</div>

---
layout: default
---

# Real-World Applications

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Code and Package Signing
- OS and driver signing (Windows, macOS, Linux distributions)
- Package managers: signed manifests and release keys
- Supply-chain security (Sigstore, Cosign)

## Web PKI
- X.509 certificates bind domain names to public keys
- Certificate Transparency logs
- OCSP stapling

</div>

<div>

## Documents and Protocols
- PDF/XML signing; long-term validation (timestamps)
- JWT/JWS for API authentication (ES256, RS256, EdDSA)
- Secure updates and firmware signing

## Recommendations
- Prefer Ed25519 or ECDSA (P-256) for new systems
- Use RSA-PSS where RSA is required
- Use robust, vetted libraries; never roll your own crypto

</div>

</div>

---
layout: default
---

# Best Practices

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Design and Implementation
- Canonicalize data before signing
- Include context strings and versioning in the signed payload
- Store public keys and metadata securely
- Rotate keys; support key revocation

</div>

<div>

## Operational Security
- Protect private keys with HSMs or secure enclaves
- Enforce strong randomness or deterministic nonces
- Log verification results and failures
- Test negative cases (tampering should fail)

</div>

</div>

---
layout: section
---

# Public Key Infrastructure (PKI)

---
layout: default
---

# Certificate Chains and Trust

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Certificate Hierarchy
- **Root CA** - Self-signed, trusted by OS/browser
- **Intermediate CA** - Signed by root, signs end-entities
- **End-entity** - Server certificates, code signing certs

## Trust Model
- **Web PKI** - Browser trust stores (Mozilla, Microsoft, Apple)
- **Enterprise PKI** - Internal CAs for corporate networks
- **Code signing** - Microsoft, Apple, Google trusted roots

</div>

<div>

## Certificate Structure (X.509)
```
Certificate:
  Version: 3
  Serial Number: unique identifier
  Issuer: CA that signed this cert
  Subject: entity this cert belongs to
  Validity: notBefore, notAfter
  Public Key: RSA/ECC public key
  Extensions: SAN, Key Usage, etc.
  Signature: CA's signature over above fields
```

## Key Extensions
- **Subject Alternative Name (SAN)** - Multiple domains/IPs
- **Key Usage** - Digital signature, key encipherment, etc.
- **Extended Key Usage** - TLS server, code signing, etc.

</div>

</div>

---
layout: default
---

# Certificate Validation Process

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Validation Steps
1. **Parse certificate** - Check format and version
2. **Check validity period** - Current time within notBefore/notAfter
3. **Verify signature** - CA's signature over certificate fields
4. **Build chain** - Trace back to trusted root
5. **Check revocation** - CRL or OCSP response
6. **Validate extensions** - Key usage, SAN, etc.

## Common Validation Libraries
- **OpenSSL** - C library, used by many applications
- **cryptography (Python)** - High-level Python bindings
- **Bouncy Castle** - Java/C# cryptographic library

</div>

<div>

## Python Certificate Validation
```python
from cryptography import x509
from cryptography.x509.verification import PolicyBuilder
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# Load certificate
with open("server.crt", "rb") as f:
    cert_data = f.read()
cert = x509.load_pem_x509_certificate(cert_data)

# Basic validation
now = datetime.datetime.now()
if now < cert.not_valid_before or now > cert.not_valid_after:
    raise ValueError("Certificate expired")

# Check subject alternative names
san_ext = cert.extensions.get_extension_for_oid(
    x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
)
san_names = san_ext.value
print(f"SAN: {san_names}")

# Verify signature (simplified)
public_key = cert.public_key()
public_key.verify(
    cert.signature,
    cert.tbs_certificate_bytes,
    cert.signature_algorithm_oid
)
```

</div>

</div>

---
layout: section
---

# JSON Web Tokens (JWT)

---
layout: default
---

# JWT Structure and Signing

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## JWT Components
```
Header.Payload.Signature
```

**Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "sub": "user123",
  "iat": 1516239022,
  "exp": 1516242622,
  "iss": "https://auth.example.com"
}
```

## Supported Algorithms
- **HS256** - HMAC with SHA-256
- **RS256** - RSA with SHA-256
- **ES256** - ECDSA with P-256 and SHA-256
- **EdDSA** - Ed25519 signatures

</div>

<div>

## JWT Implementation
```python
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Create JWT
payload = {
    "sub": "user123",
    "iat": 1516239022,
    "exp": 1516242622,
    "iss": "https://auth.example.com"
}

# Sign JWT
token = jwt.encode(
    payload,
    private_key,
    algorithm="RS256",
    headers={"kid": "key1"}
)

# Verify JWT
decoded = jwt.decode(
    token,
    public_key,
    algorithms=["RS256"],
    issuer="https://auth.example.com"
)
print(f"Subject: {decoded['sub']}")
```

</div>

</div>

---
layout: default
---

# JWT Security Considerations

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Common Vulnerabilities
- **Algorithm confusion** - "none" algorithm attack
- **Weak secrets** - Predictable HMAC keys
- **Key confusion** - Using public key as HMAC secret
- **Timing attacks** - Signature verification timing

## Best Practices
- **Validate algorithm** - Only accept expected algorithms
- **Short expiration** - Limit token lifetime
- **Secure storage** - Protect private keys
- **Key rotation** - Regular key updates

</div>

<div>

## Secure JWT Implementation
```python
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

class SecureJWT:
    def __init__(self, secret_key):
        self.secret_key = secret_key
        self.allowed_algs = ["HS256", "RS256", "ES256"]
    
    def create_token(self, payload, algorithm="HS256"):
        if algorithm not in self.allowed_algs:
            raise ValueError(f"Algorithm {algorithm} not allowed")
        
        # Add standard claims
        payload.update({
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,  # 1 hour
            "jti": secrets.token_urlsafe(32)  # Unique ID
        })
        
        return jwt.encode(payload, self.secret_key, algorithm=algorithm)
    
    def verify_token(self, token, algorithm="HS256"):
        try:
            decoded = jwt.decode(
                token,
                self.secret_key,
                algorithms=[algorithm],
                options={"verify_exp": True}
            )
            return decoded
        except jwt.ExpiredSignatureError:
            raise ValueError("Token expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")
```

</div>

</div>

---
layout: section
---

# Blockchain and Cryptocurrency Signatures

---
layout: default
---

# Bitcoin Transaction Signatures

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Bitcoin Transaction Structure
```
Transaction:
  Inputs: [previous_tx_hash, output_index, scriptSig]
  Outputs: [value, scriptPubKey]
  Locktime: block height or timestamp
```

## ScriptSig and ScriptPubKey
- **ScriptSig** - Contains signature and public key
- **ScriptPubKey** - Defines spending conditions
- **P2PKH** - Pay-to-Public-Key-Hash (most common)

## Signature Process
1. Create transaction hash (double SHA-256)
2. Sign hash with private key (ECDSA)
3. Include signature in ScriptSig
4. Miners verify signature during validation

</div>

<div>

## Bitcoin Signature Implementation
```python
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

class BitcoinTransaction:
    def __init__(self, private_key):
        self.private_key = private_key
        self.public_key = private_key.public_key()
    
    def create_transaction_hash(self, inputs, outputs, locktime=0):
        """Create transaction hash for signing"""
        # Simplified - real implementation is more complex
        tx_data = f"{inputs}{outputs}{locktime}".encode()
        return hashlib.sha256(hashlib.sha256(tx_data).digest()).digest()
    
    def sign_transaction(self, inputs, outputs, locktime=0):
        """Sign transaction with ECDSA"""
        tx_hash = self.create_transaction_hash(inputs, outputs, locktime)
        
        signature = self.private_key.sign(
            tx_hash,
            ec.ECDSA(hashes.SHA256())
        )
        
        return signature
    
    def verify_transaction(self, signature, inputs, outputs, locktime=0):
        """Verify transaction signature"""
        tx_hash = self.create_transaction_hash(inputs, outputs, locktime)
        
        try:
            self.public_key.verify(
                signature,
                tx_hash,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            return False
```

</div>

</div>

---
layout: default
---

# Ethereum Smart Contract Signatures

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Ethereum Transaction Structure
```
Transaction:
  nonce: transaction sequence number
  gasPrice: fee per gas unit
  gasLimit: maximum gas to use
  to: recipient address
  value: ETH amount
  data: contract call data
  v, r, s: signature components
```

## EIP-1559 (London Fork)
- **Base fee** - Network-determined fee
- **Priority fee** - User-determined tip
- **Max fee** - Maximum user willing to pay

</div>

<div>

## Ethereum Signature Implementation
```python
import rlp
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3

class EthereumTransaction:
    def __init__(self, private_key):
        self.private_key = private_key
        self.account = Account.from_key(private_key)
    
    def create_transaction(self, to, value, gas_price, gas_limit, nonce, data=b''):
        """Create unsigned transaction"""
        return {
            'to': to,
            'value': value,
            'gas': gas_limit,
            'gasPrice': gas_price,
            'nonce': nonce,
            'data': data,
            'chainId': 1  # Mainnet
        }
    
    def sign_transaction(self, transaction):
        """Sign transaction with EIP-155"""
        signed_txn = self.account.sign_transaction(transaction)
        return signed_txn.rawTransaction
    
    def verify_transaction(self, raw_transaction):
        """Verify transaction signature"""
        try:
            decoded = Account.recover_transaction(raw_transaction)
            return decoded == self.account.address
        except:
            return False
```

</div>

</div>

---
layout: section
---

# Advanced Signature Schemes

---
layout: default
---

# Threshold Signatures

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Concept
- **Threshold (t,n)** - Any t out of n parties can sign
- **Secret sharing** - Private key split among parties
- **Distributed signing** - No single party has full key
- **Applications** - Multi-sig wallets, consensus protocols

## Benefits
- **Fault tolerance** - Works even if some parties fail
- **Security** - No single point of failure
- **Flexibility** - Adjustable threshold

</div>

<div>

## Simplified Implementation
```python
from cryptography.hazmat.primitives.asymmetric import ed25519
import secrets

class ThresholdSignature:
    def __init__(self, threshold, total_parties):
        self.threshold = threshold
        self.total_parties = total_parties
        self.shares = []
    
    def generate_shares(self):
        """Generate secret shares (simplified)"""
        # In practice, use Shamir's Secret Sharing
        master_key = ed25519.Ed25519PrivateKey.generate()
        
        for i in range(self.total_parties):
            # Simplified: just generate random shares
            share = secrets.token_bytes(32)
            self.shares.append(share)
        
        return self.shares
    
    def combine_signatures(self, signatures):
        """Combine partial signatures"""
        if len(signatures) < self.threshold:
            raise ValueError("Not enough signatures")
        
        # Simplified combination
        combined = b''.join(signatures[:self.threshold])
        return combined
    
    def verify_threshold_signature(self, message, signature, public_key):
        """Verify threshold signature"""
        try:
            public_key.verify(signature, message)
            return True
        except:
            return False
```

</div>

</div>

---
layout: default
---

# Blind Signatures

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Concept
- **Blind signature** - Signer doesn't see the message
- **Unlinkability** - Signer can't link signature to message
- **Applications** - Electronic voting, anonymous credentials

## Process
1. **Blinding** - User blinds message with random factor
2. **Signing** - Signer signs blinded message
3. **Unblinding** - User removes blind factor
4. **Verification** - Anyone can verify unblinded signature

</div>

<div>

## Blind Signature Implementation
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import secrets

class BlindSignature:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def blind_message(self, message, blinding_factor):
        """Blind the message"""
        n = self.public_key.public_numbers().n
        e = self.public_key.public_numbers().e
        
        # Convert message to integer
        m = int.from_bytes(message, 'big')
        
        # Blind: m' = m * r^e mod n
        blinded = (m * pow(blinding_factor, e, n)) % n
        
        return blinded.to_bytes((blinded.bit_length() + 7) // 8, 'big')
    
    def sign_blinded_message(self, blinded_message):
        """Sign the blinded message"""
        return self.private_key.sign(
            blinded_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def unblind_signature(self, blinded_signature, blinding_factor):
        """Unblind the signature"""
        n = self.private_key.private_numbers().private_exponent
        
        # Convert signature to integer
        s = int.from_bytes(blinded_signature, 'big')
        
        # Unblind: s' = s / r mod n
        unblinded = (s * pow(blinding_factor, -1, n)) % n
        
        return unblinded.to_bytes((unblinded.bit_length() + 7) // 8, 'big')
```

</div>

</div>

---
layout: section
---

# Signature Performance and Optimization

---
layout: default
---

# Performance Comparison

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Algorithm Performance
| Algorithm | Key Size | Signature Size | Sign Speed | Verify Speed |
|-----------|----------|---------------|------------|--------------|
| RSA-2048  | 2048 bits| 256 bytes     | Slow       | Fast         |
| RSA-3072  | 3072 bits| 384 bytes     | Slower      | Medium       |
| ECDSA P-256| 256 bits | 64 bytes      | Fast        | Fast         |
| Ed25519   | 256 bits | 64 bytes      | Very Fast   | Very Fast   |

## When to Use What
- **RSA** - Legacy systems, certificate authorities
- **ECDSA** - TLS, blockchain, mobile applications
- **Ed25519** - New systems, high-performance applications

</div>

<div>

## Benchmarking Code
```python
import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import hashes

def benchmark_signature_algorithm(algorithm_name, private_key, public_key, message, iterations=1000):
    """Benchmark signature algorithm performance"""
    
    # Signing benchmark
    start_time = time.time()
    for _ in range(iterations):
        if algorithm_name == "RSA":
            signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif algorithm_name == "ECDSA":
            signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        elif algorithm_name == "Ed25519":
            signature = private_key.sign(message)
    
    sign_time = time.time() - start_time
    
    # Verification benchmark
    start_time = time.time()
    for _ in range(iterations):
        if algorithm_name == "RSA":
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif algorithm_name == "ECDSA":
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif algorithm_name == "Ed25519":
            public_key.verify(signature, message)
    
    verify_time = time.time() - start_time
    
    return {
        'sign_time': sign_time / iterations,
        'verify_time': verify_time / iterations,
        'signature_size': len(signature)
    }
```

</div>

</div>

---
layout: default
---

# Hardware Security Modules (HSMs)

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## HSM Benefits
- **Tamper resistance** - Physical protection
- **Key isolation** - Keys never leave HSM
- **Audit logging** - Track all operations
- **Compliance** - Meet regulatory requirements

## HSM Types
- **Network HSMs** - Remote access over network
- **USB HSMs** - Direct computer connection
- **Smart cards** - Portable, PIN-protected
- **Cloud HSMs** - AWS CloudHSM, Azure Dedicated HSM

</div>

<div>

## HSM Integration Example
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import pkcs11

class HSMKeyManager:
    def __init__(self, hsm_lib_path, token_label, pin):
        self.lib = pkcs11.lib(hsm_lib_path)
        self.token = self.lib.get_token(token_label)
        self.session = self.token.open(rw=True, user_pin=pin)
    
    def generate_key_pair(self, key_id, key_size=2048):
        """Generate RSA key pair in HSM"""
        public_key, private_key = self.session.generate_keypair(
            pkcs11.Mechanism.RSA_PKCS_KEY_PAIR_GEN,
            pkcs11.KeyType.RSA,
            key_size,
            id=key_id,
            token=True,
            private=True,
            sign=True,
            verify=True
        )
        return public_key, private_key
    
    def sign_with_hsm(self, private_key_id, message):
        """Sign message using HSM private key"""
        private_key = self.session.get_key(
            pkcs11.ObjectClass.PRIVATE_KEY,
            id=private_key_id
        )
        
        signature = self.session.sign(
            private_key,
            message,
            pkcs11.Mechanism.RSA_PKCS
        )
        
        return signature
    
    def verify_signature(self, public_key_id, message, signature):
        """Verify signature using HSM public key"""
        public_key = self.session.get_key(
            pkcs11.ObjectClass.PUBLIC_KEY,
            id=public_key_id
        )
        
        return self.session.verify(
            public_key,
            message,
            signature,
            pkcs11.Mechanism.RSA_PKCS
        )
```

</div>

</div>

---
layout: section
---

# Signature Attacks and Defenses

---
layout: default
---

# Common Signature Attacks

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## ECDSA Nonce Reuse
- **Problem** - Same k used for multiple signatures
- **Attack** - Recover private key from two signatures
- **Defense** - Use RFC 6979 deterministic nonces

## Fault Injection Attacks
- **Problem** - Hardware faults during signing
- **Attack** - Extract private key from faulty signatures
- **Defense** - Error checking, redundant computations

## Side-Channel Attacks
- **Problem** - Timing/power analysis reveals key
- **Attack** - Statistical analysis of execution traces
- **Defense** - Constant-time implementations

</div>

<div>

## Attack Mitigation Example
```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import hmac
import hashlib

class SecureECDSA:
    def __init__(self, private_key):
        self.private_key = private_key
        self.public_key = private_key.public_key()
    
    def deterministic_nonce(self, message_hash):
        """Generate deterministic nonce per RFC 6979"""
        # Simplified implementation
        private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Use HMAC-DRBG for deterministic nonce
        k = hmac.new(
            private_bytes,
            message_hash,
            hashlib.sha256
        ).digest()
        
        return int.from_bytes(k, 'big')
    
    def constant_time_verify(self, signature, message):
        """Constant-time signature verification"""
        try:
            self.public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            # Always take same time regardless of result
            time.sleep(0.001)  # Dummy delay
            return False
```

</div>

</div>

---
layout: default
---

# Post-Quantum Signatures

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Quantum Threat
- **Shor's algorithm** - Breaks RSA and ECDSA
- **Grover's algorithm** - Reduces symmetric key security
- **Timeline** - 10-30 years until practical quantum computers

## Post-Quantum Algorithms
- **Lattice-based** - Dilithium, Falcon
- **Hash-based** - SPHINCS+, XMSS
- **Code-based** - Classic McEliece
- **Multivariate** - Rainbow

</div>

<div>

## Dilithium Implementation (Concept)
```python
# Conceptual implementation - real Dilithium is much more complex
class DilithiumSignature:
    def __init__(self, security_level=2):
        self.security_level = security_level
        # Parameters vary by security level
        self.n = 256  # Polynomial degree
        self.q = 8380417  # Modulus
        self.eta = 2  # Secret coefficient bound
    
    def key_generation(self):
        """Generate Dilithium key pair"""
        # Simplified key generation
        # Real implementation uses polynomial arithmetic
        secret_key = self.generate_secret_polynomial()
        public_key = self.compute_public_key(secret_key)
        return secret_key, public_key
    
    def sign(self, message, secret_key):
        """Sign message with Dilithium"""
        # Simplified signing process
        # Real implementation is much more complex
        challenge = self.hash_message(message)
        signature = self.compute_signature(secret_key, challenge)
        return signature
    
    def verify(self, message, signature, public_key):
        """Verify Dilithium signature"""
        # Simplified verification
        challenge = self.hash_message(message)
        return self.verify_signature(signature, challenge, public_key)
```

</div>

</div>

---
layout: end
---

# Questions?

<div class="pt-6">
  <span class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Let's discuss digital signatures! ✍️
  </span>
</div>

<div class="mt-4 text-sm text-gray-600">
<p><strong>Next Week:</strong> Cryptographic protocols in web development (TLS usage, JWTs in practice).</p>
<p><strong>Assignment:</strong> Implement Ed25519 signing/verification with canonical JSON and test tamper detection.</p>
</div>


