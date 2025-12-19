# Elliptic Curve Diffie-Hellman (ECDH)

## Overview

**Elliptic Curve Diffie-Hellman (ECDH)** is a key agreement protocol that allows two parties to establish a shared secret over an insecure channel using elliptic curve cryptography. It is a variant of the classical Diffie-Hellman protocol but provides equivalent security with much smaller key sizes.

## Purpose

- **Secure Key Exchange**: Establish a shared secret between two parties without transmitting the secret itself
- **Forward Secrecy**: Generate ephemeral keys for each session
- **Efficiency**: Achieve strong security with smaller keys compared to traditional DH
- **Applications**: TLS/SSL, SSH, VPN, secure messaging (Signal, WhatsApp)

## Algorithm Specification

### Key Components

1. **Elliptic Curve**: A predefined elliptic curve (e.g., secp256r1, Curve25519, secp256k1)
2. **Generator Point (G)**: A base point on the elliptic curve
3. **Private Keys**: Random integers `a` (Alice) and `b` (Bob)
4. **Public Keys**: Points on the curve `A = aG` and `B = bG`
5. **Shared Secret**: Point `S = aB = bA = abG`

### Mathematical Foundation

Elliptic curves follow the equation:
- **Weierstrass Form**: y² = x³ + ax + b (mod p)
- **Montgomery Form**: By² = x³ + Ax² + x (mod p)

The difficulty of the **Elliptic Curve Discrete Logarithm Problem (ECDLP)** ensures security.

## How ECDH Works

### Step-by-Step Process

**1. Initialization**
- Both parties agree on:
  - Elliptic curve parameters
  - Generator point G
  - Curve domain parameters

**2. Key Generation (Alice's Side)**
```
a = random private key (256-bit random number)
A = a × G (public key - point on curve)
```

**3. Key Generation (Bob's Side)**
```
b = random private key (256-bit random number)
B = b × G (public key - point on curve)
```

**4. Key Exchange**
- Alice sends public key A to Bob
- Bob sends public key B to Alice

**5. Shared Secret Computation**

**Alice computes**:
```
S = a × B = a × (b × G) = ab × G
```

**Bob computes**:
```
S = b × A = b × (a × G) = ab × G
```

Both arrive at the same shared secret S.

**6. Key Derivation**
- Extract x-coordinate of point S
- Apply Key Derivation Function (KDF):
  ```
  K = HKDF-SHA256(x_coordinate, salt, info)
  ```

## Standard Curves

### Recommended Curves

| Curve | Key Size | Security Level | Usage |
|-------|----------|----------------|-------|
| **secp256r1** (P-256) | 256 bits | 128-bit | TLS, general purpose |
| **secp384r1** (P-384) | 384 bits | 192-bit | High security apps |
| **secp521r1** (P-521) | 521 bits | 256-bit | Maximum security |
| **Curve25519** | 255 bits | 128-bit | Modern protocols, SSH |
| **secp256k1** | 256 bits | 128-bit | Bitcoin, Ethereum |

### Curve25519 Advantages
- **Fast**: Optimized for speed
- **Safe**: Resistant to implementation errors
- **Simple**: Easier to implement securely
- **No timing attacks**: Constant-time operations

## Implementation Example

### Python Implementation (using cryptography library)

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class ECDHKeyExchange:
    def __init__(self, curve=ec.SECP256R1()):
        """Initialize ECDH with specified curve"""
        self.curve = curve
        self.private_key = ec.generate_private_key(self.curve)
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self):
        """Get public key in PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def compute_shared_secret(self, peer_public_bytes):
        """Compute shared secret from peer's public key"""
        # Load peer's public key
        peer_public = serialization.load_pem_public_key(peer_public_bytes)

        # Perform ECDH
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public)

        # Derive encryption key using HKDF
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=None,
            info=b'handshake data'
        )
        return kdf.derive(shared_key)

# Usage Example
# Alice's side
alice = ECDHKeyExchange()
alice_public = alice.get_public_bytes()

# Bob's side
bob = ECDHKeyExchange()
bob_public = bob.get_public_bytes()

# Both compute shared secret
alice_shared = alice.compute_shared_secret(bob_public)
bob_shared = bob.compute_shared_secret(alice_public)

# Verify they match
assert alice_shared == bob_shared
print(f"Shared secret established: {alice_shared.hex()[:32]}...")
```

### JavaScript/Node.js Implementation

```javascript
const crypto = require('crypto');

class ECDHKeyExchange {
    constructor(curveName = 'secp256k1') {
        this.ecdh = crypto.createECDH(curveName);
        this.ecdh.generateKeys();
    }

    getPublicKey() {
        return this.ecdh.getPublicKey('hex');
    }

    computeSharedSecret(peerPublicKey) {
        return this.ecdh.computeSecret(peerPublicKey, 'hex', 'hex');
    }
}

// Usage
const alice = new ECDHKeyExchange();
const bob = new ECDHKeyExchange();

const aliceShared = alice.computeSharedSecret(bob.getPublicKey());
const bobShared = bob.computeSharedSecret(alice.getPublicKey());

console.log('Shared secrets match:', aliceShared === bobShared);
```

## Security Considerations

### Strengths

1. **Small Key Sizes**: 256-bit ECC ≈ 3072-bit RSA security
2. **Computational Efficiency**: Faster than RSA/traditional DH
3. **Low Bandwidth**: Smaller keys = less data transmission
4. **Perfect Forward Secrecy**: When using ephemeral keys

### Vulnerabilities & Mitigations

| Vulnerability | Mitigation |
|---------------|------------|
| **Man-in-the-Middle** | Use authenticated ECDH (certificates, signatures) |
| **Weak Random Numbers** | Use cryptographically secure RNG (CSPRNG) |
| **Invalid Curve Attacks** | Validate public keys are on the curve |
| **Small Subgroup Attacks** | Check public key order |
| **Timing Attacks** | Use constant-time implementations |

### Best Practices

```python
def validate_public_key(public_key, curve):
    """Validate ECDH public key"""
    # 1. Check key is not point at infinity
    if public_key.is_infinity():
        raise ValueError("Invalid key: point at infinity")

    # 2. Check point is on the curve
    if not curve.contains_point(public_key):
        raise ValueError("Invalid key: not on curve")

    # 3. Check point order (prevent small subgroup attacks)
    if not has_correct_order(public_key, curve.order):
        raise ValueError("Invalid key: wrong order")

    return True
```

## Real-World Applications

### TLS 1.3 Handshake

```python
class TLS13Handshake:
    def __init__(self):
        self.ecdh = ECDHKeyExchange()
        self.cipher_suites = ['TLS_AES_256_GCM_SHA384', 
                              'TLS_CHACHA20_POLY1305_SHA256']

    def create_client_hello(self):
        return {
            'version': 'TLS 1.3',
            'cipher_suites': self.cipher_suites,
            'key_share': self.ecdh.get_public_bytes(),
            'supported_groups': ['secp256r1', 'x25519']
        }

    def process_server_hello(self, server_hello):
        peer_public = server_hello['key_share']
        shared_secret = self.ecdh.compute_shared_secret(peer_public)

        # Derive handshake and application keys
        handshake_key = self.derive_key(shared_secret, b'handshake')
        app_key = self.derive_key(shared_secret, b'application')

        return handshake_key, app_key
```

### Secure Messaging (Signal Protocol)

Uses ECDH with:
- **X3DH**: Extended Triple Diffie-Hellman for initial key agreement
- **Double Ratchet**: Continuous ECDH for forward secrecy

### Blockchain Applications

- **Bitcoin/Ethereum**: secp256k1 curve for key generation
- **Key Derivation**: BIP32/BIP44 hierarchical deterministic wallets

## Performance Comparison

| Operation | secp256r1 | Curve25519 | RSA-2048 |
|-----------|-----------|------------|----------|
| **Key Generation** | ~1 ms | ~0.5 ms | ~100 ms |
| **Shared Secret** | ~1 ms | ~0.5 ms | N/A |
| **Key Size** | 32 bytes | 32 bytes | 256 bytes |
| **Public Key** | 65 bytes | 32 bytes | 256 bytes |

## Conclusion

ECDH provides efficient, secure key agreement for modern cryptographic protocols. Its combination of strong security guarantees, small key sizes, and computational efficiency makes it the preferred choice for:

- **TLS/SSL**: Web security
- **SSH**: Secure remote access
- **VPNs**: WireGuard, IPsec
- **Messaging**: Signal, WhatsApp
- **Blockchain**: Bitcoin, Ethereum

**Key Takeaway**: Always use authenticated ECDH (with certificates or signatures) in production to prevent man-in-the-middle attacks.
