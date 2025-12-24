# Key Wrapping: The Definitive Guide

**Version:** 1.0  
**Author:** Research Agent  
**Date:** December 2025  
**Standards:** NIST SP 800-38F, RFC 3394, RFC 5649  

---

## 1. Executive Summary

**Key Wrapping** is a specific class of authenticated encryption algorithms designed to protect cryptographic keys. Unlike general data encryption, key wrapping algorithms are optimized for short, high-entropy data (keys) and focus on providing **robustness**—meaning every bit of the output depends on every bit of the input.

This prevents specific attacks where an attacker might manipulate individual bits of a key to weaken it without detection. Key wrapping is the foundation of **Key Management Systems (KMS)**, **Hardware Security Modules (HSM)**, and **Envelope Encryption** architectures.

### Why not just use AES-GCM?
| Feature | Key Wrapping (AES-KW) | AES-GCM |
| :--- | :--- | :--- |
| **Goal** | Encrypting Keys | Encrypting Data |
| **Overhead** | Low (8 bytes) | High (IV + Tag = ~28 bytes) |
| **Determinism** | **Deterministic** (Same key = Same ciphertext) | **Probabilistic** (Requires unique Nonce) |
| **Robustness** | High (Bit manipulation breaks entire key) | High (Auth tag protects integrity) |
| **Standard Use** | HSMs, Smart Cards, Key Import | TLS, File Encryption, Database |

---

## 2. Core Concepts & Terminology

*   **KEK (Key Encryption Key)**: The "master" key used to wrap other keys. This key must remain static and highly secured (often inside an HSM).
*   **DEK (Data Encryption Key)**: The "working" key used to encrypt actual data. This key is wrapped by the KEK.
*   **Wrapped Key**: The ciphertext resulting from encrypting a DEK with a KEK.
*   **IV (Integrity Check Value)**: A magic constant used to verify that the unwrapped key is valid. If the IV doesn't match after decryption, the key is considered corrupted.

---

## 3. The Algorithms

The two global standards for key wrapping are **AES-KW** (RFC 3394) and **AES-KWP** (RFC 5649). Both are approved by NIST under Special Publication 800-38F.

### 3.1 AES-KW (RFC 3394)
Used when the key to be wrapped is a multiple of 64 bits (e.g., 128-bit, 192-bit, 256-bit keys).

**The Magic Constant (IV):**
$$ IV = \text{0xA6A6A6A6A6A6A6A6} $$

**The Logic:**
AES-KW uses a "Feistel network" structure. It repeatedly encrypts the key blocks with the main KEK while mixing in a round counter. This ensures that every bit of the output is affected by every bit of the input.

**Algorithm ($W(S)$):**
Given a plaintext $P$ consisting of $n$ 64-bit blocks ($P_1, P_2, ..., P_n$):
1.  Initialize $A = IV$.
2.  For $t = 1$ to $6(n)$:
    *   $A = MSB_{64}(AES_K(A \parallel R[i])) \oplus t$
    *   $R[i] = LSB_{64}(AES_K(A \parallel R[i]))$
    *   (Where $R[i]$ are the key blocks)
3.  Output $C = A \parallel R_1 \parallel ... \parallel R_n$

### 3.2 AES-KWP (RFC 5649)
Used when the key length is **not** a multiple of 64 bits (e.g., an RSA private key which might be 2048 bits + metadata). It adds padding and a length indicator.

**The Magic Constant (IV):**
$$ IV = \text{0xA65959A6} $$

**The Wrap Process:**
1.  Append padding to the input so it matches 64-bit alignment.
2.  Construct the IV block: `0xA65959A6` || `32-bit Length of Key`.
3.  Run the standard AES-KW algorithm on this padded data.

---

## 4. Implementation Guide

### 4.1 Python (Using `cryptography`)
The standard for Python security.

```python
from cryptography.hazmat.primitives import keywrap
import os

# 1. The Master Key (KEK) - 256 bit
kek = os.urandom(32)

# 2. The Key to Protect (DEK) - 256 bit
dek = os.urandom(32)

# 3. WRAP
# Uses AES-KW (RFC 3394)
wrapped_key = keywrap.aes_key_wrap(
    wrapping_key=kek,
    key_to_wrap=dek
)

print(f"Original DEK: {dek.hex()}")
print(f"Wrapped DEK:  {wrapped_key.hex()}") 
# Note: Wrapped key is 8 bytes longer than DEK (IV size)

# 4. UNWRAP
try:
    unwrapped_dek = keywrap.aes_key_unwrap(
        wrapping_key=kek,
        wrapped_key=wrapped_key
    )
    assert dek == unwrapped_dek
    print("Success: Key unwrapped and integrity verified.")
except keywrap.InvalidUnwrap:
    print("Error: Integrity check failed (wrong KEK or corrupted data).")
```

### 4.2 OpenSSL CLI
Useful for shell scripts and manual key management.

```bash
# Generate a random 256-bit KEK (hex encoded)
openssl rand -hex 32 > kek.hex

# Generate a DEK (binary)
openssl rand -out dek.bin 32

# WRAP (using AES-256-KW)
# -id-aes256-wrap is the specific cipher OID for RFC 3394
# -K requires the hex representation of the key
openssl enc -id-aes256-wrap -e -in dek.bin -out dek.wrapped -K $(cat kek.hex)

# UNWRAP
# -d for decrypt
openssl enc -id-aes256-wrap -d -in dek.wrapped -out dek.unwrapped -K $(cat kek.hex)
```

**Note:** For padding support (RFC 5649), use `-id-aes256-wrap-pad`.

### 4.3 Java (Bouncy Castle)
Java's standard crypto library often requires Bouncy Castle for specific KW padding modes.

```java
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;

public class KeyWrapExample {
    public static byte[] wrapKey(byte[] kek, byte[] dek) {
        AESWrapEngine engine = new AESWrapEngine();
        engine.init(true, new KeyParameter(kek)); // true = wrap
        return engine.wrap(dek, 0, dek.length);
    }

    public static byte[] unwrapKey(byte[] kek, byte[] wrappedKey) throws Exception {
        AESWrapEngine engine = new AESWrapEngine();
        engine.init(false, new KeyParameter(kek)); // false = unwrap
        return engine.unwrap(wrappedKey, 0, wrappedKey.length);
    }
}
```

---

## 5. Cloud Integration Patterns

### 5.1 Envelope Encryption
This is the standard pattern for encrypting databases and file systems in the cloud (AWS KMS, Google Cloud KMS, Azure Key Vault).

1.  **Generate**: The application generates a plaintext DEK locally.
2.  **Encrypt Data**: The application encrypts the file with the plaintext DEK (using AES-GCM).
3.  **Wrap**: The application sends the plaintext DEK to the Cloud KMS.
4.  **Store**: The Cloud KMS returns the **Wrapped DEK**. The application destroys the plaintext DEK from memory and stores the Wrapped DEK alongside the encrypted file.

### 5.2 BYOK (Bring Your Own Key)
When importing your own keys into a Cloud HSM, you cannot send the raw key over TLS. It must be wrapped.

**Typical Workflow (AWS/GCP):**
1.  **Download Wrapping Key**: You download a public RSA key from the Cloud Provider.
2.  **Wrap**: You wrap your AES key using this RSA key (often using `RSA-OAEP`).
3.  **Upload**: You upload the wrapped bundle. The Cloud HSM unwraps it internally using its private key.

**Google Cloud specific**: Google supports `RSA-OAEP+AES-KWP`. This means:
1.  Generate a temporary ephemeral AES key.
2.  Wrap your target key with the ephemeral AES key using **AES-KWP**.
3.  Wrap the ephemeral AES key with Google's RSA public key.
4.  Send both.

---

## 6. Security Cheat Sheet

| Parameter | Value | Notes |
| :--- | :--- | :--- |
| **IV (KW)** | `A6A6A6A6A6A6A6A6` | 64-bit Hex |
| **IV (KWP)** | `A65959A6` | 32-bit Hex (+ 32-bit length) |
| **Block Size** | 64 bits | Unlike standard AES (128-bit) |
| **Overhead** | +8 bytes | For the IV |
| **Padding** | None (KW) / 8-byte align (KWP) | KW requires input % 8 == 0 |
| **Max Size** | ~25 MB (KW) / 4 GB (KWP) | Rarely an issue for keys |

---

## 7. Common Pitfalls

1.  **Wrong Algorithm**: Using `AES-KW` for an RSA private key. **Fix**: Use `AES-KWP` (RFC 5649) because RSA keys are rarely exact multiples of 64 bits.
2.  **Re-using IVs**: In AES-KW, the IV is fixed. Do not try to generate a random IV; the algorithm relies on the specific constant `0xA6...` to verify integrity.
3.  **Bit-flipping**: If you flip a single bit in the wrapped key, the unwrap operation will return an error (usually `IntegrityError` or `BadPaddingException`). This is a feature, not a bug.
