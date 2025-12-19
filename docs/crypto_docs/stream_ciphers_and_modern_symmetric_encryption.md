---
theme: default
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Lecture 4: Stream Ciphers and Modern Symmetric Encryption
  MAT364 - Cryptography Course
drawings:
  persist: false
transition: slide-left
title: Stream Ciphers and Modern Symmetric Encryption
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

/* Adaptive animations */
.animation-container {
  margin: 1rem 0;
  padding: 1rem;
  border-radius: 0.5rem;
}

.animation-container .flex {
  flex-wrap: wrap;
  gap: 0.5rem;
  justify-content: center;
  align-items: center;
}

.animation-container .w-8, .animation-container .w-12 {
  width: 2rem;
  height: 2rem;
  font-size: 0.7rem;
  display: flex;
  align-items: center;
  justify-content: center;
}

.animation-container .w-6 {
  width: 1.5rem;
  height: 1.5rem;
  font-size: 0.6rem;
  display: flex;
  align-items: center;
  justify-content: center;
}

/* Adaptive task containers */
.task-container {
  margin: 1rem 0;
  padding: 1rem;
  border-radius: 0.5rem;
}

.task-container h3 {
  font-size: 1.1rem;
  margin-bottom: 0.8rem;
}

.task-container p, .task-container div {
  font-size: 0.9rem;
  margin: 0.4rem 0;
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
  
  .animation-container {
    padding: 0.75rem;
  }
  
  .animation-container .w-8, .animation-container .w-12 {
    width: 1.75rem;
    height: 1.75rem;
    font-size: 0.65rem;
  }
  
  .animation-container .w-6 {
    width: 1.25rem;
    height: 1.25rem;
    font-size: 0.55rem;
  }
  
  .task-container {
    padding: 0.75rem;
  }
}

/* Ensure content fits within viewport */
.slidev-page {
  max-height: 100vh;
  overflow-y: auto;
}
</style>

# Stream Ciphers and Modern Symmetric Encryption
## MAT364 - Cryptography Course

**Instructor:** Adil Akhmetov  
**University:** SDU  
**Week 4**

<div class="pt-6">
  <span @click="$slidev.nav.next" class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Press Space for next page →
  </span>
</div>

<!-- Animation: Title entrance with glow effect -->
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 30, scale: 0.8, rotateX: -20 }"
     :enter="{ opacity: 1, y: 0, scale: 1, rotateX: 0, transition: { duration: 1200, type: 'spring', bounce: 0.3 } }">
</div>

---
layout: default
---

# What Are Stream Ciphers?

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, x: -50, rotateY: -10 }"
     :enter="{ opacity: 1, x: 0, rotateY: 0, transition: { duration: 800, delay: 200, type: 'spring' } }">

## Definition
**Stream ciphers** encrypt data bit-by-bit or byte-by-byte using a keystream generated from a secret key.

<v-clicks>

## Key Characteristics
- **Synchronous** - Keystream independent of plaintext
- **Asynchronous** - Keystream depends on plaintext
- **Fast** - Suitable for real-time applications
- **Simple** - Easy to implement in hardware

</v-clicks>

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, x: 50, rotateY: 10 }"
     :enter="{ opacity: 1, x: 0, rotateY: 0, transition: { duration: 800, delay: 400, type: 'spring' } }">

## How They Work
<v-clicks>

- **Generate keystream** from secret key
- **XOR plaintext** with keystream
- **Same keystream** for decryption
- **Key determines** keystream generation

</v-clicks>

## Advantages
<v-clicks>

- **High speed** - Very fast encryption
- **Low latency** - Real-time processing
- **Hardware friendly** - Easy to implement
- **Memory efficient** - Minimal storage needed

</v-clicks>

</div>

</div>

<!-- Visual Animation: Stream Cipher Process -->
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 30, scale: 0.8 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 1000, delay: 600, type: 'spring', bounce: 0.4 } }"
     class="mt-4 p-4 bg-gradient-to-r from-blue-50 to-purple-50 rounded-lg border-2 border-blue-200 animation-container">

<div class="text-center mb-4">
<h3 class="text-lg font-bold text-blue-800">Stream Cipher Process Visualization</h3>
</div>

<div class="flex items-center justify-center space-x-4 text-sm">
<div v-motion
     :initial="{ x: -100, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 800 } }"
     class="bg-white p-3 rounded-lg shadow-md border">
<div class="font-bold text-green-600">Plaintext</div>
<div class="text-xs">"HELLO"</div>
</div>

<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1000 } }"
     class="text-2xl text-blue-600">→</div>

<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1200 } }"
     class="bg-white p-3 rounded-lg shadow-md border">
<div class="font-bold text-purple-600">Keystream</div>
<div class="text-xs">"XKLMN"</div>
</div>

<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1400 } }"
     class="text-2xl text-blue-600">⊕</div>

<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1600 } }"
     class="bg-white p-3 rounded-lg shadow-md border">
<div class="font-bold text-red-600">Ciphertext</div>
<div class="text-xs">"MIXED"</div>
</div>
</div>

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20, scale: 0.9 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 600, delay: 600, type: 'spring' } }"
     class="mt-4 p-3 bg-blue-100 rounded-lg text-sm">
<strong>Remember:</strong> Stream ciphers are perfect for real-time applications like video streaming and secure communications!
</div>

---
layout: default
---

# 🎯 Student Task: Stream Cipher Basics

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-yellow-50 to-orange-50 rounded-lg border-2 border-yellow-300 task-container">

## Task: Simple XOR Stream Cipher

<v-clicks>

**Given:**
- Plaintext: "CRYPTO"
- Key: 5 (single byte)
- Operation: XOR each character with the key

**Your Task:**
1. Convert each letter to its ASCII value
2. XOR each ASCII value with the key (5)
3. Convert back to characters
4. What is the ciphertext?

**Hint:** A = 65, B = 66, C = 67, etc.

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 2000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center text-sm text-gray-600">
<strong>Take 2 minutes to work this out!</strong>
</div>
</div>

</div>

---
layout: default
---

# ✅ Solution: Stream Cipher Task

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-green-50 to-blue-50 rounded-lg border-2 border-green-300 task-container">

## Step-by-Step Solution

<v-clicks>

**Step 1: Convert to ASCII**
```
C = 67, R = 82, Y = 89, P = 80, T = 84, O = 79
```

**Step 2: XOR with key (5)**
```
67 ⊕ 5 = 70 (F)
82 ⊕ 5 = 87 (W)  
89 ⊕ 5 = 92 (\)  ← Special character!
80 ⊕ 5 = 85 (U)
84 ⊕ 5 = 81 (Q)
79 ⊕ 5 = 74 (J)
```

**Step 3: Result**
```
Ciphertext: "FW\UQJ"
```

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 3000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center">
<strong class="text-green-600">Key Insight:</strong> XOR is reversible! To decrypt, just XOR again with the same key.
</div>
</div>

</div>

---
layout: default
---

# Stream Cipher vs Block Cipher

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Stream Ciphers
- **Encrypt bit/byte** at a time
- **Keystream** generated from key
- **XOR operation** with plaintext
- **Examples:** RC4, ChaCha20, A5/1

## Advantages
- **Fast** - Very high speed
- **Low latency** - Real-time processing
- **Simple** - Easy implementation
- **Memory efficient** - Minimal storage

</div>

<div>

## Block Ciphers
- **Encrypt fixed-size blocks** (64, 128 bits)
- **Same key** for all blocks
- **Complex operations** - Substitution, permutation
- **Examples:** AES, DES, Blowfish

## Advantages
- **Secure** - Well-analyzed algorithms
- **Standardized** - NIST approved
- **Flexible** - Multiple modes of operation
- **Widely used** - Industry standard

</div>

</div>

<div class="mt-4 p-3 bg-green-100 rounded-lg text-sm">
<strong>Key Insight:</strong> Stream ciphers are like a continuous flow, while block ciphers work in discrete chunks!
</div>

---
layout: section
---

# Stream Cipher Design

---
layout: default
---

# Linear Feedback Shift Registers (LFSR)

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## How LFSR Works
<v-clicks>

- **Shift register** with feedback
- **Linear function** of register bits
- **Generates** pseudo-random sequence
- **Period** depends on register length

</v-clicks>

## Example: 4-bit LFSR
<v-clicks>

```
Register: [1,0,1,1]
Feedback: XOR of bits 3 and 1
Output: 1 (rightmost bit)
Next: [0,1,0,1] (shift right, feedback in)
```

</v-clicks>

</div>

<div>

## Implementation
```python
class LFSR:
    def __init__(self, seed, taps):
        self.register = seed
        self.taps = taps  # Positions to XOR
    
    def step(self):
        # Calculate feedback
        feedback = 0
        for tap in self.taps:
            feedback ^= (self.register >> tap) & 1
        
        # Shift and insert feedback
        self.register = (self.register >> 1) | (feedback << (len(self.register) - 1))
        
        # Return output bit
        return self.register & 1
    
    def generate_keystream(self, length):
        keystream = []
        for _ in range(length):
            keystream.append(self.step())
        return keystream
```

</div>

</div>

<!-- LFSR Animation -->
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 30, scale: 0.9 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 1000, delay: 400 } }"
     class="mt-4 p-4 bg-gradient-to-r from-purple-50 to-pink-50 rounded-lg border-2 border-purple-200 animation-container">

<div class="text-center mb-4">
<h3 class="text-lg font-bold text-purple-800">LFSR Animation: 4-bit Register</h3>
</div>

<div class="flex items-center justify-center space-x-2">
<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 600 } }"
     class="text-sm font-bold text-purple-600">Step 1:</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 800 } }"
     class="flex space-x-1">
<div class="w-8 h-8 bg-blue-200 border-2 border-blue-400 rounded flex items-center justify-center text-sm font-bold">1</div>
<div class="w-8 h-8 bg-gray-200 border-2 border-gray-400 rounded flex items-center justify-center text-sm font-bold">0</div>
<div class="w-8 h-8 bg-blue-200 border-2 border-blue-400 rounded flex items-center justify-center text-sm font-bold">1</div>
<div class="w-8 h-8 bg-blue-200 border-2 border-blue-400 rounded flex items-center justify-center text-sm font-bold">1</div>
</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1000 } }"
     class="text-sm text-gray-600">→ Output: 1</div>
</div>

<div class="flex items-center justify-center space-x-2 mt-4">
<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1200 } }"
     class="text-sm font-bold text-purple-600">Step 2:</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1400 } }"
     class="flex space-x-1">
<div class="w-8 h-8 bg-gray-200 border-2 border-gray-400 rounded flex items-center justify-center text-sm font-bold">0</div>
<div class="w-8 h-8 bg-blue-200 border-2 border-blue-400 rounded flex items-center justify-center text-sm font-bold">1</div>
<div class="w-8 h-8 bg-gray-200 border-2 border-gray-400 rounded flex items-center justify-center text-sm font-bold">0</div>
<div class="w-8 h-8 bg-blue-200 border-2 border-blue-400 rounded flex items-center justify-center text-sm font-bold">1</div>
</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1600 } }"
     class="text-sm text-gray-600">→ Output: 1</div>
</div>

<div v-motion
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { delay: 1800 } }"
     class="text-center mt-4 text-sm text-gray-600">
<strong>Feedback:</strong> XOR of positions 3 and 1 (1 ⊕ 1 = 0)
</div>

</div>

---
layout: default
---

# 🎯 Student Task: LFSR Keystream

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-indigo-50 to-cyan-50 rounded-lg border-2 border-indigo-300 task-container">

## Task: Generate LFSR Keystream

<v-clicks>

**Given:**
- 3-bit LFSR with seed: [1, 0, 1]
- Feedback taps: positions 2 and 0 (XOR of bits 2 and 0)
- Generate 8 bits of keystream

**Your Task:**
1. Start with register [1, 0, 1]
2. Output the rightmost bit (1)
3. Calculate feedback: bit[2] ⊕ bit[0] = 1 ⊕ 1 = 0
4. Shift right and insert feedback: [0, 1, 0]
5. Repeat for 8 steps

**What is the 8-bit keystream?**

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

# ✅ Solution: LFSR Keystream

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-green-50 to-emerald-50 rounded-lg border-2 border-green-300 task-container">

## Step-by-Step Solution

<v-clicks>

**Step 1:** [1,0,1] → Output: 1, Feedback: 1⊕1 = 0 → Next: [0,1,0]
**Step 2:** [0,1,0] → Output: 0, Feedback: 0⊕0 = 0 → Next: [0,0,1]  
**Step 3:** [0,0,1] → Output: 1, Feedback: 0⊕1 = 1 → Next: [1,0,0]
**Step 4:** [1,0,0] → Output: 0, Feedback: 1⊕0 = 1 → Next: [1,1,0]
**Step 5:** [1,1,0] → Output: 0, Feedback: 1⊕1 = 0 → Next: [0,1,1]
**Step 6:** [0,1,1] → Output: 1, Feedback: 0⊕1 = 1 → Next: [1,0,1]
**Step 7:** [1,0,1] → Output: 1, Feedback: 1⊕1 = 0 → Next: [0,1,0]
**Step 8:** [0,1,0] → Output: 0, Feedback: 0⊕0 = 0 → Next: [0,0,1]

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 3000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center">
<strong class="text-green-600">Answer:</strong> <code class="bg-gray-100 px-2 py-1 rounded">10100110</code>
</div>
<div class="text-sm text-gray-600 mt-2">
Notice the pattern repeats after 7 steps (period = 7)
</div>
</div>

</div>

---
layout: default
---

# RC4 Stream Cipher

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## How RC4 Works
1. **Key Scheduling Algorithm (KSA)** - Initialize S-box
2. **Pseudo-Random Generation Algorithm (PRGA)** - Generate keystream
3. **XOR** plaintext with keystream
4. **Same process** for decryption

## Key Features
- **Variable key length** - 1-256 bytes
- **Simple implementation** - Easy to code
- **Fast** - Very efficient
- **Widely used** - SSL/TLS, WEP

</div>

<div>

## Implementation
```python
class RC4:
    def __init__(self, key):
        self.key = key
        self.S = list(range(256))
        self._ksa()
    
    def _ksa(self):
        """Key Scheduling Algorithm"""
        j = 0
        for i in range(256):
            j = (j + self.S[i] + self.key[i % len(self.key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
    
    def _prga(self, length):
        """Pseudo-Random Generation Algorithm"""
        i = j = 0
        keystream = []
        
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + self.S[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
            keystream.append(self.S[(self.S[i] + self.S[j]) % 256])
        
        return keystream
    
    def encrypt(self, plaintext):
        keystream = self._prga(len(plaintext))
        return bytes(a ^ b for a, b in zip(plaintext, keystream))
```

</div>

</div>

---
layout: default
---

# ChaCha20 Stream Cipher

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Why ChaCha20?
- **RC4 vulnerabilities** - Weak key scheduling
- **AES timing attacks** - Side-channel vulnerabilities
- **ChaCha20 advantages** - Constant-time, fast, secure
- **Modern standard** - Used in TLS 1.3

## Design Principles
- **ARX operations** - Add, Rotate, XOR
- **Constant-time** - No timing attacks
- **Fast software** - Optimized for CPUs
- **Simple design** - Easy to analyze

</div>

<div>

## ChaCha20 Structure
```python
def chacha20_quarter_round(state, a, b, c, d):
    """Quarter round function"""
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = state[d] ^ state[a]
    state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xFFFFFFFF
    
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = state[b] ^ state[c]
    state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xFFFFFFFF
    
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = state[d] ^ state[a]
    state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xFFFFFFFF
    
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = state[b] ^ state[c]
    state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xFFFFFFFF

def chacha20_block(key, nonce, counter):
    """Generate one ChaCha20 block"""
    # Initialize state
    state = [0] * 16
    # ... (full implementation)
    return state
```

</div>

</div>

---
layout: section
---

# Block Cipher Modes of Operation

---
layout: default
---

# Electronic Codebook (ECB) Mode

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## How ECB Works
<v-clicks>

- **Each block** encrypted independently
- **Same plaintext** → same ciphertext
- **No chaining** between blocks
- **Parallel processing** possible

</v-clicks>

## Example
<v-clicks>

```
Plaintext:  HELLO WORLD
Blocks:     HELL | O WO | RLD
Encrypt:    AES(HELL) | AES(O WO) | AES(RLD)
Ciphertext: XKLM | YZAB | CDE
```

</v-clicks>

</div>

<div>

## Problems with ECB
<v-clicks>

- **Pattern leakage** - Identical blocks produce identical ciphertext
- **Not secure** - Reveals structure of plaintext
- **Example vulnerability:**
```
Image: [BLACK][WHITE][BLACK][WHITE]
ECB:   [ENCR1][ENCR2][ENCR1][ENCR2]
Result: Pattern still visible!
```

</v-clicks>

## When to Use
<v-clicks>

- **Never for real data** - Too insecure
- **Educational purposes** - Understanding block ciphers
- **Single block** - Only one block to encrypt

</v-clicks>

</div>

</div>

<!-- ECB Animation -->
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 30, scale: 0.9 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 1000, delay: 400 } }"
     class="mt-4 p-4 bg-gradient-to-r from-red-50 to-orange-50 rounded-lg border-2 border-red-200 animation-container">

<div class="text-center mb-4">
<h3 class="text-lg font-bold text-red-800">ECB Mode Visualization</h3>
</div>

<div class="flex items-center justify-center space-x-2">
<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 600 } }"
     class="text-sm font-bold text-red-600">Plaintext:</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 800 } }"
     class="flex space-x-1">
<div class="w-12 h-8 bg-blue-200 border-2 border-blue-400 rounded flex items-center justify-center text-xs font-bold">HELL</div>
<div class="w-12 h-8 bg-green-200 border-2 border-green-400 rounded flex items-center justify-center text-xs font-bold">O WO</div>
<div class="w-12 h-8 bg-blue-200 border-2 border-blue-400 rounded flex items-center justify-center text-xs font-bold">RLD</div>
</div>
</div>

<div class="flex items-center justify-center space-x-2 mt-4">
<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1000 } }"
     class="text-sm font-bold text-red-600">ECB Result:</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1200 } }"
     class="flex space-x-1">
<div class="w-12 h-8 bg-red-200 border-2 border-red-400 rounded flex items-center justify-center text-xs font-bold">XKLM</div>
<div class="w-12 h-8 bg-yellow-200 border-2 border-yellow-400 rounded flex items-center justify-center text-xs font-bold">YZAB</div>
<div class="w-12 h-8 bg-red-200 border-2 border-red-400 rounded flex items-center justify-center text-xs font-bold">CDE</div>
</div>
</div>

<div v-motion
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { delay: 1400 } }"
     class="text-center mt-4 text-sm text-red-600">
<strong>⚠️ Problem:</strong> Same colors = same patterns! Not secure!
</div>

</div>

<div class="mt-4 p-3 bg-red-100 rounded-lg text-sm">
<strong>Warning:</strong> ECB mode is insecure for most applications! Use CBC, GCM, or other secure modes.
</div>

---
layout: default
---

# 🎯 Student Task: Block Cipher Modes

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-amber-50 to-yellow-50 rounded-lg border-2 border-amber-300 task-container">

## Task: Identify the Problem

<v-clicks>

**Scenario:** You're encrypting an image with a block cipher.

**Image Pattern:**
```
[BLACK][WHITE][BLACK][WHITE]
[WHITE][BLACK][WHITE][BLACK]
[BLACK][WHITE][BLACK][WHITE]
[WHITE][BLACK][WHITE][BLACK]
```

**ECB Encryption Result:**
```
[ENCR1][ENCR2][ENCR1][ENCR2]
[ENCR2][ENCR1][ENCR2][ENCR1]
[ENCR1][ENCR2][ENCR1][ENCR2]
[ENCR2][ENCR1][ENCR2][ENCR1]
```

**Questions:**
1. What security problem does this demonstrate?
2. Why is this a problem for real applications?
3. What mode would you use instead?

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 2000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center text-sm text-gray-600">
<strong>Think about pattern recognition and security!</strong>
</div>
</div>

</div>

---
layout: default
---

# ✅ Solution: Block Cipher Modes

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-green-50 to-teal-50 rounded-lg border-2 border-green-300 task-container">

## Answers

<v-clicks>

**1. Security Problem:**
- **Pattern leakage** - Identical plaintext blocks produce identical ciphertext blocks
- **Structure preservation** - The encrypted image still shows the original pattern
- **Information disclosure** - Attacker can see the structure without knowing the key

**2. Why This Matters:**
- **Images** - Patterns in photos, logos, diagrams are visible
- **Documents** - Repeated headers, footers, formatting revealed
- **Databases** - Duplicate records can be identified
- **Real-world impact** - Complete loss of confidentiality

**3. Better Solution:**
- **CBC mode** - Each block XORed with previous ciphertext
- **GCM mode** - Authenticated encryption with random IV
- **CTR mode** - Counter-based encryption
- **Any mode with chaining** - Breaks the pattern

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 3000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center">
<strong class="text-green-600">Key Lesson:</strong> Never use ECB for real data! Always use modes that break patterns.
</div>
</div>

</div>

---
layout: default
---

# Cipher Block Chaining (CBC) Mode

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## How CBC Works
<v-clicks>

- **XOR each block** with previous ciphertext
- **First block** XORed with IV (Initialization Vector)
- **Chaining** prevents pattern leakage
- **Sequential** - Cannot parallelize encryption

</v-clicks>

## Encryption Process
<v-clicks>

```
P1 = Plaintext block 1
P2 = Plaintext block 2
IV = Initialization Vector

C1 = Encrypt(P1 ⊕ IV)
C2 = Encrypt(P2 ⊕ C1)
C3 = Encrypt(P3 ⊕ C2)
```

</v-clicks>

</div>

<div>

## Decryption Process
<v-clicks>

```
C1 = Ciphertext block 1
C2 = Ciphertext block 2

P1 = Decrypt(C1) ⊕ IV
P2 = Decrypt(C2) ⊕ C1
P3 = Decrypt(C3) ⊕ C2
```

</v-clicks>

## Implementation
```python
def cbc_encrypt(plaintext, key, iv):
    """CBC mode encryption"""
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b''
    prev_block = iv
    
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        # Pad if necessary
        if len(block) < 16:
            block = pad(block, 16)
        
        # XOR with previous ciphertext
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        encrypted = cipher.encrypt(xored)
        ciphertext += encrypted
        prev_block = encrypted
    
    return ciphertext
```

</div>

</div>

<!-- CBC Animation -->
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 30, scale: 0.9 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 1000, delay: 400 } }"
     class="mt-4 p-4 bg-gradient-to-r from-blue-50 to-cyan-50 rounded-lg border-2 border-blue-200 animation-container">

<div class="text-center mb-4">
<h3 class="text-lg font-bold text-blue-800">CBC Mode Visualization</h3>
</div>

<div class="flex items-center justify-center space-x-2">
<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 600 } }"
     class="text-sm font-bold text-blue-600">IV:</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 800 } }"
     class="w-12 h-8 bg-gray-200 border-2 border-gray-400 rounded flex items-center justify-center text-xs font-bold">RAND</div>
</div>

<div class="flex items-center justify-center space-x-2 mt-4">
<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1000 } }"
     class="text-sm font-bold text-blue-600">Block 1:</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1200 } }"
     class="flex space-x-1">
<div class="w-12 h-8 bg-green-200 border-2 border-green-400 rounded flex items-center justify-center text-xs font-bold">HELL</div>
<div class="text-2xl text-blue-600">⊕</div>
<div class="w-12 h-8 bg-gray-200 border-2 border-gray-400 rounded flex items-center justify-center text-xs font-bold">RAND</div>
<div class="text-2xl text-blue-600">→</div>
<div class="w-12 h-8 bg-red-200 border-2 border-red-400 rounded flex items-center justify-center text-xs font-bold">C1</div>
</div>
</div>

<div class="flex items-center justify-center space-x-2 mt-4">
<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1400 } }"
     class="text-sm font-bold text-blue-600">Block 2:</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1600 } }"
     class="flex space-x-1">
<div class="w-12 h-8 bg-green-200 border-2 border-green-400 rounded flex items-center justify-center text-xs font-bold">O WO</div>
<div class="text-2xl text-blue-600">⊕</div>
<div class="w-12 h-8 bg-red-200 border-2 border-red-400 rounded flex items-center justify-center text-xs font-bold">C1</div>
<div class="text-2xl text-blue-600">→</div>
<div class="w-12 h-8 bg-purple-200 border-2 border-purple-400 rounded flex items-center justify-center text-xs font-bold">C2</div>
</div>
</div>

<div v-motion
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { delay: 1800 } }"
     class="text-center mt-4 text-sm text-blue-600">
<strong>✅ Result:</strong> Each block depends on the previous one - no patterns!
</div>

</div>

---
layout: default
---

# Galois/Counter Mode (GCM)

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Why GCM?
- **Authenticated encryption** - Provides both confidentiality and integrity
- **Parallelizable** - Can encrypt blocks in parallel
- **Efficient** - Fast implementation
- **Widely used** - TLS 1.3, IPsec

## Key Features
- **CTR mode** for encryption
- **GHASH** for authentication
- **No padding** required
- **Associated data** support

</div>

<div>

## GCM Structure
```python
def gcm_encrypt(plaintext, key, iv, aad=b''):
    """GCM mode encryption with authentication"""
    # Generate counter blocks
    counter_blocks = generate_counters(iv, len(plaintext))
    
    # Encrypt counter blocks
    cipher = AES.new(key, AES.MODE_ECB)
    keystream = b''.join(cipher.encrypt(ctr) for ctr in counter_blocks)
    
    # XOR with plaintext
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
    
    # Calculate authentication tag
    tag = ghash(ciphertext, aad, key)
    
    return ciphertext, tag

def gcm_decrypt(ciphertext, key, iv, tag, aad=b''):
    """GCM mode decryption with verification"""
    # Verify tag first
    expected_tag = ghash(ciphertext, aad, key)
    if tag != expected_tag:
        raise ValueError("Authentication failed")
    
    # Decrypt (same as encryption)
    return gcm_encrypt(ciphertext, key, iv, aad)[0]
```

</div>

</div>

---
layout: section
---

# Advanced Symmetric Encryption

---
layout: default
---

# AES (Advanced Encryption Standard)

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## AES Overview
<v-clicks>

- **Rijndael algorithm** - Winner of AES competition
- **Block size** - 128 bits (16 bytes)
- **Key sizes** - 128, 192, 256 bits
- **Rounds** - 10, 12, 14 (depends on key size)

</v-clicks>

## AES Structure
<v-clicks>

- **SubBytes** - Non-linear substitution
- **ShiftRows** - Transposition
- **MixColumns** - Linear transformation
- **AddRoundKey** - XOR with round key

</v-clicks>

</div>

<div>

## AES Implementation
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def aes_encrypt(plaintext, key):
    """AES encryption"""
    # Generate random IV
    iv = get_random_bytes(16)
    
    # Create cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad plaintext
    padded = pad(plaintext, AES.block_size)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded)
    
    return iv + ciphertext

def aes_decrypt(ciphertext, key):
    """AES decryption"""
    # Extract IV
    iv = ciphertext[:16]
    encrypted = ciphertext[16:]
    
    # Create cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt
    padded = cipher.decrypt(encrypted)
    
    # Remove padding
    return unpad(padded, AES.block_size)
```

</div>

</div>

<!-- AES Animation -->
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 30, scale: 0.9 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 1000, delay: 400 } }"
     class="mt-4 p-4 bg-gradient-to-r from-indigo-50 to-purple-50 rounded-lg border-2 border-indigo-200 animation-container">

<div class="text-center mb-4">
<h3 class="text-lg font-bold text-indigo-800">AES Round Function</h3>
</div>

<div class="flex items-center justify-center space-x-2">
<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 600 } }"
     class="text-sm font-bold text-indigo-600">State:</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 800 } }"
     class="grid grid-cols-4 gap-1">
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">A</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">B</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">C</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">D</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">E</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">F</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">G</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">H</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">I</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">J</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">K</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">L</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">M</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">N</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">O</div>
<div class="w-6 h-6 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center">P</div>
</div>
</div>

<div class="flex items-center justify-center space-x-4 mt-4">
<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1000 } }"
     class="text-center">
<div class="text-xs font-bold text-indigo-600">SubBytes</div>
<div class="text-xs text-gray-600">S-box lookup</div>
</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1200 } }"
     class="text-center">
<div class="text-xs font-bold text-indigo-600">ShiftRows</div>
<div class="text-xs text-gray-600">Row rotation</div>
</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1400 } }"
     class="text-center">
<div class="text-xs font-bold text-indigo-600">MixColumns</div>
<div class="text-xs text-gray-600">Column mixing</div>
</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1600 } }"
     class="text-center">
<div class="text-xs font-bold text-indigo-600">AddRoundKey</div>
<div class="text-xs text-gray-600">XOR with key</div>
</div>
</div>

<div v-motion
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { delay: 1800 } }"
     class="text-center mt-4 text-sm text-indigo-600">
<strong>Repeat 10-14 rounds</strong> depending on key size
</div>

</div>

---
layout: default
---

# 🎯 Student Task: AES Key Sizes

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-violet-50 to-purple-50 rounded-lg border-2 border-violet-300 task-container">

## Task: Choose the Right AES Key Size

<v-clicks>

**Scenario:** You're designing a secure messaging app.

**Requirements:**
- Messages contain sensitive financial data
- Must be secure for at least 20 years
- Performance is important but security is critical
- Must comply with government standards

**Available Options:**
- **AES-128** - 128-bit key, 10 rounds
- **AES-192** - 192-bit key, 12 rounds  
- **AES-256** - 256-bit key, 14 rounds

**Questions:**
1. Which key size would you choose and why?
2. What are the trade-offs between security and performance?
3. How does the number of rounds affect security?

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 2000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center text-sm text-gray-600">
<strong>Consider security requirements and future-proofing!</strong>
</div>
</div>

</div>

---
layout: default
---

# ✅ Solution: AES Key Sizes

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-green-50 to-emerald-50 rounded-lg border-2 border-green-300 task-container">

## Recommended Answer

<v-clicks>

**1. Choose AES-256**
- **Future-proof** - 256-bit keys provide 2^256 security level
- **Government standard** - Required for classified information
- **Long-term security** - Will remain secure for decades
- **Minimal performance cost** - Only 40% slower than AES-128

**2. Trade-offs:**
- **AES-128**: Fast, but may become vulnerable to quantum computers
- **AES-192**: Good middle ground, but not widely supported
- **AES-256**: Best security, slightly slower, widely supported

**3. Round Impact:**
- **More rounds** = More security through confusion and diffusion
- **AES-128**: 10 rounds (sufficient for 128-bit security)
- **AES-256**: 14 rounds (necessary for 256-bit security)
- **Each round** adds exponential complexity for attackers

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 3000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center">
<strong class="text-green-600">Best Practice:</strong> Use AES-256 for sensitive data, AES-128 for general use.
</div>
</div>

</div>

---
layout: default
---

# Key Derivation Functions

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Why Key Derivation?
- **Password-based** encryption
- **Key stretching** - Slow down brute force
- **Salt** - Prevent rainbow table attacks
- **Multiple keys** from one password

## PBKDF2
- **Password-Based Key Derivation Function 2**
- **HMAC** as pseudorandom function
- **Configurable iterations** - 100,000+ recommended
- **Salt** - Random data to prevent attacks

</div>

<div>

## Implementation
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

def derive_key(password, salt=None, iterations=100000):
    """Derive key from password using PBKDF2"""
    if salt is None:
        salt = secrets.token_bytes(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=iterations,
    )
    
    key = kdf.derive(password.encode())
    return key, salt

def verify_password(password, stored_key, salt, iterations=100000):
    """Verify password against stored key"""
    derived_key, _ = derive_key(password, salt, iterations)
    return derived_key == stored_key
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

# Complete Encryption Suite

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Stream Cipher Class
```python
class StreamCipher:
    def __init__(self, key):
        self.key = key
        self.position = 0
    
    def encrypt(self, plaintext):
        """Encrypt plaintext using stream cipher"""
        keystream = self._generate_keystream(len(plaintext))
        return bytes(a ^ b for a, b in zip(plaintext, keystream))
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext (same as encryption)"""
        return self.encrypt(ciphertext)
    
    def _generate_keystream(self, length):
        """Generate keystream of specified length"""
        # Implementation depends on specific cipher
        pass
```

</div>

<div>

## Block Cipher Class
```python
class BlockCipher:
    def __init__(self, key, mode='CBC'):
        self.key = key
        self.mode = mode
    
    def encrypt(self, plaintext, iv=None):
        """Encrypt plaintext using block cipher"""
        if self.mode == 'ECB':
            return self._ecb_encrypt(plaintext)
        elif self.mode == 'CBC':
            return self._cbc_encrypt(plaintext, iv)
        elif self.mode == 'GCM':
            return self._gcm_encrypt(plaintext, iv)
    
    def decrypt(self, ciphertext, iv=None, tag=None):
        """Decrypt ciphertext"""
        if self.mode == 'ECB':
            return self._ecb_decrypt(ciphertext)
        elif self.mode == 'CBC':
            return self._cbc_decrypt(ciphertext, iv)
        elif self.mode == 'GCM':
            return self._gcm_decrypt(ciphertext, iv, tag)
```

</div>

</div>

---
layout: default
---

# Security Considerations

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Key Management
- **Generate keys** using secure random
- **Store keys** securely (HSM, key vault)
- **Rotate keys** regularly
- **Use different keys** for different purposes

## Implementation Security
- **Constant-time** operations
- **Avoid timing attacks** - Use constant-time comparisons
- **Clear sensitive data** from memory
- **Validate inputs** properly

</div>

<div>

## Common Mistakes
- **❌ Reusing keys** across different contexts
- **❌ Weak random** number generation
- **❌ Predictable IVs** - Use random IVs
- **❌ Not authenticating** - Use authenticated encryption

## Best Practices
- **✅ Use established** libraries
- **✅ Follow** security guidelines
- **✅ Test thoroughly** for vulnerabilities
- **✅ Keep libraries** updated

</div>

</div>

---
layout: section
---

# Practice Tasks

---
layout: default
---

# Task 1: Implement Stream Cipher

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Requirements
Create a complete stream cipher implementation:

1. **LFSR-based** keystream generator
2. **RC4-style** cipher
3. **ChaCha20** implementation
4. **Interactive** testing interface

## Features
- **Key generation** from passwords
- **File encryption/decryption**
- **Performance testing**
- **Security analysis**

</div>

<div>

## Implementation Guide
```python
# LFSR Stream Cipher
class LFSRCipher:
    def __init__(self, key):
        self.lfsr = LFSR(key, [3, 1])  # 4-bit LFSR
    
    def encrypt(self, data):
        keystream = self.lfsr.generate_keystream(len(data) * 8)
        result = []
        
        for i, byte in enumerate(data):
            byte_bits = [(byte >> j) & 1 for j in range(8)]
            keystream_bits = keystream[i*8:(i+1)*8]
            
            encrypted_bits = [a ^ b for a, b in zip(byte_bits, keystream_bits)]
            encrypted_byte = sum(bit << j for j, bit in enumerate(encrypted_bits))
            result.append(encrypted_byte)
        
        return bytes(result)
```

</div>

</div>

---
layout: default
---

# Task 2: Block Cipher Modes

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Requirements
Implement different block cipher modes:

1. **ECB mode** - Educational purposes
2. **CBC mode** - Secure encryption
3. **CTR mode** - Counter mode
4. **GCM mode** - Authenticated encryption

## Features
- **AES implementation** using libraries
- **Padding schemes** (PKCS7)
- **IV generation** and management
- **Authentication** for GCM mode

</div>

<div>

## Implementation Guide
```python
# CBC Mode Implementation
def cbc_encrypt(plaintext, key, iv):
    """CBC mode encryption"""
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b''
    prev_block = iv
    
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        if len(block) < 16:
            block = pad(block, 16)
        
        # XOR with previous ciphertext
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        encrypted = cipher.encrypt(xored)
        ciphertext += encrypted
        prev_block = encrypted
    
    return ciphertext

def cbc_decrypt(ciphertext, key, iv):
    """CBC mode decryption"""
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = b''
    prev_block = iv
    
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        
        # Decrypt block
        decrypted = cipher.decrypt(block)
        
        # XOR with previous ciphertext
        xored = bytes(a ^ b for a, b in zip(decrypted, prev_block))
        plaintext += xored
        prev_block = block
    
    return unpad(plaintext, 16)
```

</div>

</div>

---
layout: default
---

# Task 3: Security Analysis

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Requirements
Analyze security of different ciphers:

1. **Frequency analysis** on stream ciphers
2. **Pattern detection** in ECB mode
3. **Timing attacks** on implementations
4. **Key recovery** from weak implementations

## Tools
- **Statistical analysis** - Letter frequencies
- **Pattern recognition** - Block patterns
- **Timing measurements** - Execution time analysis
- **Cryptanalysis** - Breaking weak ciphers

</div>

<div>

## Analysis Framework
```python
class SecurityAnalyzer:
    def __init__(self):
        self.english_freq = self._load_english_frequencies()
    
    def analyze_stream_cipher(self, ciphertext):
        """Analyze stream cipher security"""
        # Frequency analysis
        freq = self._frequency_analysis(ciphertext)
        
        # Chi-squared test
        chi_squared = self._chi_squared_test(freq)
        
        # Autocorrelation
        autocorr = self._autocorrelation(ciphertext)
        
        return {
            'frequency_analysis': freq,
            'chi_squared': chi_squared,
            'autocorrelation': autocorr
        }
    
    def analyze_block_cipher(self, ciphertext, block_size=16):
        """Analyze block cipher security"""
        blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
        
        # Check for repeated blocks (ECB vulnerability)
        repeated_blocks = len(blocks) - len(set(blocks))
        
        # Block frequency analysis
        block_freq = Counter(blocks)
        
        return {
            'repeated_blocks': repeated_blocks,
            'block_frequency': block_freq,
            'entropy': self._calculate_entropy(ciphertext)
        }
```

</div>

</div>

---
layout: default
---

# Task 4: Performance Testing

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Requirements
Compare performance of different ciphers:

1. **Speed testing** - Encryption/decryption speed
2. **Memory usage** - RAM consumption
3. **Throughput** - Data processed per second
4. **Scalability** - Performance with large files

## Metrics
- **Encryption speed** - MB/s
- **Memory usage** - Peak RAM
- **CPU usage** - Processor utilization
- **Latency** - Time per operation

</div>

<div>

## Performance Testing Framework
```python
import time
import psutil
import os

class PerformanceTester:
    def __init__(self):
        self.results = {}
    
    def test_cipher_performance(self, cipher_class, data_sizes=[1, 10, 100, 1000]):
        """Test cipher performance across different data sizes"""
        results = {}
        
        for size_mb in data_sizes:
            # Generate test data
            test_data = os.urandom(size_mb * 1024 * 1024)
            
            # Test encryption
            start_time = time.time()
            start_memory = psutil.Process().memory_info().rss
            
            cipher = cipher_class(b'test_key_32_bytes_long')
            encrypted = cipher.encrypt(test_data)
            
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss
            
            # Calculate metrics
            encryption_time = end_time - start_time
            throughput = len(test_data) / encryption_time / (1024 * 1024)  # MB/s
            memory_usage = end_memory - start_memory
            
            results[size_mb] = {
                'encryption_time': encryption_time,
                'throughput': throughput,
                'memory_usage': memory_usage
            }
        
        return results
    
    def compare_ciphers(self, ciphers, data_size=100):
        """Compare multiple ciphers"""
        comparison = {}
        
        for name, cipher_class in ciphers.items():
            results = self.test_cipher_performance(cipher_class, [data_size])
            comparison[name] = results[data_size]
        
        return comparison
```

</div>

</div>

---
layout: default
---

# Common Vulnerabilities

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Stream Cipher Issues
- **Weak key scheduling** - RC4 vulnerabilities
- **Key reuse** - Same keystream for different messages
- **Predictable IVs** - Weak initialization
- **Linear feedback** - LFSR predictability

## Block Cipher Issues
- **ECB mode** - Pattern leakage
- **Weak padding** - Padding oracle attacks
- **IV reuse** - CBC mode vulnerabilities
- **Timing attacks** - Implementation flaws

</div>

<div>

## Implementation Mistakes
- **❌ Hardcoded keys** - Never embed secrets
- **❌ Weak randomness** - Use secure random
- **❌ Reusing IVs** - Generate random IVs
- **❌ Not authenticating** - Use authenticated encryption

## Best Practices
- **✅ Use established** libraries
- **✅ Follow** security guidelines
- **✅ Test thoroughly** for vulnerabilities
- **✅ Keep libraries** updated

</div>

</div>

---
layout: default
---

# Real-World Applications

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Stream Ciphers
- **TLS/SSL** - ChaCha20 in TLS 1.3
- **WiFi** - WPA3 uses ChaCha20
- **VPN** - WireGuard uses ChaCha20
- **Disk encryption** - Some implementations

## Block Ciphers
- **TLS/SSL** - AES in all versions
- **Disk encryption** - BitLocker, FileVault
- **Database encryption** - Transparent Data Encryption
- **File encryption** - PGP, S/MIME

</div>

<div>

## Modern Trends
- **Authenticated encryption** - GCM mode preferred
- **Post-quantum** - Preparing for quantum computers
- **Hardware acceleration** - AES-NI instructions
- **Cloud security** - Key management services

## Future Directions
- **Quantum-resistant** algorithms
- **Homomorphic encryption** - Computation on encrypted data
- **Zero-knowledge** proofs - Prove without revealing
- **Secure multi-party** computation

</div>

</div>

---
layout: end
---

# Questions?

<div class="pt-6">
  <span class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Let's discuss stream ciphers! 💬
  </span>
</div>

<div class="mt-4 text-sm text-gray-600">
<p><strong>Next Week:</strong> We'll explore public key cryptography and learn about RSA and elliptic curves!</p>
<p><strong>Assignment:</strong> Implement and test different stream and block ciphers to understand their strengths and weaknesses!</p>
</div>
