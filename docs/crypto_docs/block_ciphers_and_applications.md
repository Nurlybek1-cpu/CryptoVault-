---
theme: default
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Lecture 5: Block Ciphers and Applications
  MAT364 - Cryptography Course
drawings:
  persist: false
transition: slide-left
title: Block Ciphers and Applications
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

# Block Ciphers and Applications
## MAT364 - Cryptography Course

**Instructor:** Adil Akhmetov
**University:** SDU
**Week 5**

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

# What Are Block Ciphers?

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, x: -50, rotateY: -10 }"
     :enter="{ opacity: 1, x: 0, rotateY: 0, transition: { duration: 800, delay: 200, type: 'spring' } }">

## Definition
**Block ciphers** encrypt data in fixed-size blocks (typically 64, 128, or 256 bits) using a secret key.

<v-clicks>

## Key Characteristics
- **Fixed block size** - Always encrypt same amount of data
- **Deterministic** - Same input always produces same output
- **Reversible** - Can decrypt to get original plaintext
- **Key-dependent** - Output depends on secret key

</v-clicks>

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, x: 50, rotateY: 10 }"
     :enter="{ opacity: 1, x: 0, rotateY: 0, transition: { duration: 800, delay: 400, type: 'spring' } }">

## How They Work
<v-clicks>

- **Divide plaintext** into fixed-size blocks
- **Apply encryption function** to each block
- **Use same key** for all blocks
- **Combine blocks** to form ciphertext

</v-clicks>

## Common Block Sizes
<v-clicks>

- **64 bits** - Older ciphers (DES, 3DES)
- **128 bits** - Modern standard (AES)
- **256 bits** - High security applications
- **Variable** - Some ciphers support multiple sizes

</v-clicks>

</div>

</div>

<!-- Visual Animation: Block Cipher Process -->
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 30, scale: 0.8 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 1000, delay: 600, type: 'spring', bounce: 0.4 } }"
     class="mt-4 p-4 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg border-2 border-blue-200 animation-container">

<div class="text-center mb-4">
<h3 class="text-lg font-bold text-blue-800">Block Cipher Process Visualization</h3>
</div>

<div class="flex items-center justify-center space-x-4 text-sm">
<div v-motion
     :initial="{ x: -100, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 800 } }"
     class="bg-white p-3 rounded-lg shadow-md border">
<div class="font-bold text-green-600">Plaintext</div>
<div class="text-xs">"HELLO WORLD 123"</div>
</div>

<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1000 } }"
     class="text-2xl text-blue-600">→</div>

<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1200 } }"
     class="bg-white p-3 rounded-lg shadow-md border">
<div class="font-bold text-purple-600">128-bit Blocks</div>
<div class="text-xs">16 bytes each</div>
</div>

<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1400 } }"
     class="text-2xl text-blue-600">→</div>

<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1600 } }"
     class="bg-white p-3 rounded-lg shadow-md border">
<div class="font-bold text-red-600">Ciphertext</div>
<div class="text-xs">Encrypted blocks</div>
</div>
</div>

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20, scale: 0.9 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 600, delay: 600, type: 'spring' } }"
     class="mt-4 p-3 bg-blue-100 rounded-lg text-sm">
<strong>Remember:</strong> Block ciphers are the foundation of modern symmetric encryption and are used everywhere!
</div>

---
layout: default
---

# 🎯 Student Task: Block Cipher Basics

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-yellow-50 to-orange-50 rounded-lg border-2 border-yellow-300 task-container">

## Task: Understanding Block Sizes

<v-clicks>

**Given:**
- Message: "CRYPTOGRAPHY ROCKS"
- Block size: 128 bits (16 bytes)
- Each character = 1 byte

**Your Task:**
1. How many bytes is the message?
2. How many complete blocks can be formed?
3. How many bytes are left over?
4. What needs to be done with the leftover bytes?

**Hint:** Count the characters including spaces!

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 2000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center text-sm text-gray-600">
<strong>Take 2 minutes to figure this out!</strong>
</div>
</div>

</div>

---
layout: default
---

# ✅ Solution: Block Cipher Task

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-green-50 to-blue-50 rounded-lg border-2 border-green-300 task-container">

## Step-by-Step Solution

<v-clicks>

**Step 1: Count the bytes**
```
"CRYPTOGRAPHY ROCKS" = 18 characters = 18 bytes
```

**Step 2: Calculate complete blocks**
```
Block size: 16 bytes
Complete blocks: 18 ÷ 16 = 1 complete block
```

**Step 3: Calculate leftover bytes**
```
Leftover: 18 - 16 = 2 bytes
```

**Step 4: Handle leftover bytes**
```
Need padding! Add 14 bytes to make it 16 bytes total.
Common method: PKCS#7 padding
```

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 3000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center">
<strong class="text-green-600">Key Insight:</strong> Block ciphers require padding when data doesn't fit perfectly into blocks!
</div>
</div>

</div>

---
layout: section
---

# Block Cipher Design Principles

---
layout: default
---

# Confusion and Diffusion

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Confusion
<v-clicks>

- **Obscure relationship** between key and ciphertext
- **Make it hard** to find the key from ciphertext
- **Implemented through** substitution operations
- **Example:** S-boxes in AES

</v-clicks>

## How Confusion Works
<v-clicks>

```python
# S-box substitution (simplified)
def substitute_byte(byte_value):
    s_box = [0x63, 0x7C, 0x77, 0x7B, ...]  # 256 values
    return s_box[byte_value]

# Each input byte maps to different output byte
input_byte = 0x53
output_byte = substitute_byte(input_byte)  # 0xED
```

</v-clicks>

</div>

<div>

## Diffusion
<v-clicks>

- **Spread influence** of each plaintext bit
- **Small change** in input → big change in output
- **Implemented through** permutation operations
- **Example:** MixColumns in AES

</v-clicks>

## How Diffusion Works
<v-clicks>

```python
# Simple diffusion (shift and mix)
def diffusion(data):
    # Shift bits around
    shifted = ((data << 1) | (data >> 7)) & 0xFF

    # Mix with itself
    mixed = shifted ^ (shifted >> 4)

    return mixed

# Small change creates big difference
input1 = 0b10101010  # 170
input2 = 0b10101011  # 171 (1 bit different)
output1 = diffusion(input1)
output2 = diffusion(input2)
# Outputs are very different!
```

</v-clicks>

</div>

</div>

<!-- Animation: Confusion and Diffusion -->
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 30, scale: 0.9 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 1000, delay: 400 } }"
     class="mt-4 p-4 bg-gradient-to-r from-purple-50 to-pink-50 rounded-lg border-2 border-purple-200 animation-container">

<div class="text-center mb-4">
<h3 class="text-lg font-bold text-purple-800">Confusion + Diffusion = Security</h3>
</div>

<div class="flex items-center justify-center space-x-4">
<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 600 } }"
     class="text-center">
<div class="w-16 h-16 bg-blue-200 border-2 border-blue-400 rounded-lg flex items-center justify-center text-sm font-bold">
Input
</div>
<div class="text-xs mt-2">Original data</div>
</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 800 } }"
     class="text-center">
<div class="text-2xl text-purple-600">→</div>
<div class="text-xs">Confusion</div>
</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1000 } }"
     class="text-center">
<div class="w-16 h-16 bg-yellow-200 border-2 border-yellow-400 rounded-lg flex items-center justify-center text-sm font-bold">
Mixed
</div>
<div class="text-xs mt-2">Substituted</div>
</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1200 } }"
     class="text-center">
<div class="text-2xl text-purple-600">→</div>
<div class="text-xs">Diffusion</div>
</div>

<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1400 } }"
     class="text-center">
<div class="w-16 h-16 bg-red-200 border-2 border-red-400 rounded-lg flex items-center justify-center text-sm font-bold">
Output
</div>
<div class="text-xs mt-2">Scrambled</div>
</div>
</div>

<div v-motion
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { delay: 1600 } }"
     class="text-center mt-4 text-sm text-purple-600">
<strong>Result:</strong> Each input bit affects many output bits, making cryptanalysis extremely difficult!
</div>

</div>

---
layout: default
---

# Feistel Networks

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## What is a Feistel Network?
<v-clicks>

- **Symmetric structure** for block ciphers
- **Splits input** into left and right halves
- **Applies round function** to one half
- **XORs result** with other half
- **Swaps halves** and repeats

</v-clicks>

## Why Feistel Networks?
<v-clicks>

- **Encryption/decryption** use same structure
- **Round function** doesn't need to be invertible
- **Easy to implement** in hardware/software
- **Proven security** when properly designed

</v-clicks>

</div>

<div>

## Feistel Round Function
```python
def feistel_round(left, right, round_key):
    """Single round of Feistel network"""
    # Apply round function to right half
    f_output = round_function(right, round_key)

    # XOR with left half
    new_right = left ^ f_output

    # Swap halves
    new_left = right

    return new_left, new_right

def round_function(data, key):
    """Round function (can be any function)"""
    # Substitute
    substituted = substitute(data, key)

    # Permute
    permuted = permute(substituted)

    return permuted

# Example: 4 rounds of Feistel
def feistel_encrypt(plaintext, keys):
    left, right = split_block(plaintext)

    for i in range(4):
        left, right = feistel_round(left, right, keys[i])

    # Final swap
    return combine_blocks(right, left)
```

</div>

</div>

---
layout: default
---

# 🎯 Student Task: Feistel Network

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-indigo-50 to-cyan-50 rounded-lg border-2 border-indigo-300 task-container">

## Task: Trace Feistel Rounds

<v-clicks>

**Given:**
- Initial block: L₀ = 1010, R₀ = 1100
- Round function: F(R, K) = R ⊕ K (simple XOR)
- Round keys: K₁ = 1001, K₂ = 0110

**Your Task:**
Trace through 2 rounds of the Feistel network:

**Round 1:**
- F(R₀, K₁) = ?
- L₁ = ?
- R₁ = ?

**Round 2:**
- F(R₁, K₂) = ?
- L₂ = ?
- R₂ = ?

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 2000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center text-sm text-gray-600">
<strong>Remember: L₁ = R₀ and R₁ = L₀ ⊕ F(R₀, K₁)</strong>
</div>
</div>

</div>

---
layout: default
---

# ✅ Solution: Feistel Network

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-green-50 to-emerald-50 rounded-lg border-2 border-green-300 task-container">

## Step-by-Step Solution

<v-clicks>

**Initial State:**
```
L₀ = 1010, R₀ = 1100
```

**Round 1:**
```
F(R₀, K₁) = 1100 ⊕ 1001 = 0101
L₁ = R₀ = 1100
R₁ = L₀ ⊕ F(R₀, K₁) = 1010 ⊕ 0101 = 1111
```

**Round 2:**
```
F(R₁, K₂) = 1111 ⊕ 0110 = 1001
L₂ = R₁ = 1111
R₂ = L₁ ⊕ F(R₁, K₂) = 1100 ⊕ 1001 = 0101
```

**Final Result:** L₂R₂ = 11110101

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 3000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center">
<strong class="text-green-600">Key Insight:</strong> Feistel networks are elegant because the same structure works for both encryption and decryption!
</div>
</div>

</div>

---
layout: section
---

# Advanced Encryption Standard (AES)

---
layout: default
---

# AES Overview

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## AES History
<v-clicks>

- **Originally Rijndael** - Designed by Joan Daemen and Vincent Rijmen
- **NIST competition** - Selected in 2001
- **Replaced DES** - Much stronger than previous standard
- **Widely adopted** - Used everywhere today

</v-clicks>

## AES Specifications
<v-clicks>

- **Block size:** 128 bits (16 bytes)
- **Key sizes:** 128, 192, 256 bits
- **Rounds:** 10, 12, 14 (depending on key size)
- **Structure:** Substitution-Permutation Network (not Feistel)

</v-clicks>

</div>

<div>

## AES Round Functions
<v-clicks>

1. **SubBytes** - Byte substitution using S-box
2. **ShiftRows** - Cyclically shift rows
3. **MixColumns** - Mix data within columns
4. **AddRoundKey** - XOR with round key

</v-clicks>

## AES Implementation
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

def aes_encrypt(plaintext, key):
    """AES encryption with CBC mode"""
    # Generate random IV
    iv = os.urandom(16)

    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Add PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext
```

</div>

</div>

---
layout: default
---

# AES Round Function Detail

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## SubBytes Operation
```python
# AES S-box (partial)
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    # ... (256 total values)
]

def sub_bytes(state):
    """Apply S-box substitution"""
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]
    return state
```

## ShiftRows Operation
```python
def shift_rows(state):
    """Shift rows cyclically"""
    # Row 0: no shift
    # Row 1: shift left by 1
    # Row 2: shift left by 2
    # Row 3: shift left by 3

    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

    return state
```

</div>

<div>

## MixColumns Operation
```python
def mix_columns(state):
    """Mix columns using matrix multiplication"""
    # Multiplication matrix for AES
    mix_matrix = [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
    ]

    for col in range(4):
        column = [state[row][col] for row in range(4)]
        mixed = matrix_multiply_gf(mix_matrix, column)
        for row in range(4):
            state[row][col] = mixed[row]

    return state

def add_round_key(state, round_key):
    """XOR state with round key"""
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]

    return state
```

## Complete AES Round
```python
def aes_round(state, round_key):
    """One complete AES round"""
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, round_key)
    return state
```

</div>

</div>

---
layout: default
---

# AES State Matrix

<!-- AES State Visualization -->
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 30, scale: 0.9 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 1000, delay: 200 } }"
     class="mt-4 p-4 bg-gradient-to-r from-indigo-50 to-blue-50 rounded-lg border-2 border-indigo-200 animation-container">

<div class="text-center mb-6">
<h3 class="text-lg font-bold text-indigo-800">AES 128-bit State Matrix (4×4 bytes)</h3>
</div>

<div class="flex items-center justify-center space-x-8">

<!-- Initial State -->
<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 400 } }"
     class="text-center">
<div class="text-sm font-bold text-indigo-600 mb-2">Initial State</div>
<div class="grid grid-cols-4 gap-1">
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">A0</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">A1</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">A2</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">A3</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">B0</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">B1</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">B2</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">B3</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">C0</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">C1</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">C2</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">C3</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">D0</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">D1</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">D2</div>
<div class="w-8 h-8 bg-blue-200 border border-blue-400 rounded text-xs flex items-center justify-center font-mono">D3</div>
</div>
</div>

<!-- Arrow -->
<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 600 } }"
     class="text-3xl text-indigo-600">→</div>

<!-- After SubBytes -->
<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 800 } }"
     class="text-center">
<div class="text-sm font-bold text-indigo-600 mb-2">After SubBytes</div>
<div class="grid grid-cols-4 gap-1">
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">S0</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">S1</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">S2</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">S3</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">S4</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">S5</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">S6</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">S7</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">S8</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">S9</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">SA</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">SB</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">SC</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">SD</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">SE</div>
<div class="w-8 h-8 bg-green-200 border border-green-400 rounded text-xs flex items-center justify-center font-mono">SF</div>
</div>
</div>

<!-- Arrow -->
<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1000 } }"
     class="text-3xl text-indigo-600">→</div>

<!-- Final State -->
<div v-motion
     :initial="{ x: -30, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 1200 } }"
     class="text-center">
<div class="text-sm font-bold text-indigo-600 mb-2">After All Operations</div>
<div class="grid grid-cols-4 gap-1">
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">X0</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">X1</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">X2</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">X3</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">X4</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">X5</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">X6</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">X7</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">X8</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">X9</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">XA</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">XB</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">XC</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">XD</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">XE</div>
<div class="w-8 h-8 bg-red-200 border border-red-400 rounded text-xs flex items-center justify-center font-mono">XF</div>
</div>
</div>

</div>

<div v-motion
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { delay: 1400 } }"
     class="text-center mt-4 text-sm text-indigo-600">
<strong>Process:</strong> SubBytes → ShiftRows → MixColumns → AddRoundKey (repeat 10-14 times)
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

## Task: Choose the Right AES Configuration

<v-clicks>

**Scenario:** You're building a secure file storage system.

**Requirements:**
- Store personal financial documents
- Must be secure for at least 30 years
- Users upload files frequently (performance matters)
- Government compliance required

**Options:**
- **AES-128:** 128-bit key, 10 rounds, fastest
- **AES-192:** 192-bit key, 12 rounds, medium speed
- **AES-256:** 256-bit key, 14 rounds, slowest

**Consider:**
- Quantum computers may break AES-128 in the future
- Government standards require AES-256 for classified data
- Performance difference is about 40% between AES-128 and AES-256

**Questions:**
1. Which AES configuration would you choose?
2. What's your reasoning?
3. How would you handle the performance vs. security trade-off?

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 2000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center text-sm text-gray-600">
<strong>Think about long-term security and compliance!</strong>
</div>
</div>

</div>

---
layout: default
---

# ✅ Solution: AES Configuration

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-green-50 to-emerald-50 rounded-lg border-2 border-green-300 task-container">

## Recommended Solution: AES-256

<v-clicks>

**1. Why AES-256:**
- **Future-proof:** Resistant to quantum attacks (effectively becomes AES-128 post-quantum)
- **Compliance:** Meets government standards for sensitive data
- **30-year security:** Strong enough for long-term protection
- **Industry standard:** Widely adopted for financial applications

**2. Reasoning:**
- **Security priority:** Financial documents require maximum protection
- **Regulatory compliance:** Government standards mandate AES-256
- **Future threats:** Quantum computers will weaken all current encryption
- **Cost of breach:** Much higher than performance overhead

**3. Performance Trade-offs:**
- **Accept 40% slower encryption** for much better security
- **Use hardware acceleration** (AES-NI instructions on modern CPUs)
- **Optimize implementation** with established libraries
- **Consider hybrid approach:** AES-256 for data, AES-128 for temporary operations

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 3000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center">
<strong class="text-green-600">Best Practice:</strong> When in doubt, choose stronger security. Performance can be optimized, but breaches are permanent.
</div>
</div>

</div>

---
layout: section
---

# Block Cipher Modes of Operation

---
layout: default
---

# Why Do We Need Modes?

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## The Problem
<v-clicks>

- **Block ciphers** only encrypt fixed-size blocks
- **Real data** is usually larger than one block
- **Naive approach** - encrypt each block independently
- **Security issues** with independent encryption

</v-clicks>

## ECB Mode Problems
<v-clicks>

```python
# ECB Mode (Electronic Codebook) - INSECURE!
def ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = split_into_blocks(plaintext, 16)
    ciphertext = b''

    for block in blocks:
        ciphertext += cipher.encrypt(block)

    return ciphertext

# Problem: Same plaintext block = Same ciphertext block
```

</v-clicks>

</div>

<div>

## Security Issues
<v-clicks>

- **Pattern leakage** - Identical blocks show patterns
- **No randomness** - Predictable outputs
- **Vulnerable to analysis** - Easy to detect structure
- **Real-world impact** - Can reveal image patterns, repeated data

</v-clicks>

## Example: Image Encryption
<v-clicks>

```
Original Image: [BLACK][WHITE][BLACK][WHITE]
ECB Result:     [ENCR1][ENCR2][ENCR1][ENCR2]
                 ↑       ↑       ↑       ↑
              Same!   Same!   Same!   Same!

Problem: The pattern is still visible!
```

</v-clicks>

</div>

</div>

<div class="mt-4 p-3 bg-red-100 rounded-lg text-sm">
<strong>Warning:</strong> Never use ECB mode for any real application! It's fundamentally insecure.
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
- **First block** XORed with random IV
- **Creates dependency** between blocks
- **Same plaintext** → different ciphertext (due to IV)

</v-clicks>

## CBC Encryption
<v-clicks>

```python
def cbc_encrypt(plaintext, key, iv):
    """CBC mode encryption"""
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = split_into_blocks(plaintext, 16)
    ciphertext = b''
    prev_block = iv  # Start with IV

    for block in blocks:
        # XOR with previous ciphertext
        xored = xor_bytes(block, prev_block)

        # Encrypt the XORed result
        encrypted = cipher.encrypt(xored)
        ciphertext += encrypted

        # This becomes the previous block
        prev_block = encrypted

    return iv + ciphertext  # Prepend IV
```

</v-clicks>

</div>

<div>

## CBC Decryption
<v-clicks>

```python
def cbc_decrypt(ciphertext, key):
    """CBC mode decryption"""
    # Extract IV
    iv = ciphertext[:16]
    encrypted_blocks = ciphertext[16:]

    cipher = AES.new(key, AES.MODE_ECB)
    blocks = split_into_blocks(encrypted_blocks, 16)
    plaintext = b''
    prev_block = iv

    for block in blocks:
        # Decrypt the block
        decrypted = cipher.decrypt(block)

        # XOR with previous ciphertext
        plain_block = xor_bytes(decrypted, prev_block)
        plaintext += plain_block

        # This block becomes previous
        prev_block = block

    return plaintext
```

</v-clicks>

## CBC Properties
<v-clicks>

- **Random IV** required for each encryption
- **Sequential** - Cannot parallelize encryption
- **Self-synchronizing** - Errors don't propagate
- **Widely used** - Standard mode for many applications

</v-clicks>

</div>

</div>

---
layout: default
---

# Counter (CTR) Mode

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## How CTR Works
<v-clicks>

- **Turns block cipher** into stream cipher
- **Encrypt counter values** to create keystream
- **XOR keystream** with plaintext
- **Parallelizable** - Can encrypt blocks independently

</v-clicks>

## CTR Implementation
<v-clicks>

```python
def ctr_encrypt(plaintext, key, nonce):
    """Counter mode encryption"""
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = split_into_blocks(plaintext, 16)
    ciphertext = b''
    counter = 0

    for block in blocks:
        # Create counter block
        counter_block = nonce + counter.to_bytes(8, 'big')

        # Encrypt counter to get keystream
        keystream = cipher.encrypt(counter_block)

        # XOR with plaintext
        encrypted_block = xor_bytes(block, keystream[:len(block)])
        ciphertext += encrypted_block

        counter += 1

    return nonce + ciphertext

def ctr_decrypt(ciphertext, key):
    """CTR decryption (same as encryption)"""
    return ctr_encrypt(ciphertext, key)
```

</v-clicks>

</div>

<div>

## CTR Advantages
<v-clicks>

- **Parallelizable** - Can process blocks in parallel
- **Random access** - Can decrypt any block independently
- **No padding** - Works with any data length
- **Stream cipher properties** - XOR-based operation

</v-clicks>

## CTR Requirements
<v-clicks>

- **Unique nonce** for each encryption
- **Counter must not repeat** with same key
- **Nonce + counter** must be unique
- **No authentication** - needs additional MAC

</v-clicks>

## CTR Security
<v-clicks>

```python
# Counter construction (common approach)
def create_counter_block(nonce, counter):
    """Create 128-bit counter block"""
    # 64-bit nonce + 64-bit counter
    return nonce + counter.to_bytes(8, 'big')

# Security requirement: NEVER reuse nonce with same key!
```

</v-clicks>

</div>

</div>

---
layout: default
---

# Galois/Counter Mode (GCM)

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## What is GCM?
<v-clicks>

- **Authenticated encryption** - Provides confidentiality AND integrity
- **Combines CTR mode** with Galois field authentication
- **Industry standard** - Used in TLS 1.3, IPsec
- **High performance** - Hardware acceleration available

</v-clicks>

## GCM Components
<v-clicks>

- **CTR mode** for encryption
- **GHASH** for authentication
- **Additional Associated Data (AAD)** support
- **Authentication tag** verifies integrity

</v-clicks>

</div>

<div>

## GCM Implementation
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def gcm_encrypt(plaintext, key, aad=b''):
    """GCM mode encryption with authentication"""
    # Generate random nonce
    nonce = os.urandom(12)  # 96-bit nonce for GCM

    # Create AESGCM cipher
    aesgcm = AESGCM(key)

    # Encrypt and authenticate
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    return nonce + ciphertext

def gcm_decrypt(encrypted_data, key, aad=b''):
    """GCM mode decryption with verification"""
    # Extract nonce
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    # Create AESGCM cipher
    aesgcm = AESGCM(key)

    try:
        # Decrypt and verify
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext
    except Exception:
        raise ValueError("Authentication failed!")
```

</div>

</div>

---
layout: default
---

# 🎯 Student Task: Mode Comparison

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-amber-50 to-yellow-50 rounded-lg border-2 border-amber-300 task-container">

## Task: Choose the Right Mode

<v-clicks>

**Scenario 1: Video Streaming Service**
- Need to encrypt video files for streaming
- Users may seek to different parts of the video
- Performance is critical
- Authentication not required (separate signature)

**Scenario 2: Secure Messaging App**
- Encrypt chat messages
- Need both confidentiality and integrity
- Messages are small (< 1KB typically)
- Security is more important than performance

**Scenario 3: Database Encryption**
- Encrypt database records
- Need to decrypt individual records randomly
- Performance matters for queries
- Integrity verification needed

**Your Task:**
Match each scenario with the best mode (ECB, CBC, CTR, GCM) and explain why.

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 2000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center text-sm text-gray-600">
<strong>Consider: Parallelization, Authentication, Random Access, Security</strong>
</div>
</div>

</div>

---
layout: default
---

# ✅ Solution: Mode Comparison

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600 } }"
     class="p-4 bg-gradient-to-r from-green-50 to-teal-50 rounded-lg border-2 border-green-300 task-container">

## Optimal Mode Choices

<v-clicks>

**Scenario 1 → CTR Mode**
- **Random access:** Can seek to any part of video
- **Parallelizable:** Can decrypt multiple blocks simultaneously
- **No padding:** Works perfectly with video frame boundaries
- **High performance:** Excellent for streaming applications

**Scenario 2 → GCM Mode**
- **Authenticated encryption:** Provides both confidentiality and integrity
- **Small messages:** Overhead is acceptable for small data
- **Security priority:** Perfect for messaging applications
- **Standard choice:** Used in Signal, WhatsApp, etc.

**Scenario 3 → GCM Mode**
- **Random access:** Can decrypt individual records
- **Authentication:** Verifies database integrity
- **Performance:** Good for database applications
- **Standard compliance:** Meets enterprise security requirements

**Never use ECB:** It's fundamentally insecure for any real application!

</v-clicks>

<div v-motion
     :initial="{ opacity: 0, scale: 0.8 }"
     :enter="{ opacity: 1, scale: 1, transition: { delay: 3000, duration: 800 } }"
     class="mt-4 p-4 bg-white rounded-lg shadow-md">
<div class="text-center">
<strong class="text-green-600">Rule of Thumb:</strong> Use GCM for most applications, CTR when you need custom authentication.
</div>
</div>

</div>

---
layout: section
---

# Padding and Data Handling

---
layout: default
---

# PKCS#7 Padding

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Why Padding?
<v-clicks>

- **Block ciphers** require complete blocks
- **Real data** rarely fits perfectly
- **Must pad** incomplete blocks
- **Padding must be removable** after decryption

</v-clicks>

## PKCS#7 Algorithm
<v-clicks>

- **Add N bytes** each with value N
- **If block is complete** - add full block of padding
- **Always unambiguous** - Can always remove correctly
- **Most common** padding scheme

</v-clicks>

</div>

<div>

## PKCS#7 Implementation
```python
def pkcs7_pad(data, block_size):
    """Add PKCS#7 padding to data"""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(padded_data):
    """Remove PKCS#7 padding from data"""
    if len(padded_data) == 0:
        raise ValueError("Empty data")

    padding_length = padded_data[-1]

    # Validate padding
    if padding_length == 0 or padding_length > len(padded_data):
        raise ValueError("Invalid padding")

    # Check all padding bytes are correct
    for i in range(padding_length):
        if padded_data[-(i+1)] != padding_length:
            raise ValueError("Invalid padding")

    return padded_data[:-padding_length]

# Examples
data1 = b"HELLO WORLD"     # 11 bytes
padded1 = pkcs7_pad(data1, 16)  # "HELLO WORLD\x05\x05\x05\x05\x05"

data2 = b"EXACTLY16BYTES!!"  # 16 bytes
padded2 = pkcs7_pad(data2, 16)  # Add full 16-byte padding block
```

</div>

</div>

---
layout: default
---

# Padding Examples

<!-- Padding Visualization -->
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 30, scale: 0.9 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 1000, delay: 200 } }"
     class="mt-4 p-4 bg-gradient-to-r from-green-50 to-blue-50 rounded-lg border-2 border-green-200 animation-container">

<div class="text-center mb-6">
<h3 class="text-lg font-bold text-green-800">PKCS#7 Padding Examples</h3>
</div>

<!-- Example 1: 11 bytes -->
<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 400 } }"
     class="mb-4">
<div class="text-sm font-bold text-green-600 mb-2">Example 1: "HELLO WORLD" (11 bytes) → 16-byte block</div>
<div class="flex items-center space-x-1">
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-2 py-1 font-mono">H</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-2 py-1 font-mono">E</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-2 py-1 font-mono">L</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-2 py-1 font-mono">L</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-2 py-1 font-mono">O</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-2 py-1 font-mono"> </div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-2 py-1 font-mono">W</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-2 py-1 font-mono">O</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-2 py-1 font-mono">R</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-2 py-1 font-mono">L</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-2 py-1 font-mono">D</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">05</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">05</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">05</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">05</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">05</div>
</div>
<div class="text-xs text-gray-600 mt-1">Need 5 padding bytes, so add five 0x05 bytes</div>
</div>

<!-- Example 2: 16 bytes -->
<div v-motion
     :initial="{ x: -50, opacity: 0 }"
     :enter="{ x: 0, opacity: 1, transition: { delay: 600 } }"
     class="mb-4">
<div class="text-sm font-bold text-green-600 mb-2">Example 2: "EXACTLY16BYTES!!" (16 bytes) → Need another block</div>
<div class="flex items-center space-x-1 mb-2">
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">E</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">X</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">A</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">C</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">T</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">L</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">Y</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">1</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">6</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">B</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">Y</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">T</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">E</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">S</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">!</div>
<div class="text-xs bg-blue-200 border border-blue-400 rounded px-1 py-1 font-mono">!</div>
</div>
<div class="flex items-center space-x-1">
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
<div class="text-xs bg-red-200 border border-red-400 rounded px-2 py-1 font-mono">10</div>
</div>
<div class="text-xs text-gray-600 mt-1">Complete block needs full 16-byte padding block (sixteen 0x10 bytes)</div>
</div>

<div v-motion
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { delay: 800 } }"
     class="text-center mt-4 text-sm text-green-600">
<strong>Key Rule:</strong> Padding length = value of padding bytes. This makes removal unambiguous!
</div>

</div>

---
layout: section
---

# Real-World Applications

---
layout: default
---

# File Encryption System

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Complete File Encryption
```python
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class FileEncryption:
    def __init__(self, password):
        self.password = password.encode()

    def _derive_key(self, salt):
        """Derive key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(self.password)

    def encrypt_file(self, input_file, output_file):
        """Encrypt a file using AES-CBC"""
        # Generate random salt and IV
        salt = os.urandom(16)
        iv = os.urandom(16)

        # Derive key from password
        key = self._derive_key(salt)

        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Setup padding
        padder = padding.PKCS7(128).padder()

        with open(input_file, 'rb') as infile, \
             open(output_file, 'wb') as outfile:

            # Write salt and IV first
            outfile.write(salt + iv)

            # Encrypt file in chunks
            while True:
                chunk = infile.read(8192)  # 8KB chunks
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    # Last chunk - apply padding
                    chunk = padder.update(chunk) + padder.finalize()

                encrypted_chunk = encryptor.update(chunk)
                outfile.write(encrypted_chunk)

            # Finalize encryption
            outfile.write(encryptor.finalize())
```

</div>

<div>

## File Decryption
```python
def decrypt_file(self, input_file, output_file):
    """Decrypt a file using AES-CBC"""
    with open(input_file, 'rb') as infile:
        # Read salt and IV
        salt = infile.read(16)
        iv = infile.read(16)

        # Derive key from password
        key = self._derive_key(salt)

        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        # Read encrypted data
        encrypted_data = infile.read()

    # Decrypt all data
    padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Write decrypted file
    with open(output_file, 'wb') as outfile:
        outfile.write(plaintext)

# Usage example
def main():
    encryptor = FileEncryption("my_secure_password")

    # Encrypt a file
    encryptor.encrypt_file("document.pdf", "document.pdf.enc")

    # Decrypt the file
    encryptor.decrypt_file("document.pdf.enc", "document_decrypted.pdf")

    print("File encryption/decryption complete!")

if __name__ == "__main__":
    main()
```

</div>

</div>

---
layout: default
---

# Database Encryption

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Column-Level Encryption
```python
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64

class EncryptedDatabase:
    def __init__(self, db_path, encryption_key):
        self.conn = sqlite3.connect(db_path)
        self.aesgcm = AESGCM(encryption_key)
        self.setup_tables()

    def setup_tables(self):
        """Create tables with encrypted columns"""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                email_encrypted TEXT NOT NULL,
                ssn_encrypted TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()

    def encrypt_field(self, plaintext):
        """Encrypt a field value"""
        if plaintext is None:
            return None

        # Generate random nonce
        nonce = os.urandom(12)

        # Encrypt data
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode(), b'')

        # Combine nonce + ciphertext and base64 encode
        encrypted_data = base64.b64encode(nonce + ciphertext).decode()
        return encrypted_data

    def decrypt_field(self, encrypted_data):
        """Decrypt a field value"""
        if encrypted_data is None:
            return None

        try:
            # Base64 decode
            data = base64.b64decode(encrypted_data)

            # Split nonce and ciphertext
            nonce = data[:12]
            ciphertext = data[12:]

            # Decrypt
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, b'')
            return plaintext.decode()
        except Exception:
            raise ValueError("Decryption failed")
```

</div>

<div>

## Database Operations
```python
def add_user(self, username, email, ssn):
    """Add user with encrypted sensitive data"""
    encrypted_email = self.encrypt_field(email)
    encrypted_ssn = self.encrypt_field(ssn)

    self.conn.execute('''
        INSERT INTO users (username, email_encrypted, ssn_encrypted)
        VALUES (?, ?, ?)
    ''', (username, encrypted_email, encrypted_ssn))
    self.conn.commit()

def get_user(self, user_id):
    """Get user and decrypt sensitive data"""
    cursor = self.conn.execute('''
        SELECT id, username, email_encrypted, ssn_encrypted, created_at
        FROM users WHERE id = ?
    ''', (user_id,))

    row = cursor.fetchone()
    if not row:
        return None

    # Decrypt sensitive fields
    return {
        'id': row[0],
        'username': row[1],
        'email': self.decrypt_field(row[2]),
        'ssn': self.decrypt_field(row[3]),
        'created_at': row[4]
    }

def search_users(self, username_pattern):
    """Search users (only non-encrypted fields)"""
    cursor = self.conn.execute('''
        SELECT id, username, created_at
        FROM users WHERE username LIKE ?
    ''', (f'%{username_pattern}%',))

    return cursor.fetchall()

# Usage example
def main():
    # Generate key (in practice, use secure key management)
    key = AESGCM.generate_key(256)

    # Create encrypted database
    db = EncryptedDatabase('users.db', key)

    # Add users
    db.add_user('alice', 'alice@example.com', '123-45-6789')
    db.add_user('bob', 'bob@example.com', '987-65-4321')

    # Retrieve user
    user = db.get_user(1)
    print(f"User: {user['username']}, Email: {user['email']}")
```

</div>

</div>

---
layout: default
---

# Web API Encryption

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## API Payload Encryption
```python
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import base64
import os

app = Flask(__name__)

class APIEncryption:
    def __init__(self, key):
        self.aesgcm = AESGCM(key)

    def encrypt_payload(self, data):
        """Encrypt JSON payload"""
        # Convert to JSON string
        json_data = json.dumps(data)

        # Generate nonce
        nonce = os.urandom(12)

        # Encrypt
        ciphertext = self.aesgcm.encrypt(nonce, json_data.encode(), b'')

        # Return base64 encoded result
        encrypted_payload = base64.b64encode(nonce + ciphertext).decode()
        return encrypted_payload

    def decrypt_payload(self, encrypted_data):
        """Decrypt JSON payload"""
        try:
            # Decode base64
            data = base64.b64decode(encrypted_data)

            # Split nonce and ciphertext
            nonce = data[:12]
            ciphertext = data[12:]

            # Decrypt
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, b'')

            # Parse JSON
            return json.loads(plaintext.decode())
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

# Initialize encryption
encryption_key = AESGCM.generate_key(256)
api_crypto = APIEncryption(encryption_key)

@app.route('/api/secure-data', methods=['POST'])
def handle_secure_data():
    """Handle encrypted API requests"""
    try:
        # Get encrypted payload
        encrypted_data = request.json.get('encrypted_payload')

        # Decrypt payload
        decrypted_data = api_crypto.decrypt_payload(encrypted_data)

        # Process the request
        result = process_sensitive_data(decrypted_data)

        # Encrypt response
        encrypted_response = api_crypto.encrypt_payload(result)

        return jsonify({
            'status': 'success',
            'encrypted_response': encrypted_response
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
```

</div>

<div>

## Client-Side Usage
```python
import requests
import json

class SecureAPIClient:
    def __init__(self, api_url, encryption_key):
        self.api_url = api_url
        self.api_crypto = APIEncryption(encryption_key)

    def send_secure_request(self, data):
        """Send encrypted request to API"""
        # Encrypt payload
        encrypted_payload = self.api_crypto.encrypt_payload(data)

        # Send request
        response = requests.post(
            f'{self.api_url}/api/secure-data',
            json={'encrypted_payload': encrypted_payload},
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 200:
            response_data = response.json()

            if response_data['status'] == 'success':
                # Decrypt response
                decrypted_response = self.api_crypto.decrypt_payload(
                    response_data['encrypted_response']
                )
                return decrypted_response
            else:
                raise Exception(f"API error: {response_data['message']}")
        else:
            raise Exception(f"HTTP error: {response.status_code}")

def process_sensitive_data(data):
    """Process sensitive data on server"""
    # Example processing
    if 'personal_info' in data:
        # Perform some sensitive operations
        return {
            'result': 'processed',
            'record_id': '12345',
            'status': 'completed'
        }
    else:
        return {'error': 'Invalid data format'}

# Usage example
def main():
    client = SecureAPIClient('http://localhost:5000', encryption_key)

    # Send encrypted request
    sensitive_data = {
        'personal_info': {
            'name': 'John Doe',
            'ssn': '123-45-6789',
            'account_number': '9876543210'
        }
    }

    try:
        result = client.send_secure_request(sensitive_data)
        print(f"Secure response: {result}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    app.run(debug=True)
```

</div>

</div>

---
layout: section
---

# Performance and Security

---
layout: default
---

# Block Cipher Performance

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Performance Factors
<v-clicks>

- **Algorithm choice** - AES vs alternatives
- **Key size** - 128 vs 256 bits
- **Mode of operation** - CBC vs CTR vs GCM
- **Implementation** - Software vs hardware
- **Data size** - Small vs large blocks

</v-clicks>

## Hardware Acceleration
<v-clicks>

- **AES-NI** - Intel/AMD processors
- **ARMv8 Crypto** - ARM processors
- **Dedicated chips** - Hardware security modules
- **GPU acceleration** - Parallel processing

</v-clicks>

</div>

<div>

## Performance Benchmark
```python
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def benchmark_aes_modes():
    """Benchmark different AES modes"""
    key = os.urandom(32)  # 256-bit key
    data = os.urandom(1024 * 1024)  # 1MB test data

    modes_to_test = [
        ('CBC', modes.CBC(os.urandom(16))),
        ('CTR', modes.CTR(os.urandom(16))),
        ('GCM', modes.GCM(os.urandom(12))),
    ]

    results = {}

    for mode_name, mode in modes_to_test:
        cipher = Cipher(algorithms.AES(key), mode)
        encryptor = cipher.encryptor()

        # Warm up
        for _ in range(10):
            encryptor.update(data[:1024])

        # Benchmark
        start_time = time.time()
        for _ in range(100):
            encrypted = encryptor.update(data)
        end_time = time.time()

        throughput = (len(data) * 100) / (end_time - start_time) / (1024 * 1024)
        results[mode_name] = f"{throughput:.2f} MB/s"

    return results

# Example results (will vary by hardware):
# CBC: 150 MB/s
# CTR: 200 MB/s
# GCM: 180 MB/s
```

</div>

</div>

---
layout: default
---

# Security Best Practices

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Key Management
<v-clicks>

- **Use strong keys** - 256-bit minimum
- **Generate securely** - Cryptographically secure random
- **Store safely** - Hardware security modules, key vaults
- **Rotate regularly** - Change keys periodically
- **Separate keys** - Different keys for different purposes

</v-clicks>

## Implementation Security
<v-clicks>

- **Use established libraries** - Don't implement crypto yourself
- **Validate inputs** - Check all parameters
- **Handle errors** - Don't leak information through errors
- **Clear memory** - Wipe sensitive data after use

</v-clicks>

</div>

<div>

## Common Mistakes
<v-clicks>

- **❌ Weak randomness** - Using `random()` instead of `secrets`
- **❌ Key reuse** - Using same key for different purposes
- **❌ Predictable IVs** - Not using random IVs
- **❌ ECB mode** - Never use ECB for real data
- **❌ Hardcoded keys** - Never embed keys in code

</v-clicks>

## Security Checklist
<v-clicks>

- **✅ Use AES-256** with secure modes (GCM preferred)
- **✅ Generate random IVs** for each encryption
- **✅ Implement proper padding** (PKCS#7)
- **✅ Use authenticated encryption** (GCM mode)
- **✅ Test thoroughly** including edge cases
- **✅ Keep libraries updated** for security patches

</v-clicks>

</div>

</div>

---
layout: default
---

# Common Vulnerabilities

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Padding Oracle Attacks
<v-clicks>

- **Attack on CBC mode** with padding validation
- **Information leakage** through error messages
- **Can decrypt** without knowing the key
- **Mitigation:** Use authenticated encryption (GCM)

</v-clicks>

## Bit-flipping Attacks
<v-clicks>

- **Attack on CBC mode** - Modify ciphertext to change plaintext
- **Exploits XOR** properties of CBC
- **Can modify** specific plaintext bits
- **Mitigation:** Use authenticated encryption

</v-clicks>

</div>

<div>

## Timing Attacks
<v-clicks>

- **Measure execution time** to leak information
- **Affects key comparison** and validation
- **Can extract keys** bit by bit
- **Mitigation:** Constant-time implementations

</v-clicks>

## Example: Secure Comparison
```python
import hmac

def secure_compare(a, b):
    """Constant-time string comparison"""
    return hmac.compare_digest(a, b)

def insecure_compare(a, b):
    """Vulnerable to timing attacks"""
    if len(a) != len(b):
        return False

    for i in range(len(a)):
        if a[i] != b[i]:  # Early exit leaks timing
            return False
    return True

# Always use secure_compare for cryptographic comparisons!
```

</div>

</div>

---
layout: section
---

# Practical Tasks

---
layout: default
---

# Task 1: Complete AES Implementation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Requirements
Create a complete AES encryption system:

1. **Key derivation** from passwords using PBKDF2
2. **Multiple modes** - CBC, CTR, GCM
3. **Proper padding** - PKCS#7 implementation
4. **File encryption** - Handle large files efficiently
5. **Error handling** - Robust error management

## Features to Implement
- **Password-based encryption**
- **Salt generation and storage**
- **IV generation and management**
- **Integrity verification** (for GCM mode)
- **Performance measurement**

</div>

<div>

## Implementation Framework
```python
class AdvancedAES:
    def __init__(self, password=None, key=None):
        if password:
            self.key = self._derive_key_from_password(password)
        elif key:
            self.key = key
        else:
            self.key = os.urandom(32)  # Generate random key

    def encrypt_cbc(self, plaintext):
        # Implement CBC mode encryption
        pass

    def decrypt_cbc(self, ciphertext):
        # Implement CBC mode decryption
        pass

    def encrypt_ctr(self, plaintext):
        # Implement CTR mode encryption
        pass

    def decrypt_ctr(self, ciphertext):
        # Implement CTR mode decryption
        pass

    def encrypt_gcm(self, plaintext, aad=b''):
        # Implement GCM mode encryption
        pass

    def decrypt_gcm(self, ciphertext, tag, aad=b''):
        # Implement GCM mode decryption
        pass

    def encrypt_file(self, input_file, output_file, mode='gcm'):
        # Implement file encryption
        pass

    def decrypt_file(self, input_file, output_file, mode='gcm'):
        # Implement file decryption
        pass
```

</div>

</div>

---
layout: default
---

# Task 2: Mode Comparison Tool

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Requirements
Build a tool to compare block cipher modes:

1. **Performance testing** - Measure speed of different modes
2. **Security analysis** - Demonstrate ECB vulnerabilities
3. **Pattern detection** - Show pattern leakage in ECB
4. **Visual comparison** - Create charts/graphs
5. **Report generation** - Comprehensive analysis

## Test Cases
- **Different data sizes** - 1KB to 100MB
- **Different patterns** - Repeated blocks, images
- **Performance metrics** - Throughput, latency
- **Security metrics** - Pattern detection, entropy

</div>

<div>

## Analysis Framework
```python
class ModeAnalyzer:
    def __init__(self):
        self.key = os.urandom(32)
        self.test_data_sizes = [1024, 10240, 102400, 1048576]

    def performance_test(self, mode, data_size):
        """Test encryption/decryption performance"""
        test_data = os.urandom(data_size)

        # Measure encryption time
        start_time = time.time()
        encrypted = self.encrypt_with_mode(test_data, mode)
        encryption_time = time.time() - start_time

        # Measure decryption time
        start_time = time.time()
        decrypted = self.decrypt_with_mode(encrypted, mode)
        decryption_time = time.time() - start_time

        return {
            'data_size': data_size,
            'encryption_time': encryption_time,
            'decryption_time': decryption_time,
            'throughput': data_size / encryption_time / (1024*1024)
        }

    def pattern_analysis(self, mode):
        """Analyze pattern leakage"""
        # Create data with repeating patterns
        pattern = b"REPEATING_BLOCK_"  # 16 bytes
        test_data = pattern * 100  # Repeat 100 times

        encrypted = self.encrypt_with_mode(test_data, mode)

        # Count unique blocks
        blocks = [encrypted[i:i+16] for i in range(0, len(encrypted), 16)]
        unique_blocks = len(set(blocks))
        total_blocks = len(blocks)

        return {
            'mode': mode,
            'total_blocks': total_blocks,
            'unique_blocks': unique_blocks,
            'pattern_leakage': (total_blocks - unique_blocks) / total_blocks
        }
```

</div>

</div>

---
layout: default
---

# Task 3: Secure Database System

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Requirements
Create a secure database with encrypted columns:

1. **Field-level encryption** - Encrypt sensitive columns
2. **Searchable encryption** - Support some queries on encrypted data
3. **Key management** - Secure key storage and rotation
4. **Audit logging** - Track all encryption/decryption operations
5. **Performance optimization** - Efficient encryption/decryption

## Features
- **Multiple encryption keys** for different data types
- **Encrypted indexes** for search functionality
- **Backup encryption** - Secure database backups
- **User access control** - Role-based encryption access

</div>

<div>

## Database Schema
```python
class SecureDatabase:
    def __init__(self, db_path, master_key):
        self.conn = sqlite3.connect(db_path)
        self.crypto = self._setup_encryption(master_key)
        self.audit_log = AuditLogger()
        self.setup_schema()

    def setup_schema(self):
        """Create tables with encrypted fields"""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email_encrypted BLOB,
                ssn_encrypted BLOB,
                phone_encrypted BLOB,
                address_encrypted BLOB,
                credit_score_encrypted BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                encryption_version INTEGER DEFAULT 1
            )
        ''')

        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS encryption_keys (
                key_id INTEGER PRIMARY KEY,
                key_purpose TEXT NOT NULL,
                key_data_encrypted BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                retired_at TIMESTAMP NULL
            )
        ''')

    def add_customer(self, name, email, ssn, phone, address, credit_score):
        """Add customer with encrypted PII"""
        # Encrypt sensitive fields
        encrypted_data = {
            'email': self.encrypt_field(email, 'email'),
            'ssn': self.encrypt_field(ssn, 'ssn'),
            'phone': self.encrypt_field(phone, 'phone'),
            'address': self.encrypt_field(address, 'address'),
            'credit_score': self.encrypt_field(str(credit_score), 'financial')
        }

        # Log the operation
        self.audit_log.log_encryption('customer_add',
                                    ['email', 'ssn', 'phone', 'address', 'credit_score'])

        # Insert into database
        self.conn.execute('''
            INSERT INTO customers
            (name, email_encrypted, ssn_encrypted, phone_encrypted,
             address_encrypted, credit_score_encrypted)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, encrypted_data['email'], encrypted_data['ssn'],
              encrypted_data['phone'], encrypted_data['address'],
              encrypted_data['credit_score']))

        self.conn.commit()
```

</div>

</div>

---
layout: default
---

# Task 4: Performance Benchmarking

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Requirements
Create comprehensive performance benchmarking:

1. **Algorithm comparison** - AES vs ChaCha20 vs others
2. **Mode comparison** - CBC vs CTR vs GCM
3. **Key size impact** - 128 vs 192 vs 256 bits
4. **Hardware utilization** - CPU vs hardware acceleration
5. **Memory usage** - RAM consumption analysis

## Metrics to Measure
- **Throughput** - MB/s for encryption/decryption
- **Latency** - Time per operation
- **CPU usage** - Processor utilization
- **Memory usage** - RAM consumption
- **Scalability** - Performance with data size

</div>

<div>

## Benchmark Framework
```python
import psutil
import matplotlib.pyplot as plt
from contextlib import contextmanager

class CryptoBenchmark:
    def __init__(self):
        self.results = {}
        self.data_sizes = [1024, 10*1024, 100*1024, 1024*1024, 10*1024*1024]

    @contextmanager
    def measure_resources(self):
        """Context manager to measure CPU and memory"""
        process = psutil.Process()

        # Initial measurements
        cpu_before = process.cpu_percent()
        memory_before = process.memory_info().rss

        start_time = time.perf_counter()

        yield

        end_time = time.perf_counter()

        # Final measurements
        cpu_after = process.cpu_percent()
        memory_after = process.memory_info().rss

        return {
            'execution_time': end_time - start_time,
            'cpu_usage': cpu_after - cpu_before,
            'memory_delta': memory_after - memory_before
        }

    def benchmark_algorithm(self, algorithm_class, key_size, mode, data_size):
        """Benchmark specific algorithm configuration"""
        test_data = os.urandom(data_size)
        key = os.urandom(key_size // 8)

        algorithm = algorithm_class(key, mode)

        with self.measure_resources() as metrics:
            # Encryption benchmark
            encrypted = algorithm.encrypt(test_data)

            # Decryption benchmark
            decrypted = algorithm.decrypt(encrypted)

        throughput = data_size / metrics['execution_time'] / (1024 * 1024)

        return {
            'algorithm': algorithm_class.__name__,
            'key_size': key_size,
            'mode': mode,
            'data_size': data_size,
            'throughput_mbps': throughput,
            'cpu_usage': metrics['cpu_usage'],
            'memory_delta': metrics['memory_delta']
        }

    def generate_report(self):
        """Generate comprehensive benchmark report"""
        # Create visualizations
        self.plot_throughput_comparison()
        self.plot_cpu_usage()
        self.plot_memory_usage()

        # Generate summary statistics
        return self.calculate_summary_stats()
```

</div>

</div>

---
layout: default
---

# Best Practices Summary

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Algorithm Selection
<v-clicks>

- **Use AES-256** for most applications
- **Choose GCM mode** for authenticated encryption
- **Consider ChaCha20** for software-only implementations
- **Avoid deprecated** algorithms (DES, 3DES, RC4)

</v-clicks>

## Key Management
<v-clicks>

- **Generate keys** using cryptographically secure random
- **Use key derivation** (PBKDF2, Argon2) for passwords
- **Store keys securely** (HSM, key vaults)
- **Rotate keys** regularly
- **Use different keys** for different purposes

</v-clicks>

</div>

<div>

## Implementation Guidelines
<v-clicks>

- **Use established libraries** - Don't implement crypto yourself
- **Generate random IVs** for each encryption
- **Implement proper error handling**
- **Clear sensitive data** from memory
- **Use constant-time operations** when possible

</v-clicks>

## Security Checklist
<v-clicks>

- **✅ Never use ECB mode**
- **✅ Always use random IVs**
- **✅ Implement proper padding**
- **✅ Use authenticated encryption**
- **✅ Validate all inputs**
- **✅ Test thoroughly**
- **✅ Keep libraries updated**

</v-clicks>

</div>

</div>

---
layout: end
---

# Questions?

<div class="pt-6">
  <span class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Let's discuss block ciphers! 💬
  </span>
</div>

<div class="mt-4 text-sm text-gray-600">
<p><strong>Next Week:</strong> We'll explore hash functions and data integrity verification!</p>
<p><strong>Assignment:</strong> Implement a complete block cipher system with multiple modes and analyze their security properties!</p>
</div>