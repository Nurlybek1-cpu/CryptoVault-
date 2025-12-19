---
theme: default
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Lecture 3: Cryptanalysis and Attacks
  MAT364 - Cryptography Course
drawings:
  persist: false
transition: slide-left
title: Cryptanalysis and Attacks
css: unocss
---

<style>
.slidev-layout {
  font-size: 0.9rem;
}

.slidev-layout h1 {
  font-size: 2.2rem;
  margin-bottom: 1rem;
}

.slidev-layout h2 {
  font-size: 1.6rem;
  margin-bottom: 0.8rem;
}

.slidev-layout h3 {
  font-size: 1.3rem;
  margin-bottom: 0.6rem;
}

.slidev-layout pre {
  font-size: 0.75rem;
  max-height: 20rem;
  overflow-y: auto;
}

.slidev-layout code {
  font-size: 0.8rem;
}

.slidev-layout .grid {
  max-height: 85vh;
  overflow-y: auto;
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

@media (max-width: 768px) {
  .slidev-layout {
    font-size: 0.8rem;
  }
  
  .slidev-layout h1 {
    font-size: 1.8rem;
  }
  
  .slidev-layout h2 {
    font-size: 1.4rem;
  }
  
  .slidev-layout h3 {
    font-size: 1.2rem;
  }
  
  .slidev-layout pre {
    font-size: 0.7rem;
    max-height: 15rem;
  }
}
</style>

# Cryptanalysis and Attacks
## MAT364 - Cryptography Course

**Instructor:** Adil Akhmetov  
**University:** SDU  
**Week 3**

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

# What is Cryptanalysis?

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, x: -50, rotateY: -10 }"
     :enter="{ opacity: 1, x: 0, rotateY: 0, transition: { duration: 800, delay: 200, type: 'spring' } }">

## Definition
**Cryptanalysis** is the art and science of breaking cryptographic systems without knowing the secret key.

## Goals
- **Recover plaintext** from ciphertext
- **Determine the key** used for encryption
- **Find weaknesses** in cryptographic algorithms
- **Understand security** of cryptographic systems

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, x: 50, rotateY: 10 }"
     :enter="{ opacity: 1, x: 0, rotateY: 0, transition: { duration: 800, delay: 400, type: 'spring' } }">

## Types of Attacks
- **Ciphertext-only** - Only ciphertext available
- **Known-plaintext** - Some plaintext-ciphertext pairs known
- **Chosen-plaintext** - Attacker can choose plaintext
- **Chosen-ciphertext** - Attacker can choose ciphertext

## Attack Complexity
- **Computational complexity** - Time and space required
- **Data complexity** - Amount of data needed
- **Success probability** - Likelihood of success

</div>

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20, scale: 0.9 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 600, delay: 600, type: 'spring' } }"
     class="mt-4 p-3 bg-blue-100 rounded-lg text-sm">
<strong>Remember:</strong> Cryptanalysis helps us understand security weaknesses and improve cryptographic systems!
</div>

---
layout: default
---

# Brute Force Attacks

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## How It Works
- **Try every possible key** systematically
- **Test each key** against known plaintext
- **Stop when** correct key is found
- **Time complexity:** O(2^n) where n = key length

## When It's Feasible
- **Small key spaces** (Caesar cipher: 25 keys)
- **Weak algorithms** with limited keys
- **Known plaintext** available for verification
- **Sufficient computational power**

</div>

<div>

## Implementation
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20, scale: 0.95 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 800, delay: 200 } }">

```python
def brute_force_caesar(ciphertext, known_plaintext):
    """Brute force Caesar cipher"""
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        if known_plaintext.lower() in decrypted.lower():
            return shift, decrypted
    return None, None

def caesar_decrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            letter_pos = ord(char) - ascii_offset
            new_pos = (letter_pos - shift) % 26
            result += chr(new_pos + ascii_offset)
        else:
            result += char
    return result
```

</div>

</div>

</div>

---
layout: default
---

# Frequency Analysis

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## English Letter Frequencies
**Most common letters:**
- E: 12.7%, T: 9.1%, A: 8.2%, O: 7.5%
- I: 7.0%, N: 6.7%, S: 6.3%, H: 6.1%
- R: 6.0%, D: 4.3%, L: 4.0%, C: 2.8%

**Least common letters:**
- J: 0.2%, X: 0.2%, Q: 0.1%, Z: 0.1%

## Method
1. **Count frequencies** in ciphertext
2. **Match to English** letter frequencies
3. **Use common patterns** (digraphs, trigraphs)
4. **Refine mapping** iteratively

</div>

<div>

## Implementation
```python
def frequency_analysis(ciphertext):
    """Analyze letter frequencies"""
    text = ciphertext.upper().replace(' ', '')
    frequencies = {}
    total_chars = len(text)
    
    for char in text:
        if char.isalpha():
            frequencies[char] = frequencies.get(char, 0) + 1
    
    # Convert to percentages
    for char in frequencies:
        frequencies[char] = (frequencies[char] / total_chars) * 100
    
    return dict(sorted(frequencies.items(), 
                      key=lambda x: x[1], reverse=True))

def find_most_likely_mapping(cipher_freq, english_freq):
    """Find most likely letter mapping"""
    mapping = {}
    cipher_letters = list(cipher_freq.keys())
    english_letters = list(english_freq.keys())
    
    for i in range(min(len(cipher_letters), len(english_letters))):
        mapping[cipher_letters[i]] = english_letters[i]
    
    return mapping
```

</div>

</div>

---
layout: section
---

# Advanced Attack Techniques

---
layout: default
---

# Timing Attacks

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## How It Works
- **Measure execution time** of cryptographic operations
- **Correlate timing** with secret data
- **Extract information** from timing variations
- **Works on** software implementations

## Vulnerable Operations
- **String comparison** - Early exit on mismatch
- **Modular exponentiation** - Different paths for 0/1 bits
- **Table lookups** - Cache timing differences
- **Branching** - Different execution paths

</div>

<div>

## Example: String Comparison
```python
def vulnerable_compare(a, b):
    """Vulnerable string comparison"""
    if len(a) != len(b):
        return False
    
    for i in range(len(a)):
        if a[i] != b[i]:  # Early exit reveals position
            return False
    return True

def secure_compare(a, b):
    """Constant-time string comparison"""
    if len(a) != len(b):
        return False
    
    result = 0
    for i in range(len(a)):
        result |= ord(a[i]) ^ ord(b[i])
    
    return result == 0

# Timing attack example
def timing_attack(target, known_prefix):
    """Extract characters using timing"""
    for char in range(256):
        test_string = known_prefix + chr(char)
        start_time = time.time()
        vulnerable_compare(target, test_string)
        end_time = time.time()
        
        # Longer time = more matching characters
        timing = end_time - start_time
        print(f"Char {chr(char)}: {timing:.6f}s")
```

</div>

</div>

---
layout: default
---

# Side-Channel Attacks

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Types of Side Channels
**Power Analysis:**
- **Simple Power Analysis (SPA)** - Direct power consumption
- **Differential Power Analysis (DPA)** - Statistical analysis
- **Correlation Power Analysis (CPA)** - Advanced statistical methods

**Electromagnetic Analysis:**
- **EM emissions** from cryptographic operations
- **Correlate with** secret data
- **Non-invasive** attack method

</div>

<div>

## Cache Attacks
**Cache Timing:**
- **Monitor cache access** patterns
- **Extract information** from cache misses/hits
- **Works on** shared cache systems

**Implementation:**
```python
import time
import psutil

def cache_timing_attack():
    """Simple cache timing attack"""
    # Flush cache
    data = [0] * 1024 * 1024  # 1MB array
    
    # Measure access time
    start_time = time.perf_counter()
    _ = data[0]  # Should be cache hit
    end_time = time.perf_counter()
    
    hit_time = end_time - start_time
    
    # Access different memory location
    start_time = time.perf_counter()
    _ = data[512 * 1024]  # Might be cache miss
    end_time = time.perf_counter()
    
    miss_time = end_time - start_time
    
    print(f"Cache hit time: {hit_time:.9f}s")
    print(f"Cache miss time: {miss_time:.9f}s")
    print(f"Difference: {miss_time - hit_time:.9f}s")
```

</div>

</div>

---
layout: default
---

# Differential Cryptanalysis

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Basic Concept
- **Study differences** between plaintext pairs
- **Analyze how differences** propagate through cipher
- **Find patterns** that reveal key information
- **Works on** block ciphers and hash functions

## Differential Characteristics
- **Input difference** - XOR of two plaintexts
- **Output difference** - XOR of corresponding ciphertexts
- **Probability** - Likelihood of characteristic
- **Round function** - How differences propagate

</div>

<div>

## Example: Simple Block Cipher
```python
def simple_block_cipher(plaintext, key, rounds=4):
    """Simple block cipher for demonstration"""
    state = plaintext
    
    for round in range(rounds):
        # XOR with round key
        state = state ^ key[round % len(key)]
        
        # Simple substitution
        state = ((state << 1) | (state >> 7)) & 0xFF
        
        # Simple permutation
        state = ((state & 0x0F) << 4) | ((state & 0xF0) >> 4)
    
    return state

def differential_analysis():
    """Find differential characteristics"""
    # Test different input pairs
    for p1 in range(256):
        for p2 in range(256):
            if p1 != p2:
                input_diff = p1 ^ p2
                
                # Encrypt both plaintexts
                c1 = simple_block_cipher(p1, [0x12, 0x34, 0x56, 0x78])
                c2 = simple_block_cipher(p2, [0x12, 0x34, 0x56, 0x78])
                
                output_diff = c1 ^ c2
                
                # Look for interesting patterns
                if output_diff == input_diff:
                    print(f"Fixed point: {p1:02x} ^ {p2:02x} = {input_diff:02x}")
```

</div>

</div>

---
layout: section
---

# Modern Attack Vectors

---
layout: default
---

# Fault Attacks

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## How It Works
- **Introduce faults** during computation
- **Analyze faulty outputs** to extract secrets
- **Methods:** Voltage glitching, clock glitching, laser attacks
- **Targets:** Smart cards, embedded devices

## Types of Faults
- **Single-bit faults** - Flip one bit
- **Multi-bit faults** - Flip multiple bits
- **Timing faults** - Skip operations
- **Instruction faults** - Skip instructions

</div>

<div>

## Example: RSA Fault Attack
```python
def rsa_sign(message, private_key, n, d):
    """RSA signature with potential fault"""
    m_hash = hash(message) % n
    
    # Simulate fault injection
    if fault_injection_point():
        d = d ^ 0x1000  # Flip a bit in private key
    
    signature = pow(m_hash, d, n)
    return signature

def fault_attack_rsa():
    """Extract RSA private key using fault attack"""
    # This is a simplified example
    n = 0x1234567890ABCDEF  # Public modulus
    d = 0x9876543210FEDCBA  # Private exponent
    
    # Collect faulty signatures
    faulty_signatures = []
    for i in range(100):
        sig = rsa_sign(f"message_{i}", None, n, d)
        faulty_signatures.append(sig)
    
    # Analyze faulty signatures to extract key
    # (This is a complex process in practice)
    return analyze_faults(faulty_signatures, n)
```

</div>

</div>

---
layout: default
---

# Cache Attacks

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Cache-Based Attacks
**Flush+Reload:**
- **Flush** target memory from cache
- **Trigger** cryptographic operation
- **Reload** and measure access time
- **Determine** which data was accessed

**Prime+Probe:**
- **Prime** cache with known data
- **Trigger** cryptographic operation
- **Probe** cache to see what was evicted
- **Infer** secret data from cache state

</div>

<div>

## Implementation Example
```python
import time
import mmap
import os

class CacheAttacker:
    def __init__(self, target_size=4096):
        self.target_size = target_size
        self.cache_line_size = 64
        
    def flush_cache(self, address):
        """Flush specific cache line"""
        # Use clflush instruction (simplified)
        pass
    
    def measure_access_time(self, address):
        """Measure memory access time"""
        start = time.perf_counter()
        _ = address[0]  # Access memory
        end = time.perf_counter()
        return end - start
    
    def flush_reload_attack(self, target_address):
        """Flush+Reload attack"""
        # Flush target from cache
        self.flush_cache(target_address)
        
        # Trigger cryptographic operation
        # (This would be done by the victim process)
        
        # Measure reload time
        reload_time = self.measure_access_time(target_address)
        
        # Fast reload = was in cache (accessed)
        # Slow reload = was not in cache (not accessed)
        return reload_time < 100  # Threshold for cache hit
```

</div>

</div>

---
layout: default
---

# Spectre and Meltdown

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Spectre Attack
**Speculative Execution:**
- **CPU predicts** future execution paths
- **Executes instructions** speculatively
- **Leaves traces** in cache and branch predictors
- **Attacker can read** these traces

**Variants:**
- **Spectre v1** - Bounds check bypass
- **Spectre v2** - Branch target injection
- **Spectre v4** - Speculative store bypass

</div>

<div>

## Meltdown Attack
**Memory Access:**
- **Access kernel memory** from user space
- **Speculative execution** allows access
- **Cache side effects** reveal data
- **Works on** most Intel processors

## Mitigations
**Hardware:**
- **Intel CET** - Control-flow Enforcement Technology
- **ARM Pointer Authentication**
- **AMD Shadow Stack**

**Software:**
- **KPTI** - Kernel Page Table Isolation
- **Retpoline** - Return trampoline
- **Compiler barriers** - Prevent speculation

</div>

</div>

---
layout: section
---

# Practical Attack Tools

---
layout: default
---

# Attack Frameworks

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Popular Tools
**Cryptanalysis:**
- **Cryptool** - Educational cryptanalysis
- **John the Ripper** - Password cracking
- **Hashcat** - GPU-accelerated cracking
- **Aircrack-ng** - WiFi security testing

**Side-Channel:**
- **ChipWhisperer** - Hardware security testing
- **Oscilloscope** - Power analysis
- **Logic analyzer** - Signal analysis

</div>

<div>

## Python Libraries
```python
# Cryptographic attacks
import hashlib
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Timing attacks
import time
import statistics

# Frequency analysis
from collections import Counter
import matplotlib.pyplot as plt

# Example: Password cracking
def crack_password_hash(target_hash, wordlist):
    """Simple password hash cracking"""
    for password in wordlist:
        # Try different hash algorithms
        if hashlib.md5(password.encode()).hexdigest() == target_hash:
            return password
        if hashlib.sha1(password.encode()).hexdigest() == target_hash:
            return password
        if hashlib.sha256(password.encode()).hexdigest() == target_hash:
            return password
    return None
```

</div>

</div>

---
layout: default
---

# Frequency Analysis Tool

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Complete Implementation
```python
import matplotlib.pyplot as plt
from collections import Counter
import string

class FrequencyAnalyzer:
    def __init__(self):
        self.english_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0,
            'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3,
            'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4,
            'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.3,
            'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2, 'Q': 0.1, 'Z': 0.1
        }
    
    def analyze(self, text):
        """Analyze letter frequencies in text"""
        text = text.upper().replace(' ', '')
        counter = Counter(char for char in text if char.isalpha())
        total = sum(counter.values())
        
        frequencies = {char: (count/total) * 100 
                      for char, count in counter.items()}
        
        return dict(sorted(frequencies.items(), 
                          key=lambda x: x[1], reverse=True))
    
    def plot_frequencies(self, cipher_freq, title="Letter Frequencies"):
        """Plot frequency comparison"""
        letters = list(string.ascii_uppercase)
        cipher_values = [cipher_freq.get(letter, 0) for letter in letters]
        english_values = [self.english_freq.get(letter, 0) for letter in letters]
        
        x = range(len(letters))
        width = 0.35
        
        plt.figure(figsize=(12, 6))
        plt.bar([i - width/2 for i in x], cipher_values, width, 
                label='Ciphertext', alpha=0.7)
        plt.bar([i + width/2 for i in x], english_values, width, 
                label='English', alpha=0.7)
        
        plt.xlabel('Letters')
        plt.ylabel('Frequency (%)')
        plt.title(title)
        plt.xticks(x, letters)
        plt.legend()
        plt.tight_layout()
        plt.show()
```

</div>

<div>

## Usage Example
```python
# Example usage
analyzer = FrequencyAnalyzer()

# Analyze ciphertext
ciphertext = "KHOOR ZRUOG"
cipher_freq = analyzer.analyze(ciphertext)

print("Ciphertext frequencies:")
for letter, freq in cipher_freq.items():
    print(f"{letter}: {freq:.2f}%")

# Plot comparison
analyzer.plot_frequencies(cipher_freq, "Caesar Cipher Analysis")

# Find most likely mapping
def find_mapping(cipher_freq, english_freq):
    mapping = {}
    cipher_letters = list(cipher_freq.keys())
    english_letters = list(english_freq.keys())
    
    for i in range(min(len(cipher_letters), len(english_letters))):
        mapping[cipher_letters[i]] = english_letters[i]
    
    return mapping

mapping = find_mapping(cipher_freq, analyzer.english_freq)
print(f"Most likely mapping: {mapping}")

# Apply mapping to decrypt
def apply_mapping(text, mapping):
    result = ""
    for char in text:
        if char.isalpha():
            result += mapping.get(char.upper(), char)
        else:
            result += char
    return result

decrypted = apply_mapping(ciphertext, mapping)
print(f"Decrypted: {decrypted}")
```

</div>

</div>

---
layout: default
---

# Timing Attack Implementation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Vulnerable Implementation
```python
import time
import random
import statistics

def vulnerable_compare(a, b):
    """Vulnerable string comparison"""
    if len(a) != len(b):
        return False
    
    for i in range(len(a)):
        if a[i] != b[i]:  # Early exit reveals position
            return False
    return True

def timing_attack(target, charset, max_length=8):
    """Extract string using timing attack"""
    known_prefix = ""
    
    for pos in range(max_length):
        best_char = None
        best_time = 0
        
        for char in charset:
            test_string = known_prefix + char
            times = []
            
            # Take multiple measurements
            for _ in range(100):
                start = time.perf_counter()
                vulnerable_compare(target, test_string)
                end = time.perf_counter()
                times.append(end - start)
            
            avg_time = statistics.mean(times)
            
            if avg_time > best_time:
                best_time = avg_time
                best_char = char
        
        if best_char:
            known_prefix += best_char
            print(f"Found character: {best_char} (time: {best_time:.9f}s)")
        else:
            break
    
    return known_prefix
```

</div>

<div>

## Secure Implementation
```python
def secure_compare(a, b):
    """Constant-time string comparison"""
    if len(a) != len(b):
        return False
    
    result = 0
    for i in range(len(a)):
        result |= ord(a[i]) ^ ord(b[i])
    
    return result == 0

def hmac_verify(message, signature, key):
    """Secure HMAC verification"""
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    return secure_compare(signature, expected)

# Example usage
def test_timing_attack():
    """Test timing attack on vulnerable implementation"""
    target = "secret"
    charset = string.ascii_lowercase + string.digits
    
    print("Testing timing attack...")
    result = timing_attack(target, charset)
    print(f"Extracted: {result}")
    print(f"Target: {target}")
    print(f"Success: {result == target}")

# Mitigation techniques
def add_random_delay():
    """Add random delay to prevent timing attacks"""
    time.sleep(random.uniform(0.001, 0.005))

def constant_time_operation():
    """Ensure constant time for all operations"""
    # Always perform same operations regardless of input
    # Use bitwise operations instead of branches
    pass
```

</div>

</div>

---
layout: section
---

# Defensive Measures

---
layout: default
---

# Countermeasures

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Against Timing Attacks
**Constant-Time Implementation:**
- **Avoid early returns** in comparisons
- **Use bitwise operations** instead of branches
- **Add random delays** to mask timing
- **Use hardware** constant-time instructions

**Code Example:**
```python
def constant_time_compare(a, b):
    """Constant-time string comparison"""
    if len(a) != len(b):
        return False
    
    result = 0
    for i in range(len(a)):
        result |= ord(a[i]) ^ ord(b[i])
    
    return result == 0
```

</div>

<div>

## Against Side-Channel Attacks
**Power Analysis Protection:**
- **Randomize** execution order
- **Add noise** to power consumption
- **Use masking** techniques
- **Implement** countermeasures in hardware

**Cache Attack Protection:**
- **Flush sensitive data** from cache
- **Use dedicated** cache lines
- **Implement** cache partitioning
- **Monitor** cache access patterns

</div>

</div>

---
layout: default
---

# Secure Programming Practices

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## General Principles
**Input Validation:**
- **Validate all inputs** before processing
- **Use whitelist** approach when possible
- **Sanitize data** before cryptographic operations
- **Implement** proper error handling

**Memory Management:**
- **Clear sensitive data** from memory
- **Use secure memory** allocation
- **Implement** memory protection
- **Avoid** memory leaks

</div>

<div>

## Cryptographic Best Practices
**Key Management:**
- **Generate keys** using secure random
- **Store keys** securely
- **Rotate keys** regularly
- **Use different keys** for different purposes

**Implementation:**
- **Use established** cryptographic libraries
- **Follow** security guidelines
- **Test thoroughly** for vulnerabilities
- **Keep libraries** updated

```python
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def secure_key_generation():
    """Generate secure cryptographic keys"""
    # Use cryptographically secure random
    key = secrets.token_bytes(32)  # 256-bit key
    
    # Derive key from password
    password = b"secure_password"
    salt = secrets.token_bytes(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    derived_key = kdf.derive(password)
    
    return key, derived_key
```

</div>

</div>

---
layout: default
---

# Practical Exercises

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Exercise 1: Frequency Analysis
**Task:** Break a monoalphabetic substitution cipher

1. **Implement** frequency analysis tool
2. **Analyze** given ciphertext
3. **Find** most likely letter mapping
4. **Decrypt** the message
5. **Verify** correctness

**Ciphertext:** "WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ"

## Exercise 2: Timing Attack
**Task:** Extract password using timing attack

1. **Implement** vulnerable password check
2. **Create** timing attack tool
3. **Extract** password character by character
4. **Implement** secure version
5. **Compare** timing differences

</div>

<div>

## Exercise 3: Side-Channel Analysis
**Task:** Analyze power consumption patterns

1. **Implement** simple cryptographic function
2. **Simulate** power consumption
3. **Analyze** patterns in power data
4. **Extract** secret information
5. **Implement** countermeasures

## Exercise 4: Differential Analysis
**Task:** Find differential characteristics

1. **Implement** simple block cipher
2. **Test** different input pairs
3. **Find** differential characteristics
4. **Analyze** probability distributions
5. **Use** characteristics for key recovery

</div>

</div>

<div class="mt-4 p-3 bg-green-100 rounded-lg text-sm">
<strong>Goal:</strong> Practice real attack techniques to understand how to defend against them!
</div>

---
layout: default
---

# Common Vulnerabilities

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Implementation Errors
**❌ Weak Random Number Generation:**
- Using `random()` instead of `secrets`
- Predictable seeds
- Insufficient entropy

**❌ Timing Vulnerabilities:**
- Early returns in comparisons
- Different execution paths
- Cache-dependent operations

**❌ Memory Issues:**
- Not clearing sensitive data
- Buffer overflows
- Memory leaks

</div>

<div>

## Design Flaws
**❌ Weak Algorithms:**
- Using deprecated algorithms
- Insufficient key lengths
- Poor key scheduling

**❌ Protocol Issues:**
- Reusing keys
- Weak authentication
- Missing integrity checks

**❌ Side-Channel Leakage:**
- Power consumption patterns
- Electromagnetic emissions
- Cache access patterns

</div>

</div>

---
layout: default
---

# Modern Attack Trends

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Emerging Threats
**AI-Powered Attacks:**
- **Machine learning** for pattern recognition
- **Automated** vulnerability discovery
- **Enhanced** side-channel analysis
- **Adaptive** attack strategies

**Quantum Computing:**
- **Shor's algorithm** breaks RSA/ECC
- **Grover's algorithm** halves key strength
- **Post-quantum** cryptography needed
- **Hybrid** classical-quantum attacks

</div>

<div>

## Defense Strategies
**AI Defense:**
- **ML-based** anomaly detection
- **Automated** vulnerability scanning
- **Intelligent** threat response
- **Adaptive** security measures

**Quantum Resistance:**
- **Lattice-based** cryptography
- **Code-based** cryptography
- **Multivariate** cryptography
- **Hash-based** signatures

</div>

</div>

<div class="mt-4 p-3 bg-purple-100 rounded-lg text-sm">
<strong>Future:</strong> Cryptanalysis is evolving with AI and quantum computing - we must stay ahead of the curve!
</div>

---
layout: end
---

# Questions?

<div class="pt-6">
  <span class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Let's discuss cryptanalysis! 💬
  </span>
</div>

<div class="mt-4 text-sm text-gray-600">
<p><strong>Next Week:</strong> We'll explore stream ciphers and learn about modern symmetric encryption!</p>
<p><strong>Assignment:</strong> Implement and test various attack techniques on classical ciphers!</p>
</div>
