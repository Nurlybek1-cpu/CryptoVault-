---
theme: default
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Kasiski Method Deep Dive
  MAT364 - Cryptography Course
drawings:
  persist: false
transition: slide-left
title: Kasiski Method Deep Dive
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

/* Animation styles */
.highlight {
  background-color: #fef3c7;
  padding: 2px 4px;
  border-radius: 3px;
  transition: all 0.3s ease;
}

.pattern-highlight {
  background-color: #dbeafe;
  padding: 2px 4px;
  border-radius: 3px;
  font-weight: bold;
}

.distance-highlight {
  background-color: #fce7f3;
  padding: 2px 4px;
  border-radius: 3px;
  font-weight: bold;
}

.gcd-highlight {
  background-color: #dcfce7;
  padding: 2px 4px;
  border-radius: 3px;
  font-weight: bold;
}

.step-number {
  background-color: #3b82f6;
  color: white;
  border-radius: 50%;
  width: 30px;
  height: 30px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-weight: bold;
  margin-right: 10px;
}
</style>

# Kasiski Method Deep Dive
## Breaking the Vigenère Cipher

**Instructor:** Adil Akhmetov  
**University:** SDU  
**Course:** MAT364 - Cryptography

<div class="pt-6">
  <span @click="$slidev.nav.next" class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Press Space for next page →
  </span>
</div>

<!-- Animation: Title entrance -->
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 30, scale: 0.9 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 1000, type: 'spring' } }">
</div>

---
layout: default
---

# Historical Context

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, x: -50, rotateY: -15 }"
     :enter="{ opacity: 1, x: 0, rotateY: 0, transition: { duration: 800, delay: 200 } }">

## The Vigenère Cipher
- **Invented:** 1553 by Giovan Battista Bellaso
- **Popularized:** 1586 by Blaise de Vigenère
- **Considered unbreakable** for 300+ years
- **Used by:** Military, diplomats, spies

## Why It Was "Unbreakable"
- **Multiple alphabets** - not just one substitution
- **Key-dependent** - different shifts for each position
- **Breaks frequency analysis** - same letter maps to different ciphertext
- **Large key space** - 26^k possible keys

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, x: 50, rotateY: 15 }"
     :enter="{ opacity: 1, x: 0, rotateY: 0, transition: { duration: 800, delay: 400 } }">

## Friedrich Kasiski (1805-1881)
- **Prussian officer** and cryptanalyst
- **Published method** in 1863
- **First systematic attack** on Vigenère cipher
- **Revolutionary breakthrough** in cryptanalysis

## The Breakthrough
- **Pattern recognition** in repeated sequences
- **Mathematical analysis** of distances
- **Key length estimation** using GCD
- **Foundation** for modern cryptanalysis

</div>

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20, scale: 0.95 }"
     :enter="{ opacity: 1, y: 0, scale: 1, transition: { duration: 600, delay: 600, type: 'spring' } }"
     class="mt-4 p-3 bg-blue-100 rounded-lg text-sm">
<strong>Historical Impact:</strong> Kasiski's method ended the era of "unbreakable" Vigenère cipher and revolutionized cryptanalysis!
</div>

---
layout: default
---

# The Core Insight

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Why Patterns Repeat
**Key insight:** When the same plaintext pattern appears at positions where the keyword repeats, it produces the same ciphertext pattern.

**Example:**
- Plaintext: "THE" appears at positions 0 and 6
- Keyword: "KEY" (length 3)
- At position 0: T + K, H + E, E + Y
- At position 6: T + K, H + E, E + Y (same!)

</div>

<div>

## Mathematical Foundation
**Distance between repetitions:**
- If pattern repeats at positions i and j
- Distance = j - i
- If keyword length divides this distance
- Same keyword letters are used
- Same ciphertext pattern results

**Key length estimation:**
- Find all distances between repetitions
- Calculate GCD of all distances
- GCD is likely the keyword length

</div>

</div>

<div class="mt-4 p-3 bg-yellow-100 rounded-lg text-sm">
<strong>Key Insight:</strong> Repeated patterns in ciphertext reveal the keyword length through mathematical analysis of distances!
</div>

---
layout: default
---

# Step-by-Step Process

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, x: -50 }"
     :enter="{ opacity: 1, x: 0, transition: { duration: 600, delay: 200 } }">

## <span class="step-number">1</span>Find Repeated Patterns
1. **Scan ciphertext** for repeated sequences
2. **Minimum length** of 3 characters
3. **Record positions** of each occurrence
4. **Ignore single occurrences**

## <span class="step-number">2</span>Calculate Distances
1. **For each pattern** with multiple occurrences
2. **Calculate distances** between all pairs
3. **Record all distances** found
4. **Note frequency** of each distance

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, x: 50 }"
     :enter="{ opacity: 1, x: 0, transition: { duration: 600, delay: 400 } }">

## <span class="step-number">3</span>Find GCD
1. **List all distances** found
2. **Calculate GCD** of all distances
3. **Consider common factors** of distances
4. **Estimate keyword length**

## <span class="step-number">4</span>Verify and Refine
1. **Test estimated length** by grouping letters
2. **Apply frequency analysis** to each group
3. **Refine estimate** if needed
4. **Proceed to key recovery**

</div>

</div>

---
layout: default
---

# Detailed Example Walkthrough

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Given Information
**Ciphertext:** "WICVQRXWICVQRXWICVQRX"  
**Plaintext:** "ATTACKATDAWN"  
**Keyword:** "BATTLE" (length 6)

## Step 1: Find Patterns
Looking for repeated sequences of length 3+:

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, scale: 0.9 }"
     :enter="{ opacity: 1, scale: 1, transition: { duration: 500, delay: 200 } }">

**Pattern "WIC":**
- Position 0: <span class="pattern-highlight">WIC</span>
- Position 7: <span class="pattern-highlight">WIC</span>  
- Position 14: <span class="pattern-highlight">WIC</span>

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, scale: 0.9 }"
     :enter="{ opacity: 1, scale: 1, transition: { duration: 500, delay: 400 } }">

**Pattern "VQR":**
- Position 3: <span class="pattern-highlight">VQR</span>
- Position 10: <span class="pattern-highlight">VQR</span>
- Position 17: <span class="pattern-highlight">VQR</span>

</div>

</div>

<div>

## Step 2: Calculate Distances
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600, delay: 200 } }">

**For pattern "WIC":**
- Distance 1: 7 - 0 = <span class="distance-highlight">7</span>
- Distance 2: 14 - 7 = <span class="distance-highlight">7</span>
- Distance 3: 14 - 0 = <span class="distance-highlight">14</span>

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, y: 20 }"
     :enter="{ opacity: 1, y: 0, transition: { duration: 600, delay: 400 } }">

**For pattern "VQR":**
- Distance 1: 10 - 3 = <span class="distance-highlight">7</span>
- Distance 2: 17 - 10 = <span class="distance-highlight">7</span>
- Distance 3: 17 - 3 = <span class="distance-highlight">14</span>

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, scale: 1.1 }"
     :enter="{ opacity: 1, scale: 1, transition: { duration: 500, delay: 600 } }">

**All distances:** [<span class="distance-highlight">7</span>, <span class="distance-highlight">7</span>, <span class="distance-highlight">14</span>, <span class="distance-highlight">7</span>, <span class="distance-highlight">7</span>, <span class="distance-highlight">14</span>]

</div>

</div>

</div>

---
layout: default
---

# GCD Calculation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Finding the GCD
<div v-motion-slide-visible-once
     :initial="{ opacity: 0, scale: 0.9 }"
     :enter="{ opacity: 1, scale: 1, transition: { duration: 500, delay: 200 } }">

**Distances found:** [7, 7, 14, 7, 7, 14]

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, x: -20 }"
     :enter="{ opacity: 1, x: 0, transition: { duration: 600, delay: 400 } }">

**GCD calculation:**
- GCD(7, 7) = <span class="gcd-highlight">7</span>
- GCD(7, 14) = <span class="gcd-highlight">7</span>
- GCD(7, 7) = <span class="gcd-highlight">7</span>
- GCD(7, 14) = <span class="gcd-highlight">7</span>
- GCD(7, 7) = <span class="gcd-highlight">7</span>

</div>

<div v-motion-slide-visible-once
     :initial="{ opacity: 0, scale: 1.2, y: 20 }"
     :enter="{ opacity: 1, scale: 1, y: 0, transition: { duration: 700, delay: 600, type: 'spring' } }">

**Result:** GCD = <span class="gcd-highlight" style="font-size: 1.2em; font-weight: bold;">7</span>

</div>

## Verification
**Keyword length:** 6 (actual)  
**Estimated length:** 7 (from GCD)

**Why the difference?**
- Some distances are multiples of the actual key length
- 14 = 2 × 7, but 7 is close to 6
- Need to consider common factors

</div>

<div>

## Refined Analysis
**Common factors of distances:**
- 7: appears 4 times
- 14: appears 2 times
- 2: factor of 14
- 1: factor of all

**Most likely candidates:**
- 7 (most frequent)
- 2 (factor of 14)
- 1 (too small)

**Best estimate:** 7 (closest to actual 6)

</div>

</div>

---
layout: default
---

# Python Implementation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Basic Kasiski Method
```python
import math
from collections import defaultdict

def kasiski_method(ciphertext, min_pattern_length=3):
    """Estimate keyword length using Kasiski method"""
    
    # Step 1: Find repeated patterns
    patterns = defaultdict(list)
    
    for i in range(len(ciphertext) - min_pattern_length + 1):
        pattern = ciphertext[i:i + min_pattern_length]
        patterns[pattern].append(i)
    
    # Filter patterns with multiple occurrences
    repeated_patterns = {p: pos for p, pos in patterns.items() 
                        if len(pos) > 1}
    
    print("Repeated patterns found:")
    for pattern, positions in repeated_patterns.items():
        print(f"'{pattern}': positions {positions}")
    
    return repeated_patterns
```

</div>

<div>

## Distance Calculation
```python
def calculate_distances(repeated_patterns):
    """Calculate distances between pattern occurrences"""
    all_distances = []
    
    for pattern, positions in repeated_patterns.items():
        print(f"\nPattern '{pattern}':")
        
        # Calculate all pairwise distances
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                distance = positions[j] - positions[i]
                all_distances.append(distance)
                print(f"  Distance: {positions[j]} - {positions[i]} = {distance}")
    
    return all_distances

def find_gcd(distances):
    """Find GCD of all distances"""
    if not distances:
        return 1
    
    result = distances[0]
    for distance in distances[1:]:
        result = math.gcd(result, distance)
    
    return result
```

</div>

</div>

---
layout: default
---

# Complete Implementation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Full Kasiski Analysis
```python
def complete_kasiski_analysis(ciphertext, min_pattern_length=3):
    """Complete Kasiski analysis with detailed output"""
    
    print("=== KASISKI METHOD ANALYSIS ===")
    print(f"Ciphertext: {ciphertext}")
    print(f"Length: {len(ciphertext)}")
    print()
    
    # Step 1: Find repeated patterns
    patterns = kasiski_method(ciphertext, min_pattern_length)
    
    if not patterns:
        print("No repeated patterns found!")
        return None
    
    # Step 2: Calculate distances
    distances = calculate_distances(patterns)
    
    print(f"\nAll distances: {distances}")
    
    # Step 3: Find GCD
    gcd_result = find_gcd(distances)
    print(f"\nGCD of all distances: {gcd_result}")
    
    # Step 4: Analyze common factors
    factor_counts = defaultdict(int)
    for distance in distances:
        for factor in range(1, distance + 1):
            if distance % factor == 0:
                factor_counts[factor] += 1
    
    print("\nFactor analysis:")
    for factor, count in sorted(factor_counts.items(), 
                               key=lambda x: x[1], reverse=True):
        print(f"  Factor {factor}: appears {count} times")
    
    return gcd_result
```

</div>

<div>

## Usage Example
```python
# Example usage
ciphertext = "WICVQRXWICVQRXWICVQRX"
estimated_length = complete_kasiski_analysis(ciphertext)

print(f"\n=== RESULT ===")
print(f"Estimated keyword length: {estimated_length}")

# Test with different minimum pattern lengths
for min_len in [2, 3, 4, 5]:
    print(f"\n--- Testing with min pattern length {min_len} ---")
    result = complete_kasiski_analysis(ciphertext, min_len)
    if result:
        print(f"Estimated length: {result}")
```

</div>

</div>

---
layout: default
---

# Advanced Analysis

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Statistical Refinement
```python
def statistical_kasiski(ciphertext, min_pattern_length=3):
    """Enhanced Kasiski with statistical analysis"""
    
    patterns = kasiski_method(ciphertext, min_pattern_length)
    distances = calculate_distances(patterns)
    
    if not distances:
        return None
    
    # Statistical analysis
    from collections import Counter
    distance_counts = Counter(distances)
    
    print("Distance frequency analysis:")
    for distance, count in distance_counts.most_common():
        print(f"  Distance {distance}: {count} occurrences")
    
    # Find most common factors
    factor_scores = defaultdict(int)
    for distance, count in distance_counts.items():
        for factor in range(1, distance + 1):
            if distance % factor == 0:
                factor_scores[factor] += count
    
    # Return factor with highest score
    best_factor = max(factor_scores.items(), key=lambda x: x[1])
    print(f"\nBest factor: {best_factor[0]} (score: {best_factor[1]})")
    
    return best_factor[0]
```

</div>

<div>

## Multiple Pattern Lengths
```python
def multi_length_kasiski(ciphertext):
    """Test multiple pattern lengths for better accuracy"""
    
    results = {}
    
    for min_len in range(2, min(8, len(ciphertext) // 2)):
        print(f"\n=== Testing pattern length {min_len} ===")
        result = statistical_kasiski(ciphertext, min_len)
        if result:
            results[min_len] = result
    
    # Find consensus
    if results:
        length_counts = Counter(results.values())
        consensus_length = length_counts.most_common(1)[0][0]
        
        print(f"\n=== CONSENSUS RESULT ===")
        print(f"Most common estimated length: {consensus_length}")
        print(f"Confidence: {length_counts[consensus_length]}/{len(results)} tests")
        
        return consensus_length
    
    return None
```

</div>

</div>

---
layout: default
---

# Visualization of the Method

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Pattern Visualization
```
Ciphertext: WICVQRXWICVQRXWICVQRX
Position:   0123456789012345678901

Pattern "WIC":
  Position 0:  WIC
  Position 7:      WIC
  Position 14:           WIC
  Distances: 7, 7, 14

Pattern "VQR":
  Position 3:    VQR
  Position 10:        VQR
  Position 17:             VQR
  Distances: 7, 7, 14
```

</div>

<div>

## Distance Analysis
```
All distances: [7, 7, 14, 7, 7, 14]

Factor analysis:
  Factor 1: appears 6 times
  Factor 7: appears 6 times
  Factor 2: appears 2 times
  Factor 14: appears 2 times

GCD calculation:
  GCD(7, 7) = 7
  GCD(7, 14) = 7
  GCD(7, 7) = 7
  GCD(7, 14) = 7
  GCD(7, 7) = 7

Result: 7
```

</div>

</div>

---
layout: default
---

# Limitations and Improvements

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Limitations
**Short ciphertext:**
- **Insufficient patterns** for reliable analysis
- **Random coincidences** may mislead
- **Need longer text** for accuracy

**Short keywords:**
- **Fewer repetitions** expected
- **Harder to detect** patterns
- **Less reliable** estimates

**Noisy data:**
- **Transmission errors** can break patterns
- **Character substitutions** affect analysis
- **Need error correction**

</div>

<div>

## Improvements
**Friedman's Index of Coincidence:**
- **Statistical measure** of pattern repetition
- **More reliable** than simple pattern matching
- **Works better** with shorter texts

**Modern enhancements:**
- **Machine learning** approaches
- **Probabilistic analysis** of patterns
- **Combined methods** for better accuracy

**Practical considerations:**
- **Multiple tests** with different parameters
- **Cross-validation** with other methods
- **Human verification** of results

</div>

</div>

---
layout: default
---

# Practical Application

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Real-World Example
**Ciphertext:** "QPWKA LVRXC QZIKR VWRKA TTTZT ZDOKR XHIXA VFOCL QFZFC RHG"

**Analysis:**
1. **Find patterns** of length 3+
2. **Calculate distances** between repetitions
3. **Find GCD** of all distances
4. **Estimate keyword length**

**Expected result:** Keyword length around 6-8

</div>

<div>

## Complete Workflow
```python
def break_vigenere(ciphertext):
    """Complete Vigenère breaking workflow"""
    
    # Step 1: Estimate keyword length
    key_length = multi_length_kasiski(ciphertext)
    print(f"Estimated keyword length: {key_length}")
    
    # Step 2: Group letters by position
    groups = [[] for _ in range(key_length)]
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            groups[i % key_length].append(char)
    
    # Step 3: Apply frequency analysis to each group
    for i, group in enumerate(groups):
        print(f"Group {i}: {''.join(group)}")
        # Apply frequency analysis here
    
    return key_length
```

</div>

</div>

---
layout: default
---

# Mathematical Foundation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Probability Theory
**Expected repetitions:**
- **Probability** of pattern repetition
- **Depends on** pattern length and text length
- **Higher probability** for longer patterns
- **Lower probability** for shorter patterns

**Statistical significance:**
- **Chi-square test** for pattern significance
- **Z-score** for distance analysis
- **Confidence intervals** for estimates

</div>

<div>

## Information Theory
**Entropy analysis:**
- **Measure randomness** in ciphertext
- **Compare with** expected entropy
- **Identify patterns** that reduce entropy
- **Quantify information** gained

**Mutual information:**
- **Measure dependence** between positions
- **Identify key length** through dependencies
- **More robust** than simple GCD

</div>

</div>

---
layout: default
---

# Modern Extensions

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Machine Learning Approaches
**Neural networks:**
- **Learn patterns** automatically
- **Handle noise** better than traditional methods
- **Adapt to** different cipher types
- **Improve accuracy** with training

**Deep learning:**
- **CNN for** pattern recognition
- **RNN for** sequence analysis
- **Transformer** for attention-based analysis
- **State-of-the-art** performance

</div>

<div>

## Quantum Cryptanalysis
**Quantum algorithms:**
- **Grover's algorithm** for key search
- **Quantum Fourier transform** for pattern analysis
- **Quantum machine learning** for cryptanalysis
- **Future-proof** methods

**Hybrid approaches:**
- **Classical preprocessing** + quantum analysis
- **Quantum pattern recognition**
- **Quantum statistical analysis**
- **Next-generation** cryptanalysis

</div>

</div>

---
layout: default
---

# Hands-On Exercise

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Exercise: Break This Cipher
**Ciphertext:** "QPWKA LVRXC QZIKR VWRKA TTTZT ZDOKR XHIXA VFOCL QFZFC RHG"

**Tasks:**
1. **Implement** Kasiski method
2. **Find repeated patterns** of length 3+
3. **Calculate distances** between repetitions
4. **Estimate keyword length** using GCD
5. **Verify** with frequency analysis

</div>

<div>

## Solution Steps
```python
# Step 1: Clean and prepare ciphertext
ciphertext = "QPWKA LVRXC QZIKR VWRKA TTTZT ZDOKR XHIXA VFOCL QFZFC RHG"
clean_text = ciphertext.replace(" ", "")

# Step 2: Apply Kasiski method
key_length = complete_kasiski_analysis(clean_text)

# Step 3: Group by estimated key length
groups = [[] for _ in range(key_length)]
for i, char in enumerate(clean_text):
    groups[i % key_length].append(char)

# Step 4: Analyze each group
for i, group in enumerate(groups):
    print(f"Group {i}: {''.join(group)}")
    # Apply frequency analysis to find key letter
```

</div>

</div>

---
layout: default
---

# Common Pitfalls

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Implementation Errors
**❌ Insufficient pattern length:**
- Using patterns too short (1-2 characters)
- High chance of random coincidences
- **Solution:** Use patterns of length 3+

**❌ Ignoring factor analysis:**
- Only using GCD without considering factors
- Missing better estimates
- **Solution:** Analyze all factors and their frequencies

</div>

<div>

## Analysis Mistakes
**❌ Single test reliance:**
- Using only one pattern length
- Not cross-validating results
- **Solution:** Test multiple pattern lengths

**❌ Ignoring statistical significance:**
- Not considering probability of random patterns
- **Solution:** Use statistical tests for significance

</div>

</div>

---
layout: default
---

# Best Practices

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Implementation Tips
**✅ Use multiple pattern lengths:**
- Test patterns of length 2, 3, 4, 5+
- Find consensus among results
- Increase confidence in estimate

**✅ Statistical validation:**
- Use chi-square tests for significance
- Calculate confidence intervals
- Verify with other methods

</div>

<div>

## Analysis Guidelines
**✅ Cross-validation:**
- Compare with Friedman's method
- Use frequency analysis to verify
- Test with known examples

**✅ Error handling:**
- Handle cases with no patterns
- Provide fallback methods
- Give confidence measures

</div>

</div>

---
layout: end
---

# Questions?

<div class="pt-6">
  <span class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Let's discuss the Kasiski method! 💬
  </span>
</div>

<div class="mt-4 text-sm text-gray-600">
<p><strong>Key Takeaway:</strong> The Kasiski method is a brilliant example of how mathematical analysis can break seemingly unbreakable ciphers!</p>
<p><strong>Next Steps:</strong> Practice implementing the method and try it on various Vigenère ciphers!</p>
</div>
