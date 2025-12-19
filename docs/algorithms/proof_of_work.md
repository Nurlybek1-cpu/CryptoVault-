# Proof of Work (PoW)

## Overview

**Proof of Work (PoW)** is a consensus mechanism that requires participants to perform computational work to validate transactions and create new blocks. It's the foundation of Bitcoin's security and is used to prevent spam, double-spending, and Sybil attacks.

## Purpose

- **Consensus**: Achieve agreement in decentralized networks
- **Security**: Make attacks computationally expensive
- **Block Creation**: Rate-limit block production
- **Spam Prevention**: Require cost for actions
- **Fair Distribution**: Reward computational work

## Algorithm Specification

### Core Concept

Find a nonce such that:

```
Hash(Block_Data || Nonce) < Target
```

Where:
- **Block_Data**: Block header information
- **Nonce**: Number used once (varied to find valid hash)
- **Target**: Difficulty threshold
- **Hash**: Cryptographic hash function (SHA-256 for Bitcoin)

### Bitcoin PoW Formula

```
SHA256(SHA256(Block_Header || Nonce)) < Target

Target = 2^256 / Difficulty
```

## How Proof of Work Works

### Mining Process

**1. Prepare Block Header**
```
Block Header = {
    version: 0x20000000,
    previous_block_hash: 256-bit hash,
    merkle_root: 256-bit hash of transactions,
    timestamp: Unix timestamp,
    bits: Difficulty target (compact format),
    nonce: 0 (start value)
}
```

**2. Set Target**
```
Target = Maximum_Target / Difficulty

Bitcoin Maximum Target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
```

**3. Mining Loop**
```
nonce = 0
while True:
    hash = SHA256(SHA256(block_header + nonce))

    if hash < target:
        # Valid block found!
        return nonce, hash

    nonce += 1
```

**4. Verification**
```
Anyone can verify:
hash = SHA256(SHA256(block_header + nonce))
if hash < target:
    Valid ✓
```

## Implementation Example

### Simple Proof of Work

```python
import hashlib
import time

class ProofOfWork:
    def __init__(self, difficulty=4):
        """
        Initialize PoW with difficulty

        Args:
            difficulty: Number of leading zeros required in hash
        """
        self.difficulty = difficulty
        self.target = '0' * difficulty

    def mine(self, block_data):
        """
        Mine block by finding valid nonce

        Args:
            block_data: Block data (string or bytes)

        Returns:
            (nonce, hash, hash_count)
        """
        nonce = 0
        start_time = time.time()

        while True:
            # Create block with nonce
            data = f"{block_data}{nonce}".encode()

            # Hash the data
            block_hash = hashlib.sha256(data).hexdigest()

            # Check if valid
            if block_hash.startswith(self.target):
                elapsed = time.time() - start_time
                hashrate = nonce / elapsed if elapsed > 0 else 0

                return {
                    'nonce': nonce,
                    'hash': block_hash,
                    'attempts': nonce,
                    'time': elapsed,
                    'hashrate': hashrate
                }

            nonce += 1

# Usage Example
pow = ProofOfWork(difficulty=5)
block_data = "Block #1: Alice -> Bob: 50 BTC"

print("Mining block...")
result = pow.mine(block_data)

print(f"Block mined!")
print(f"  Nonce: {result['nonce']}")
print(f"  Hash: {result['hash']}")
print(f"  Attempts: {result['attempts']:,}")
print(f"  Time: {result['time']:.2f}s")
print(f"  Hashrate: {result['hashrate']:,.0f} H/s")
```

### Bitcoin-Style PoW

```python
import struct

class BitcoinPoW:
    def __init__(self, bits):
        """
        Bitcoin-style Proof of Work

        Args:
            bits: Difficulty in compact format (e.g., 0x1d00ffff)
        """
        self.bits = bits
        self.target = self.bits_to_target(bits)

    @staticmethod
    def bits_to_target(bits):
        """Convert compact bits to target"""
        exponent = bits >> 24
        mantissa = bits & 0xFFFFFF
        return mantissa * (256 ** (exponent - 3))

    @staticmethod
    def double_sha256(data):
        """Bitcoin's double SHA-256"""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    def mine_block(self, block_header):
        """
        Mine Bitcoin block

        Args:
            block_header: 80-byte block header (without nonce)

        Returns:
            Valid nonce
        """
        nonce = 0
        base_header = block_header[:76]  # First 76 bytes

        while nonce < 2**32:
            # Create full header with nonce
            full_header = base_header + struct.pack('<I', nonce)

            # Double SHA-256
            block_hash = self.double_sha256(full_header)
            hash_int = int.from_bytes(block_hash, 'big')

            if hash_int < self.target:
                return nonce, block_hash

            nonce += 1

        return None, None  # Failed to find nonce

    def verify_block(self, block_header, nonce):
        """Verify block hash meets target"""
        full_header = block_header[:76] + struct.pack('<I', nonce)
        block_hash = self.double_sha256(full_header)
        hash_int = int.from_bytes(block_hash, 'big')

        return hash_int < self.target

# Example
bits = 0x1d00ffff  # Bitcoin genesis block difficulty
pow = BitcoinPoW(bits)
print(f"Target: {hex(pow.target)}")
```

### Dynamic Difficulty Adjustment

```python
class DynamicPoW:
    def __init__(self, target_time=60, difficulty=4):
        """
        PoW with dynamic difficulty adjustment

        Args:
            target_time: Target seconds per block
            difficulty: Initial difficulty
        """
        self.target_time = target_time
        self.difficulty = difficulty
        self.blocks = []

    def adjust_difficulty(self):
        """Adjust difficulty based on recent block times"""
        if len(self.blocks) < 10:
            return

        # Calculate average time of last 10 blocks
        recent_blocks = self.blocks[-10:]
        avg_time = sum(b['time'] for b in recent_blocks) / len(recent_blocks)

        # Adjust difficulty
        if avg_time < self.target_time * 0.8:
            # Blocks too fast - increase difficulty
            self.difficulty += 1
            print(f"Difficulty increased to {self.difficulty}")
        elif avg_time > self.target_time * 1.2:
            # Blocks too slow - decrease difficulty
            if self.difficulty > 1:
                self.difficulty -= 1
                print(f"Difficulty decreased to {self.difficulty}")

    def mine_block(self, block_data):
        """Mine block with current difficulty"""
        pow = ProofOfWork(self.difficulty)
        result = pow.mine(block_data)

        # Record block
        self.blocks.append(result)

        # Adjust difficulty
        self.adjust_difficulty()

        return result

# Simulate blockchain mining
dynamic_pow = DynamicPoW(target_time=10, difficulty=4)

for i in range(20):
    block_data = f"Block #{i}: Transactions..."
    result = dynamic_pow.mine_block(block_data)
    print(f"Block {i}: {result['time']:.2f}s, Difficulty: {dynamic_pow.difficulty}")
```

## Difficulty Calculation

### Bitcoin Difficulty

```python
def calculate_bitcoin_difficulty(target):
    """Calculate Bitcoin difficulty from target"""
    max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    difficulty = max_target / target
    return difficulty

def target_from_difficulty(difficulty):
    """Calculate target from difficulty"""
    max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    return int(max_target / difficulty)

# Example
difficulty = 1000000  # Current difficulty
target = target_from_difficulty(difficulty)
print(f"Difficulty: {difficulty:,}")
print(f"Target: {hex(target)}")
print(f"Leading zeros: ~{256 - target.bit_length()}")
```

### Expected Number of Hashes

```
Expected Hashes = 2^256 / Target = Difficulty × 2^32

For difficulty = 1,000,000:
Expected Hashes = 1,000,000 × 2^32 ≈ 4.3 × 10^15 hashes
```

## Security Analysis

### Attack Cost

**51% Attack Cost**:
```
Cost = (Network Hashrate × Time × Electricity Cost) / 2

Bitcoin (2025):
- Network Hashrate: ~400 EH/s
- Cost per kWh: $0.05
- Power consumption: ~3.5 GW
- 1-hour attack: ~$175,000
```

### Double-Spend Protection

```python
def confirm_security(confirmations, attacker_hashrate_percent):
    """
    Calculate probability of successful double-spend

    Args:
        confirmations: Number of confirmations
        attacker_hashrate_percent: Attacker's hashrate percentage
    """
    q = attacker_hashrate_percent / 100
    p = 1 - q

    # Probability attacker catches up after k confirmations
    if q >= p:
        return 1.0  # Attacker will eventually succeed

    # Poisson distribution
    import math
    lambda_val = confirmations * (q / p)
    probability = 1 - sum(
        (lambda_val ** k) * math.exp(-lambda_val) / math.factorial(k)
        for k in range(confirmations + 1)
    )

    return probability

# Example: 6 confirmations with 10% attacker hashrate
prob = confirm_security(6, 10)
print(f"Double-spend success probability: {prob:.6%}")
```

## Real-World Applications

### Bitcoin Mining

```python
class BitcoinMiner:
    def __init__(self, miner_address, hashrate):
        """
        Simplified Bitcoin miner

        Args:
            miner_address: Bitcoin address for block reward
            hashrate: Hashes per second
        """
        self.address = miner_address
        self.hashrate = hashrate

    def create_coinbase_tx(self, block_height, reward=6.25):
        """Create coinbase transaction (block reward)"""
        return {
            'type': 'coinbase',
            'block_height': block_height,
            'reward': reward,  # BTC
            'recipient': self.address
        }

    def mine(self, pending_transactions, previous_hash, difficulty):
        """Mine new block"""
        # Add coinbase transaction
        transactions = [self.create_coinbase_tx(0)] + pending_transactions

        # Build Merkle tree
        merkle_root = build_merkle_root(transactions)

        # Create block header
        block_header = {
            'version': 0x20000000,
            'previous_hash': previous_hash,
            'merkle_root': merkle_root,
            'timestamp': int(time.time()),
            'bits': difficulty,
            'nonce': 0
        }

        # Mine block
        pow = BitcoinPoW(difficulty)
        nonce, block_hash = pow.mine_block(serialize_header(block_header))

        return {
            'header': block_header,
            'nonce': nonce,
            'hash': block_hash,
            'transactions': transactions
        }
```

### Hashcash (Email Spam Prevention)

```python
class Hashcash:
    """Hashcash PoW for email spam prevention"""

    @staticmethod
    def mint(resource, bits=20):
        """
        Mint Hashcash stamp

        Args:
            resource: Email address or resource
            bits: Difficulty (bits of zeros)
        """
        import random
        import base64

        version = 1
        date = time.strftime("%Y%m%d%H%M%S")
        counter = 0

        while True:
            stamp = f"{version}:{bits}:{date}:{resource}::{base64.b64encode(random.randbytes(8)).decode()}:{counter}"
            hash_result = hashlib.sha1(stamp.encode()).digest()

            # Check if first 'bits' bits are zero
            if int.from_bytes(hash_result, 'big') < (2 ** (160 - bits)):
                return stamp

            counter += 1

    @staticmethod
    def verify(stamp, resource, required_bits=20):
        """Verify Hashcash stamp"""
        parts = stamp.split(':')
        if len(parts) != 7:
            return False

        version, bits, date, res, ext, rand, counter = parts

        if res != resource or int(bits) < required_bits:
            return False

        hash_result = hashlib.sha1(stamp.encode()).digest()
        return int.from_bytes(hash_result, 'big') < (2 ** (160 - int(bits)))

# Example: Email with PoW
stamp = Hashcash.mint("recipient@example.com", bits=20)
print(f"Hashcash stamp: {stamp}")

is_valid = Hashcash.verify(stamp, "recipient@example.com", required_bits=20)
print(f"Stamp valid: {is_valid}")
```

## Performance Characteristics

### Hash Rate Units

| Unit | Hashes/Second | Example |
|------|---------------|---------|
| **H/s** | 1 | Early CPU mining |
| **KH/s** | 10³ | Modern CPU |
| **MH/s** | 10⁶ | GPU |
| **GH/s** | 10⁹ | ASIC (old) |
| **TH/s** | 10¹² | ASIC (current) |
| **PH/s** | 10¹⁵ | Mining pool |
| **EH/s** | 10¹⁸ | Bitcoin network |

### Energy Consumption

```python
def calculate_energy_cost(hashrate, watts_per_th, hours, kwh_cost=0.05):
    """
    Calculate mining energy cost

    Args:
        hashrate: TH/s
        watts_per_th: Watts per TH/s
        hours: Mining time in hours
        kwh_cost: Cost per kWh

    Returns:
        Energy cost in USD
    """
    total_watts = hashrate * watts_per_th
    kwh = (total_watts * hours) / 1000
    cost = kwh * kwh_cost

    return cost, kwh

# Example: 100 TH/s miner for 24 hours
cost, energy = calculate_energy_cost(100, 30, 24, 0.05)
print(f"Energy: {energy:.2f} kWh")
print(f"Cost: ${cost:.2f}")
```

## PoW vs Alternatives

| Mechanism | Energy | Security | Decentralization | Speed |
|-----------|--------|----------|------------------|-------|
| **PoW** | Very High | Excellent | High | Slow |
| **PoS** | Low | Good | Medium | Fast |
| **PoA** | Very Low | Medium | Low | Very Fast |
| **DPoS** | Low | Good | Medium | Fast |

## Best Practices

1. ✅ **Use double SHA-256** for blockchain applications
2. ✅ **Implement difficulty adjustment** for stable block times
3. ✅ **Verify proofs** before accepting blocks
4. ✅ **Set appropriate difficulty** based on network hashrate
5. ✅ **Monitor energy consumption** for sustainability
6. ❌ **Don't use weak hash functions** (MD5, SHA-1)
7. ❌ **Don't set difficulty too low** (enables attacks)
8. ❌ **Don't ignore 51% attack risk** in low-hashrate chains

## Conclusion

Proof of Work is the **original blockchain consensus mechanism** providing:

**Advantages**:
- Battle-tested security (Bitcoin since 2009)
- True decentralization
- Predictable issuance
- Simple to verify

**Disadvantages**:
- High energy consumption
- Slow transaction finality
- Vulnerable to 51% attacks
- Centralization of mining pools

**Use PoW for**:
- High-security applications (Bitcoin)
- Spam prevention (Hashcash)
- Rate limiting
- Sybil attack prevention

**Consider alternatives** (PoS) for energy-efficient applications.
