---
theme: default
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Lecture 12: Cryptography in Blockchain
  MAT364 - Cryptography Course
drawings:
  persist: false
transition: slide-left
title: Cryptography in Blockchain
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

# Cryptography in Blockchain
## MAT364 - Cryptography Course

**Instructor:** Adil Akhmetov  
**University:** SDU  
**Week 12**

<div class="pt-6">
  <span @click="$slidev.nav.next" class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Press Space for next page →
  </span>
</div>

---
layout: default
---

# Week 12 Focus

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Motivation
- Blockchains rely on cryptographic primitives for security
- Digital signatures prove ownership and authorize transactions
- Hash functions ensure data integrity and consensus
- Understanding crypto is essential for blockchain development

## Learning Outcomes
1. Implement Bitcoin/Ethereum transaction signing with ECDSA
2. Build Merkle trees for data verification
3. Generate blockchain addresses from public keys
4. Understand cryptographic security in smart contracts

</div>

<div>

## Agenda
- Blockchain cryptographic primitives overview
- Bitcoin transaction signatures and address generation
- Ethereum transaction signatures and EIP-1559
- Merkle trees and Merkle proofs
- Hash functions in consensus (Proof of Work)
- Smart contract cryptographic security
- Lab: Build a simple blockchain with crypto

</div>

</div>

---
layout: section
---

# Blockchain Cryptography Overview

---
layout: default
---

# Cryptographic Primitives in Blockchain

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Core Components
- **Hash Functions** (SHA-256, Keccak-256)
  - Block hashing, Merkle trees, proof-of-work
- **Digital Signatures** (ECDSA, EdDSA)
  - Transaction authorization, ownership proof
- **Public Key Cryptography**
  - Address generation, key derivation

## Security Properties
- **Immutability** - Hash chains prevent tampering
- **Authentication** - Signatures prove ownership
- **Integrity** - Merkle trees verify data
- **Consensus** - Cryptographic puzzles (PoW)

</div>

<div>

## Blockchain Structure
```
Block:
  - Previous Block Hash (SHA-256)
  - Merkle Root (SHA-256 of transactions)
  - Timestamp
  - Nonce (for PoW)
  - Transactions (signed with ECDSA)
```

## Transaction Flow
1. User creates transaction
2. Sign with private key (ECDSA)
3. Broadcast to network
4. Miners verify signature
5. Include in block with Merkle tree
6. Block hash links to previous block

</div>

</div>

<div class="mt-4 p-3 bg-blue-50 rounded-lg text-sm">
<strong>Key insight:</strong> Blockchains are essentially cryptographic data structures secured by hash functions and digital signatures.
</div>

---
layout: section
---

# Bitcoin Cryptography

---
layout: default
---

# Bitcoin Transaction Signatures

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Transaction Structure
- **Inputs:** Previous transaction outputs (UTXOs)
- **Outputs:** Recipient addresses and amounts
- **ScriptSig:** Signature + public key
- **ScriptPubKey:** Spending conditions

## Signing Process
1. Create transaction hash (double SHA-256)
2. Sign hash with private key (ECDSA secp256k1)
3. Include signature in ScriptSig
4. Miners verify signature during validation

## ECDSA Parameters
- **Curve:** secp256k1
- **Hash:** SHA-256 (double hashed)
- **Signature format:** DER-encoded (r, s)

</div>

<div>

## Python Implementation
```python
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from ecdsa import SigningKey, SECP256k1

class BitcoinTransaction:
    def __init__(self, private_key):
        self.private_key = private_key
        self.public_key = private_key.public_key()
    
    def create_transaction_hash(self, inputs, outputs, locktime=0):
        """Create transaction hash for signing"""
        # Simplified - real Bitcoin uses more complex serialization
        tx_data = f"{inputs}{outputs}{locktime}".encode()
        # Double SHA-256 (Bitcoin standard)
        first_hash = hashlib.sha256(tx_data).digest()
        return hashlib.sha256(first_hash).digest()
    
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

# Bitcoin Address Generation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Address Generation Steps
1. **Generate ECDSA key pair** (secp256k1)
2. **Compress public key** (33 bytes: 0x02/0x03 + x-coordinate)
3. **Hash public key** with SHA-256
4. **Hash again** with RIPEMD-160 → 20 bytes
5. **Add version byte** (0x00 for mainnet)
6. **Double SHA-256** for checksum (first 4 bytes)
7. **Base58 encode** final address

## Address Types
- **P2PKH** (Pay-to-Public-Key-Hash): Legacy, starts with '1'
- **P2SH** (Pay-to-Script-Hash): Multisig, starts with '3'
- **Bech32** (SegWit): Native SegWit, starts with 'bc1'

</div>

<div>

## Implementation
```python
import hashlib
import base58
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_bitcoin_address(public_key, network='mainnet'):
    """Generate Bitcoin address from public key"""
    
    # Compress public key
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    
    # SHA-256
    sha256_hash = hashlib.sha256(public_bytes).digest()
    
    # RIPEMD-160
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    hash160 = ripemd160.digest()
    
    # Add version byte
    version = b'\x00' if network == 'mainnet' else b'\x6f'
    versioned_hash = version + hash160
    
    # Checksum (first 4 bytes of double SHA-256)
    checksum = hashlib.sha256(
        hashlib.sha256(versioned_hash).digest()
    ).digest()[:4]
    
    # Base58 encode
    address_bytes = versioned_hash + checksum
    address = base58.b58encode(address_bytes).decode('ascii')
    
    return address

# Usage
private_key = ec.generate_private_key(ec.SECP256K1())
public_key = private_key.public_key()
address = generate_bitcoin_address(public_key)
print(f"Bitcoin Address: {address}")
```

</div>

</div>

---
layout: default
---

# Bitcoin Script and Verification

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Script Language
- **Stack-based** programming language
- **ScriptSig:** Unlocks previous output
- **ScriptPubKey:** Locks current output
- **Execution:** ScriptSig + ScriptPubKey must evaluate to true

## Common Script Types
- **P2PKH:** `OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`
- **P2SH:** `OP_HASH160 <scriptHash> OP_EQUAL`
- **Multisig:** `OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG`

</div>

<div>

## Simplified Script Execution
```python
class BitcoinScript:
    def __init__(self):
        self.stack = []
    
    def op_dup(self):
        """Duplicate top stack item"""
        if len(self.stack) < 1:
            return False
        self.stack.append(self.stack[-1])
        return True
    
    def op_hash160(self):
        """Hash top stack item with RIPEMD-160(SHA-256(x))"""
        if len(self.stack) < 1:
            return False
        item = self.stack.pop()
        sha256_hash = hashlib.sha256(item).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        self.stack.append(ripemd160.digest())
        return True
    
    def op_checksig(self, public_key, signature, message):
        """Verify ECDSA signature"""
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            self.stack.append(b'\x01')  # True
            return True
        except:
            self.stack.append(b'\x00')  # False
            return False
    
    def execute(self, script_sig, script_pubkey, message):
        """Execute script and return result"""
        # Simplified execution
        # Real Bitcoin script is more complex
        return len(self.stack) > 0 and self.stack[-1] == b'\x01'
```

</div>

</div>

---
layout: section
---

# Ethereum Cryptography

---
layout: default
---

# Ethereum Transaction Signatures

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Transaction Structure
- **nonce:** Transaction sequence number
- **gasPrice/gasFeeCap:** Fee parameters
- **gasLimit:** Maximum gas to use
- **to:** Recipient address (or contract)
- **value:** ETH amount (wei)
- **data:** Contract call data
- **v, r, s:** ECDSA signature components

## EIP-1559 (London Fork)
- **Base fee:** Network-determined fee
- **Priority fee:** User-determined tip
- **Max fee:** Maximum user willing to pay
- **Chain ID:** Prevents replay attacks

## Signing Process
1. RLP-encode transaction fields
2. Keccak-256 hash of encoded data
3. Sign hash with private key (ECDSA secp256k1)
4. Recover signature components (v, r, s)

</div>

<div>

## Python Implementation
```python
import rlp
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
import hashlib

class EthereumTransaction:
    def __init__(self, private_key):
        self.private_key = private_key
        self.account = Account.from_key(private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    def create_transaction(self, to, value, gas_price, gas_limit, nonce, data=b'', chain_id=1):
        """Create unsigned transaction"""
        return {
            'to': to,
            'value': value,
            'gas': gas_limit,
            'gasPrice': gas_price,
            'nonce': nonce,
            'data': data,
            'chainId': chain_id
        }
    
    def sign_transaction(self, transaction):
        """Sign transaction with EIP-155"""
        # Using eth_account library for proper signing
        signed_txn = self.account.sign_transaction(transaction)
        return signed_txn.rawTransaction
    
    def get_address(self):
        """Get Ethereum address from public key"""
        public_key = self.account.key.hex()
        # Simplified - real implementation uses Keccak-256
        keccak = hashlib.sha3_256(public_key.encode()).digest()
        # Take last 20 bytes
        address = '0x' + keccak[-20:].hex()
        return address
    
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
layout: default
---

# Ethereum Address Generation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Address Generation
1. **Generate ECDSA key pair** (secp256k1)
2. **Serialize public key** (uncompressed, 64 bytes)
3. **Keccak-256 hash** of public key
4. **Take last 20 bytes** as address
5. **Add '0x' prefix** for hex representation

## Key Differences from Bitcoin
- **No Base58 encoding** - uses hex
- **Keccak-256** instead of SHA-256 + RIPEMD-160
- **No version byte** or checksum
- **Shorter addresses** (20 bytes vs 25 bytes)

</div>

<div>

## Implementation
```python
from Crypto.Hash import keccak

def generate_ethereum_address(public_key):
    """Generate Ethereum address from public key"""
    
    # Get uncompressed public key (64 bytes, no 0x04 prefix)
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    # Remove 0x04 prefix (first byte)
    public_key_bytes = public_bytes[1:]
    
    # Keccak-256 hash
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(public_key_bytes)
    hash_bytes = keccak_hash.digest()
    
    # Take last 20 bytes
    address_bytes = hash_bytes[-20:]
    
    # Convert to hex with 0x prefix
    address = '0x' + address_bytes.hex()
    
    return address

# Usage
private_key = ec.generate_private_key(ec.SECP256K1())
public_key = private_key.public_key()
address = generate_ethereum_address(public_key)
print(f"Ethereum Address: {address}")
```

</div>

</div>

---
layout: section
---

# Merkle Trees

---
layout: default
---

# Merkle Trees in Blockchain

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## What is a Merkle Tree?
- **Binary tree** of hashes
- **Leaf nodes:** Hash of data (transactions)
- **Internal nodes:** Hash of child nodes
- **Root:** Single hash representing all data

## Properties
- **Efficient verification:** O(log n) proof size
- **Tamper detection:** Any change affects root
- **Batch verification:** Verify multiple items at once
- **SPV (Simplified Payment Verification):** Light clients

## Use Cases
- **Blockchain:** Transaction verification
- **Git:** Commit verification
- **IPFS:** Content addressing
- **Certificate Transparency:** Log verification

</div>

<div>

## Merkle Tree Structure
```
        Root Hash
       /         \
    Hash01      Hash23
    /    \      /    \
  Hash0 Hash1 Hash2 Hash3
   |     |     |     |
  Tx0   Tx1   Tx2   Tx3
```

## Merkle Proof
To prove Tx2 is in the tree:
- Provide: Hash3, Hash01, Root
- Verify: Hash(Tx2) → Hash2, Hash(Hash2 || Hash3) → Hash23, Hash(Hash01 || Hash23) → Root

</div>

</div>

---
layout: default
---

# Merkle Tree Implementation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Building the Tree
```python
import hashlib
from typing import List, Optional

class MerkleTree:
    def __init__(self, data: List[bytes]):
        self.data = data
        self.leaves = [self.hash(item) for item in data]
        self.root = self.build_tree(self.leaves)
    
    def hash(self, data: bytes) -> bytes:
        """Double SHA-256 (Bitcoin style)"""
        return hashlib.sha256(
            hashlib.sha256(data).digest()
        ).digest()
    
    def build_tree(self, leaves: List[bytes]) -> bytes:
        """Build Merkle tree from leaves"""
        if len(leaves) == 0:
            return b''
        if len(leaves) == 1:
            return leaves[0]
        
        # Pair up leaves and hash
        next_level = []
        for i in range(0, len(leaves), 2):
            if i + 1 < len(leaves):
                # Hash of two children
                combined = leaves[i] + leaves[i + 1]
                next_level.append(self.hash(combined))
            else:
                # Odd number, hash with itself
                combined = leaves[i] + leaves[i]
                next_level.append(self.hash(combined))
        
        return self.build_tree(next_level)
```

</div>

<div>

## Merkle Proof Generation
```python
    def generate_proof(self, index: int) -> List[bytes]:
        """Generate Merkle proof for leaf at index"""
        if index >= len(self.leaves):
            return []
        
        proof = []
        current_level = self.leaves
        current_index = index
        
        while len(current_level) > 1:
            # Find sibling
            if current_index % 2 == 0:
                sibling_index = current_index + 1
            else:
                sibling_index = current_index - 1
            
            if sibling_index < len(current_level):
                proof.append(current_level[sibling_index])
            else:
                # No sibling, use self
                proof.append(current_level[current_index])
            
            # Move to next level
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = current_level[i] + current_level[i + 1]
                    next_level.append(self.hash(combined))
                else:
                    combined = current_level[i] + current_level[i]
                    next_level.append(self.hash(combined))
            
            current_level = next_level
            current_index //= 2
        
        return proof
    
    def verify_proof(self, leaf: bytes, proof: List[bytes], root: bytes, index: int) -> bool:
        """Verify Merkle proof"""
        current_hash = leaf
        
        for i, sibling in enumerate(proof):
            if (index >> i) % 2 == 0:
                current_hash = self.hash(current_hash + sibling)
            else:
                current_hash = self.hash(sibling + current_hash)
        
        return current_hash == root
```

</div>

</div>

---
layout: default
---

# Merkle Tree Usage Example

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Example: Transaction Verification
```python
# Create transactions
transactions = [
    b"Alice -> Bob: 1 BTC",
    b"Bob -> Charlie: 0.5 BTC",
    b"Charlie -> Alice: 0.3 BTC",
    b"Dave -> Eve: 2 BTC"
]

# Build Merkle tree
tree = MerkleTree(transactions)
print(f"Merkle Root: {tree.root.hex()}")

# Generate proof for transaction at index 1
proof = tree.generate_proof(1)
print(f"Proof length: {len(proof)} nodes")

# Verify proof
leaf_hash = tree.hash(transactions[1])
is_valid = tree.verify_proof(
    leaf_hash,
    proof,
    tree.root,
    1
)
print(f"Proof valid: {is_valid}")
```

## SPV (Simplified Payment Verification)
- **Light clients** don't download full blockchain
- **Only need:** Block headers + Merkle proofs
- **Verify:** Transaction is in block without full data
- **Efficient:** O(log n) proof size vs O(n) full data

</div>

<div>

## Block Header Structure
```python
class BlockHeader:
    def __init__(self, prev_hash, merkle_root, timestamp, nonce, difficulty):
        self.prev_hash = prev_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.nonce = nonce
        self.difficulty = difficulty
    
    def hash(self):
        """Hash block header"""
        data = (
            self.prev_hash +
            self.merkle_root +
            self.timestamp.to_bytes(8, 'big') +
            self.nonce.to_bytes(4, 'big') +
            self.difficulty.to_bytes(4, 'big')
        )
        return hashlib.sha256(
            hashlib.sha256(data).digest()
        ).digest()
    
    def verify_proof_of_work(self, target):
        """Verify proof of work"""
        block_hash = self.hash()
        return int.from_bytes(block_hash, 'big') < target
```

## Benefits
- **Reduced storage:** Only headers, not full blocks
- **Fast verification:** Merkle proofs are small
- **Security:** Can't fake Merkle proof without breaking hash function

</div>

</div>

---
layout: section
---

# Hash Functions in Consensus

---
layout: default
---

# Proof of Work (PoW)

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## How PoW Works
1. **Mine block:** Find nonce such that hash(block + nonce) < target
2. **Difficulty:** Target adjusts to maintain block time
3. **Validation:** Anyone can verify hash < target
4. **Security:** Requires computational work to find valid nonce

## Hash Function Requirements
- **Preimage resistance:** Can't find input from hash
- **Avalanche effect:** Small change → completely different hash
- **Deterministic:** Same input → same output
- **Fast computation:** Millions of hashes per second

## Bitcoin PoW
- **Algorithm:** Double SHA-256
- **Target:** Adjusts every 2016 blocks
- **Block time:** ~10 minutes
- **Difficulty:** ~2^256 / target

</div>

<div>

## Simplified PoW Implementation
```python
import hashlib
import time

class ProofOfWork:
    def __init__(self, difficulty=4):
        self.difficulty = difficulty
        self.target = 2 ** (256 - difficulty * 4)  # Simplified target
    
    def mine_block(self, block_data: bytes) -> tuple:
        """Mine block by finding valid nonce"""
        nonce = 0
        start_time = time.time()
        
        while True:
            # Create block with nonce
            block_with_nonce = block_data + nonce.to_bytes(4, 'big')
            
            # Hash block
            block_hash = hashlib.sha256(
                hashlib.sha256(block_with_nonce).digest()
            ).digest()
            
            # Check if hash meets target
            hash_int = int.from_bytes(block_hash, 'big')
            if hash_int < self.target:
                elapsed = time.time() - start_time
                return nonce, block_hash, elapsed
            
            nonce += 1
    
    def verify(self, block_data: bytes, nonce: int) -> bool:
        """Verify proof of work"""
        block_with_nonce = block_data + nonce.to_bytes(4, 'big')
        block_hash = hashlib.sha256(
            hashlib.sha256(block_with_nonce).digest()
        ).digest()
        
        hash_int = int.from_bytes(block_hash, 'big')
        return hash_int < self.target

# Usage
pow = ProofOfWork(difficulty=4)
block_data = b"Previous Hash + Merkle Root + Timestamp"
nonce, block_hash, elapsed = pow.mine_block(block_data)
print(f"Mined in {elapsed:.2f}s, nonce: {nonce}, hash: {block_hash.hex()[:16]}...")
```

</div>

</div>

---
layout: section
---

# Smart Contract Security

---
layout: default
---

# Cryptographic Security in Smart Contracts

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Common Vulnerabilities
- **Reentrancy:** External calls before state updates
- **Integer overflow:** Arithmetic operations
- **Access control:** Missing authorization checks
- **Randomness:** Predictable random numbers
- **Signature replay:** Reusing signatures across chains

## Cryptographic Considerations
- **Signature verification:** Always verify signatures
- **Hash functions:** Use Keccak-256 for Ethereum
- **Randomness:** Use block hashes + external randomness
- **Key management:** Never store private keys in contracts

</div>

<div>

## Secure Signature Verification
```solidity
// Solidity example
pragma solidity ^0.8.0;

contract SecureSignature {
    using ECDSA for bytes32;
    
    function verifySignature(
        bytes32 messageHash,
        bytes memory signature,
        address signer
    ) public pure returns (bool) {
        // Recover signer from signature
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address recovered = ethSignedMessageHash.recover(signature);
        
        // Verify signer matches
        return recovered == signer;
    }
    
    function verifyWithNonce(
        bytes32 messageHash,
        bytes memory signature,
        address signer,
        uint256 nonce
    ) public view returns (bool) {
        // Include nonce to prevent replay
        bytes32 hashWithNonce = keccak256(
            abi.encodePacked(messageHash, nonce, msg.sender)
        );
        return verifySignature(hashWithNonce, signature, signer);
    }
}
```

</div>

</div>

---
layout: default
---

# Commit-Reveal Scheme

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Problem: On-Chain Randomness
- **Block hashes** are predictable by miners
- **Block timestamps** can be manipulated
- **Need:** Unpredictable randomness for games, lotteries

## Solution: Commit-Reveal
1. **Commit phase:** Users submit hash(secret + value)
2. **Reveal phase:** Users reveal secret + value
3. **Verification:** Check hash(secret + value) matches commit
4. **Randomness:** Combine all revealed values

## Use Cases
- **Voting:** Hide votes until reveal
- **Lotteries:** Fair random selection
- **Auctions:** Sealed bid auctions

</div>

<div>

## Implementation
```solidity
contract CommitReveal {
    struct Commit {
        bytes32 commitment;
        bool revealed;
        uint256 value;
    }
    
    mapping(address => Commit) public commits;
    uint256 public revealDeadline;
    uint256 public randomSeed;
    
    function commit(bytes32 commitment) public {
        require(block.timestamp < revealDeadline, "Commit phase ended");
        commits[msg.sender] = Commit(commitment, false, 0);
    }
    
    function reveal(uint256 secret, uint256 value) public {
        require(block.timestamp >= revealDeadline, "Reveal phase not started");
        require(!commits[msg.sender].revealed, "Already revealed");
        
        // Verify commitment
        bytes32 commitment = keccak256(abi.encodePacked(secret, value));
        require(commitment == commits[msg.sender].commitment, "Invalid reveal");
        
        // Record reveal
        commits[msg.sender].revealed = true;
        commits[msg.sender].value = value;
        
        // Update random seed
        randomSeed ^= value;
    }
    
    function getRandom() public view returns (uint256) {
        return randomSeed;
    }
}
```

## Python Commit Generation
```python
import hashlib
import secrets

def create_commitment(value: int) -> tuple:
    """Create commit-reveal commitment"""
    secret = secrets.token_bytes(32)
    commitment = hashlib.sha256(
        secret + value.to_bytes(32, 'big')
    ).digest()
    return commitment, secret, value
```

</div>

</div>

---
layout: section
---

# Lab: Simple Blockchain

---
layout: default
---

# 🎯 Student Lab Assignment

<div class="p-4 bg-gradient-to-r from-slate-50 to-indigo-50 rounded-lg border border-indigo-200">

## Scenario
Build a simplified blockchain that demonstrates core cryptographic concepts.

## Requirements
1. **Block Structure:**
   - Previous block hash
   - Merkle root of transactions
   - Timestamp
   - Nonce (for PoW)
   - Block hash

2. **Transaction Structure:**
   - Sender address
   - Recipient address
   - Amount
   - ECDSA signature

3. **Implement:**
   - ECDSA transaction signing and verification
   - Merkle tree construction and proof generation
   - Simple proof-of-work mining
   - Address generation from public keys

### Deliverables
- Python implementation with all components
- Test with 5+ transactions across 3+ blocks
- Demonstrate Merkle proof verification
- Show PoW mining process

</div>

---
layout: default
---

# ✅ Solution Outline

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Block Class
```python
class Block:
    def __init__(self, prev_hash, transactions, difficulty=4):
        self.prev_hash = prev_hash
        self.transactions = transactions
        self.timestamp = int(time.time())
        self.merkle_root = self.calculate_merkle_root()
        self.nonce = 0
        self.hash = None
        self.mine(difficulty)
    
    def calculate_merkle_root(self):
        tree = MerkleTree([tx.hash() for tx in self.transactions])
        return tree.root
    
    def mine(self, difficulty):
        target = 2 ** (256 - difficulty * 4)
        block_data = (
            self.prev_hash +
            self.merkle_root +
            self.timestamp.to_bytes(8, 'big')
        )
        
        pow = ProofOfWork(difficulty)
        self.nonce, self.hash, _ = pow.mine_block(block_data)
```

</div>

<div>

## Transaction Class
```python
class Transaction:
    def __init__(self, sender, recipient, amount, private_key):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = self.sign(private_key)
    
    def sign(self, private_key):
        tx_data = f"{self.sender}{self.recipient}{self.amount}".encode()
        return private_key.sign(tx_data, ec.ECDSA(hashes.SHA256()))
    
    def verify(self, public_key):
        tx_data = f"{self.sender}{self.recipient}{self.amount}".encode()
        try:
            public_key.verify(
                self.signature,
                tx_data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            return False
    
    def hash(self):
        tx_data = f"{self.sender}{self.recipient}{self.amount}".encode()
        return hashlib.sha256(tx_data).digest()
```

</div>

</div>

---
layout: default
---

# Best Practices & Pitfalls

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Security Best Practices
- **Use standard curves:** secp256k1 for Bitcoin/Ethereum
- **Verify all signatures:** Never trust, always verify
- **Protect private keys:** Use hardware wallets, never store in code
- **Use proper randomness:** `secrets` module, not `random`
- **Validate all inputs:** Check addresses, amounts, nonces

## Common Mistakes
- ❌ Reusing nonces in ECDSA signatures
- ❌ Storing private keys in smart contracts
- ❌ Using predictable randomness
- ❌ Not verifying Merkle proofs
- ❌ Ignoring signature malleability

</div>

<div>

## Implementation Guidelines
- **Libraries:** Use `cryptography`, `eth-account`, `web3.py`
- **Testing:** Test with testnets before mainnet
- **Key management:** Use proper key derivation (BIP32/BIP44)
- **Error handling:** Always handle signature verification failures
- **Documentation:** Document cryptographic assumptions

## Resources
- **Bitcoin:** [Bitcoin Developer Guide](https://bitcoin.org/en/developer-guide)
- **Ethereum:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf)
- **Cryptography:** [Real-World Cryptography](https://www.manning.com/books/real-world-cryptography)

</div>

</div>

---
layout: default
---

# Summary

- Blockchains rely on **hash functions** (SHA-256, Keccak-256) for integrity and consensus
- **Digital signatures** (ECDSA) prove ownership and authorize transactions
- **Merkle trees** enable efficient verification with O(log n) proofs
- **Address generation** differs between Bitcoin (Base58) and Ethereum (hex)
- **Proof of Work** uses cryptographic puzzles to secure the network
- **Smart contracts** require careful cryptographic design to prevent vulnerabilities

<div class="mt-4 text-sm text-gray-600">
<p><strong>Next Week:</strong> Quantum cryptography and post-quantum cryptography.</p>
<p><strong>Assignment:</strong> Complete the blockchain lab and submit code with test cases.</p>
</div>

---
layout: end
---

# Questions?

<div class="pt-6">
  <span class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Thanks for exploring blockchain cryptography! ⛓️🔐
  </span>
</div>

