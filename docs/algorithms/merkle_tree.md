# Merkle Tree (Hash Tree)

## Overview

A **Merkle Tree** (also called a hash tree) is a tree data structure where every leaf node contains a hash of data, and every non-leaf node contains a hash of its child nodes. It allows efficient and secure verification of large data structures and is fundamental to blockchain technology.

## Purpose

- **Efficient Verification**: Verify data integrity without downloading entire dataset
- **Tamper Detection**: Any change in data changes the root hash
- **Blockchain**: Transaction verification in Bitcoin, Ethereum
- **Distributed Systems**: Git, IPFS, BitTorrent
- **Merkle Proofs**: Prove data inclusion with O(log n) proof size

## Structure

```
         Root Hash
        /           \
    Hash AB       Hash CD
    /    \        /    \
 Hash A  Hash B  Hash C  Hash D
   |      |        |      |
  Data  Data    Data   Data
   A      B        C      D
```

### Properties

- **Binary Tree**: Each node has 0 or 2 children
- **Leaf Nodes**: Contain hashes of actual data
- **Non-Leaf Nodes**: Contain hashes of concatenated child hashes
- **Root Hash**: Single hash representing entire tree
- **Height**: log₂(n) where n = number of leaves

## How Merkle Trees Work

### Construction Process

**Step 1: Hash Leaf Data**
```
H(A) = SHA256(Data_A)
H(B) = SHA256(Data_B)
H(C) = SHA256(Data_C)
H(D) = SHA256(Data_D)
```

**Step 2: Pair and Hash**
```
H(AB) = SHA256(H(A) || H(B))
H(CD) = SHA256(H(C) || H(D))
```

**Step 3: Repeat Until Root**
```
Root = SHA256(H(AB) || H(CD))
```

### Handling Odd Number of Nodes

If odd number of nodes, duplicate the last node:

```
Example: 5 transactions

Level 0: H(A) H(B) H(C) H(D) H(E)
Level 1: H(AB) H(CD) H(EE)  ← Duplicate H(E)
Level 2: H(ABCD) H(EE)
Root:    H(ABCDEE)
```

## Implementation Example

### Python Implementation

```python
import hashlib

class MerkleTree:
    def __init__(self, data_list):
        """
        Build Merkle tree from list of data

        Args:
            data_list: List of bytes objects to hash
        """
        self.data = data_list
        self.leaves = [self.hash_data(item) for item in data_list]
        self.root = self.build_tree(self.leaves)

    @staticmethod
    def hash_data(data):
        """Hash single piece of data"""
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha256(data).digest()

    def build_tree(self, leaves):
        """Build Merkle tree and return root hash"""
        if len(leaves) == 0:
            return b''
        if len(leaves) == 1:
            return leaves[0]

        # Process current level
        next_level = []
        for i in range(0, len(leaves), 2):
            if i + 1 < len(leaves):
                # Pair exists
                combined = leaves[i] + leaves[i + 1]
                next_level.append(self.hash_data(combined))
            else:
                # Odd number - duplicate last hash
                combined = leaves[i] + leaves[i]
                next_level.append(self.hash_data(combined))

        # Recursively build tree
        return self.build_tree(next_level)

    def get_root(self):
        """Return root hash as hex string"""
        return self.root.hex()

# Usage Example
transactions = [
    b"Alice -> Bob: 1 BTC",
    b"Bob -> Charlie: 0.5 BTC",
    b"Charlie -> Alice: 0.3 BTC",
    b"Dave -> Eve: 2 BTC"
]

tree = MerkleTree(transactions)
print(f"Merkle Root: {tree.get_root()}")

# Any change in data changes root
transactions[0] = b"Alice -> Bob: 999 BTC"
tree2 = MerkleTree(transactions)
print(f"Modified Root: {tree2.get_root()}")
```

### Advanced Implementation with Proof Generation

```python
class AdvancedMerkleTree:
    def __init__(self, data_list):
        self.data = data_list
        self.leaves = [self.hash_data(item) for item in data_list]
        self.tree = self.build_tree_structure(self.leaves)
        self.root = self.tree[0] if self.tree else b''

    @staticmethod
    def hash_data(data):
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha256(data).digest()

    def build_tree_structure(self, leaves):
        """Build tree and store all levels"""
        if not leaves:
            return []

        tree = [leaves]
        current_level = leaves

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = current_level[i] + current_level[i + 1]
                else:
                    combined = current_level[i] + current_level[i]
                next_level.append(self.hash_data(combined))
            tree.insert(0, next_level)
            current_level = next_level

        return tree

    def generate_proof(self, index):
        """
        Generate Merkle proof for item at index

        Returns list of (hash, 'left'/'right') tuples
        """
        if index >= len(self.leaves):
            return None

        proof = []
        current_index = index

        for level in reversed(self.tree[1:]):
            if current_index % 2 == 0:
                # Current node is left child
                if current_index + 1 < len(level):
                    sibling = level[current_index + 1]
                    proof.append((sibling, 'right'))
                else:
                    sibling = level[current_index]
                    proof.append((sibling, 'right'))
            else:
                # Current node is right child
                sibling = level[current_index - 1]
                proof.append((sibling, 'left'))

            current_index //= 2

        return proof

    def verify_proof(self, data, index, proof):
        """Verify Merkle proof"""
        current_hash = self.hash_data(data)

        for sibling, position in proof:
            if position == 'left':
                combined = sibling + current_hash
            else:
                combined = current_hash + sibling
            current_hash = self.hash_data(combined)

        return current_hash == self.root

# Example: Generate and verify proof
data = [b"tx1", b"tx2", b"tx3", b"tx4"]
tree = AdvancedMerkleTree(data)

# Generate proof for tx2 (index 1)
proof = tree.generate_proof(1)
print(f"Proof for tx2: {[p[0].hex()[:16]+'...' for p in proof]}")

# Verify proof
is_valid = tree.verify_proof(b"tx2", 1, proof)
print(f"Proof valid: {is_valid}")

# Try with wrong data
is_valid_fake = tree.verify_proof(b"fake_tx", 1, proof)
print(f"Fake proof valid: {is_valid_fake}")
```

### Blockchain Implementation

```python
class BlockchainMerkleTree:
    def __init__(self, transactions):
        """Bitcoin-style Merkle tree (double SHA-256)"""
        self.transactions = transactions
        self.leaves = [self.double_sha256(tx) for tx in transactions]
        self.root = self.build_tree(self.leaves)

    @staticmethod
    def double_sha256(data):
        """Double SHA-256 hash (Bitcoin standard)"""
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    def build_tree(self, leaves):
        if len(leaves) == 1:
            return leaves[0]

        next_level = []
        for i in range(0, len(leaves), 2):
            if i + 1 < len(leaves):
                combined = leaves[i] + leaves[i + 1]
            else:
                combined = leaves[i] + leaves[i]  # Duplicate if odd
            next_level.append(self.double_sha256(combined))

        return self.build_tree(next_level)

    def get_root_hex(self):
        """Return root in Bitcoin format (reversed hex)"""
        return self.root[::-1].hex()  # Bitcoin reverses byte order

# Bitcoin-style usage
txs = [
    "01000000...",  # Transaction 1
    "01000000...",  # Transaction 2
    "01000000...",  # Transaction 3
]
btc_tree = BlockchainMerkleTree(txs)
print(f"Block Merkle Root: {btc_tree.get_root_hex()}")
```

## Merkle Proofs

### Proof Size

For n transactions:
- **Full data**: O(n) size
- **Merkle proof**: O(log n) size

Example:
- 1,000 transactions: Proof has ~10 hashes (log₂1000 ≈ 10)
- 1,000,000 transactions: Proof has ~20 hashes (log₂1M ≈ 20)

### Proof Verification Process

```python
def verify_merkle_proof(leaf_data, proof, root, index):
    """
    Verify Merkle proof

    Args:
        leaf_data: Original data
        proof: List of (hash, position) tuples
        root: Expected root hash
        index: Leaf index

    Returns:
        True if proof valid
    """
    current = hashlib.sha256(leaf_data).digest()

    for sibling, position in proof:
        if position == 'left':
            current = hashlib.sha256(sibling + current).digest()
        else:
            current = hashlib.sha256(current + sibling).digest()

    return current == root
```

## Real-World Applications

### Bitcoin SPV (Simplified Payment Verification)

```python
class BitcoinSPVClient:
    """Lightweight Bitcoin client using Merkle proofs"""

    def verify_transaction_in_block(self, tx, block_header, merkle_proof):
        """
        Verify transaction is in block without downloading full block

        Args:
            tx: Transaction data
            block_header: Block header (contains merkle root)
            merkle_proof: Merkle proof from full node
        """
        # Extract merkle root from block header
        merkle_root = block_header['merkle_root']

        # Verify proof
        tx_hash = self.double_sha256(tx)

        current = tx_hash
        for sibling in merkle_proof:
            current = self.double_sha256(current + sibling)

        return current == merkle_root
```

### Git Commit History

Git uses Merkle trees for commit history:

```
Commit Hash = SHA1(
    tree_hash +      ← Merkle root of file tree
    parent_hash +    ← Previous commit
    author +
    message
)
```

### IPFS Content Addressing

IPFS uses Merkle DAGs (Directed Acyclic Graphs):

```python
class IPFSMerkleDAG:
    def add_file(self, file_data, chunk_size=256*1024):
        """Split file into chunks and build Merkle DAG"""
        chunks = [file_data[i:i+chunk_size] 
                  for i in range(0, len(file_data), chunk_size)]

        # Hash each chunk
        chunk_hashes = [hashlib.sha256(chunk).digest() 
                        for chunk in chunks]

        # Build Merkle tree
        tree = MerkleTree([hash for hash in chunk_hashes])

        # IPFS CID (Content Identifier)
        cid = base58.b58encode(tree.root).decode()
        return cid
```

## Security Considerations

### Tamper Detection

Any modification changes root hash:

```python
def demonstrate_tamper_detection():
    original = [b"tx1", b"tx2", b"tx3", b"tx4"]
    tree1 = MerkleTree(original)
    root1 = tree1.get_root()

    # Tamper with one transaction
    modified = [b"tx1_MODIFIED", b"tx2", b"tx3", b"tx4"]
    tree2 = MerkleTree(modified)
    root2 = tree2.get_root()

    print(f"Original root:  {root1}")
    print(f"Modified root:  {root2}")
    print(f"Roots match: {root1 == root2}")  # False

demonstrate_tamper_detection()
```

### Attack Resistance

| Attack | Resistance |
|--------|------------|
| **Modify single transaction** | Detected (root changes) |
| **Swap transactions** | Detected (order matters) |
| **Remove transaction** | Detected (changes tree structure) |
| **Collision attack** | Requires breaking hash function |
| **Second preimage** | Requires breaking hash function |

## Performance Characteristics

| Operation | Complexity | Description |
|-----------|------------|-------------|
| **Build tree** | O(n) | Hash all n items once |
| **Generate proof** | O(log n) | Traverse tree height |
| **Verify proof** | O(log n) | Hash proof hashes |
| **Memory** | O(n) | Store all hashes |

## Merkle Tree vs Alternatives

| Structure | Verification | Proof Size | Use Case |
|-----------|--------------|------------|----------|
| **Merkle Tree** | O(log n) | O(log n) | Blockchain, Git |
| **Hash List** | O(n) | O(n) | Simple checksums |
| **Merkle DAG** | O(log n) | Variable | IPFS, Ethereum |
| **Patricia Trie** | O(log n) | O(log n) | Ethereum state |

## Best Practices

1. ✅ **Use SHA-256** or stronger hash function
2. ✅ **Double-hash** in blockchain applications (Bitcoin standard)
3. ✅ **Handle odd numbers** by duplicating last node
4. ✅ **Store root in block header** for blockchain
5. ✅ **Generate minimal proofs** (only required hashes)
6. ✅ **Verify proofs** before trusting data
7. ❌ **Don't use weak hash functions** (MD5, SHA-1)
8. ❌ **Don't skip verification** (always verify proofs)

## Conclusion

Merkle Trees are **fundamental data structures** in blockchain and distributed systems:

**Advantages**:
- Efficient verification: O(log n) proof size
- Tamper detection: Any change detected
- Scalability: Light clients possible
- Standardized: Used in Bitcoin, Ethereum, Git, IPFS

**Applications**:
- **Bitcoin**: Transaction verification (SPV)
- **Ethereum**: State and transaction tries
- **Git**: Commit and file tree hashing
- **IPFS**: Content-addressed storage
- **Certificate Transparency**: Log verification

**Use Merkle Trees when you need efficient, verifiable data structures for large datasets!**
