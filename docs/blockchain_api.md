# Blockchain API Reference

This document describes the HTTP API for the Blockchain module, including request/response examples, validation, error codes, and security considerations.

## Authentication & Authorization
- All endpoints MUST be served over TLS (HTTPS).
- Transactions and sensitive operations require authenticated clients.
- Requests that modify state (POST endpoints below) MUST include a valid client authentication token (e.g., bearer token) or be performed by an authorized internal service account. Specific auth method depends on deployment configuration.

## Common HTTP responses
- `200 OK` — operation successful (response body contains details)
- `400 Bad Request` — malformed request or validation failure
- `401 Unauthorized` — missing/invalid authentication
- `403 Forbidden` — authenticated but not permitted
- `404 Not Found` — referenced resource not found
- `429 Too Many Requests` — rate limit exceeded
- `500 Internal Server Error` — server-side error

---

## Add Transaction

- Endpoint: `POST /blockchain/transaction/add`
- Description: Adds a transaction to the node's pending transaction pool.

Request (application/json):

{
    "sender": "alice_id",
    "recipient": "bob_id",
    "amount": 100,
    "timestamp": 1703330400,
    "signature": "base64-encoded"
}

Notes:
- `sender` and `recipient` are account identifiers (address, user id, or public-key fingerprint depending on system).
- `signature` MUST be a signature over a canonical serialization of the transaction fields (sender, recipient, amount, timestamp) produced by the sender's private key.
- The server MUST verify the signature before accepting the transaction.
- The server SHOULD enforce replay protection (e.g., nonce or timestamp bounds) and reject transactions with timestamps too far in the past/future.

Response (application/json):

{
    "success": true,
    "transaction_id": "tx_abc123",
    "pending_count": 5,
    "status": "pending"
}

Validation errors example:

HTTP 400
{
  "success": false,
  "error": "invalid_signature",
  "message": "Signature verification failed"
}

Security considerations:
- Always validate and rate-limit transaction submissions to mitigate spam / DoS.
- Store minimal sensitive data and avoid logging raw signatures or private material.
- Rate-limit per-sender and per-IP.

---

## Mine Block

- Endpoint: `POST /blockchain/mine`
- Description: Triggers mining of a new block using the node's pending transactions. Usually restricted to miner nodes or internal services.

Request: No body required. Optional JSON parameters may include `max_transactions` or `reward_address` depending on implementation.

Response (application/json):

{
    "success": true,
    "block_index": 10,
    "block_hash": "0000a7f8e9c3d2b1a0f...",
    "nonce": 245738,
    "difficulty": 4,
    "transactions": 5,
    "mining_time": 2.34
}

Notes:
- Access to this endpoint should be tightly controlled — mining typically runs as a background process.
- Return metrics such as `mining_time` to monitor performance.

---

## Validate Chain

- Endpoint: `GET /blockchain/validate`
- Description: Validates the entire chain for internal integrity checks (hash links, PoW, Merkle roots).

Response (application/json):

{
    "valid": true,
    "blocks_validated": 150,
    "chain_length": 150,
    "merkle_verified": true,
    "pow_verified": true,
    "errors": []
}

Notes:
- This endpoint can be expensive on long chains; consider asynchronous or paginated validation for large deployments.
- Results SHOULD include a list of validation errors if invalid.

---

## Get Merkle Proof

- Endpoint: `POST /blockchain/merkle-proof`
- Description: Returns a Merkle proof for a transaction included in a block.

Request (application/json):

{
    "transaction_hash": "abc123...",
    "block_index": 10
}

Response (application/json):

{
    "success": true,
    "transaction_hash": "abc123...",
    "merkle_root": "def456...",
    "proof": [
        ["right", "ghi789..."],
        ["left", "jkl012..."]
    ]
}

Notes:
- `proof` is an ordered list of pairs `["left"|"right", sibling_hash]` used to recompute the Merkle root starting from `transaction_hash`.
- If the transaction is not found in the block, return a 404 with a clear message.

---

## Verify Merkle Proof

- Endpoint: `POST /blockchain/merkle-proof/verify`
- Description: Server-side verification of a Merkle proof against a provided Merkle root.

Request (application/json):

{
    "transaction_hash": "abc123...",
    "proof": [...],
    "merkle_root": "def456..."
}

Response (application/json):

{
    "success": true,
    "verified": true
}

Notes:
- This endpoint performs deterministic reconstruction of the Merkle root and compares it to the provided `merkle_root`.

---

## Input validation & schema suggestions
- Use strict JSON schema validation on all endpoints.
- Enforce field types and length limits (e.g., max string lengths for IDs, numeric bounds for `amount`).
- Reject unknown fields unless explicitly allowed.

## Error handling
- Provide structured errors with machine-readable `error` codes and human-friendly `message` fields.
- Example:

HTTP 400
{
  "success": false,
  "error": "invalid_payload",
  "message": "Missing required field: signature"
}

## Rate limiting & abuse mitigation
- Implement per-IP and per-account rate limits for transaction submission.
- Use backpressure and queuing for mining-related operations.

## Storage & privacy
- Do not store private keys. Only store public keys, signatures, and non-sensitive metadata.
- Consider encrypting on-disk private metadata related to transactions and keys at rest.

## Operational notes
- Monitor `pending_count`, block propagation times, and mining performance.
- Provide metrics endpoints for observability (Prometheus, etc.).

## Examples (curl)

Add transaction:

```bash
curl -X POST https://node.example.com/blockchain/transaction/add \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sender":"alice","recipient":"bob","amount":10,"timestamp":1703330400,"signature":"..."}'
```

Get merkle proof:

```bash
curl -X POST https://node.example.com/blockchain/merkle-proof \
  -H "Content-Type: application/json" \
  -d '{"transaction_hash":"abc123","block_index":10}'
```

---

## Security considerations (summary)
- Always verify cryptographic signatures server-side.
- Use TLS, authenticated endpoints, and strict validation.
- Protect mining and validation endpoints with access control.
- Defend against replay and double-spend by validating nonces/timestamps and transaction uniqueness before accepting into pending pool.

## References
- Bitcoin whitepaper — consensus and PoW concepts
- Merkle tree and proof construction references
