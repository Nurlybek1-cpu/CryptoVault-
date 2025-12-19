# TOTP (Time-Based One-Time Password)

## Overview

**TOTP** (Time-Based One-Time Password) is a widely-used two-factor authentication (2FA) algorithm that generates temporary numeric codes based on the current time. It's defined in RFC 6238 and is used by Google Authenticator, Microsoft Authenticator, and many other 2FA apps.

## Purpose

- **Two-Factor Authentication (2FA)**: Add second layer of security
- **Time-Based Security**: Codes expire after 30 seconds
- **Offline Generation**: No internet required
- **Standardized**: RFC 6238 ensures compatibility
- **Applications**: Google, GitHub, AWS, banking, VPNs

## Algorithm Specification

### Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| **Secret Key (K)** | 160+ bits | Shared secret (Base32 encoded) |
| **Time Step (X)** | 30 seconds | Time window duration |
| **T0** | 0 (Unix epoch) | Start time for counting |
| **Digits** | 6-8 | Output code length |
| **Hash** | SHA-1 (default) | HMAC hash function |

### TOTP Formula

```
TOTP = HOTP(K, T)

Where:
T = floor((Current_Unix_Time - T0) / X)
```

## How TOTP Works

### Step-by-Step Process

**1. Calculate Time Counter**
```
T = floor((Unix_Time - T0) / Time_Step)

Example:
Unix_Time = 1234567890
T0 = 0
Time_Step = 30

T = floor(1234567890 / 30) = 41152263
```

**2. Generate HOTP**
```
HOTP(K, T):
    # Create HMAC-SHA1 hash
    HS = HMAC-SHA1(K, T)

    # Dynamic truncation
    Offset = last_4_bits_of(HS)
    P = HS[Offset : Offset+4]  # Extract 4 bytes

    # Convert to integer and truncate
    Code = (P & 0x7FFFFFFF) mod 10^Digits
```

**3. Format Output**
```
Pad with leading zeros to Digits length
Example: 123456 (6 digits)
```

## Implementation Example

### Python Implementation

```python
import hmac
import hashlib
import time
import struct
import base64

class TOTP:
    def __init__(self, secret, digits=6, interval=30, hash_algo='sha1'):
        """
        Initialize TOTP generator

        Args:
            secret: Base32-encoded secret key
            digits: Number of digits in code (6 or 8)
            interval: Time step in seconds (default 30)
            hash_algo: Hash algorithm ('sha1', 'sha256', 'sha512')
        """
        self.secret = base64.b32decode(secret, casefold=True)
        self.digits = digits
        self.interval = interval
        self.hash_algo = hash_algo

    def generate_hotp(self, counter):
        """Generate HOTP code for given counter"""
        # Create HMAC hash
        hash_algos = {
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }

        counter_bytes = struct.pack('>Q', counter)
        hmac_hash = hmac.new(
            self.secret,
            counter_bytes,
            hash_algos[self.hash_algo]
        ).digest()

        # Dynamic truncation
        offset = hmac_hash[-1] & 0x0F
        code = struct.unpack('>I', hmac_hash[offset:offset+4])[0]
        code = (code & 0x7FFFFFFF) % (10 ** self.digits)

        # Pad with leading zeros
        return str(code).zfill(self.digits)

    def generate(self, timestamp=None):
        """Generate TOTP code for current time"""
        if timestamp is None:
            timestamp = time.time()

        counter = int(timestamp) // self.interval
        return self.generate_hotp(counter)

    def verify(self, code, timestamp=None, window=1):
        """
        Verify TOTP code with time window

        Args:
            code: Code to verify
            timestamp: Time to check (default: now)
            window: Number of time steps to check (+/- window)

        Returns:
            True if code valid within window
        """
        if timestamp is None:
            timestamp = time.time()

        counter = int(timestamp) // self.interval

        # Check current time and window before/after
        for i in range(-window, window + 1):
            check_counter = counter + i
            if self.generate_hotp(check_counter) == code:
                return True

        return False

# Usage Example
secret = "JBSWY3DPEHPK3PXP"  # Base32-encoded secret
totp = TOTP(secret, digits=6, interval=30)

# Generate code
code = totp.generate()
print(f"Current TOTP code: {code}")

# Verify code
is_valid = totp.verify(code)
print(f"Code valid: {is_valid}")

# Wait and generate new code
time.sleep(30)
new_code = totp.generate()
print(f"New TOTP code: {new_code}")
```

### QR Code Generation (for 2FA apps)

```python
import pyqrcode

def generate_totp_qr(secret, issuer, account_name):
    """
    Generate QR code for Google Authenticator

    Args:
        secret: Base32-encoded secret
        issuer: Service name (e.g., "MyApp")
        account_name: User identifier (e.g., "user@example.com")

    Returns:
        QR code URL
    """
    # Create otpauth URL
    url = f"otpauth://totp/{issuer}:{account_name}?secret={secret}&issuer={issuer}"

    # Generate QR code
    qr = pyqrcode.create(url)
    qr.png('totp_qr.png', scale=8)

    return url

# Example
secret = "JBSWY3DPEHPK3PXP"
url = generate_totp_qr(secret, "MyApp", "user@example.com")
print(f"Scan this with authenticator app:")
print(f"URL: {url}")
```

### Node.js Implementation

```javascript
const crypto = require('crypto');

class TOTP {
    constructor(secret, digits = 6, interval = 30, algorithm = 'sha1') {
        this.secret = Buffer.from(secret, 'base32');
        this.digits = digits;
        this.interval = interval;
        this.algorithm = algorithm;
    }

    generateHOTP(counter) {
        // Create HMAC
        const counterBuffer = Buffer.alloc(8);
        counterBuffer.writeBigUInt64BE(BigInt(counter));

        const hmac = crypto.createHmac(this.algorithm, this.secret);
        hmac.update(counterBuffer);
        const hash = hmac.digest();

        // Dynamic truncation
        const offset = hash[hash.length - 1] & 0x0f;
        const code = (
            ((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff)
        ) % Math.pow(10, this.digits);

        return code.toString().padStart(this.digits, '0');
    }

    generate(timestamp = Date.now()) {
        const counter = Math.floor(timestamp / 1000 / this.interval);
        return this.generateHOTP(counter);
    }

    verify(code, timestamp = Date.now(), window = 1) {
        const counter = Math.floor(timestamp / 1000 / this.interval);

        for (let i = -window; i <= window; i++) {
            if (this.generateHOTP(counter + i) === code) {
                return true;
            }
        }

        return false;
    }
}

// Usage
const totp = new TOTP('JBSWY3DPEHPK3PXP', 6, 30);
console.log('TOTP Code:', totp.generate());
```

## Security Considerations

### Secret Key Generation

```python
import secrets
import base64

def generate_totp_secret(length=20):
    """
    Generate random TOTP secret

    Args:
        length: Secret length in bytes (20 recommended)

    Returns:
        Base32-encoded secret
    """
    # Generate random bytes
    random_bytes = secrets.token_bytes(length)

    # Encode in Base32
    secret = base64.b32encode(random_bytes).decode('utf-8')

    # Remove padding
    return secret.rstrip('=')

# Generate new secret
new_secret = generate_totp_secret()
print(f"New TOTP secret: {new_secret}")
```

### Time Synchronization

**Critical**: Server and client must have synchronized time

```python
import ntplib
from datetime import datetime

def get_network_time():
    """Get accurate time from NTP server"""
    try:
        client = ntplib.NTPClient()
        response = client.request('pool.ntp.org', version=3)
        return response.tx_time
    except:
        return time.time()

# Use network time for TOTP
network_time = get_network_time()
code = totp.generate(timestamp=network_time)
```

### Rate Limiting

```python
class RateLimitedTOTP:
    def __init__(self, secret, max_attempts=3, lockout_time=300):
        self.totp = TOTP(secret)
        self.max_attempts = max_attempts
        self.lockout_time = lockout_time
        self.failed_attempts = {}

    def verify_with_rate_limit(self, user_id, code):
        """Verify TOTP with rate limiting"""
        now = time.time()

        # Check if user is locked out
        if user_id in self.failed_attempts:
            attempts, last_attempt = self.failed_attempts[user_id]

            if attempts >= self.max_attempts:
                if now - last_attempt < self.lockout_time:
                    return False, "Account locked. Try again later."
                else:
                    # Lockout expired
                    del self.failed_attempts[user_id]

        # Verify code
        if self.totp.verify(code):
            # Success - reset attempts
            if user_id in self.failed_attempts:
                del self.failed_attempts[user_id]
            return True, "Success"
        else:
            # Failed - record attempt
            if user_id not in self.failed_attempts:
                self.failed_attempts[user_id] = [1, now]
            else:
                attempts, _ = self.failed_attempts[user_id]
                self.failed_attempts[user_id] = [attempts + 1, now]

            remaining = self.max_attempts - self.failed_attempts[user_id][0]
            return False, f"Invalid code. {remaining} attempts remaining."

# Usage
protected_totp = RateLimitedTOTP("JBSWY3DPEHPK3PXP")
success, message = protected_totp.verify_with_rate_limit("user123", "123456")
print(message)
```

## Real-World Applications

### User Registration Flow

```python
class TwoFactorAuth:
    def __init__(self, app_name):
        self.app_name = app_name

    def enable_2fa(self, user_id, email):
        """Enable 2FA for user"""
        # Generate secret
        secret = generate_totp_secret()

        # Store secret in database (encrypted!)
        db.store_user_secret(user_id, encrypt(secret))

        # Generate QR code
        qr_url = generate_totp_qr(secret, self.app_name, email)

        return {
            'secret': secret,  # Show once to user
            'qr_url': qr_url,
            'backup_codes': self.generate_backup_codes(user_id)
        }

    def generate_backup_codes(self, user_id, count=10):
        """Generate one-time backup codes"""
        codes = [secrets.token_hex(4) for _ in range(count)]

        # Store hashed backup codes
        for code in codes:
            db.store_backup_code(user_id, hash_backup_code(code))

        return codes

    def verify_login(self, user_id, code):
        """Verify 2FA code during login"""
        # Get user's secret
        encrypted_secret = db.get_user_secret(user_id)
        secret = decrypt(encrypted_secret)

        # Verify TOTP
        totp = TOTP(secret)
        if totp.verify(code, window=1):
            return True

        # Check backup codes
        if self.verify_backup_code(user_id, code):
            return True

        return False
```

### API Authentication

```python
class TOTPAuthenticatedAPI:
    def __init__(self):
        self.sessions = {}

    def require_totp(self, user_id, api_key, totp_code):
        """Decorator for TOTP-protected API endpoints"""
        # Verify API key
        if not self.verify_api_key(user_id, api_key):
            return {"error": "Invalid API key"}, 401

        # Verify TOTP
        secret = db.get_user_secret(user_id)
        totp = TOTP(secret)

        if not totp.verify(totp_code, window=2):
            return {"error": "Invalid TOTP code"}, 401

        # Create session
        session_token = secrets.token_urlsafe(32)
        self.sessions[session_token] = {
            'user_id': user_id,
            'created': time.time(),
            'expires': time.time() + 3600  # 1 hour
        }

        return {"session_token": session_token}, 200

# Example API call
api = TOTPAuthenticatedAPI()
response, status = api.require_totp(
    user_id="123",
    api_key="abc123",
    totp_code="123456"
)
```

## TOTP vs Alternatives

| Method | Security | Usability | Offline | Cost |
|--------|----------|-----------|---------|------|
| **TOTP** | High | Good | Yes | Free |
| **SMS OTP** | Medium | Easy | No | Paid |
| **Push Notifications** | High | Easy | No | Paid |
| **Hardware Keys (U2F)** | Highest | Good | Yes | Hardware cost |
| **Email OTP** | Low | Easy | No | Free |

## Best Practices

1. ✅ **Use 160-bit (20-byte) secrets** minimum
2. ✅ **Generate secrets with CSPRNG** (secrets.token_bytes)
3. ✅ **Store secrets encrypted** in database
4. ✅ **Provide backup codes** (10-20 one-time codes)
5. ✅ **Allow time window** (±1 time step = 60s total)
6. ✅ **Implement rate limiting** (3-5 attempts per lockout)
7. ✅ **Use QR codes** for easy setup
8. ✅ **Support recovery methods** (backup codes, admin recovery)
9. ❌ **Don't transmit secrets** over insecure channels
10. ❌ **Don't use short secrets** (<128 bits)
11. ❌ **Don't allow unlimited attempts** (prevents brute force)

## Conclusion

TOTP is the **industry standard** for time-based two-factor authentication:

**Advantages**:
- Standardized (RFC 6238)
- Offline generation
- No SMS costs
- Wide app support (Google Authenticator, Authy, etc.)
- More secure than SMS

**Implementation Checklist**:
```
✓ Generate 160-bit random secret
✓ Store encrypted in database
✓ Display QR code for user
✓ Provide backup codes
✓ Implement rate limiting
✓ Allow ±1 time step window
✓ Use SHA-1 (default) or SHA-256
✓ 6-digit codes (or 8 for high security)
```

**Use TOTP for**:
- User account protection
- API authentication
- Privileged operations
- Compliance requirements (PCI-DSS, HIPAA)

**TOTP is the recommended 2FA method for modern applications!**
