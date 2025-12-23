# Authentication Module API Reference

This document describes the RESTful API endpoints provided by the Authentication Module, request/response formats, error responses, authentication headers, and references.

**Base path:** `/auth`

**Notes:**
- All timestamps are UTC and represented as UNIX epoch seconds unless otherwise specified.
- Sensitive values (passwords, TOTP codes, session tokens) are never logged in plaintext.
- All responses use `application/json`.

**Table of Contents**
- User Registration — `POST /auth/register`
- User Login — `POST /auth/login`
- TOTP Setup — `POST /auth/setup-totp`
- Password Reset Request — `POST /auth/reset-password-request`
- Password Reset — `POST /auth/reset-password`
- Common error codes
- Authentication headers
- References

---

**User Registration**

POST /auth/register

Registers a new user account with secure password hashing and TOTP setup. Returns one-time secrets (TOTP secret and backup codes) which must be shown to the user only once.

Request JSON:

```json
{
  "username": "john_doe",
  "password": "SecurePassword123!@#",
  "client_ip": "203.0.113.12"  // optional, used for audit hashing
}
```

Success Response (201 or 200):

```json
{
  "success": true,
  "user_id": "uuid-here",
  "username": "john_doe",
  "totp_secret": "JBSWY3DPEBLW64TMMQ======",
  "backup_codes": [
    "A1B2-C3D4",
    "E5F6-G7H8",
    "..."
  ],
  "message": "Registration successful. Save backup codes and set up TOTP.",
  "qr_code_url": "data:image/png;base64,..."  
}
```

Error Responses:

- 400 Bad Request
  ```json
  {"error": "Password too weak", "reason": "Minimum length not met"}
  ```
- 409 Conflict
  ```json
  {"error": "Username already taken"}
  ```
- 500 Internal Server Error
  ```json
  {"error": "Registration failed"}
  ```

Security & Audit notes:
- The server logs an `AUTH_REGISTRATION` audit event to the blockchain using a SHA256 hash of the username (`user_hash`) and a hashed IP (`ip_hash`) if `client_ip` is provided.
- The `totp_secret` and `backup_codes` MUST be shown only once to the user; they are not stored in plaintext in external logs.

---

**User Login**

POST /auth/login

Authenticates a user and creates a session. If the user has TOTP enabled, the API may return an intermediate response requesting MFA.

Request JSON:

```json
{
  "username": "john_doe",
  "password": "SecurePassword123!@#",
  "totp_code": "123456",         // Optional, required if TOTP enabled
  "backup_code": "A1B2-C3D4",    // Optional alternative to totp_code
  "client_ip": "203.0.113.12"    // optional, for audit hashing
}
```

Success Response (200):

```json
{
  "success": true,
  "user_id": "uuid-here",
  "username": "john_doe",
  "session_token": "base64-encoded-token",
  "expires_at": 1702900000,
  "message": "Login successful"
}
```

Awaiting MFA Response (200):

```json
{
  "success": false,
  "status": "AWAITING_MFA",
  "message": "TOTP code required",
  "requires_mfa": true
}
```

Error Responses:

- 401 Unauthorized
  ```json
  {"error": "Invalid credentials"}
  ```
- 429 Too Many Requests
  ```json
  {"error": "Too many login attempts", "retry_after": 60}
  ```
- 423 Locked
  ```json
  {"error": "Account locked until 2024-12-21 10:30:00"}
  ```
- 500 Internal Server Error
  ```json
  {"error": "Authentication failed"}
  ```

Security & Audit notes:
- Successful logins emit an `AUTH_LOGIN` audit event containing `user_hash` (sha256 of username), `mfa_used` (boolean), `ip_hash` (sha256 of client IP if provided), and a hashed `session_id` (sha256 of the session token). Session tokens are not logged in plaintext.
- Failed login attempts emit `AUTH_LOGIN_FAILED` events with the failure reason (`invalid_password`, `user_not_found`, or `account_locked`) and failed attempt counts.

---

**TOTP Setup**

POST /auth/setup-totp

Generates a TOTP secret and a QR code (provisioning URI) for the authenticator app. User must confirm setup by providing a valid TOTP code (endpoint for confirmation may be separate depending on implementation).

Request JSON:

```json
{
  "session_token": "valid-session-token",
  "client_ip": "203.0.113.12" // optional
}
```

Success Response (200):

```json
{
  "success": true,
  "secret": "JBSWY3DPEBLW64TMMQ======",
  "qr_code_url": "data:image/png;base64,...",
  "provisioning_uri": "otpauth://totp/CryptoVault:username?secret=...",
  "message": "Scan QR code with authenticator app"
}
```

Error Responses: standard codes (401, 400, 500) as applicable.

Audit notes:
- On successful setup the system emits an `AUTH_MFA_SETUP` event to the blockchain containing `user_hash`, `mfa_method` ("TOTP") and `timestamp`.

---

**Password Reset (Bonus flow)**

POST /auth/reset-password-request

Requests a password reset token to be issued via secure channel (email/SMS) if an account exists. This endpoint MUST not reveal whether an account exists to prevent enumeration.

Request JSON:

```json
{
  "username": "john_doe"
}
```

Response (200):

```json
{
  "success": true,
  "message": "If account exists, reset instructions sent"
}
```

POST /auth/reset-password

Resets password using a token delivered to the user.

Request JSON:

```json
{
  "token": "reset-token-from-email",
  "new_password": "NewSecurePassword123!@#",
  "client_ip": "203.0.113.12"  // optional
}
```

Success Response (200):

```json
{
  "success": true,
  "message": "Password reset successful, please login"
}
```

Error Responses:
- 400 Bad Request — invalid token or weak password
- 401 Unauthorized — token expired or invalid
- 500 Internal Server Error

Audit notes:
- Successful resets emit `AUTH_PASSWORD_RESET` events with `user_hash`, `sessions_invalidated` (count), and `timestamp`.
- On reset, all active sessions for the user SHOULD be invalidated server-side.

---

**Common Error Codes**

The authentication API uses the following HTTP status codes and JSON formats for errors:

- 400 Bad Request
  ```json
  {"error": "Bad Request", "reason": "..."}
  ```
- 401 Unauthorized
  ```json
  {"error": "Unauthorized"}
  ```
- 409 Conflict
  ```json
  {"error": "Conflict", "reason": "Username already exists"}
  ```
- 429 Too Many Requests
  ```json
  {"error": "Too Many Requests", "retry_after": 60}
  ```
- 423 Locked
  ```json
  {"error": "Locked", "reason": "Account locked until ..."}
  ```
- 500 Internal Server Error
  ```json
  {"error": "Internal Server Error"}
  ```

Always prefer generic error messages for authentication failures to avoid username enumeration.

---

**Authentication Headers**

- `Authorization: Bearer <session_token>` — used to authenticate requests that require a logged-in user
- `X-CSRF-Token: <csrf_token>` — include when applicable for browser-based flows
- `Content-Type: application/json` — required for request bodies

Session token handling:
- Session tokens are opaque values generated by the server and must be presented in the `Authorization` header.
- Session tokens are valid until the `expires_at` timestamp returned at login. The server may support refresh tokens (not described here).

---

**Audit & Privacy**

- All authentication events are logged to an immutable blockchain audit ledger using the `AuditLogger`. Events use `user_hash` (SHA256(username)) and `ip_hash` (SHA256(client_ip)) to preserve privacy.
- Never include plaintext passwords, TOTP codes, or session tokens in audit entries. Only hashed session identifiers are recorded.

---

**OpenAPI / Swagger Notes**

This document can be converted to an OpenAPI (v3) spec. Recommended fields for OpenAPI:
- `components/schemas` for requests and responses
- Security scheme: `bearerAuth` (HTTP bearer token)
- Example responses per endpoint

A minimal OpenAPI security snippet:

```yaml
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
security:
  - bearerAuth: []
```

---

**References**

- RESTful API design standards
- OWASP Authentication Cheat Sheet
- OpenAPI/Swagger specification

---

*Document generated: Authentication Module API Reference*
