"""
Session management module for CryptoVault.

This module provides secure session token generation, verification, and management
for user authentication sessions. It implements industry-standard session security
practices including HMAC signing, expiration tracking, and activity monitoring.

Security Features:
- HMAC-SHA256 signed session tokens
- Cryptographically secure random nonces
- Session expiration tracking
- Activity-based session management
- Secure session invalidation
- Automatic cleanup of expired sessions

Session Lifecycle:
1. Session created on successful login
2. Session verified on each authenticated request
3. Activity updated on each request
4. Session invalidated on logout or security event
5. Expired sessions cleaned up periodically

References:
- OWASP Session Management Cheat Sheet
- docs/algorithms/totp.md
- NIST SP 800-63B (Digital Identity Guidelines)
"""

import base64
import hmac
import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from typing import Any, Optional

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Manages user authentication sessions with secure token generation and verification.
    
    This class provides comprehensive session management including token generation,
    verification, activity tracking, and cleanup. Sessions are cryptographically
    signed using HMAC-SHA256 to prevent tampering.
    
    Security Properties:
    - HMAC-SHA256 signed tokens (prevents tampering)
    - Cryptographically secure random nonces
    - Session expiration enforcement
    - Activity tracking for security monitoring
    - Secure invalidation (soft delete)
    - Automatic cleanup of expired sessions
    
    Attributes:
        secret_key: Application secret key for HMAC signing
        default_expiry_hours: Default session expiration time (24 hours)
        db: Database connection for session storage
    """
    
    def __init__(
        self,
        secret_key: bytes | None = None,
        default_expiry_hours: int = 24,
        db: Any = None
    ) -> None:
        """
        Initialize SessionManager with secret key and configuration.
        
        Args:
            secret_key: Application secret key for HMAC signing.
                       If None, generates a random key (not recommended for production).
            default_expiry_hours: Default session expiration in hours (default: 24)
            db: Database connection for session storage
        """
        # Generate secret key if not provided (for development only)
        if secret_key is None:
            logger.warning("No secret key provided, generating random key (not for production!)")
            secret_key = secrets.token_bytes(32)
        
        self.secret_key = secret_key
        self.default_expiry_hours = default_expiry_hours
        self.db = db
        
        logger.info("SessionManager initialized")
        logger.debug(f"Default session expiry: {default_expiry_hours} hours")
    
    def generate_session_token(self, user_id: str) -> str:
        """
        Generate a secure session token using HMAC-SHA256.
        
        Creates a cryptographically signed session token that includes the user ID,
        timestamp, and random nonce. The token is signed with HMAC-SHA256 to
        prevent tampering.
        
        Token Format:
        - Message: user_id || timestamp || nonce (all as bytes)
        - Signature: HMAC-SHA256(message, secret_key)
        - Output: base64(user_id || timestamp || nonce || signature)
        
        Security Notes:
        - Uses cryptographically secure random nonce
        - HMAC prevents token tampering
        - Base64 encoding for safe transmission
        - Timestamp included for expiration validation
        
        Args:
            user_id: User identifier for the session
            
        Returns:
            Base64-encoded session token string
            
        Example:
            >>> manager = SessionManager(secret_key=b"my_secret_key")
            >>> token = manager.generate_session_token("user123")
            >>> print(token[:20])
            eyJ0eXAiOiJKV1QiLCJhbGc
        """
        if not user_id:
            error_msg = "User ID cannot be empty"
            logger.error(f"Session token generation failed: {error_msg}")
            raise ValueError(error_msg)
        
        # Generate random nonce (32 bytes = 256 bits)
        nonce = secrets.token_bytes(32)
        
        # Get current timestamp
        timestamp = int(datetime.utcnow().timestamp())
        timestamp_bytes = timestamp.to_bytes(8, byteorder='big')
        
        # Create message: user_id || timestamp || nonce
        user_id_bytes = user_id.encode('utf-8')
        message = user_id_bytes + timestamp_bytes + nonce
        
        # Sign message with HMAC-SHA256
        signature = hmac.new(
            self.secret_key,
            message,
            hashlib.sha256
        ).digest()
        
        # Combine message and signature: user_id || timestamp || nonce || signature
        token_data = message + signature
        
        # Encode to base64 for safe transmission
        session_token = base64.urlsafe_b64encode(token_data).decode('utf-8')
        
        logger.debug(f"Session token generated for user_id: {user_id}")
        
        return session_token
    
    def create_session(
        self,
        user_id: str,
        expires_in_hours: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None
    ) -> dict[str, Any]:
        """
        Create a new session and store it in the database.
        
        Generates a session token, creates a session record with metadata,
        and stores it in the database. The session includes tracking information
        for security monitoring.
        
        Args:
            user_id: User identifier for the session
            expires_in_hours: Session expiration in hours (default: 24)
            ip_address: Optional client IP address (hashed before storage)
            user_agent: Optional user agent string (hashed before storage)
            
        Returns:
            Dictionary containing session information:
            {
                "session_id": str,
                "user_id": str,
                "session_token": str,
                "created_at": datetime,
                "expires_at": datetime,
                "ip_hash": str | None,
                "user_agent_hash": str | None,
                "is_active": bool,
                "last_activity": datetime
            }
            
        Raises:
            ValueError: If user_id is empty
            RuntimeError: If database operation fails
        """
        if not user_id:
            error_msg = "User ID cannot be empty"
            logger.error(f"Session creation failed: {error_msg}")
            raise ValueError(error_msg)
        
        if expires_in_hours is None:
            expires_in_hours = self.default_expiry_hours
        
        if expires_in_hours < 1:
            logger.warning(f"Invalid expires_in_hours={expires_in_hours}, using default")
            expires_in_hours = self.default_expiry_hours
        
        # Generate session token
        session_token = self.generate_session_token(user_id)
        
        # Generate unique session ID
        session_id = secrets.token_urlsafe(16)
        
        # Get current timestamp
        current_time = datetime.utcnow()
        expires_at = current_time + timedelta(hours=expires_in_hours)
        
        # Hash IP address if provided
        ip_hash = None
        if ip_address:
            ip_hash = hashlib.sha256(ip_address.encode('utf-8')).hexdigest()
        
        # Hash user agent if provided
        user_agent_hash = None
        if user_agent:
            user_agent_hash = hashlib.sha256(user_agent.encode('utf-8')).hexdigest()
        
        # Create session record
        session_record = {
            'session_id': session_id,
            'user_id': user_id,
            'session_token': session_token,
            'created_at': current_time,
            'expires_at': expires_at,
            'ip_hash': ip_hash,
            'user_agent_hash': user_agent_hash,
            'is_active': True,
            'last_activity': current_time,
        }
        
        # Store session in database
        if self.db is not None:
            try:
                insert_query = """
                    INSERT INTO sessions (
                        session_id, user_id, session_token, created_at,
                        expires_at, ip_hash, user_agent_hash, is_active, last_activity
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                
                self.db.execute(
                    insert_query,
                    (
                        session_id,
                        user_id,
                        session_token,
                        current_time,
                        expires_at,
                        ip_hash,
                        user_agent_hash,
                        True,
                        current_time,
                    )
                )
                
                if hasattr(self.db, 'commit'):
                    self.db.commit()
                
                logger.info(f"Session created for user_id: {user_id} (session_id: {session_id})")
                
            except Exception as db_error:
                error_msg = "Failed to create session in database"
                logger.error(f"{error_msg} for user_id {user_id}: {db_error}")
                raise RuntimeError(error_msg) from db_error
        else:
            logger.warning("No database connection, session not persisted")
        
        return session_record
    
    def verify_session(self, session_token: str) -> tuple[bool, dict[str, Any] | None]:
        """
        Verify a session token and return session information.
        
        This method performs comprehensive session verification including:
        - Token format validation
        - HMAC signature verification
        - Database lookup
        - Active status check
        - Expiration check
        
        Security Notes:
        - Uses constant-time comparison for token matching
        - Verifies HMAC signature to prevent tampering
        - Checks expiration to prevent use of expired sessions
        - Validates active status for revoked sessions
        
        Args:
            session_token: Session token to verify
            
        Returns:
            Tuple of (is_valid: bool, session_dict: dict | None)
            - If valid: (True, session dictionary)
            - If invalid: (False, None)
            
        Example:
            >>> manager = SessionManager(secret_key=b"my_secret_key")
            >>> session = manager.create_session("user123")
            >>> is_valid, session_data = manager.verify_session(session['session_token'])
            >>> print(is_valid)
            True
        """
        if not session_token:
            logger.debug("Session verification failed: empty token")
            return False, None
        
        try:
            # Decode base64 token
            try:
                token_data = base64.urlsafe_b64decode(session_token.encode('utf-8'))
            except Exception as decode_error:
                logger.debug(f"Session verification failed: invalid base64 token: {decode_error}")
                return False, None
            
            # Extract components
            # Token format: user_id || timestamp || nonce || signature
            # Signature is 32 bytes (SHA-256 output)
            if len(token_data) < 32:
                logger.debug("Session verification failed: token too short")
                return False, None
            
            signature = token_data[-32:]
            message = token_data[:-32]
            
            # Verify HMAC signature
            expected_signature = hmac.new(
                self.secret_key,
                message,
                hashlib.sha256
            ).digest()
            
            # Constant-time comparison
            if not hmac.compare_digest(signature, expected_signature):
                logger.warning("Session verification failed: invalid signature")
                return False, None
            
            # Extract user_id and timestamp from message
            # Message format: user_id (variable) || timestamp (8 bytes) || nonce (32 bytes)
            if len(message) < 40:  # At least 8 bytes timestamp + 32 bytes nonce
                logger.debug("Session verification failed: message too short")
                return False, None
            
            timestamp_bytes = message[-40:-32]
            timestamp = int.from_bytes(timestamp_bytes, byteorder='big')
            
            # Check if token is expired (older than 24 hours by default)
            current_timestamp = int(datetime.utcnow().timestamp())
            token_age = current_timestamp - timestamp
            
            # Allow tokens up to default_expiry_hours old
            max_age = self.default_expiry_hours * 3600
            if token_age > max_age:
                logger.debug(f"Session verification failed: token expired (age: {token_age}s)")
                return False, None
            
            # Look up session in database
            if self.db is not None:
                try:
                    cursor = self.db.execute(
                        "SELECT session_id, user_id, session_token, created_at, "
                        "expires_at, ip_hash, user_agent_hash, is_active, last_activity "
                        "FROM sessions WHERE session_token = ?",
                        (session_token,)
                    )
                    session_record = cursor.fetchone()
                    
                    if session_record is None:
                        logger.debug("Session verification failed: session not found in database")
                        return False, None
                    
                    # Extract session data
                    (session_id, user_id, stored_token, created_at, expires_at,
                     ip_hash, user_agent_hash, is_active, last_activity) = session_record
                    
                    # Verify token matches (constant-time comparison)
                    if not hmac.compare_digest(session_token, stored_token):
                        logger.warning("Session verification failed: token mismatch")
                        return False, None
                    
                    # Check if session is active
                    if not is_active:
                        logger.debug("Session verification failed: session inactive")
                        return False, None
                    
                    # Check if session has expired
                    current_time = datetime.utcnow()
                    if expires_at and expires_at < current_time:
                        logger.debug("Session verification failed: session expired")
                        # Mark as inactive
                        try:
                            self.db.execute(
                                "UPDATE sessions SET is_active = ? WHERE session_token = ?",
                                (False, session_token)
                            )
                            if hasattr(self.db, 'commit'):
                                self.db.commit()
                        except Exception:
                            pass  # Best effort
                        return False, None
                    
                    # Session is valid
                    session_dict = {
                        'session_id': session_id,
                        'user_id': user_id,
                        'session_token': session_token,
                        'created_at': created_at,
                        'expires_at': expires_at,
                        'ip_hash': ip_hash,
                        'user_agent_hash': user_agent_hash,
                        'is_active': is_active,
                        'last_activity': last_activity,
                    }
                    
                    logger.debug(f"Session verified successfully for user_id: {user_id}")
                    return True, session_dict
                    
                except Exception as db_error:
                    logger.error(f"Database error during session verification: {db_error}")
                    return False, None
            else:
                # No database, just verify token signature
                logger.debug("No database connection, verifying token signature only")
                return True, None
                
        except Exception as e:
            logger.error(f"Session verification failed: unexpected error: {e}")
            return False, None
    
    def invalidate_session(self, session_token: str) -> bool:
        """
        Invalidate a session by marking it as inactive.
        
        This method performs a soft delete by setting is_active = False.
        The session record remains in the database for audit purposes but
        cannot be used for authentication.
        
        Args:
            session_token: Session token to invalidate
            
        Returns:
            True if session was successfully invalidated, False otherwise
            
        Example:
            >>> manager = SessionManager(secret_key=b"my_secret_key")
            >>> session = manager.create_session("user123")
            >>> manager.invalidate_session(session['session_token'])
            True
        """
        if not session_token:
            logger.warning("Session invalidation failed: empty token")
            return False
        
        if self.db is None:
            logger.warning("Session invalidation failed: no database connection")
            return False
        
        try:
            # Mark session as inactive
            cursor = self.db.execute(
                "UPDATE sessions SET is_active = ? WHERE session_token = ?",
                (False, session_token)
            )
            
            if hasattr(self.db, 'commit'):
                self.db.commit()
            
            rows_affected = cursor.rowcount if hasattr(cursor, 'rowcount') else 0
            
            if rows_affected > 0:
                logger.info(f"Session invalidated: {session_token[:16]}...")
                return True
            else:
                logger.debug("Session invalidation: session not found")
                return False
                
        except Exception as e:
            logger.error(f"Session invalidation failed: {e}")
            return False
    
    def update_activity(self, session_token: str) -> bool:
        """
        Update the last activity timestamp for a session.
        
        This method is called on each authenticated request to track session
        activity. It helps identify active vs. idle sessions for security
        monitoring and can be used to extend session lifetime.
        
        Args:
            session_token: Session token to update
            
        Returns:
            True if activity was successfully updated, False otherwise
            
        Example:
            >>> manager = SessionManager(secret_key=b"my_secret_key")
            >>> session = manager.create_session("user123")
            >>> manager.update_activity(session['session_token'])
            True
        """
        if not session_token:
            logger.warning("Activity update failed: empty token")
            return False
        
        if self.db is None:
            logger.debug("Activity update skipped: no database connection")
            return False
        
        try:
            current_time = datetime.utcnow()
            
            cursor = self.db.execute(
                "UPDATE sessions SET last_activity = ? WHERE session_token = ? AND is_active = ?",
                (current_time, session_token, True)
            )
            
            if hasattr(self.db, 'commit'):
                self.db.commit()
            
            rows_affected = cursor.rowcount if hasattr(cursor, 'rowcount') else 0
            
            if rows_affected > 0:
                logger.debug(f"Session activity updated: {session_token[:16]}...")
                return True
            else:
                logger.debug("Activity update: session not found or inactive")
                return False
                
        except Exception as e:
            logger.error(f"Activity update failed: {e}")
            return False
    
    def cleanup_expired_sessions(self) -> int:
        """
        Delete all expired sessions from the database.
        
        This method should be called periodically (e.g., via a background task)
        to remove expired session records and prevent database bloat.
        
        Security Notes:
        - Only deletes sessions where expires_at < current_time
        - Does not delete active sessions
        - Returns count for monitoring purposes
        
        Returns:
            Number of sessions deleted
            
        Example:
            >>> manager = SessionManager(secret_key=b"my_secret_key")
            >>> deleted_count = manager.cleanup_expired_sessions()
            >>> print(f"Deleted {deleted_count} expired sessions")
            Deleted 15 expired sessions
        """
        if self.db is None:
            logger.warning("Cleanup skipped: no database connection")
            return 0
        
        try:
            current_time = datetime.utcnow()
            
            # Delete expired sessions
            cursor = self.db.execute(
                "DELETE FROM sessions WHERE expires_at < ?",
                (current_time,)
            )
            
            if hasattr(self.db, 'commit'):
                self.db.commit()
            
            deleted_count = cursor.rowcount if hasattr(cursor, 'rowcount') else 0
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} expired sessions")
            else:
                logger.debug("No expired sessions to clean up")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")
            return 0

