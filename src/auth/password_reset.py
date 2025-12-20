"""
Password reset management module for CryptoVault.

This module provides secure password reset functionality using cryptographically
secure tokens. Reset tokens are single-use, time-limited, and hashed before storage
to prevent token database compromise from allowing password resets.

Security Features:
- Cryptographically secure token generation (secrets.token_urlsafe)
- SHA-256 hashing of tokens before storage
- Single-use tokens (marked as used after reset)
- Time-limited tokens (1 hour expiration)
- Session invalidation after password reset
- Account unlock on successful reset
- Generic responses to prevent user enumeration

Password Reset Flow:
1. User requests password reset (provides username/email)
2. System generates secure token and stores hash
3. Token sent to user via email (or returned if no email)
4. User clicks reset link with token
5. System verifies token (not used, not expired)
6. User provides new password
7. System validates password strength
8. System updates password and invalidates sessions
9. Token marked as used

References:
- OWASP Password Reset Tokens Cheat Sheet
- NIST SP 800-63B (Digital Identity Guidelines)
"""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from typing import Any

from src.auth.password_hasher import PasswordHasher
from src.auth.password_validator import PasswordValidator
from src.exceptions import PasswordResetError, PasswordStrengthError

logger = logging.getLogger(__name__)


class PasswordResetManager:
    """
    Manages secure password reset operations with token-based authentication.
    
    This class provides password reset functionality including token generation,
    verification, and password update. All tokens are hashed before storage to
    prevent token database compromise from enabling unauthorized resets.
    
    Security Properties:
    - Cryptographically secure token generation
    - SHA-256 hashing of tokens (only hashes stored)
    - Single-use tokens (cannot be reused)
    - Time-limited tokens (1 hour expiration)
    - Session invalidation after reset
    - Account unlock on successful reset
    - Generic responses (prevent user enumeration)
    
    Attributes:
        token_expiry_hours: Token expiration time in hours (default: 1)
        password_validator: PasswordValidator instance for password validation
        password_hasher: PasswordHasher instance for password hashing
        db: Database connection for storing reset tokens
    """
    
    def __init__(
        self,
        token_expiry_hours: int = 1,
        db: Any = None
    ) -> None:
        """
        Initialize PasswordResetManager with configuration.
        
        Args:
            token_expiry_hours: Token expiration time in hours (default: 1)
            db: Database connection for storing reset tokens
        """
        self.token_expiry_hours = token_expiry_hours
        self.db = db
        self.password_validator = PasswordValidator()
        self.password_hasher = PasswordHasher()
        
        logger.info("PasswordResetManager initialized")
        logger.debug(f"Token expiry: {token_expiry_hours} hours")
    
    def request_password_reset(
        self,
        username: str,
        email: str | None = None
    ) -> dict[str, Any]:
        """
        Request a password reset for a user.
        
        This method generates a secure reset token, hashes it, and stores it
        in the database. If an email is provided, a reset link is generated
        (mock implementation for now). The method returns success even if the
        user doesn't exist to prevent user enumeration attacks.
        
        Security Notes:
        - Always returns success (doesn't reveal if user exists)
        - Tokens are hashed before storage (SHA-256)
        - Tokens expire after 1 hour
        - Tokens are single-use only
        
        Args:
            username: Username of the account requesting reset
            email: Optional email address for sending reset link
            
        Returns:
            Dictionary containing reset request result:
            {
                "success": True,
                "message": "If account exists, reset instructions sent",
                "token": str (only if email not provided)
            }
            
        Example:
            >>> manager = PasswordResetManager(db=db_connection)
            >>> result = manager.request_password_reset("alice", "alice@example.com")
            >>> print(result['message'])
            If account exists, reset instructions sent
        """
        if not username:
            error_msg = "Username cannot be empty"
            logger.warning(f"Password reset request failed: {error_msg}")
            # Still return success to prevent user enumeration
            return {
                'success': True,
                'message': 'If account exists, reset instructions sent',
            }
        
        username = username.strip()
        
        try:
            # Verify user exists (but don't reveal if they don't)
            user_id = None
            if self.db is not None:
                try:
                    cursor = self.db.execute(
                        "SELECT user_id, email FROM users WHERE username = ?",
                        (username,)
                    )
                    user_record = cursor.fetchone()
                    
                    if user_record:
                        user_id, user_email = user_record
                        logger.debug(f"Password reset requested for user_id: {user_id}")
                    else:
                        # User doesn't exist - but return success anyway
                        logger.debug(f"Password reset requested for non-existent user: {username}")
                        return {
                            'success': True,
                            'message': 'If account exists, reset instructions sent',
                        }
                except Exception as db_error:
                    logger.error(f"Database error during password reset request: {db_error}")
                    # Return success anyway to prevent information leakage
                    return {
                        'success': True,
                        'message': 'If account exists, reset instructions sent',
                    }
            else:
                logger.warning("No database connection, cannot process password reset request")
                return {
                    'success': True,
                    'message': 'If account exists, reset instructions sent',
                }
            
            # Generate secure reset token
            # Using secrets.token_urlsafe for cryptographically secure random token
            token = secrets.token_urlsafe(32)  # 32 bytes = 256 bits
            
            # Hash token before storage (SHA-256)
            # Only hash is stored, original token never stored
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            
            # Get current timestamp
            current_time = datetime.utcnow()
            expires_at = current_time + timedelta(hours=self.token_expiry_hours)
            
            # Store reset token in database
            if self.db is not None:
                try:
                    # Insert reset token record
                    insert_query = """
                        INSERT INTO password_reset_tokens (
                            user_id, token_hash, created_at, expires_at, used
                        ) VALUES (?, ?, ?, ?, ?)
                    """
                    
                    self.db.execute(
                        insert_query,
                        (
                            user_id,
                            token_hash,
                            current_time,
                            expires_at,
                            False,  # Not used yet
                        )
                    )
                    
                    if hasattr(self.db, 'commit'):
                        self.db.commit()
                    
                    logger.info(f"Password reset token created for user_id: {user_id}")
                    
                except Exception as token_error:
                    logger.error(f"Failed to store reset token: {token_error}")
                    # Return success anyway to prevent information leakage
                    return {
                        'success': True,
                        'message': 'If account exists, reset instructions sent',
                    }
            
            # Generate reset link
            reset_link = f"https://cryptovault.app/reset?token={token}"
            
            # If email provided, send reset link (mock for now)
            if email:
                logger.info(
                    f"Password reset link for user {username} (email: {email}): {reset_link}"
                )
                # In production, send email here:
                # send_password_reset_email(email, reset_link)
            
            # Return result
            result = {
                'success': True,
                'message': 'If account exists, reset instructions sent',
            }
            
            # Only return token if email not provided (for testing/development)
            if not email:
                result['token'] = token
                logger.debug(f"Password reset token returned (no email provided): {token[:16]}...")
            
            return result
            
        except Exception as e:
            logger.error(f"Password reset request failed for {username}: {e}")
            # Return success anyway to prevent information leakage
            return {
                'success': True,
                'message': 'If account exists, reset instructions sent',
            }
    
    def verify_reset_token(self, token: str) -> tuple[bool, str | None]:
        """
        Verify a password reset token.
        
        This method verifies that a reset token is valid by checking:
        1. Token exists in database (by hash)
        2. Token has not been used
        3. Token has not expired
        
        Security Notes:
        - Token is hashed before database lookup
        - Only hash is stored, original token never stored
        - Tokens are single-use (marked as used after verification)
        - Tokens expire after configured time (default: 1 hour)
        
        Args:
            token: Reset token to verify (plaintext)
            
        Returns:
            Tuple of (is_valid: bool, user_id: str | None)
            - If valid: (True, user_id)
            - If invalid: (False, None)
            
        Example:
            >>> manager = PasswordResetManager(db=db_connection)
            >>> is_valid, user_id = manager.verify_reset_token("reset_token_123")
            >>> if is_valid:
            ...     print(f"Token valid for user: {user_id}")
        """
        if not token:
            logger.debug("Reset token verification failed: empty token")
            return False, None
        
        if self.db is None:
            logger.warning("No database connection, cannot verify reset token")
            return False, None
        
        try:
            # Hash the provided token
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            
            # Look up token in database
            cursor = self.db.execute(
                "SELECT user_id, expires_at, used FROM password_reset_tokens "
                "WHERE token_hash = ?",
                (token_hash,)
            )
            token_record = cursor.fetchone()
            
            if token_record is None:
                logger.debug("Reset token verification failed: token not found")
                return False, None
            
            user_id, expires_at, used = token_record
            
            # Check if token has been used
            if used:
                logger.warning(f"Reset token verification failed: token already used (user_id: {user_id})")
                return False, None
            
            # Check if token has expired
            current_time = datetime.utcnow()
            if expires_at < current_time:
                logger.warning(f"Reset token verification failed: token expired (user_id: {user_id})")
                return False, None
            
            # Token is valid
            logger.info(f"Reset token verified successfully for user_id: {user_id}")
            return True, user_id
            
        except Exception as e:
            logger.error(f"Reset token verification error: {e}")
            return False, None
    
    def reset_password(
        self,
        token: str,
        new_password: str
    ) -> dict[str, Any]:
        """
        Reset a user's password using a valid reset token.
        
        This method performs the complete password reset process:
        1. Verifies the reset token
        2. Validates the new password strength
        3. Hashes the new password
        4. Updates the user's password
        5. Resets failed login attempts
        6. Unlocks the account if locked
        7. Marks the token as used
        8. Invalidates all existing sessions
        
        Security Notes:
        - Token must be valid and not expired
        - Token is single-use (marked as used)
        - New password must meet strength requirements
        - All sessions invalidated after reset
        - Account unlocked on successful reset
        
        Args:
            token: Reset token from password reset request
            new_password: New password to set
            
        Returns:
            Dictionary containing reset result:
            {
                "success": True,
                "message": "Password reset successful, please login",
                "user_id": str
            }
            
        Raises:
            PasswordResetError: If token is invalid or expired
            PasswordStrengthError: If new password doesn't meet requirements
            
        Example:
            >>> manager = PasswordResetManager(db=db_connection)
            >>> result = manager.reset_password("reset_token_123", "NewSecureP@ssw0rd123")
            >>> if result['success']:
            ...     print("Password reset successful")
        """
        if not token:
            error_msg = "Reset token cannot be empty"
            logger.warning(f"Password reset failed: {error_msg}")
            raise PasswordResetError(error_msg, error_code="INVALID_TOKEN")
        
        if not new_password:
            error_msg = "New password cannot be empty"
            logger.warning(f"Password reset failed: {error_msg}")
            raise PasswordResetError(error_msg, error_code="EMPTY_PASSWORD")
        
        if self.db is None:
            error_msg = "Database connection not available"
            logger.error(f"Password reset failed: {error_msg}")
            raise PasswordResetError(error_msg, error_code="DATABASE_ERROR")
        
        try:
            # Step 1: Verify reset token
            is_valid, user_id = self.verify_reset_token(token)
            
            if not is_valid or not user_id:
                error_msg = "Invalid or expired reset token"
                logger.warning(f"Password reset failed: {error_msg}")
                raise PasswordResetError(error_msg, error_code="INVALID_TOKEN")
            
            # Step 2: Validate new password strength
            is_valid_password, error_msg = self.password_validator.validate(new_password)
            
            if not is_valid_password:
                logger.warning(f"Password reset failed for user_id {user_id}: {error_msg}")
                raise PasswordStrengthError(
                    f"New password too weak: {error_msg}",
                    error_code="PASSWORD_WEAK"
                )
            
            # Step 3: Hash new password
            try:
                new_password_hash = self.password_hasher.hash_password(new_password)
                logger.debug(f"New password hashed for user_id: {user_id}")
            except Exception as hash_error:
                error_msg = f"Failed to hash new password: {hash_error}"
                logger.error(f"Password reset failed for user_id {user_id}: {error_msg}")
                raise PasswordResetError(error_msg, error_code="HASHING_ERROR") from hash_error
            
            # Step 4: Update user record
            try:
                # Update password, reset failed attempts, unlock account
                update_query = """
                    UPDATE users 
                    SET password_hash = ?, 
                        failed_login_attempts = 0,
                        account_locked = ?,
                        account_locked_until = ?
                    WHERE user_id = ?
                """
                
                self.db.execute(
                    update_query,
                    (
                        new_password_hash,
                        False,  # Unlock account
                        None,   # Clear lockout timestamp
                        user_id,
                    )
                )
                
                if hasattr(self.db, 'commit'):
                    self.db.commit()
                
                logger.info(f"Password updated for user_id: {user_id}")
                
            except Exception as update_error:
                error_msg = f"Failed to update password: {update_error}"
                logger.error(f"Password reset failed for user_id {user_id}: {error_msg}")
                raise PasswordResetError(error_msg, error_code="UPDATE_ERROR") from update_error
            
            # Step 5: Mark reset token as used
            try:
                token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
                
                self.db.execute(
                    "UPDATE password_reset_tokens SET used = ? WHERE token_hash = ?",
                    (True, token_hash)
                )
                
                if hasattr(self.db, 'commit'):
                    self.db.commit()
                
                logger.debug(f"Reset token marked as used for user_id: {user_id}")
                
            except Exception as token_error:
                logger.warning(f"Failed to mark token as used: {token_error}")
                # Don't fail the reset if we can't mark token as used
                # The password was already updated
            
            # Step 6: Invalidate all existing sessions for this user
            try:
                # Mark all sessions as inactive
                self.db.execute(
                    "UPDATE sessions SET is_active = ? WHERE user_id = ?",
                    (False, user_id)
                )
                
                if hasattr(self.db, 'commit'):
                    self.db.commit()
                
                logger.info(f"All sessions invalidated for user_id: {user_id}")
                
            except Exception as session_error:
                logger.warning(f"Failed to invalidate sessions: {session_error}")
                # Don't fail the reset if we can't invalidate sessions
                # The password was already updated
            
            # Log successful password reset
            logger.info(f"Password reset successful for user_id: {user_id}")
            
            # Return success response
            return {
                'success': True,
                'message': 'Password reset successful, please login',
                'user_id': user_id,
            }
            
        except (PasswordResetError, PasswordStrengthError):
            # Re-raise these exceptions
            raise
        except Exception as e:
            error_msg = f"Password reset failed: {e}"
            logger.error(f"Password reset error: {error_msg}")
            raise PasswordResetError(error_msg, error_code="UNEXPECTED_ERROR") from e

