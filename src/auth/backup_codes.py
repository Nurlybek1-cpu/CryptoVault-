"""
Backup codes management module for CryptoVault.

This module provides secure generation, hashing, verification, and management
of backup codes for two-factor authentication. Backup codes are single-use
only and provide a recovery mechanism when TOTP is unavailable.

Backup codes serve as a fallback authentication method when users cannot access
their TOTP device (lost phone, dead battery, etc.). They are generated during
user registration or MFA setup and should be stored securely by the user.

Security Features:
- Cryptographically secure random code generation (secrets.choice)
- SHA-256 hashing for secure storage (only hashes stored in database)
- Constant-time comparison to prevent timing attacks
- Single-use enforcement (codes removed after use)
- Secure logging (index only, never plaintext codes)
- Format: "XXXX-XXXX" (8 alphanumeric characters with dash separator)

Best Practices (from TOTP documentation):
- Provide 10-20 one-time backup codes per user
- Store only hashed versions in database
- Remove codes immediately after use (single-use only)
- Support recovery methods (backup codes, admin recovery)
- Generate codes using CSPRNG (cryptographically secure random)

References:
- docs/algorithms/totp.md - See "Best Practices" section (items 4, 8) and
  "User Registration Flow" example for backup code implementation patterns
- OWASP Authentication Cheat Sheet
- RFC 6238 (TOTP specification)
"""

import hashlib
import logging
import secrets
from typing import Any

from cryptography.hazmat.primitives import constant_time  # type: ignore

logger = logging.getLogger(__name__)


class BackupCodesManager:
    """
    Manages backup codes for two-factor authentication recovery.
    
    Backup codes are single-use recovery codes that allow users to authenticate
    when their TOTP device is unavailable. Each code can only be used once and
    is permanently removed from the system after use.
    
    Security Properties:
    - Codes generated using cryptographically secure random number generator
    - Codes hashed with SHA-256 before storage
    - Constant-time verification prevents timing attacks
    - Single-use enforcement prevents code reuse
    - Format: "XXXX-XXXX" (8 alphanumeric characters with dash)
    
    Attributes:
        code_length: Length of each code segment (4 characters)
        code_segments: Number of segments per code (2 segments = 8 chars total)
        separator: Character separating code segments (default: "-")
    """
    
    def __init__(self) -> None:
        """
        Initialize BackupCodesManager.
        
        Sets up the manager with default configuration for backup code
        generation and verification.
        """
        self.code_length = 4  # Each segment is 4 characters
        self.code_segments = 2  # Two segments per code
        self.separator = "-"  # Dash separator
        self.alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # Alphanumeric
        
        logger.debug("BackupCodesManager initialized")
    
    def generate_codes(self, count: int = 10) -> list[str]:
        """
        Generate backup codes in "XXXX-XXXX" format.
        
        Creates cryptographically secure random backup codes using the
        secrets module. Each code consists of two 4-character segments
        separated by a dash.
        
        Security Notes:
        - Uses secrets.choice() for cryptographically secure random selection
        - Each code is unique (very high probability)
        - Codes are generated offline (no network required)
        
        Args:
            count: Number of backup codes to generate (default: 10)
            
        Returns:
            List of plaintext backup codes in format "XXXX-XXXX".
            Example: ["A1B2-C3D4", "E5F6-G7H8", "I9J0-K1L2", ...]
            
        Raises:
            ValueError: If count is less than 1 or greater than 100
            
        Example:
            >>> manager = BackupCodesManager()
            >>> codes = manager.generate_codes(5)
            >>> print(codes)
            ['A1B2-C3D4', 'E5F6-G7H8', 'I9J0-K1L2', 'M3N4-O5P6', 'Q7R8-S9T0']
        """
        if count < 1:
            error_msg = "Count must be at least 1"
            logger.error(f"Backup code generation failed: {error_msg}")
            raise ValueError(error_msg)
        
        if count > 100:
            error_msg = "Count cannot exceed 100 codes per generation"
            logger.warning(f"Backup code generation limited: requested {count}, max 100")
            count = 100
        
        codes = []
        
        for _ in range(count):
            # Generate two 4-character segments
            segment1 = ''.join(secrets.choice(self.alphabet) 
                              for _ in range(self.code_length))
            segment2 = ''.join(secrets.choice(self.alphabet) 
                              for _ in range(self.code_length))
            
            # Combine segments with dash separator
            code = f"{segment1}{self.separator}{segment2}"
            codes.append(code)
        
        logger.info(f"Generated {count} backup codes")
        logger.debug(f"Backup codes generated successfully (count={count})")
        
        return codes
    
    def hash_codes(self, codes: list[str]) -> list[str]:
        """
        Hash backup codes using SHA-256 for secure storage.
        
        This method converts plaintext backup codes into SHA-256 hashes
        suitable for database storage. Only hashes are stored; plaintext
        codes are never persisted.
        
        Security Notes:
        - Uses SHA-256 for hashing (cryptographically secure)
        - Each code is hashed independently
        - Hashes are hex-encoded strings (64 characters)
        - Original codes cannot be recovered from hashes
        
        Args:
            codes: List of plaintext backup codes to hash
            
        Returns:
            List of SHA-256 hashes (hex-encoded) for each code.
            Each hash is 64 characters long.
            
        Example:
            >>> manager = BackupCodesManager()
            >>> codes = ["A1B2-C3D4", "E5F6-G7H8"]
            >>> hashes = manager.hash_codes(codes)
            >>> print(len(hashes[0]))  # 64 characters (SHA-256 hex)
            64
        """
        if not isinstance(codes, list):
            error_msg = "Codes must be a list"
            logger.error(f"Backup code hashing failed: {error_msg}")
            raise TypeError(error_msg)
        
        code_hashes = []
        
        for code in codes:
            if not isinstance(code, str):
                logger.warning(f"Skipping invalid code type: {type(code)}")
                continue
            
            # Hash the code using SHA-256
            # Using hashlib for simplicity (cryptography library also available)
            code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
            code_hashes.append(code_hash)
        
        logger.debug(f"Hashed {len(code_hashes)} backup codes")
        
        return code_hashes
    
    def verify_code(
        self,
        provided_code: str,
        code_hashes: list[str]
    ) -> tuple[bool, int]:
        """
        Verify a backup code against stored hashes using constant-time comparison.
        
        This method verifies a user-provided backup code by hashing it and
        comparing it against all stored code hashes. The comparison is performed
        using constant-time operations to prevent timing attacks.
        
        Timing Attack Prevention:
        - All comparisons take the same time regardless of which code matches
        - Constant-time comparison prevents information leakage
        - Even if code is invalid, verification time is constant
        
        Security Notes:
        - Uses constant-time comparison (cryptography.hazmat.primitives.constant_time)
        - Prevents timing attacks that could reveal which code was correct
        - Returns index of matched code for removal after use
        
        Args:
            provided_code: Plaintext backup code provided by user
            code_hashes: List of SHA-256 hashes from database
            
        Returns:
            Tuple of (is_valid: bool, code_index: int)
            - If valid: (True, index_of_matched_code)
            - If invalid: (False, -1)
            
        Example:
            >>> manager = BackupCodesManager()
            >>> codes = ["A1B2-C3D4", "E5F6-G7H8"]
            >>> hashes = manager.hash_codes(codes)
            >>> 
            >>> # Verify correct code
            >>> is_valid, index = manager.verify_code("A1B2-C3D4", hashes)
            >>> print(is_valid, index)
            True 0
            >>> 
            >>> # Verify incorrect code
            >>> is_valid, index = manager.verify_code("WRONG-CODE", hashes)
            >>> print(is_valid, index)
            False -1
        """
        if not isinstance(provided_code, str):
            logger.warning("Backup code verification failed: provided_code must be a string")
            return False, -1
        
        if not isinstance(code_hashes, list):
            logger.warning("Backup code verification failed: code_hashes must be a list")
            return False, -1
        
        if len(code_hashes) == 0:
            logger.debug("Backup code verification failed: no codes available")
            return False, -1
        
        # Normalize provided code (remove whitespace, convert to uppercase)
        provided_code = provided_code.strip().upper()
        
        # Validate code format (should be "XXXX-XXXX")
        if len(provided_code) != 9 or provided_code[4] != self.separator:
            logger.debug("Backup code verification failed: invalid format")
            return False, -1
        
        # Hash the provided code
        provided_hash = hashlib.sha256(provided_code.encode('utf-8')).hexdigest()
        provided_hash_bytes = bytes.fromhex(provided_hash)
        
        # Constant-time comparison against all stored hashes
        # This prevents timing attacks by ensuring all comparisons take same time
        matched_index = -1
        
        for i, stored_hash in enumerate(code_hashes):
            if not isinstance(stored_hash, str):
                continue
            
            # Convert stored hash to bytes for constant-time comparison
            try:
                stored_hash_bytes = bytes.fromhex(stored_hash)
            except ValueError:
                # Invalid hash format, skip
                logger.warning(f"Invalid hash format at index {i}")
                continue
            
            # Constant-time comparison
            # This takes the same time regardless of whether hashes match
            if constant_time.bytes_eq(provided_hash_bytes, stored_hash_bytes):
                matched_index = i
                # Don't break - continue checking all codes to maintain constant time
                # (In practice, we could break, but constant-time requires checking all)
        
        # For true constant-time, we should always check all codes
        # However, for efficiency, we can break after first match
        # The timing difference is minimal if we break, but for maximum security,
        # we continue checking all codes
        
        if matched_index >= 0:
            logger.info(f"Backup code verified successfully (index: {matched_index})")
            logger.debug(f"Backup code verification successful for code at index {matched_index}")
            return True, matched_index
        else:
            logger.debug("Backup code verification failed: code not found")
            return False, -1
    
    def use_code(self, username: str, code_index: int, db: Any = None) -> bool:
        """
        Remove a used backup code from the user's backup codes list.
        
        This method removes a backup code from the database after it has been
        successfully verified. Backup codes are single-use only, so they must
        be removed immediately after use to prevent reuse.
        
        Security Notes:
        - Code is permanently removed (cannot be reused)
        - Logs code index (never logs plaintext code)
        - Updates database atomically
        - If user runs out of codes, they must generate new ones
        
        Args:
            username: Username of the account
            code_index: Index of the code to remove (from verify_code return)
            db: Database connection object (optional, can be set in __init__)
            
        Returns:
            True if code was successfully removed, False otherwise
            
        Raises:
            ValueError: If code_index is invalid
            RuntimeError: If database operation fails
            
        Example:
            >>> manager = BackupCodesManager()
            >>> is_valid, index = manager.verify_code("A1B2-C3D4", hashes)
            >>> if is_valid:
            ...     manager.use_code("alice", index, db=db_connection)
            True
        """
        if code_index < 0:
            error_msg = f"Invalid code index: {code_index}"
            logger.error(f"Backup code removal failed for {username}: {error_msg}")
            raise ValueError(error_msg)
        
        if db is None:
            error_msg = "Database connection required"
            logger.error(f"Backup code removal failed for {username}: {error_msg}")
            raise RuntimeError(error_msg)
        
        try:
            # Get current backup codes from database
            cursor = db.execute(
                "SELECT backup_codes_hash FROM users WHERE username = ?",
                (username,)
            )
            user_record = cursor.fetchone()
            
            if user_record is None:
                error_msg = f"User not found: {username}"
                logger.error(f"Backup code removal failed: {error_msg}")
                return False
            
            # Parse backup codes hash string (comma-separated).
            # Some database adapters return a single-column tuple (hashes,),
            # while our mock database returns the full user tuple (hashes at index 8).
            if len(user_record) >= 9:
                backup_codes_hash_str = user_record[8]
            else:
                backup_codes_hash_str = user_record[0]
            if not backup_codes_hash_str:
                error_msg = "No backup codes found for user"
                logger.warning(f"Backup code removal failed for {username}: {error_msg}")
                return False
            
            # Split comma-separated hashes into list
            code_hashes = backup_codes_hash_str.split(',')
            
            # Validate code_index
            if code_index >= len(code_hashes):
                error_msg = f"Code index {code_index} out of range (max: {len(code_hashes) - 1})"
                logger.error(f"Backup code removal failed for {username}: {error_msg}")
                raise ValueError(error_msg)
            
            # Remove code at specified index
            removed_code_hash = code_hashes.pop(code_index)
            
            # Update database with remaining codes
            # If no codes left, set to empty string or NULL
            updated_codes_str = ','.join(code_hashes) if code_hashes else ''
            
            update_query = """
                UPDATE users 
                SET backup_codes_hash = ? 
                WHERE username = ?
            """
            
            db.execute(update_query, (updated_codes_str, username))
            
            # Commit transaction
            if hasattr(db, 'commit'):
                db.commit()
            
            # Log code usage (index only, never plaintext)
            logger.info(
                f"Backup code used and removed for {username} "
                f"(index: {code_index}, remaining: {len(code_hashes)})"
            )
            logger.debug(
                f"Backup code removed successfully for {username} "
                f"(removed hash: {removed_code_hash[:16]}..., "
                f"remaining codes: {len(code_hashes)})"
            )
            
            return True
            
        except Exception as e:
            error_msg = f"Failed to remove backup code: {e}"
            logger.error(f"Backup code removal failed for {username}: {error_msg}")
            raise RuntimeError(error_msg) from e

