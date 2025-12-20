"""
Password hashing module for CryptoVault using Argon2id.

This module provides secure password hashing and verification using Argon2id,
the state-of-the-art password hashing algorithm. Argon2id provides maximum
resistance to GPU/ASIC attacks and side-channel attacks.

Security Features:
- Argon2id variant (hybrid of Argon2i and Argon2d)
- Constant-time password verification (prevents timing attacks)
- Cryptographically random salt generation (automatic)
- Configurable memory, time, and parallelism costs
- Automatic hash parameter upgrade detection

References:
- OWASP Password Storage Cheat Sheet
- RFC 9106 (Argon2)
- docs/algorithms/argon2.md
"""

import logging
import secrets

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, PasswordHashError, VerifyMismatchError

logger = logging.getLogger(__name__)


class PasswordHasher:
    """
    Secure password hashing using Argon2id.
    
    This class provides password hashing and verification using Argon2id,
    following OWASP guidelines for secure password storage. Argon2id is
    the recommended variant as it provides the best balance of security
    against both GPU attacks and side-channel attacks.
    
    Security Properties:
    - Memory-hard: Resistant to GPU/ASIC cracking attacks
    - Constant-time verification: Prevents timing attacks
    - Automatic salt generation: Unique salt per password
    - Parameter upgrade support: Can detect when hashes need rehashing
    
    Attributes:
        hasher: Argon2id PasswordHasher instance
        time_cost: Number of iterations (time cost)
        memory_cost: Memory cost in KiB (65536 = 64 MB)
        parallelism: Number of parallel threads
        hash_len: Hash output length in bytes
        salt_len: Salt length in bytes
    """
    
    def __init__(
        self,
        time_cost: int = 2,
        memory_cost: int = 65536,
        parallelism: int = 1,
        hash_len: int = 16,
        salt_len: int = 16
    ) -> None:
        """
        Initialize Argon2id password hasher with specified parameters.
        
        Args:
            time_cost: Number of iterations (time cost). Recommended: 2-3.
                      Higher values increase security but slow down hashing.
            memory_cost: Memory cost in KiB. 65536 = 64 MB (recommended minimum).
                        Higher values increase GPU resistance.
            parallelism: Number of parallel threads. Recommended: 1-4.
                        Should match CPU core count for optimal performance.
            hash_len: Hash output length in bytes. Default: 16 (128 bits).
            salt_len: Salt length in bytes. Default: 16 (128 bits).
        
        Note:
            The argon2 library automatically generates cryptographically
            random salts for each password hash. No manual salt generation
            is required.
        """
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.hash_len = hash_len
        self.salt_len = salt_len
        
        # Initialize Argon2id hasher
        # Type.ID specifies Argon2id variant (recommended for password hashing)
        self.hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len,
            type=Type.ID  # Argon2id variant
        )
        
        logger.info(
            f"PasswordHasher initialized with Argon2id "
            f"(time_cost={time_cost}, memory_cost={memory_cost} KiB, "
            f"parallelism={parallelism}, hash_len={hash_len}, salt_len={salt_len})"
        )
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using Argon2id.
        
        This method hashes a password using Argon2id with the configured
        parameters. A cryptographically random salt is automatically generated
        and included in the returned hash string.
        
        Security Notes:
        - Salt is automatically generated using cryptographically secure RNG
        - Hash includes all parameters (time_cost, memory_cost, etc.)
        - Hash format: $argon2id$v=19$m=65536,t=2,p=1$salt$hash
        
        Args:
            password: The plaintext password to hash
            
        Returns:
            Argon2id hash string containing salt and all parameters.
            Format: $argon2id$v=19$m=65536,t=2,p=1$salt$hash
            
        Raises:
            PasswordHashError: If hashing fails (should not occur in normal operation)
            
        Example:
            >>> hasher = PasswordHasher()
            >>> hash_str = hasher.hash_password("MySecurePassword123!")
            >>> print(hash_str[:20])  # Shows hash prefix
            $argon2id$v=19$m=65536
        """
        if not isinstance(password, str):
            error_msg = "Password must be a string"
            logger.error(f"Password hashing failed: {error_msg}")
            raise TypeError(error_msg)
        
        if len(password) == 0:
            error_msg = "Password cannot be empty"
            logger.error(f"Password hashing failed: {error_msg}")
            raise ValueError(error_msg)
        
        try:
            # Hash password using Argon2id
            # The argon2 library automatically:
            # 1. Generates a cryptographically random salt
            # 2. Includes salt and parameters in the hash string
            # 3. Uses constant-time operations internally
            password_hash = self.hasher.hash(password)
            
            # Log successful hashing without exposing sensitive data
            logger.info(
                f"Password hashed successfully "
                f"(length={len(password)}, hash_length={len(password_hash)})"
            )
            
            return password_hash
            
        except PasswordHashError as e:
            # PasswordHashError is raised for invalid parameters or internal errors
            logger.error(f"Password hashing failed with PasswordHashError: {e}")
            raise
        except Exception as e:
            # Catch any unexpected errors
            logger.error(f"Unexpected error during password hashing: {e}")
            raise PasswordHashError(f"Password hashing failed: {e}") from e
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify a password against an Argon2id hash using constant-time comparison.
        
        This method verifies a password against a stored hash. The verification
        is performed using constant-time operations to prevent timing attacks.
        
        Timing Attack Prevention:
        - The argon2 library's verify() method uses constant-time comparison
        - Verification time is independent of password correctness
        - Prevents attackers from using timing differences to guess passwords
        - Even if password is wrong, verification takes the same time
        
        Security Notes:
        - Always returns False for invalid hashes (never raises exceptions)
        - Constant-time comparison prevents information leakage
        - Invalid hash format is handled gracefully
        
        Args:
            password: The plaintext password to verify
            password_hash: The Argon2id hash string to verify against
            
        Returns:
            True if password matches the hash, False otherwise.
            Returns False for:
            - Incorrect passwords
            - Invalid hash format
            - Corrupted hash strings
            
        Example:
            >>> hasher = PasswordHasher()
            >>> hash_str = hasher.hash_password("MyPassword123!")
            >>> hasher.verify_password("MyPassword123!", hash_str)
            True
            >>> hasher.verify_password("WrongPassword", hash_str)
            False
        """
        if not isinstance(password, str):
            logger.warning("Password verification failed: password must be a string")
            return False
        
        if not isinstance(password_hash, str):
            logger.warning("Password verification failed: password_hash must be a string")
            return False
        
        if len(password) == 0:
            logger.warning("Password verification failed: password cannot be empty")
            return False
        
        if len(password_hash) == 0:
            logger.warning("Password verification failed: password_hash cannot be empty")
            return False
        
        try:
            # Verify password using Argon2id
            # The argon2 library's verify() method:
            # 1. Uses constant-time comparison internally
            # 2. Takes the same time regardless of password correctness
            # 3. Prevents timing attacks by not short-circuiting on mismatch
            # 4. Extracts salt and parameters from hash string automatically
            self.hasher.verify(password_hash, password)
            
            # Log successful verification without exposing sensitive data
            logger.debug(
                f"Password verification successful "
                f"(password_length={len(password)}, hash_length={len(password_hash)})"
            )
            
            return True
            
        except VerifyMismatchError:
            # Password does not match hash
            # This is expected for incorrect passwords
            # Log at debug level to avoid noise, but track failed attempts
            logger.debug(
                f"Password verification failed: password mismatch "
                f"(password_length={len(password)}, hash_length={len(password_hash)})"
            )
            return False
            
        except InvalidHashError as e:
            # Hash format is invalid or corrupted
            # This could indicate:
            # - Database corruption
            # - Hash from different algorithm
            # - Malformed hash string
            logger.warning(
                f"Password verification failed: invalid hash format "
                f"(hash_length={len(password_hash)}, error={e})"
            )
            return False
            
        except Exception as e:
            # Catch any unexpected errors during verification
            # Return False to prevent information leakage
            logger.error(
                f"Unexpected error during password verification: {e} "
                f"(password_length={len(password)}, hash_length={len(password_hash)})"
            )
            return False
    
    def needs_rehash(self, password_hash: str) -> bool:
        """
        Check if a password hash needs rehashing with updated parameters.
        
        This method checks if an existing hash was created with parameters
        that differ from the current hasher configuration. This allows
        upgrading hash parameters over time as security requirements increase
        or hardware improves.
        
        Use Cases:
        - Upgrading time_cost from 2 to 3 as hardware gets faster
        - Increasing memory_cost for better GPU resistance
        - Migrating from older hash parameters to newer ones
        
        Args:
            password_hash: The Argon2id hash string to check
            
        Returns:
            True if hash needs rehashing (parameters differ), False otherwise.
            Returns True for:
            - Invalid hash format (should be rehashed)
            - Different time_cost, memory_cost, or parallelism
            - Different hash_len or salt_len
            
        Example:
            >>> hasher_old = PasswordHasher(time_cost=2, memory_cost=32768)
            >>> hash_str = hasher_old.hash_password("MyPassword123!")
            >>> 
            >>> hasher_new = PasswordHasher(time_cost=3, memory_cost=65536)
            >>> hasher_new.needs_rehash(hash_str)
            True  # Parameters changed, needs rehash
        """
        if not isinstance(password_hash, str):
            logger.warning("needs_rehash check failed: password_hash must be a string")
            return True  # Invalid format should trigger rehash
        
        if len(password_hash) == 0:
            logger.warning("needs_rehash check failed: password_hash cannot be empty")
            return True  # Empty hash should trigger rehash
        
        try:
            # Check if hash needs rehashing
            # This compares the hash's parameters with current hasher parameters
            needs_rehash = self.hasher.check_needs_rehash(password_hash)
            
            if needs_rehash:
                logger.info(
                    f"Hash needs rehashing "
                    f"(current parameters differ from hash parameters)"
                )
            else:
                logger.debug("Hash parameters match current configuration")
            
            return needs_rehash
            
        except InvalidHashError as e:
            # Invalid hash format - should be rehashed
            logger.warning(
                f"needs_rehash check failed: invalid hash format "
                f"(hash_length={len(password_hash)}, error={e})"
            )
            return True  # Invalid hash should trigger rehash
            
        except Exception as e:
            # Unexpected error - assume rehash needed for safety
            logger.error(
                f"Unexpected error during needs_rehash check: {e} "
                f"(hash_length={len(password_hash)})"
            )
            return True  # Error case - trigger rehash for safety

