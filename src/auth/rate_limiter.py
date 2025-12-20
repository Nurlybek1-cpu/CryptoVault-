"""
Rate limiting module for CryptoVault authentication.

This module provides rate limiting functionality to protect against brute-force
attacks on authentication endpoints. It tracks login attempts by identifier
(username, user_id, or IP address) and enforces limits within configurable
time windows.

Security Features:
- Per-identifier attempt tracking (username, user_id, or IP address)
- Configurable maximum attempts and time windows
- Automatic cleanup of old entries to prevent memory bloat
- Thread-safe implementation for multi-threaded environments
- Separate tracking for different identifiers

Rate Limiting Strategy:
- Track failed login attempts per identifier
- Block further attempts after threshold is reached
- Reset attempts on successful authentication
- Clean up expired entries automatically

References:
- OWASP Brute Force Protection
- Auth0 Attack Protection documentation
- NIST SP 800-63B (Digital Identity Guidelines)
"""

import logging
import threading
import time
from collections import defaultdict
from typing import Optional

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Rate limiter for authentication attempts to prevent brute-force attacks.
    
    This class tracks login attempts by identifier (username, user_id, or IP
    address) and enforces rate limits within configurable time windows. It
    prevents brute-force attacks by blocking further attempts after a threshold
    is reached.
    
    Security Properties:
    - Thread-safe: Uses locks for concurrent access
    - Memory-efficient: Automatically cleans up old entries
    - Configurable: Adjustable limits and time windows
    - Per-identifier tracking: Separate limits for each identifier
    
    Attributes:
        attempts: Dictionary mapping identifier to list of attempt timestamps
        lock: Thread lock for thread-safe operations
        cleanup_interval: Interval (in seconds) for periodic cleanup
        last_cleanup: Timestamp of last cleanup operation
    """
    
    def __init__(self, cleanup_interval: int = 300) -> None:
        """
        Initialize RateLimiter with tracking storage.
        
        Args:
            cleanup_interval: Interval in seconds for periodic cleanup of
                            old entries (default: 300 seconds = 5 minutes)
        """
        # Dictionary to store attempts: {identifier: [timestamp1, timestamp2, ...]}
        self.attempts: dict[str, list[float]] = defaultdict(list)
        
        # Thread lock for thread-safe operations
        self.lock = threading.Lock()
        
        # Cleanup configuration
        self.cleanup_interval = cleanup_interval
        self.last_cleanup = time.time()
        
        logger.info("RateLimiter initialized")
        logger.debug(f"Cleanup interval: {cleanup_interval} seconds")
    
    def _cleanup_old_entries(
        self,
        identifier: Optional[str] = None,
        window_minutes: int = 15
    ) -> None:
        """
        Remove old attempt entries outside the time window.
        
        This method cleans up timestamps that are older than the specified
        time window. It can clean up entries for a specific identifier or
        perform a global cleanup of all identifiers.
        
        Args:
            identifier: Optional identifier to clean up. If None, cleans all.
            window_minutes: Time window in minutes (default: 15)
        """
        current_time = time.time()
        cutoff_time = current_time - (window_minutes * 60)
        
        if identifier is not None:
            # Clean up entries for specific identifier
            if identifier in self.attempts:
                # Filter out timestamps older than cutoff
                self.attempts[identifier] = [
                    ts for ts in self.attempts[identifier]
                    if ts >= cutoff_time
                ]
                
                # Remove identifier if no attempts remain
                if not self.attempts[identifier]:
                    del self.attempts[identifier]
        else:
            # Global cleanup: remove old entries for all identifiers
            identifiers_to_remove = []
            
            for ident, timestamps in self.attempts.items():
                # Filter out old timestamps
                filtered_timestamps = [
                    ts for ts in timestamps
                    if ts >= cutoff_time
                ]
                
                if filtered_timestamps:
                    self.attempts[ident] = filtered_timestamps
                else:
                    identifiers_to_remove.append(ident)
            
            # Remove identifiers with no remaining attempts
            for ident in identifiers_to_remove:
                del self.attempts[ident]
    
    def _periodic_cleanup(self) -> None:
        """
        Perform periodic cleanup of old entries to prevent memory bloat.
        
        This method is called periodically to remove old attempt records
        that are no longer needed. It helps prevent memory bloat in long-running
        applications.
        """
        current_time = time.time()
        
        # Only perform cleanup if enough time has passed
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        # Perform global cleanup with a reasonable window (1 hour)
        # This removes entries older than 1 hour
        self._cleanup_old_entries(window_minutes=60)
        
        self.last_cleanup = current_time
        logger.debug("Periodic cleanup completed")
    
    def check_rate_limit(
        self,
        identifier: str,
        max_attempts: int = 5,
        window_minutes: int = 15
    ) -> tuple[bool, int]:
        """
        Check if an identifier has exceeded the rate limit.
        
        This method checks whether an identifier (username, user_id, or IP
        address) has exceeded the maximum number of attempts within the
        specified time window. It automatically cleans up old entries and
        records a new attempt if allowed.
        
        Logic:
        1. Clean up old attempts outside the time window
        2. Count remaining attempts within the window
        3. If count < max_attempts, allow and record new attempt
        4. If count >= max_attempts, block and return current count
        
        Args:
            identifier: Username, user_id, or IP address to check
            max_attempts: Maximum attempts allowed (default: 5)
            window_minutes: Time window in minutes (default: 15)
            
        Returns:
            Tuple of (is_allowed: bool, attempt_count: int)
            - If allowed: (True, current_count_after_recording)
            - If blocked: (False, current_count)
            
        Example:
            >>> limiter = RateLimiter()
            >>> # First 5 attempts allowed
            >>> for i in range(5):
            ...     allowed, count = limiter.check_rate_limit("alice", max_attempts=5)
            ...     print(f"Attempt {i+1}: allowed={allowed}, count={count}")
            Attempt 1: allowed=True, count=1
            Attempt 2: allowed=True, count=2
            ...
            Attempt 5: allowed=True, count=5
            >>> # 6th attempt blocked
            >>> allowed, count = limiter.check_rate_limit("alice", max_attempts=5)
            >>> print(f"Attempt 6: allowed={allowed}, count={count}")
            Attempt 6: allowed=False, count=5
        """
        if not identifier:
            logger.warning("Rate limit check failed: empty identifier")
            return False, 0
        
        if max_attempts < 1:
            logger.warning(f"Rate limit check: invalid max_attempts={max_attempts}, using 1")
            max_attempts = 1
        
        if window_minutes < 1:
            logger.warning(f"Rate limit check: invalid window_minutes={window_minutes}, using 1")
            window_minutes = 1
        
        with self.lock:
            # Perform periodic cleanup if needed
            self._periodic_cleanup()
            
            # Clean up old entries for this identifier
            self._cleanup_old_entries(identifier, window_minutes)
            
            # Get current attempt count
            current_attempts = len(self.attempts.get(identifier, []))
            
            # Check if limit exceeded
            if current_attempts >= max_attempts:
                logger.warning(
                    f"Rate limit exceeded for {identifier}: "
                    f"{current_attempts} attempts (max: {max_attempts}) "
                    f"within {window_minutes} minutes"
                )
                return False, current_attempts
            
            # Record new attempt
            current_time = time.time()
            self.attempts[identifier].append(current_time)
            
            updated_count = len(self.attempts[identifier])
            
            logger.debug(
                f"Rate limit check passed for {identifier}: "
                f"{updated_count}/{max_attempts} attempts "
                f"within {window_minutes} minutes"
            )
            
            return True, updated_count
    
    def record_attempt(self, identifier: str) -> None:
        """
        Record a login attempt for an identifier.
        
        This method records a failed login attempt by adding the current
        timestamp to the identifier's attempt list. It also performs cleanup
        of old entries to prevent memory bloat.
        
        Note: This method is useful when you want to record an attempt
        separately from checking the rate limit. For most use cases,
        use check_rate_limit() which both checks and records.
        
        Args:
            identifier: Username, user_id, or IP address
            
        Example:
            >>> limiter = RateLimiter()
            >>> limiter.record_attempt("alice")
            >>> count = limiter.get_attempts("alice")
            >>> print(count)
            1
        """
        if not identifier:
            logger.warning("Attempt recording failed: empty identifier")
            return
        
        with self.lock:
            current_time = time.time()
            self.attempts[identifier].append(current_time)
            
            # Clean up old entries (using default 15-minute window)
            self._cleanup_old_entries(identifier, window_minutes=15)
            
            logger.debug(f"Recorded attempt for {identifier} at {current_time}")
    
    def reset_attempts(self, identifier: str) -> None:
        """
        Clear all recorded attempts for an identifier.
        
        This method should be called on successful authentication to reset
        the attempt counter. This allows legitimate users who successfully
        authenticate to continue using the system without being blocked.
        
        Security Note:
        - Only reset attempts after successful authentication
        - Do not reset on failed authentication
        - Consider resetting after successful password reset or account unlock
        
        Args:
            identifier: Username, user_id, or IP address to reset
            
        Example:
            >>> limiter = RateLimiter()
            >>> limiter.record_attempt("alice")
            >>> limiter.record_attempt("alice")
            >>> print(limiter.get_attempts("alice"))
            2
            >>> # User successfully logs in
            >>> limiter.reset_attempts("alice")
            >>> print(limiter.get_attempts("alice"))
            0
        """
        if not identifier:
            logger.warning("Attempt reset failed: empty identifier")
            return
        
        with self.lock:
            if identifier in self.attempts:
                del self.attempts[identifier]
                logger.info(f"Reset attempts for {identifier}")
                logger.debug(f"All attempts cleared for {identifier}")
            else:
                logger.debug(f"No attempts to reset for {identifier}")
    
    def get_attempts(
        self,
        identifier: str,
        window_minutes: int = 15
    ) -> int:
        """
        Get the current number of attempts for an identifier within time window.
        
        This method returns the count of attempts made by an identifier within
        the specified time window. It's useful for debugging, logging, or
        displaying rate limit information to users.
        
        Args:
            identifier: Username, user_id, or IP address
            window_minutes: Time window in minutes (default: 15)
            
        Returns:
            Number of attempts within the time window
            
        Example:
            >>> limiter = RateLimiter()
            >>> limiter.record_attempt("alice")
            >>> limiter.record_attempt("alice")
            >>> count = limiter.get_attempts("alice")
            >>> print(f"Alice has {count} attempts in the last 15 minutes")
            Alice has 2 attempts in the last 15 minutes
        """
        if not identifier:
            logger.warning("Get attempts failed: empty identifier")
            return 0
        
        with self.lock:
            # Clean up old entries for this identifier
            self._cleanup_old_entries(identifier, window_minutes)
            
            # Return count of remaining attempts
            count = len(self.attempts.get(identifier, []))
            
            logger.debug(
                f"Attempt count for {identifier}: {count} "
                f"within {window_minutes} minutes"
            )
            
            return count
    
    def get_remaining_attempts(
        self,
        identifier: str,
        max_attempts: int = 5,
        window_minutes: int = 15
    ) -> int:
        """
        Get the number of remaining attempts before rate limit is reached.
        
        This method calculates how many attempts an identifier has remaining
        before hitting the rate limit. Useful for displaying to users:
        "You have 2 attempts remaining before being locked out."
        
        Args:
            identifier: Username, user_id, or IP address
            max_attempts: Maximum attempts allowed (default: 5)
            window_minutes: Time window in minutes (default: 15)
            
        Returns:
            Number of remaining attempts (0 if limit reached)
            
        Example:
            >>> limiter = RateLimiter()
            >>> for i in range(3):
            ...     limiter.record_attempt("alice")
            >>> remaining = limiter.get_remaining_attempts("alice", max_attempts=5)
            >>> print(f"Remaining attempts: {remaining}")
            Remaining attempts: 2
        """
        current_count = self.get_attempts(identifier, window_minutes)
        remaining = max(0, max_attempts - current_count)
        
        logger.debug(
            f"Remaining attempts for {identifier}: {remaining} "
            f"({current_count}/{max_attempts} used)"
        )
        
        return remaining
    
    def is_blocked(
        self,
        identifier: str,
        max_attempts: int = 5,
        window_minutes: int = 15
    ) -> bool:
        """
        Check if an identifier is currently blocked by rate limiting.
        
        This is a convenience method that returns True if the identifier
        has exceeded the rate limit, False otherwise. It does not record
        a new attempt.
        
        Args:
            identifier: Username, user_id, or IP address
            max_attempts: Maximum attempts allowed (default: 5)
            window_minutes: Time window in minutes (default: 15)
            
        Returns:
            True if blocked, False if allowed
        """
        current_count = self.get_attempts(identifier, window_minutes)
        is_blocked = current_count >= max_attempts
        
        if is_blocked:
            logger.debug(
                f"Identifier {identifier} is blocked: "
                f"{current_count}/{max_attempts} attempts"
            )
        
        return is_blocked
    
    def get_blocked_identifiers(
        self,
        max_attempts: int = 5,
        window_minutes: int = 15
    ) -> list[str]:
        """
        Get list of all identifiers currently blocked by rate limiting.
        
        This method is useful for monitoring and logging purposes. It returns
        all identifiers that have exceeded the rate limit threshold.
        
        Args:
            max_attempts: Maximum attempts allowed (default: 5)
            window_minutes: Time window in minutes (default: 15)
            
        Returns:
            List of blocked identifiers
        """
        with self.lock:
            # Clean up old entries globally
            self._cleanup_old_entries(window_minutes=window_minutes)
            
            blocked = []
            for identifier, timestamps in self.attempts.items():
                if len(timestamps) >= max_attempts:
                    blocked.append(identifier)
            
            if blocked:
                logger.debug(f"Found {len(blocked)} blocked identifiers")
            
            return blocked

