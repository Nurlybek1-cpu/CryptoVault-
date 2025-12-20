"""
Password validation module for CryptoVault.

This module provides password strength validation to ensure passwords meet
security requirements including minimum length, character variety, and
protection against common weak patterns.
"""

import re
import logging
from typing import tuple

logger = logging.getLogger(__name__)


class PasswordValidator:
    """
    Validates password strength according to security policies.
    
    This class enforces password requirements including:
    - Minimum length (12 characters)
    - Uppercase letters
    - Lowercase letters
    - Numbers
    - Special characters
    - Protection against common weak patterns
    
    Attributes:
        min_length: Minimum password length (default: 12)
        require_uppercase: Whether uppercase letters are required (default: True)
        require_lowercase: Whether lowercase letters are required (default: True)
        require_numbers: Whether numbers are required (default: True)
        require_special: Whether special characters are required (default: True)
        common_patterns: List of common weak patterns to reject
    """
    
    def __init__(
        self,
        min_length: int = 12,
        require_uppercase: bool = True,
        require_lowercase: bool = True,
        require_numbers: bool = True,
        require_special: bool = True
    ) -> None:
        """
        Initialize PasswordValidator with validation rules.
        
        Args:
            min_length: Minimum password length in characters
            require_uppercase: Require at least one uppercase letter
            require_lowercase: Require at least one lowercase letter
            require_numbers: Require at least one number
            require_special: Require at least one special character
        """
        self.min_length = min_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_numbers = require_numbers
        self.require_special = require_special
        
        # Common weak patterns to reject
        self.common_patterns = [
            r'123',
            r'qwerty',
            r'password',
            r'admin',
            r'letmein',
            r'welcome',
            r'monkey',
            r'dragon',
            r'123456',
            r'12345678',
            r'123456789',
            r'1234567890',
            r'qwerty123',
            r'password123',
            r'abc123',
            r'111111',
            r'000000',
            r'aaaaaa',
            r'abcdef',
            r'654321',
        ]
        
        logger.debug(
            f"PasswordValidator initialized with min_length={min_length}, "
            f"require_uppercase={require_uppercase}, "
            f"require_lowercase={require_lowercase}, "
            f"require_numbers={require_numbers}, "
            f"require_special={require_special}"
        )
    
    def validate(self, password: str) -> tuple[bool, str]:
        """
        Validate password against all security requirements.
        
        Checks the password for:
        1. Minimum length
        2. Uppercase letters (if required)
        3. Lowercase letters (if required)
        4. Numbers (if required)
        5. Special characters (if required)
        6. Common weak patterns
        
        Args:
            password: The password string to validate
            
        Returns:
            Tuple of (is_valid: bool, error_message: str)
            - If valid: (True, "")
            - If invalid: (False, descriptive error message)
            
        Examples:
            >>> validator = PasswordValidator()
            >>> validator.validate("StrongP@ssw0rd!")
            (True, "")
            >>> validator.validate("weak")
            (False, "Password must be at least 12 characters long")
        """
        if not isinstance(password, str):
            error_msg = "Password must be a string"
            logger.warning(f"Password validation failed: {error_msg}")
            return False, error_msg
        
        # Check minimum length
        if len(password) < self.min_length:
            error_msg = f"Password must be at least {self.min_length} characters long"
            logger.debug(f"Password validation failed: {error_msg}")
            return False, error_msg
        
        # Check for uppercase letters
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            error_msg = "Password must contain at least one uppercase letter"
            logger.debug(f"Password validation failed: {error_msg}")
            return False, error_msg
        
        # Check for lowercase letters
        if self.require_lowercase and not re.search(r'[a-z]', password):
            error_msg = "Password must contain at least one lowercase letter"
            logger.debug(f"Password validation failed: {error_msg}")
            return False, error_msg
        
        # Check for numbers
        if self.require_numbers and not re.search(r'\d', password):
            error_msg = "Password must contain at least one number"
            logger.debug(f"Password validation failed: {error_msg}")
            return False, error_msg
        
        # Check for special characters
        if self.require_special and not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
            error_msg = "Password must contain at least one special character"
            logger.debug(f"Password validation failed: {error_msg}")
            return False, error_msg
        
        # Check for common weak patterns (case-insensitive)
        password_lower = password.lower()
        for pattern in self.common_patterns:
            if re.search(pattern, password_lower, re.IGNORECASE):
                error_msg = f"Password contains a common weak pattern: '{pattern}'"
                logger.warning(f"Password validation failed: {error_msg}")
                return False, error_msg
        
        # All checks passed
        logger.debug("Password validation passed")
        return True, ""

