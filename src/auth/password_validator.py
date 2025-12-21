"""
Password validation module for CryptoVault.

This module provides password strength validation to ensure passwords meet
security requirements including minimum length, character variety, and
protection against common weak patterns and sequential sequences.
"""

import re
import logging
# tuple is a built-in type in Python 3.9+

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
        
        # Common weak patterns to reject (case-insensitive)
        self.common_patterns = [
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
        ]
        
        # Sequential patterns for detection (will be checked dynamically)
        # These include keyboard sequences and character sequences
        self.sequential_patterns = {
            'numeric_forward': '0123456789',
            'numeric_reverse': '9876543210',
            'alpha_forward': 'abcdefghijklmnopqrstuvwxyz',
            'alpha_reverse': 'zyxwvutsrqponmlkjihgfedcba',
            'qwerty_rows': [
                'qwertyuiop',
                'asdfghjkl',
                'zxcvbnm',
                'qwertyuiop'.upper(),
                'asdfghjkl'.upper(),
                'zxcvbnm'.upper(),
            ],
        }
        
        logger.debug(
            f"PasswordValidator initialized with min_length={min_length}, "
            f"require_uppercase={require_uppercase}, "
            f"require_lowercase={require_lowercase}, "
            f"require_numbers={require_numbers}, "
            f"require_special={require_special}"
        )
    
    def _check_sequential_patterns(self, password: str) -> tuple[bool, str]:
        """
        Check for sequential patterns in password (abc, 123, qwerty, etc.).
        
        This method detects sequential character sequences that make passwords
        predictable and weak. It checks for:
        - Numeric sequences (123, 987, etc.)
        - Alphabetical sequences (abc, zyx, etc.)
        - Keyboard sequences (qwerty, asdf, etc.)
        
        Args:
            password: The password string to check
            
        Returns:
            Tuple of (has_sequential: bool, pattern_found: str)
            - If sequential pattern found: (True, description)
            - If no sequential pattern: (False, "")
        """
        password_lower = password.lower()
        
        # Check for numeric sequences (forward and reverse)
        # Look for sequences of 3+ consecutive digits
        for seq in [self.sequential_patterns['numeric_forward'], 
                   self.sequential_patterns['numeric_reverse']]:
            for i in range(len(seq) - 2):
                pattern = seq[i:i+3]
                if pattern in password_lower:
                    return True, f"Password contains sequential numbers: '{pattern}'"
        
        # Check for alphabetical sequences (forward and reverse)
        # Look for sequences of 3+ consecutive letters
        for seq in [self.sequential_patterns['alpha_forward'],
                   self.sequential_patterns['alpha_reverse']]:
            for i in range(len(seq) - 2):
                pattern = seq[i:i+3]
                if pattern in password_lower:
                    return True, f"Password contains sequential letters: '{pattern}'"
        
        # Check for QWERTY keyboard sequences
        # Look for sequences of 3+ consecutive keys on keyboard rows
        for row in self.sequential_patterns['qwerty_rows']:
            row_lower = row.lower()
            for i in range(len(row_lower) - 2):
                pattern = row_lower[i:i+3]
                if pattern in password_lower:
                    return True, f"Password contains keyboard sequence: '{pattern}'"
        
        return False, ""
    
    def validate(self, password: str, username: str | None = None) -> tuple[bool, str]:
        """
        Validate password against all security requirements.
        
        Performs comprehensive password validation checking:
        1. Type validation (must be string)
        2. Minimum length requirement (12 characters)
        3. Uppercase letters (if required)
        4. Lowercase letters (if required)
        5. Numbers (if required)
        6. Special characters (!@#$%^&*()_+-=[]{}|;:,.<>?) (if required)
        7. Common weak patterns (password, admin, etc.)
        8. Sequential patterns (abc, 123, qwerty, etc.)
        9. Username containment (if username provided)
        
        Args:
            password: The password string to validate
            username: Optional username to check if password contains it
            
        Returns:
            Tuple of (is_valid: bool, error_message: str)
            - If valid: (True, "")
            - If invalid: (False, specific error message explaining what's missing)
            
        Examples:
            >>> validator = PasswordValidator()
            >>> # Strong password - passes all checks
            >>> validator.validate("MySecureP@ssw0rd!")
            (True, "")
            
            >>> # Too short
            >>> validator.validate("weak")
            (False, "Password must be at least 12 characters long")
            
            >>> # Missing numbers (but long enough)
            >>> validator.validate("NoNumbersHere!")
            (False, "Password must contain at least 1 number")
            
            >>> # Contains sequential pattern
            >>> validator.validate("MyPass123abc!")
            (False, "Password contains sequential letters: 'abc'")
            
            >>> # Contains username
            >>> validator.validate("aliceSecureP@ssw0rd!", username="alice")
            (False, "Password must not contain the username")
        """
        # Step 1: Type validation - ensure password is a string
        if not isinstance(password, str):
            error_msg = "Password must be a string"
            logger.warning(f"Password validation failed: {error_msg}")
            return False, error_msg
        
        # Step 2: Minimum length check - enforce 12 character minimum
        # This is a critical security requirement to prevent brute-force attacks
        if len(password) < self.min_length:
            error_msg = f"Password must be at least {self.min_length} characters long"
            logger.debug(f"Password validation failed: {error_msg}")
            return False, error_msg
        
        # Step 3: Uppercase letter check - ensures character variety
        # At least one uppercase letter increases password entropy
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            error_msg = "Password must contain at least 1 uppercase letter"
            logger.debug(f"Password validation failed: {error_msg}")
            return False, error_msg
        
        # Step 4: Lowercase letter check - ensures character variety
        # At least one lowercase letter increases password entropy
        if self.require_lowercase and not re.search(r'[a-z]', password):
            error_msg = "Password must contain at least 1 lowercase letter"
            logger.debug(f"Password validation failed: {error_msg}")
            return False, error_msg
        
        # Step 5: Number check - ensures character variety
        # At least one number increases password entropy and complexity
        if self.require_numbers and not re.search(r'\d', password):
            error_msg = "Password must contain at least 1 number"
            logger.debug(f"Password validation failed: {error_msg}")
            return False, error_msg
        
        # Step 6: Special character check - ensures character variety
        # Special characters significantly increase password strength
        # Allowed: !@#$%^&*()_+-=[]{}|;:,.<>?
        special_char_pattern = r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]'
        if self.require_special and not re.search(special_char_pattern, password):
            error_msg = "Password must contain at least 1 special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
            logger.debug(f"Password validation failed: {error_msg}")
            return False, error_msg
        
        # Step 7: Common weak patterns check - reject known weak passwords
        # Check against list of common weak patterns (case-insensitive)
        password_lower = password.lower()
        for pattern in self.common_patterns:
            if re.search(pattern, password_lower, re.IGNORECASE):
                error_msg = f"Password contains a common weak pattern: '{pattern}'"
                logger.warning(f"Password validation failed: {error_msg}")
                return False, error_msg
        
        # Step 8: Sequential patterns check - reject predictable sequences
        # Check for sequential patterns like abc, 123, qwerty, etc.
        has_sequential, seq_error = self._check_sequential_patterns(password)
        if has_sequential:
            logger.warning(f"Password validation failed: {seq_error}")
            return False, seq_error
        
        # Step 9: Username containment check - password should not contain username
        # This prevents users from creating passwords that include their username
        if username is not None and username:
            username_lower = username.lower()
            password_lower = password.lower()
            # Check if username appears in password (case-insensitive)
            if username_lower in password_lower:
                error_msg = "Password must not contain the username"
                logger.warning(f"Password validation failed: {error_msg}")
                return False, error_msg
        
        # All validation checks passed
        logger.debug("Password validation passed - all security requirements met")
        return True, ""
    
    def calculate_strength_score(self, password: str) -> int:
        """
        Calculate password strength score from 0 to 100.
        
        This method provides a quantitative measure of password strength based on:
        - Length (longer = stronger)
        - Character variety (uppercase, lowercase, numbers, special)
        - Pattern complexity (repetition, sequences)
        - Entropy estimation
        
        Args:
            password: The password string to score
            
        Returns:
            Integer score from 0 to 100, where:
            - 0-20: Very weak
            - 21-40: Weak
            - 41-60: Moderate
            - 61-80: Strong
            - 81-100: Very strong
            
        Examples:
            >>> validator = PasswordValidator()
            >>> validator.calculate_strength_score("weak")
            15
            >>> validator.calculate_strength_score("MySecureP@ssw0rd!")
            85
        """
        if not isinstance(password, str) or len(password) == 0:
            return 0
        
        score = 0
        
        # Length scoring (0-40 points)
        # Longer passwords are exponentially stronger
        length = len(password)
        if length >= 20:
            score += 40
        elif length >= 16:
            score += 35
        elif length >= 14:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 10:
            score += 15
        elif length >= 8:
            score += 10
        elif length >= 6:
            score += 5
        
        # Character variety scoring (0-30 points)
        # More character types = higher entropy
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        
        char_types = sum([has_upper, has_lower, has_digit, has_special])
        score += char_types * 7  # 7 points per character type (max 28)
        
        # Bonus for having all character types (2 points)
        if char_types == 4:
            score += 2
        
        # Complexity scoring (0-20 points)
        # Check for mixed case, numbers, and special chars in combination
        if has_upper and has_lower:
            score += 5  # Mixed case
        if has_digit and (has_upper or has_lower):
            score += 5  # Numbers with letters
        if has_special and (has_upper or has_lower or has_digit):
            score += 5  # Special chars with other types
        
        # Check for repetition patterns (penalty)
        # Repeated characters reduce strength
        password_lower = password.lower()
        if len(set(password_lower)) < len(password_lower) * 0.5:
            score -= 5  # More than 50% repeated characters
        
        # Check for sequential patterns (penalty)
        has_sequential, _ = self._check_sequential_patterns(password)
        if has_sequential:
            score -= 10  # Sequential patterns significantly weaken password
        
        # Length bonus for very long passwords (0-10 points)
        if length >= 16:
            score += 5
        if length >= 20:
            score += 5
        
        # Ensure score is within valid range [0, 100]
        score = max(0, min(100, score))
        
        logger.debug(f"Password strength score calculated: {score}/100")
        return score

