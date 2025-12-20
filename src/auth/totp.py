"""
TOTP (Time-based One-Time Password) management module for CryptoVault.

This module provides TOTP setup, verification, and management for two-factor
authentication. It implements RFC 6238 standard for TOTP generation and
verification, including QR code generation for authenticator apps.

Security Features:
- RFC 6238 compliant TOTP implementation
- HMAC-SHA1 based code generation (standard)
- 6-digit codes with 30-second time steps
- Time window tolerance for clock skew (±1 time step = 60 seconds)
- Secure QR code generation (local only, not transmitted)
- Manual entry option for secret key

TOTP Specification:
- Algorithm: HMAC-SHA1 (RFC 6238 default)
- Code length: 6 digits
- Time step: 30 seconds
- Time window: ±1 step (tolerance for clock skew)

References:
- RFC 6238 (TOTP specification)
- docs/algorithms/totp.md
- Google Authenticator, Microsoft Authenticator compatibility
"""

import hmac
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pyotp
import qrcode

from src.exceptions import TOTPError

logger = logging.getLogger(__name__)


class TOTPManager:
    """
    Manages TOTP (Time-based One-Time Password) for two-factor authentication.
    
    This class provides TOTP setup, verification, and management functionality.
    It generates secrets, creates QR codes for authenticator apps, and verifies
    TOTP codes with time window tolerance for clock skew.
    
    Security Properties:
    - RFC 6238 compliant implementation
    - HMAC-SHA1 based (standard algorithm)
    - 6-digit codes, 30-second intervals
    - Time window tolerance (±1 step = 60 seconds)
    - Secure secret generation
    - QR codes generated locally only
    
    Attributes:
        issuer: Service name for TOTP (default: "CryptoVault")
        digits: Number of digits in TOTP code (default: 6)
        interval: Time step in seconds (default: 30)
        qr_code_dir: Directory for storing QR code images
        db: Database connection for storing TOTP secrets
    """
    
    def __init__(
        self,
        issuer: str = "CryptoVault",
        digits: int = 6,
        interval: int = 30,
        qr_code_dir: str = "data/totp_qr_codes",
        db: Any = None
    ) -> None:
        """
        Initialize TOTPManager with configuration.
        
        Args:
            issuer: Service name for TOTP provisioning (default: "CryptoVault")
            digits: Number of digits in TOTP code (default: 6, standard)
            interval: Time step in seconds (default: 30, standard)
            qr_code_dir: Directory path for storing QR code images
            db: Database connection for storing TOTP secrets
        """
        self.issuer = issuer
        self.digits = digits
        self.interval = interval
        self.qr_code_dir = Path(qr_code_dir)
        self.db = db
        
        # Create QR code directory if it doesn't exist
        try:
            self.qr_code_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"QR code directory ready: {self.qr_code_dir}")
        except Exception as e:
            logger.warning(f"Failed to create QR code directory: {e}")
        
        logger.info("TOTPManager initialized")
        logger.debug(
            f"TOTP configuration: issuer={issuer}, digits={digits}, "
            f"interval={interval}s, qr_code_dir={qr_code_dir}"
        )
    
    def setup_totp(self, user_id: str, username: str) -> dict[str, Any]:
        """
        Set up TOTP for a user by generating secret and QR code.
        
        This method generates a new TOTP secret, creates a provisioning URI,
        generates a QR code image, and returns setup information. The secret
        is shown once to the user for manual entry or QR code scanning.
        
        Steps:
        1. Generate cryptographically secure TOTP secret (Base32)
        2. Create provisioning URI (otpauth://totp/...)
        3. Generate QR code image from URI
        4. Save QR code to file system
        5. Return setup information
        
        Security Notes:
        - Secret is generated using pyotp.random_base32() (cryptographically secure)
        - QR code is saved locally, not transmitted over network
        - Secret should be stored encrypted in database
        - Secret is returned once for setup, user must save it
        
        Args:
            user_id: Unique user identifier
            username: Username for TOTP account label
            
        Returns:
            Dictionary containing setup information:
            {
                "success": True,
                "secret": str (Base32 secret),
                "qr_code_path": str (path to QR code image),
                "provisioning_uri": str (otpauth:// URI),
                "manual_entry_key": str (same as secret),
                "message": str (instructions for user)
            }
            
        Raises:
            TOTPError: If setup fails (QR code generation, file I/O, etc.)
            
        Example:
            >>> manager = TOTPManager()
            >>> result = manager.setup_totp("user123", "alice")
            >>> print(result['qr_code_path'])
            data/totp_qr_codes/user123.png
        """
        if not user_id:
            error_msg = "User ID cannot be empty"
            logger.error(f"TOTP setup failed: {error_msg}")
            raise TOTPError(error_msg, error_code="INVALID_USER_ID")
        
        if not username:
            error_msg = "Username cannot be empty"
            logger.error(f"TOTP setup failed: {error_msg}")
            raise TOTPError(error_msg, error_code="INVALID_USERNAME")
        
        try:
            # Step a) Generate TOTP secret (Base32 encoded, 160+ bits)
            # pyotp.random_base32() generates a 32-character Base32 string
            # This provides 160 bits of entropy (recommended minimum)
            secret = pyotp.random_base32()
            
            logger.debug(f"TOTP secret generated for user_id: {user_id}")
            
            # Step b) Create TOTP instance and provisioning URI
            totp = pyotp.TOTP(secret, digits=self.digits, interval=self.interval)
            
            # Create provisioning URI for authenticator apps
            # Format: otpauth://totp/Issuer:Username?secret=SECRET&issuer=Issuer
            provisioning_uri = totp.provisioning_uri(
                name=username,
                issuer_name=self.issuer
            )
            
            logger.debug(f"Provisioning URI created for {username}")
            
            # Step c) Generate QR code from URI
            try:
                # Create QR code instance
                qr = qrcode.QRCode(
                    version=1,  # Auto-select version based on data
                    box_size=10,  # Size of each box in pixels
                    border=4,  # Border size (4 is minimum per QR spec)
                )
                
                # Add provisioning URI to QR code
                qr.add_data(provisioning_uri)
                qr.make(fit=True)  # Automatically fit to data
                
                # Create QR code image
                img = qr.make_image(fill_color="black", back_color="white")
                
                # Step d) Save QR code to file
                qr_code_path = self.qr_code_dir / f"{user_id}.png"
                img.save(str(qr_code_path))
                
                logger.info(f"QR code generated and saved: {qr_code_path}")
                
            except Exception as qr_error:
                error_msg = f"Failed to generate QR code: {qr_error}"
                logger.error(f"TOTP setup failed for {user_id}: {error_msg}")
                raise TOTPError(error_msg, error_code="QR_CODE_GENERATION_FAILED") from qr_error
            
            # Return setup information
            return {
                'success': True,
                'secret': secret,  # Base32 secret for manual entry
                'qr_code_path': str(qr_code_path),  # Path to QR code image
                'provisioning_uri': provisioning_uri,  # otpauth:// URI
                'manual_entry_key': secret,  # Same as secret (for manual entry)
                'message': 'Scan QR code or enter secret in authenticator app',
            }
            
        except TOTPError:
            # Re-raise TOTP errors
            raise
        except Exception as e:
            error_msg = f"TOTP setup failed: {e}"
            logger.error(f"TOTP setup failed for user_id {user_id}: {error_msg}")
            raise TOTPError(error_msg, error_code="SETUP_FAILED") from e
    
    def verify_totp(
        self,
        secret: str,
        totp_code: str,
        time_window: int = 1
    ) -> bool:
        """
        Verify a TOTP code against a secret with time window tolerance.
        
        This method verifies a TOTP code provided by the user against their
        stored secret. It checks the current code and adjacent time steps to
        handle clock skew between the server and user's device.
        
        Time Window Logic:
        - Checks current time step (0)
        - Checks previous time step (-1, 30 seconds ago)
        - Checks next time step (+1, 30 seconds in future)
        - Total tolerance: ±1 step = 60 seconds
        
        This handles:
        - Clock skew between server and device
        - Network latency
        - User entering code just before/after time step boundary
        
        Args:
            secret: User's TOTP secret (Base32 encoded)
            totp_code: 6-digit code provided by user
            time_window: Number of time steps to check on each side (default: 1)
            
        Returns:
            True if code is valid within time window, False otherwise
            
        Raises:
            TOTPError: If verification process fails
            
        Example:
            >>> manager = TOTPManager()
            >>> secret = "JBSWY3DPEHPK3PXP"
            >>> current_code = pyotp.TOTP(secret).now()
            >>> manager.verify_totp(secret, current_code)
            True
        """
        if not secret:
            error_msg = "TOTP secret cannot be empty"
            logger.error(f"TOTP verification failed: {error_msg}")
            raise TOTPError(error_msg, error_code="INVALID_SECRET")
        
        if not totp_code:
            error_msg = "TOTP code cannot be empty"
            logger.debug(f"TOTP verification failed: {error_msg}")
            return False
        
        # Normalize TOTP code (remove whitespace, ensure string)
        totp_code = str(totp_code).strip()
        
        # Validate code format (should be 6 digits)
        if not totp_code.isdigit() or len(totp_code) != self.digits:
            logger.debug(f"TOTP verification failed: invalid code format (length: {len(totp_code)})")
            return False
        
        try:
            # Create TOTP instance
            totp = pyotp.TOTP(secret, digits=self.digits, interval=self.interval)
            
            # Get current time
            current_time = time.time()
            
            # Check current code and adjacent time steps
            # time_window=1 means check: -1, 0, +1 (3 time steps total)
            for step_offset in range(-time_window, time_window + 1):
                # Calculate time for this step
                check_time = current_time + (step_offset * self.interval)
                
                # Generate code for this time step
                check_code = totp.at(int(check_time))
                
                # Constant-time comparison
                if hmac.compare_digest(str(check_code), totp_code):
                    logger.debug(
                        f"TOTP code verified successfully "
                        f"(step_offset: {step_offset}, time_window: {time_window})"
                    )
                    return True
            
            # No match found
            logger.debug("TOTP verification failed: code not valid in time window")
            return False
            
        except Exception as e:
            error_msg = f"TOTP verification error: {e}"
            logger.error(f"TOTP verification failed: {error_msg}")
            raise TOTPError(error_msg, error_code="VERIFICATION_ERROR") from e
    
    def enable_totp(self, user_id: str, secret: str, verification_code: str) -> bool:
        """
        Enable TOTP for a user after they confirm setup with a valid code.
        
        This method verifies that the user has successfully set up their
        authenticator app by requiring them to provide a valid TOTP code.
        Only after successful verification is TOTP enabled for the account.
        
        Security Flow:
        1. User scans QR code or enters secret manually
        2. User generates first TOTP code from authenticator app
        3. User provides code to confirm setup
        4. System verifies code using verify_totp()
        5. If valid: Enable TOTP in database
        6. If invalid: Don't enable, raise TOTPError
        
        Args:
            user_id: User identifier
            secret: TOTP secret to enable
            verification_code: TOTP code from user's authenticator app
            
        Returns:
            True if TOTP was successfully enabled, False otherwise
            
        Raises:
            TOTPError: If verification code is invalid or setup fails
            
        Example:
            >>> manager = TOTPManager()
            >>> secret = manager.setup_totp("user123", "alice")['secret']
            >>> # User scans QR and provides code
            >>> manager.enable_totp("user123", secret, "123456")
            True
        """
        if not user_id:
            error_msg = "User ID cannot be empty"
            logger.error(f"TOTP enable failed: {error_msg}")
            raise TOTPError(error_msg, error_code="INVALID_USER_ID")
        
        if not secret:
            error_msg = "TOTP secret cannot be empty"
            logger.error(f"TOTP enable failed: {error_msg}")
            raise TOTPError(error_msg, error_code="INVALID_SECRET")
        
        if not verification_code:
            error_msg = "Verification code is required to enable TOTP"
            logger.warning(f"TOTP enable failed for {user_id}: {error_msg}")
            raise TOTPError(error_msg, error_code="VERIFICATION_CODE_REQUIRED")
        
        # Verify the TOTP code
        is_valid = self.verify_totp(secret, verification_code, time_window=1)
        
        if not is_valid:
            error_msg = "Invalid TOTP code, setup failed"
            logger.warning(f"TOTP enable failed for {user_id}: {error_msg}")
            raise TOTPError(
                error_msg,
                error_code="INVALID_VERIFICATION_CODE",
                remaining_attempts=2  # Could track attempts
            )
        
        # Code is valid - enable TOTP in database
        if self.db is not None:
            try:
                # Update user record to enable TOTP
                # Note: In production, secret should be encrypted before storage
                self.db.execute(
                    "UPDATE users SET totp_enabled = ?, totp_secret = ? WHERE user_id = ?",
                    (True, secret, user_id)
                )
                
                if hasattr(self.db, 'commit'):
                    self.db.commit()
                
                logger.info(f"TOTP enabled for user_id: {user_id}")
                return True
                
            except Exception as db_error:
                error_msg = f"Failed to enable TOTP in database: {db_error}"
                logger.error(f"TOTP enable failed for {user_id}: {error_msg}")
                raise TOTPError(error_msg, error_code="DATABASE_ERROR") from db_error
        else:
            logger.warning("No database connection, TOTP not persisted")
            return True  # Assume success if no database
    
    def disable_totp(self, user_id: str) -> bool:
        """
        Disable TOTP for a user.
        
        This method disables TOTP authentication for a user account. The user
        should verify their password before allowing this operation for security.
        
        Security Note:
        - Should require password verification before disabling
        - Consider requiring TOTP code to disable (proves user has access)
        - Log the action for security audit
        
        Args:
            user_id: User identifier
            
        Returns:
            True if TOTP was successfully disabled, False otherwise
            
        Raises:
            TOTPError: If disable operation fails
            
        Example:
            >>> manager = TOTPManager()
            >>> manager.disable_totp("user123")
            True
        """
        if not user_id:
            error_msg = "User ID cannot be empty"
            logger.error(f"TOTP disable failed: {error_msg}")
            raise TOTPError(error_msg, error_code="INVALID_USER_ID")
        
        if self.db is not None:
            try:
                # Update user record to disable TOTP
                # Optionally clear the secret (or keep for re-enable)
                self.db.execute(
                    "UPDATE users SET totp_enabled = ? WHERE user_id = ?",
                    (False, user_id)
                )
                
                if hasattr(self.db, 'commit'):
                    self.db.commit()
                
                logger.info(f"TOTP disabled for user_id: {user_id}")
                return True
                
            except Exception as db_error:
                error_msg = f"Failed to disable TOTP in database: {db_error}"
                logger.error(f"TOTP disable failed for {user_id}: {error_msg}")
                raise TOTPError(error_msg, error_code="DATABASE_ERROR") from db_error
        else:
            logger.warning("No database connection, TOTP disable not persisted")
            return True  # Assume success if no database
    
    def get_user_totp_secret(self, user_id: str) -> str | None:
        """
        Retrieve user's TOTP secret from database.
        
        This method is used internally to get the user's TOTP secret for
        verification during login. The secret should be stored encrypted
        in production.
        
        Args:
            user_id: User identifier
            
        Returns:
            TOTP secret (Base32) if found, None otherwise
        """
        if not user_id:
            return None
        
        if self.db is None:
            logger.warning("No database connection, cannot retrieve TOTP secret")
            return None
        
        try:
            cursor = self.db.execute(
                "SELECT totp_secret FROM users WHERE user_id = ? AND totp_enabled = ?",
                (user_id, True)
            )
            result = cursor.fetchone()
            
            if result:
                return result[0]
            return None
            
        except Exception as e:
            logger.error(f"Failed to retrieve TOTP secret for {user_id}: {e}")
            return None

