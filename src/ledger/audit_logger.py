"""
Audit Logger for blockchain-based immutable audit trail.

This module provides the AuditLogger class which logs authentication and
system events to a blockchain ledger for immutable audit trail creation.
All events are cryptographically signed and stored chronologically.
"""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Audit Logger for blockchain-based event logging.
    
    This class logs authentication and security events to a blockchain ledger,
    creating an immutable audit trail of all authentication operations.
    
    Features:
    - Event validation and serialization
    - Blockchain transaction creation
    - User-specific audit trail retrieval
    - Chronological ordering
    - Cryptographic signing via blockchain
    
    Attributes:
        ledger: Blockchain ledger instance for storing events
        logger: Logger instance for audit logging operations
    """
    
    def __init__(self, blockchain_ledger: Any) -> None:
        """
        Initialize AuditLogger with blockchain ledger instance.
        
        Args:
            blockchain_ledger: Blockchain ledger instance to store audit events
            
        Raises:
            ValueError: If blockchain_ledger is None or invalid
            
        Example:
            >>> audit_logger = AuditLogger(blockchain_ledger)
            >>> audit_logger.log_auth_event(event_dict)
        """
        if blockchain_ledger is None:
            raise ValueError("blockchain_ledger cannot be None")
        
        self.ledger = blockchain_ledger
        self.logger = logging.getLogger(__name__)
        self.logger.info("AuditLogger initialized with blockchain ledger")
    
    def log_auth_event(self, event_dict: dict) -> bool:
        """
        Log an authentication event to the blockchain ledger.
        
        Validates the event structure, serializes it to JSON, and adds it
        to the blockchain as an immutable transaction. This creates a
        permanent, cryptographically-secured audit trail of authentication
        operations.
        
        Args:
            event_dict: Dictionary containing authentication event data
                       Required keys:
                       - type: str (e.g., "AUTH_LOGIN", "AUTH_REGISTRATION")
                       - user_hash: str (sha256 hash of username for privacy)
                       - timestamp: int (unix timestamp of event)
                       - success: bool (whether operation was successful)
                       
                       Optional keys:
                       - metadata: dict (additional event-specific data)
                       - ip_hash: str (sha256 hash of client IP if available)
                       - session_id: str (hashed session token)
                       - failure_reason: str (why event failed)
                       - mfa_used: bool (whether MFA was used)
                       - etc.
        
        Returns:
            True if event was successfully logged to blockchain, False otherwise
            
        Raises:
            ValueError: If event_dict is invalid or missing required fields
            
        Example:
            >>> event = {
            ...     "type": "AUTH_LOGIN",
            ...     "user_hash": "abc123def456...",
            ...     "timestamp": 1703340600,
            ...     "success": True,
            ...     "mfa_used": True,
            ...     "ip_hash": "def789abc123...",
            ... }
            >>> success = audit_logger.log_auth_event(event)
            >>> if success:
            ...     print("Event logged to blockchain")
        """
        try:
            # Validate event structure
            if not isinstance(event_dict, dict):
                raise ValueError("event_dict must be a dictionary")
            
            # Check required fields
            required_fields = ["type", "user_hash", "timestamp"]
            for field in required_fields:
                if field not in event_dict:
                    raise ValueError(f"Missing required field: {field}")
            
            # Validate event type
            valid_types = [
                "AUTH_REGISTRATION",
                "AUTH_LOGIN",
                "AUTH_LOGIN_FAILED",
                "AUTH_MFA_SETUP",
                "AUTH_TOTP_VERIFICATION",
                "AUTH_PASSWORD_RESET",
                "AUTH_ACCOUNT_LOCKOUT",
            ]
            if event_dict["type"] not in valid_types:
                raise ValueError(f"Invalid event type: {event_dict['type']}")
            
            # Validate timestamp is integer
            if not isinstance(event_dict["timestamp"], int):
                raise ValueError("timestamp must be an integer (unix timestamp)")
            
            # Validate user_hash format (should be sha256 hex string)
            user_hash = event_dict["user_hash"]
            if not isinstance(user_hash, str) or len(user_hash) != 64:
                raise ValueError("user_hash must be a 64-character hex string (sha256)")
            
            # Validate ip_hash if present
            if "ip_hash" in event_dict and event_dict["ip_hash"] is not None:
                ip_hash = event_dict["ip_hash"]
                if not isinstance(ip_hash, str) or len(ip_hash) != 64:
                    raise ValueError("ip_hash must be a 64-character hex string (sha256)")
            
            # Serialize event to JSON
            event_json = json.dumps(event_dict, separators=(',', ':'), sort_keys=True)
            
            # Add event to blockchain ledger
            # The ledger will:
            # - Add cryptographic signature
            # - Link to previous block (hash chain)
            # - Store with timestamp
            # - Create Merkle tree proof
            transaction_hash = self.ledger.add_transaction(event_json)
            
            if transaction_hash is None:
                self.logger.error(f"Failed to add audit event to blockchain: {event_dict['type']}")
                return False
            
            self.logger.debug(
                f"Audit event logged to blockchain: "
                f"type={event_dict['type']}, "
                f"user_hash={user_hash[:16]}..., "
                f"transaction_hash={transaction_hash[:16]}..."
            )
            
            return True
            
        except ValueError as e:
            self.logger.error(f"Invalid event structure: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {e}")
            return False
    
    def get_user_audit_trail(self, user_hash: str) -> list[dict]:
        """
        Retrieve all audit events for a specific user.
        
        Queries the blockchain ledger for all authentication events
        associated with a user (identified by their sha256 username hash).
        Returns events in chronological order.
        
        This method allows users to view their own audit trail for
        transparency and security monitoring. The user_hash prevents
        exposing the actual username.
        
        Args:
            user_hash: SHA256 hash of username (64-character hex string)
            
        Returns:
            List of event dictionaries in chronological order (oldest first)
            Each event contains:
            - type: str (event type)
            - user_hash: str (user identifier)
            - timestamp: int (unix timestamp)
            - success: bool (operation success/failure)
            - Plus any additional event-specific fields
            
        Raises:
            ValueError: If user_hash format is invalid
            
        Example:
            >>> user_hash = hashlib.sha256(b"alice").hexdigest()
            >>> trail = audit_logger.get_user_audit_trail(user_hash)
            >>> for event in trail:
            ...     print(f"{event['type']} at {event['timestamp']}")
        """
        try:
            # Validate user_hash format
            if not isinstance(user_hash, str) or len(user_hash) != 64:
                raise ValueError("user_hash must be a 64-character hex string (sha256)")
            
            # Query blockchain for events matching user_hash
            # This queries the immutable ledger for all transactions
            # where the parsed JSON contains matching user_hash
            events = self.ledger.query_transactions(
                filter_key="user_hash",
                filter_value=user_hash
            )
            
            if events is None:
                self.logger.debug(f"No events found for user_hash: {user_hash[:16]}...")
                return []
            
            # Parse JSON events and sort chronologically
            parsed_events = []
            for event_json in events:
                try:
                    event_dict = json.loads(event_json)
                    parsed_events.append(event_dict)
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse event JSON: {e}")
                    continue
            
            # Sort by timestamp (ascending = oldest first)
            parsed_events.sort(key=lambda e: e.get("timestamp", 0))
            
            self.logger.debug(
                f"Retrieved {len(parsed_events)} audit events for "
                f"user_hash: {user_hash[:16]}..."
            )
            
            return parsed_events
            
        except ValueError as e:
            self.logger.error(f"Invalid user_hash: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Failed to retrieve user audit trail: {e}")
            return []
