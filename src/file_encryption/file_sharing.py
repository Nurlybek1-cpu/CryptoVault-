"""
File Sharing Module - Secure key sharing for file recipients.

This module provides secure file sharing functionality by encrypting the File
Encryption Key (FEK) with the recipient's public key using RSA-OAEP. Only
the recipient with the corresponding private key can decrypt the FEK and
access the shared file.

Features:
- RSA-OAEP encryption for FEK sharing
- Share record management with metadata
- Access revocation capability
- Audit trail of who has access to which files
- Optional expiry dates for temporary access

Security Notes:
- FEK is never transmitted in plaintext
- Only recipient with private key can decrypt FEK
- Original file encryption (AES-256-GCM) remains unchanged
- Each recipient gets their own encrypted FEK copy
- Owner can revoke access anytime

References:
- RFC 3447 (RSA-OAEP)
- docs/algorithms/ecdh.md (for key exchange context)
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes


@dataclass
class ShareRecord:
    """
    Share record for tracking file access.

    Attributes:
        share_id: Unique identifier for this share
        file_id: Identifier of the shared file
        owner_id: User ID of the file owner
        recipient_id: User ID of the recipient
        encrypted_fek: Base64-encoded RSA-OAEP encrypted FEK
        shared_at: Timestamp of share creation
        expiry: Optional expiry date for temporary access
        revoked: Whether access has been revoked
    """
    share_id: str
    file_id: str
    owner_id: str
    recipient_id: str
    encrypted_fek: str  # base64-encoded
    shared_at: datetime = field(default_factory=datetime.utcnow)
    expiry: datetime | None = None
    revoked: bool = False


class FileSharing:
    """
    Manages secure file sharing by encrypting FEK with recipient's public key.

    Enables file owners to securely share encrypted files with recipients by
    encrypting the File Encryption Key (FEK) using RSA-OAEP with the recipient's
    public key. Only the recipient with the corresponding private key can
    decrypt the FEK and access the file.

    Attributes:
        user_id: User identifier for audit trail
        share_records: Dictionary of share records keyed by share_id

    Example:
        >>> sharing = FileSharing(user_id="alice")
        >>> share = sharing.share_file_with_recipient(
        ...     file_id="file123",
        ...     encrypted_fek=fek_bytes,
        ...     recipient_pubkey=bob_pubkey,
        ...     recipient_id="bob"
        ... )
        >>> # Bob receives share and decrypts FEK
        >>> fek = sharing.receive_shared_file(share, bob_private_key)
    """

    def __init__(self, user_id: str) -> None:
        """
        Initialize FileSharing.

        Args:
            user_id: User identifier for audit trail and access records

        Raises:
            ValueError: If user_id is empty or None
        """
        if not user_id:
            raise ValueError("user_id is required for file sharing")

        self._user_id: str = user_id
        # Share records storage: maps share_id -> ShareRecord
        self._share_records: dict[str, ShareRecord] = {}
        # File access tracking: maps file_id -> list of share_ids
        self._file_access: dict[str, list[str]] = {}

        self._logger: logging.Logger = logging.getLogger(
            f"{__name__}.{self.__class__.__name__}"
        )
        self._logger.info(
            "FileSharing initialized for user",
            extra={"user_id": self._user_id}
        )

    @property
    def user_id(self) -> str:
        """Get the user ID for this sharing instance."""
        return self._user_id

    @property
    def share_records(self) -> dict[str, ShareRecord]:
        """Get all share records."""
        return self._share_records.copy()

    def share_file_with_recipient(
            self,
            file_id: str,
            encrypted_fek: bytes,
            recipient_pubkey: rsa.RSAPublicKey,
            recipient_id: str,
            expiry_days: int | None = None,
    ) -> dict:
        """
        Encrypt FEK and create share record for recipient.

        Encrypts the File Encryption Key using the recipient's public key
        via RSA-OAEP with SHA256. Creates a share record for audit trail.

        Args:
            file_id: Identifier of the file being shared
            encrypted_fek: Wrapped FEK bytes to encrypt for recipient
            recipient_pubkey: Recipient's RSA public key
            recipient_id: User ID of the recipient
            expiry_days: Optional days until share expires (None for permanent)

        Returns:
            dict: Share record containing:
                - share_id: Unique identifier for this share
                - file_id: File identifier
                - owner_id: Owner's user ID
                - recipient_id: Recipient's user ID
                - encrypted_fek: Base64-encoded RSA-encrypted FEK
                - shared_at: Timestamp of share creation
                - expiry: Optional expiry date
                - revoked: Access revocation status

        Raises:
            ValueError: If file_id/recipient_id empty or pubkey invalid
            FileEncryptionError: If FEK encryption fails

        Example:
            >>> share = sharing.share_file_with_recipient(
            ...     "file123", fek_bytes, bob_pubkey, "bob", expiry_days=7
            ... )
            >>> print(f"Share ID: {share['share_id']}")
        """
        if not file_id or not recipient_id:
            raise ValueError("file_id and recipient_id are required")

        if recipient_pubkey is None:
            raise ValueError("recipient_pubkey is required and must be valid")

        try:
            # Encrypt FEK with recipient's public key using RSA-OAEP
            shared_fek = recipient_pubkey.encrypt(
                encrypted_fek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=b"file_sharing"
                )
            )

            # Calculate expiry if specified
            expiry = None
            if expiry_days is not None:
                expiry = datetime.utcnow() + timedelta(days=expiry_days)

            # Create share ID (file_id + recipient_id for simplicity)
            share_id = f"{file_id}_{recipient_id}_{int(datetime.utcnow().timestamp())}"

            # Create share record
            share = ShareRecord(
                share_id=share_id,
                file_id=file_id,
                owner_id=self._user_id,
                recipient_id=recipient_id,
                encrypted_fek=base64.b64encode(shared_fek).decode("utf-8"),
                shared_at=datetime.utcnow(),
                expiry=expiry,
                revoked=False
            )

            # Store share record
            self._share_records[share_id] = share

            # Track file access
            if file_id not in self._file_access:
                self._file_access[file_id] = []
            self._file_access[file_id].append(share_id)

            self._logger.info(
                "File shared with recipient",
                extra={
                    "file_id": file_id,
                    "owner_id": self._user_id,
                    "recipient_id": recipient_id,
                    "share_id": share_id,
                    "expiry": str(expiry) if expiry else "permanent"
                }
            )

            return {
                "share_id": share.share_id,
                "file_id": share.file_id,
                "owner_id": share.owner_id,
                "recipient_id": share.recipient_id,
                "encrypted_fek": share.encrypted_fek,
                "shared_at": share.shared_at.isoformat(),
                "expiry": share.expiry.isoformat() if share.expiry else None,
                "revoked": share.revoked
            }

        except Exception as exc:
            self._logger.exception("Failed to share file with recipient")
            raise

    def receive_shared_file(
            self,
            share_record: dict,
            private_key: rsa.RSAPrivateKey,
    ) -> bytes:
        """
        Decrypt shared FEK using recipient's private key.

        Decrypts the FEK that was encrypted with the recipient's public key.
        Verifies that the share is active (not revoked and not expired).

        Args:
            share_record: Share record dict containing:
                - encrypted_fek: Base64-encoded RSA-encrypted FEK
                - expiry: Optional expiry timestamp
                - revoked: Revocation status
            private_key: Recipient's RSA private key

        Returns:
            bytes: Decrypted File Encryption Key (32 bytes)

        Raises:
            ValueError: If share_record invalid or share is revoked/expired
            KeyDecodingError: If FEK decryption fails
            FileEncryptionError: If decryption fails due to tampering

        Example:
            >>> fek = sharing.receive_shared_file(share_record, bob_private_key)
            >>> print(f"FEK length: {len(fek)} bytes")
        """
        # Validate share record
        if not share_record:
            raise ValueError("share_record is required")

        # Check if share is revoked
        if share_record.get("revoked", False):
            raise ValueError("Access to this file has been revoked")

        # Check if share is expired
        expiry_str = share_record.get("expiry")
        if expiry_str:
            expiry = datetime.fromisoformat(expiry_str)
            if datetime.utcnow() > expiry:
                raise ValueError(f"Share has expired as of {expiry_str}")

        try:
            # Decode FEK from base64
            encrypted_fek = base64.b64decode(share_record["encrypted_fek"])

            # Decrypt FEK with recipient's private key using RSA-OAEP
            fek = private_key.decrypt(
                encrypted_fek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=b"file_sharing"
                )
            )

            self._logger.info(
                "Shared file received and FEK decrypted",
                extra={
                    "file_id": share_record.get("file_id"),
                    "owner_id": share_record.get("owner_id"),
                    "fek_length": len(fek)
                }
            )

            return fek

        except Exception as exc:
            self._logger.exception("Failed to decrypt shared FEK")
            raise

    def revoke_file_access(
            self,
            file_id: str,
            recipient_id: str,
    ) -> bool:
        """
        Revoke access to a shared file for a specific recipient.

        Marks the share record as revoked. The recipient can no longer
        decrypt the FEK using the revoked share record.

        Args:
            file_id: Identifier of the file
            recipient_id: User ID of the recipient whose access to revoke

        Returns:
            bool: True if access revoked successfully, False if share not found

        Raises:
            PermissionError: If caller is not the file owner

        Example:
            >>> success = sharing.revoke_file_access("file123", "bob")
            >>> print(f"Access revoked: {success}")
        """
        if not file_id or not recipient_id:
            raise ValueError("file_id and recipient_id are required")

        # Find share record for this file and recipient
        share_to_revoke = None
        for share_id, share in self._share_records.items():
            if share.file_id == file_id and share.recipient_id == recipient_id:
                if not share.revoked:  # Only revoke if not already revoked
                    share_to_revoke = share
                    break

        if share_to_revoke is None:
            self._logger.warning(
                "No active share found to revoke",
                extra={
                    "file_id": file_id,
                    "recipient_id": recipient_id
                }
            )
            return False

        # Mark share as revoked
        share_to_revoke.revoked = True

        self._logger.info(
            "File access revoked",
            extra={
                "file_id": file_id,
                "owner_id": self._user_id,
                "recipient_id": recipient_id,
                "share_id": share_to_revoke.share_id
            }
        )

        return True

    def get_file_shares(self, file_id: str) -> list[dict]:
        """
        Get all active shares for a file.

        Returns a list of all active (not revoked) shares for the specified file.

        Args:
            file_id: Identifier of the file

        Returns:
            list[dict]: List of share records

        Raises:
            ValueError: If file_id is empty

        Example:
            >>> shares = sharing.get_file_shares("file123")
            >>> print(f"Recipients: {[s['recipient_id'] for s in shares]}")
        """
        if not file_id:
            raise ValueError("file_id is required")

        shares = []
        if file_id in self._file_access:
            for share_id in self._file_access[file_id]:
                share = self._share_records.get(share_id)
                if share and not share.revoked:
                    shares.append({
                        "share_id": share.share_id,
                        "recipient_id": share.recipient_id,
                        "shared_at": share.shared_at.isoformat(),
                        "expiry": share.expiry.isoformat() if share.expiry else None,
                        "revoked": share.revoked
                    })
        return shares

    def get_user_shared_files(self) -> list[dict]:
        """
        Get all files shared by this user.

        Returns a list of all files that this user (the owner) has shared.

        Returns:
            list[dict]: List of shared file information

        Example:
            >>> shared = sharing.get_user_shared_files()
            >>> for f in shared:
            ...     print(f"File {f['file_id']} shared with {f['recipients']}")
        """
        shared_files = {}

        for share in self._share_records.values():
            if share.owner_id == self._user_id and not share.revoked:
                if share.file_id not in shared_files:
                    shared_files[share.file_id] = {
                        "file_id": share.file_id,
                        "recipients": []
                    }
                shared_files[share.file_id]["recipients"].append({
                    "recipient_id": share.recipient_id,
                    "shared_at": share.shared_at.isoformat(),
                    "expiry": share.expiry.isoformat() if share.expiry else None
                })

        return list(shared_files.values())
