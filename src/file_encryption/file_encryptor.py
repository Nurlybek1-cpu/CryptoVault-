"""
Streaming file encryptor using AES-256-GCM.

Implements chunked encryption/decryption to handle large files without
loading them fully into memory. File format:

[Header (1KB JSON padded)]
[Encrypted data (...)]
[Auth tag (16 bytes)]

Header fields: version, cipher, nonce (base64), encrypted_fek (base64),
file_size, timestamp
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from src.exceptions import FileEncryptionError, FileIntegrityError


HEADER_SIZE = 1024
CHUNK_SIZE = 8192


def _read_in_chunks(file_obj: BinaryIO, chunk_size: int = CHUNK_SIZE):
    while True:
        data = file_obj.read(chunk_size)
        if not data:
            break
        yield data


def _pad_header(data: bytes) -> bytes:
    if len(data) > HEADER_SIZE:
        raise ValueError("Header too large to fit in reserved header area")
    return data + b"\x00" * (HEADER_SIZE - len(data))


class FileEncryptor:
    def __init__(self, chunk_size: int = CHUNK_SIZE):
        self.chunk_size = chunk_size

    def encrypt_key_with_master_key(self, fek: bytes, master_key: bytes) -> bytes:
        # Wrap FEK with master key using AES-GCM (nonce + ciphertext_with_tag)
        nonce = os.urandom(12)
        aesgcm = AESGCM(master_key)
        ct = aesgcm.encrypt(nonce, fek, None)
        return nonce + ct

    def decrypt_key_with_master_key(self, encrypted_fek: bytes, master_key: bytes) -> bytes:
        if len(encrypted_fek) < 12 + 16:
            raise FileEncryptionError("Invalid encrypted FEK blob")
        nonce = encrypted_fek[:12]
        ct = encrypted_fek[12:]
        aesgcm = AESGCM(master_key)
        return aesgcm.decrypt(nonce, ct, None)

    def get_file_size(self, path: str) -> int:
        return os.path.getsize(path)

    def encrypt_file_streaming(self, input_path: str, output_path: str, master_key: bytes, cipher_type: str = "AES-256-GCM") -> dict:
        if cipher_type != "AES-256-GCM":
            raise FileEncryptionError("Unsupported cipher: %s" % cipher_type)

        nonce = os.urandom(12)
        fek = os.urandom(32)
        encrypted_fek = self.encrypt_key_with_master_key(fek, master_key)

        timestamp = int(time.time())
        original_size = self.get_file_size(input_path)

        header = {
            "version": 1,
            "cipher": cipher_type,
            "nonce": base64.b64encode(nonce).decode(),
            "encrypted_fek": base64.b64encode(encrypted_fek).decode(),
            "file_size": original_size,
            "timestamp": timestamp,
        }

        # Prepare GCM encryptor (streaming)
        backend = default_backend()
        cipher = Cipher(algorithms.AES(fek), modes.GCM(nonce), backend=backend)
        encryptor = cipher.encryptor()

        encrypted_size = 0

        try:
            with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
                # Reserve header space
                fout.write(b"\x00" * HEADER_SIZE)

                # Stream encryption
                for chunk in _read_in_chunks(fin, self.chunk_size):
                    ct = encryptor.update(chunk)
                    if ct:
                        fout.write(ct)
                        encrypted_size += len(ct)

                # finalize and get tag
                final_ct = encryptor.finalize()
                if final_ct:
                    fout.write(final_ct)
                    encrypted_size += len(final_ct)

                tag = encryptor.tag

                # write auth tag
                fout.write(tag)
                encrypted_size += len(tag)

            # write header into reserved area
            header_bytes = json.dumps(header).encode("utf-8")
            padded = _pad_header(header_bytes)
            with open(output_path, "r+b") as fout:
                fout.seek(0)
                fout.write(padded)

            return {
                "success": True,
                "input_file": input_path,
                "output_file": output_path,
                "encrypted_fek": base64.b64encode(encrypted_fek).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "auth_tag": base64.b64encode(tag).decode(),
                "file_size_original": original_size,
                "file_size_encrypted": encrypted_size,
                "cipher": cipher_type,
                "timestamp": timestamp,
            }

        except Exception as exc:
            raise FileEncryptionError("Encryption failed") from exc

    def decrypt_file_streaming(self, encrypted_path: str, output_path: str, master_key: bytes) -> dict:
        # Read header
        with open(encrypted_path, "rb") as fin:
            raw_header = fin.read(HEADER_SIZE)
        try:
            header_str = raw_header.rstrip(b"\x00").decode("utf-8")
            header = json.loads(header_str)
        except Exception as exc:
            raise FileEncryptionError("Failed to read file header") from exc

        encrypted_fek_b64 = header.get("encrypted_fek")
        if not encrypted_fek_b64:
            raise FileEncryptionError("Missing encrypted FEK in header")

        encrypted_fek = base64.b64decode(encrypted_fek_b64)
        fek = self.decrypt_key_with_master_key(encrypted_fek, master_key)

        nonce = base64.b64decode(header.get("nonce"))

        total_size = os.path.getsize(encrypted_path)
        # encrypted data region: from HEADER_SIZE to total_size - 16 (tag)
        tag_offset = total_size - 16

        backend = default_backend()
        # read tag
        with open(encrypted_path, "rb") as fin:
            fin.seek(tag_offset)
            tag = fin.read(16)

        cipher = Cipher(algorithms.AES(fek), modes.GCM(nonce, tag), backend=backend)
        decryptor = cipher.decryptor()

        decrypted_size = 0
        try:
            with open(encrypted_path, "rb") as fin, open(output_path, "wb") as fout:
                fin.seek(HEADER_SIZE)
                remaining = tag_offset - HEADER_SIZE
                while remaining > 0:
                    to_read = min(self.chunk_size, remaining)
                    chunk = fin.read(to_read)
                    if not chunk:
                        break
                    pt = decryptor.update(chunk)
                    if pt:
                        fout.write(pt)
                        decrypted_size += len(pt)
                    remaining -= len(chunk)

                # finalize (verifies tag)
                final = decryptor.finalize()
                if final:
                    fout.write(final)
                    decrypted_size += len(final)

            return {
                "success": True,
                "encrypted_file": encrypted_path,
                "output_file": output_path,
                "file_size_decrypted": decrypted_size,
                "integrity_verified": True,
                "timestamp": int(time.time()),
            }

        except Exception as exc:
            # If tag verification fails, cryptography raises InvalidTag inside finalize
            raise FileIntegrityError("File authentication failed - file may be tampered") from exc
