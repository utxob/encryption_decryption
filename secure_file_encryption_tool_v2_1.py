#!/usr/bin/env python3
"""
Secure File Encryption & Decryption Tool
Version 2.1.0

Features:
- AES-256-GCM and ChaCha20-Poly1305
- Argon2id and PBKDF2-HMAC-SHA256
- Streaming/chunked encryption for large files
- Fresh 96-bit nonce for every AEAD record
- Authenticated binary container; filename/extension is irrelevant
- Encrypted original filename metadata
- Optional plaintext SHA-256 verification
- Atomic temporary-file output
- Safe cancellation
- GUI + CLI + drag/drop + inspect + tests

Dependencies:
    pip install cryptography argon2-cffi
    Optional drag/drop: pip install tkinterdnd2
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import math
import os
import secrets
import struct
import sys
import tempfile
import threading
import queue
import time
import tkinter as tk
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, BinaryIO, Callable, Dict, Optional

from argon2 import Type
from argon2 import low_level
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from tkinterdnd2 import TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False


MAGIC_HEADER = b"SECURE02"
VERSION = 2
HEADER_SIZE = 64
NONCE_SIZE = 12
SALT_SIZE = 16
AEAD_TAG_SIZE = 16
DEFAULT_CHUNK_SIZE = 1024 * 1024
MIN_CHUNK_SIZE = 4 * 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
MAX_METADATA_SIZE = 1024 * 1024
MAX_FILENAME_BYTES = 4096
MAX_CHUNKS = (1 << 64) - 1

# 64-byte fixed header:
# 8s magic, B version, B flags, B algorithm, B kdf,
# 16s salt, 3I KDF params, 2H KDF params, I metadata ciphertext length,
# Q total chunks, Q plaintext file size
HEADER_STRUCT = struct.Struct(">8sBBBB16sIIIHHIQQ")

METADATA_RECORD_TYPE = 1
FILE_RECORD_TYPE = 2

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536       # KiB = 64 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
PBKDF2_ITERATIONS = 600_000
PBKDF2_HASH_LEN = 32

# Parser safety bounds. These stop a hostile header from requesting absurd KDF work.
MAX_ARGON2_TIME = 10
MAX_ARGON2_MEMORY_KIB = 1024 * 1024  # 1 GiB
MAX_ARGON2_PARALLELISM = 16
MAX_KDF_HASH_LEN = 32
MIN_PBKDF2_ITERATIONS = 100_000
MAX_PBKDF2_ITERATIONS = 5_000_000


class EncryptionError(Exception):
    pass


class InvalidFileError(EncryptionError):
    pass


class UnsupportedVersionError(EncryptionError):
    pass


class UnsupportedAlgorithmError(EncryptionError):
    pass


class UnsupportedKDFError(EncryptionError):
    pass


class AuthenticationError(EncryptionError):
    pass


class IntegrityError(EncryptionError):
    pass


class TruncatedFileError(EncryptionError):
    pass


class MalformedFileError(EncryptionError):
    pass


class SHA256VerificationError(EncryptionError):
    pass


class CancelledError(EncryptionError):
    pass


class Algorithm(IntEnum):
    AES_256_GCM = 1
    CHACHA20_POLY1305 = 2


class KDF(IntEnum):
    ARGON2ID = 1
    PBKDF2 = 2


@dataclass
class HeaderData:
    raw: bytes
    magic: bytes
    version: int
    flags: int
    algorithm_id: int
    kdf_id: int
    salt: bytes
    kdf_params: Dict[str, int]
    metadata_length: int
    total_chunks: int
    file_size: int


@dataclass
class EncryptedFileInfo:
    is_encrypted: bool
    version: Optional[int] = None
    algorithm: Optional[str] = None
    kdf: Optional[str] = None
    original_filename: Optional[str] = None
    file_size: Optional[int] = None
    chunk_size: Optional[int] = None
    sha256: Optional[str] = None
    has_metadata: bool = False


class KDFManager:
    @staticmethod
    def derive_argon2id(password: bytes, salt: bytes, params: Dict[str, int]) -> bytes:
        try:
            return low_level.hash_secret_raw(
                secret=password,
                salt=salt,
                time_cost=params["time_cost"],
                memory_cost=params["memory_cost"],
                parallelism=params["parallelism"],
                hash_len=params["hash_len"],
                type=Type.ID,
            )
        except Exception as exc:
            raise EncryptionError("Argon2id key derivation failed") from exc

    @staticmethod
    def derive_pbkdf2(password: bytes, salt: bytes, params: Dict[str, int]) -> bytes:
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=params["hash_len"],
                salt=salt,
                iterations=params["iterations"],
            )
            return kdf.derive(password)
        except Exception as exc:
            raise EncryptionError("PBKDF2 key derivation failed") from exc

    @staticmethod
    def default_params(kdf_id: int) -> Dict[str, int]:
        if int(kdf_id) == int(KDF.ARGON2ID):
            return {
                "time_cost": ARGON2_TIME_COST,
                "memory_cost": ARGON2_MEMORY_COST,
                "parallelism": ARGON2_PARALLELISM,
                "hash_len": ARGON2_HASH_LEN,
            }
        if int(kdf_id) == int(KDF.PBKDF2):
            return {"iterations": PBKDF2_ITERATIONS, "hash_len": PBKDF2_HASH_LEN}
        raise UnsupportedKDFError(f"Unsupported KDF ID: {kdf_id}")

    @staticmethod
    def validate(kdf_id: int, params: Dict[str, int]) -> None:
        if int(kdf_id) == int(KDF.ARGON2ID):
            t = int(params.get("time_cost", 0))
            m = int(params.get("memory_cost", 0))
            p = int(params.get("parallelism", 0))
            h = int(params.get("hash_len", 0))
            if not (1 <= t <= MAX_ARGON2_TIME):
                raise MalformedFileError("Invalid Argon2id time cost")
            if not (8 * 1024 <= m <= MAX_ARGON2_MEMORY_KIB):
                raise MalformedFileError("Invalid Argon2id memory cost")
            if not (1 <= p <= MAX_ARGON2_PARALLELISM):
                raise MalformedFileError("Invalid Argon2id parallelism")
            if h != 32:
                raise MalformedFileError("Unsupported Argon2id key length")
        elif int(kdf_id) == int(KDF.PBKDF2):
            i = int(params.get("iterations", 0))
            h = int(params.get("hash_len", 0))
            if not (MIN_PBKDF2_ITERATIONS <= i <= MAX_PBKDF2_ITERATIONS):
                raise MalformedFileError("Invalid PBKDF2 iteration count")
            if h != 32:
                raise MalformedFileError("Unsupported PBKDF2 key length")
        else:
            raise UnsupportedKDFError(f"Unsupported KDF ID: {kdf_id}")


class SecureEncryptor:
    def __init__(self, algorithm: str = "AES-256-GCM", chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.algorithm_name = algorithm
        self.algorithm_id = self._algorithm_id_from_name(algorithm)
        self.chunk_size = self._validate_chunk_size(chunk_size)
        self.progress_callback: Optional[Callable[[int, int], None]] = None
        self.status_callback: Optional[Callable[[str, bool], None]] = None
        self._cancel_event = threading.Event()
        self._operation_lock = threading.Lock()

    @staticmethod
    def _validate_chunk_size(size: int) -> int:
        size = int(size)
        if not MIN_CHUNK_SIZE <= size <= MAX_CHUNK_SIZE:
            raise ValueError(f"Chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes")
        return size

    @staticmethod
    def _algorithm_id_from_name(name: str) -> int:
        if name == "AES-256-GCM":
            return int(Algorithm.AES_256_GCM)
        if name == "ChaCha20-Poly1305":
            return int(Algorithm.CHACHA20_POLY1305)
        raise UnsupportedAlgorithmError(f"Unsupported algorithm: {name}")

    @staticmethod
    def _algorithm_name(algo_id: int) -> str:
        if int(algo_id) == int(Algorithm.AES_256_GCM):
            return "AES-256-GCM"
        if int(algo_id) == int(Algorithm.CHACHA20_POLY1305):
            return "ChaCha20-Poly1305"
        raise UnsupportedAlgorithmError(f"Unsupported algorithm ID: {algo_id}")

    @staticmethod
    def _kdf_name(kdf_id: int) -> str:
        if int(kdf_id) == int(KDF.ARGON2ID):
            return "Argon2id"
        if int(kdf_id) == int(KDF.PBKDF2):
            return "PBKDF2"
        raise UnsupportedKDFError(f"Unsupported KDF ID: {kdf_id}")

    def set_progress_callback(self, callback: Optional[Callable[[int, int], None]]) -> None:
        self.progress_callback = callback

    def set_status_callback(self, callback: Optional[Callable[[str, bool], None]]) -> None:
        self.status_callback = callback

    def cancel(self) -> None:
        self._cancel_event.set()

    def _reset_cancel(self) -> None:
        self._cancel_event.clear()

    def _check_cancelled(self) -> None:
        if self._cancel_event.is_set():
            raise CancelledError("Operation cancelled by user")

    def _update_progress(self, current: int, total: int) -> None:
        if self.progress_callback:
            self.progress_callback(current, total)

    def _status(self, message: str, error: bool = False) -> None:
        if self.status_callback:
            self.status_callback(message, error)

    @staticmethod
    def _password_bytes(password: str) -> bytes:
        if not isinstance(password, str) or not password:
            raise ValueError("Password cannot be empty")
        return password.encode("utf-8")

    @staticmethod
    def _derive_key(password: bytes, salt: bytes, kdf_id: int, params: Dict[str, int]) -> bytes:
        KDFManager.validate(kdf_id, params)
        if int(kdf_id) == int(KDF.ARGON2ID):
            return KDFManager.derive_argon2id(password, salt, params)
        if int(kdf_id) == int(KDF.PBKDF2):
            return KDFManager.derive_pbkdf2(password, salt, params)
        raise UnsupportedKDFError(f"Unsupported KDF ID: {kdf_id}")

    @staticmethod
    def _create_cipher(key: bytes, algorithm_id: int):
        if int(algorithm_id) == int(Algorithm.AES_256_GCM):
            return AESGCM(key)
        if int(algorithm_id) == int(Algorithm.CHACHA20_POLY1305):
            return ChaCha20Poly1305(key)
        raise UnsupportedAlgorithmError(f"Unsupported algorithm ID: {algorithm_id}")

    @staticmethod
    def _calculate_file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _safe_filename(name: str) -> str:
        if not isinstance(name, str) or not name:
            raise MalformedFileError("Invalid original filename metadata")
        if len(name.encode("utf-8")) > MAX_FILENAME_BYTES:
            raise MalformedFileError("Original filename is too long")
        if name in {".", ".."} or "/" in name or "\\" in name:
            raise MalformedFileError("Unsafe original filename")
        if any(ord(ch) < 32 for ch in name):
            raise MalformedFileError("Original filename contains control characters")
        return name

    @staticmethod
    def _create_header(
        algorithm_id: int,
        kdf_id: int,
        salt: bytes,
        kdf_params: Dict[str, int],
        metadata_length: int,
        total_chunks: int,
        file_size: int,
        flags: int = 0,
    ) -> bytes:
        if len(salt) != SALT_SIZE:
            raise ValueError("Invalid salt length")
        if metadata_length <= AEAD_TAG_SIZE or metadata_length > MAX_METADATA_SIZE:
            raise ValueError("Invalid metadata length")
        if total_chunks < 0 or total_chunks > MAX_CHUNKS:
            raise ValueError("Invalid chunk count")
        if file_size < 0:
            raise ValueError("Invalid file size")

        if int(kdf_id) == int(KDF.ARGON2ID):
            params = (
                int(kdf_params["time_cost"]),
                int(kdf_params["memory_cost"]),
                int(kdf_params["parallelism"]),
                int(kdf_params["hash_len"]),
                0,
            )
        elif int(kdf_id) == int(KDF.PBKDF2):
            params = (
                int(kdf_params["iterations"]),
                0,
                0,
                int(kdf_params["hash_len"]),
                0,
            )
        else:
            raise UnsupportedKDFError(f"Unsupported KDF ID: {kdf_id}")

        raw = HEADER_STRUCT.pack(
            MAGIC_HEADER,
            VERSION,
            flags,
            int(algorithm_id),
            int(kdf_id),
            salt,
            params[0], params[1], params[2], params[3], params[4],
            int(metadata_length),
            int(total_chunks),
            int(file_size),
        )
        if len(raw) != HEADER_SIZE:
            raise AssertionError("Internal header size error")
        return raw

    @staticmethod
    def _parse_header(f: BinaryIO) -> HeaderData:
        raw = f.read(HEADER_SIZE)
        if len(raw) != HEADER_SIZE:
            raise TruncatedFileError("Encrypted file has an incomplete header")

        try:
            (
                magic, version, flags, algo_id, kdf_id, salt,
                p1, p2, p3, p4, _reserved,
                metadata_length, total_chunks, file_size,
            ) = HEADER_STRUCT.unpack(raw)
        except struct.error as exc:
            raise MalformedFileError("Invalid header structure") from exc

        if magic != MAGIC_HEADER:
            raise InvalidFileError("Not a Secure02 encrypted container")
        if version != VERSION:
            raise UnsupportedVersionError(f"Unsupported format version: {version}")

        # Validate identifiers before doing any KDF work.
        SecureEncryptor._algorithm_name(algo_id)
        SecureEncryptor._kdf_name(kdf_id)

        if flags != 0:
            raise MalformedFileError("Unsupported header flags")
        if metadata_length <= AEAD_TAG_SIZE or metadata_length > MAX_METADATA_SIZE:
            raise MalformedFileError("Invalid metadata length")
        if total_chunks > MAX_CHUNKS:
            raise MalformedFileError("Invalid chunk count")

        if int(kdf_id) == int(KDF.ARGON2ID):
            params = {
                "time_cost": p1,
                "memory_cost": p2,
                "parallelism": p3,
                "hash_len": p4,
            }
        elif int(kdf_id) == int(KDF.PBKDF2):
            params = {"iterations": p1, "hash_len": p4}
        else:
            raise UnsupportedKDFError(f"Unsupported KDF ID: {kdf_id}")

        KDFManager.validate(kdf_id, params)

        expected_chunks = math.ceil(file_size / DEFAULT_CHUNK_SIZE) if file_size else 0
        # We cannot require DEFAULT_CHUNK_SIZE because the actual chunk size is encrypted metadata.
        # But a non-empty file must have at least one chunk and an empty file must have zero chunks.
        if file_size == 0 and total_chunks != 0:
            raise MalformedFileError("Empty file has non-zero chunk count")
        if file_size > 0 and total_chunks == 0:
            raise MalformedFileError("Non-empty file has zero chunks")

        return HeaderData(
            raw=raw,
            magic=magic,
            version=version,
            flags=flags,
            algorithm_id=algo_id,
            kdf_id=kdf_id,
            salt=salt,
            kdf_params=params,
            metadata_length=metadata_length,
            total_chunks=total_chunks,
            file_size=file_size,
        )

    @staticmethod
    def _metadata_aad(header_raw: bytes) -> bytes:
        return b"SECURE02-METADATA\x00" + header_raw

    @staticmethod
    def _chunk_aad(header_raw: bytes, index: int, plaintext_len: int, ciphertext_len: int) -> bytes:
        return (
            b"SECURE02-CHUNK\x00" + header_raw +
            struct.pack(">QII", index, plaintext_len, ciphertext_len)
        )

    def _write_chunk_record(
        self, f: BinaryIO, index: int, plaintext_len: int,
        nonce: bytes, ciphertext: bytes, header_raw: bytes,
    ) -> None:
        if len(nonce) != NONCE_SIZE:
            raise ValueError("Invalid nonce length")
        if len(ciphertext) != plaintext_len + AEAD_TAG_SIZE:
            raise ValueError("Invalid ciphertext length")
        f.write(struct.pack(">QI", index, plaintext_len))
        f.write(nonce)
        f.write(struct.pack(">I", len(ciphertext)))
        f.write(ciphertext)

    def _read_chunk_record(self, f: BinaryIO, expected_index: int, file_size: int) -> Dict[str, Any]:
        raw = f.read(12)
        if len(raw) != 12:
            raise TruncatedFileError(f"Missing chunk {expected_index} header")
        index, plaintext_len = struct.unpack(">QI", raw)
        if index != expected_index:
            raise MalformedFileError(f"Unexpected chunk index: {index}")
        if plaintext_len > self.chunk_size:
            raise MalformedFileError(f"Chunk {index} is larger than configured chunk size")
        if plaintext_len == 0 and file_size != 0:
            raise MalformedFileError(f"Chunk {index} has zero plaintext length")

        nonce = f.read(NONCE_SIZE)
        if len(nonce) != NONCE_SIZE:
            raise TruncatedFileError(f"Missing nonce for chunk {index}")

        clen_raw = f.read(4)
        if len(clen_raw) != 4:
            raise TruncatedFileError(f"Missing ciphertext length for chunk {index}")
        ciphertext_len = struct.unpack(">I", clen_raw)[0]
        if ciphertext_len != plaintext_len + AEAD_TAG_SIZE:
            raise MalformedFileError(f"Invalid ciphertext length for chunk {index}")

        ciphertext = f.read(ciphertext_len)
        if len(ciphertext) != ciphertext_len:
            raise TruncatedFileError(f"Truncated ciphertext in chunk {index}")

        return {
            "index": index,
            "plaintext_len": plaintext_len,
            "nonce": nonce,
            "ciphertext_len": ciphertext_len,
            "ciphertext": ciphertext,
        }

    def _encrypt_metadata(self, cipher, metadata: bytes, nonce: bytes, header_raw: bytes) -> bytes:
        return cipher.encrypt(nonce, metadata, self._metadata_aad(header_raw))

    def _decrypt_metadata(self, cipher, f: BinaryIO, header: HeaderData) -> Dict[str, Any]:
        nonce = f.read(NONCE_SIZE)
        if len(nonce) != NONCE_SIZE:
            raise TruncatedFileError("Missing metadata nonce")
        encrypted = f.read(header.metadata_length)
        if len(encrypted) != header.metadata_length:
            raise TruncatedFileError("Truncated encrypted metadata")
        try:
            plaintext = cipher.decrypt(
                nonce, encrypted, self._metadata_aad(header.raw)
            )
        except Exception as exc:
            raise AuthenticationError("Wrong password or corrupted encrypted metadata") from exc
        if len(plaintext) > MAX_METADATA_SIZE:
            raise MalformedFileError("Metadata is too large")
        try:
            metadata = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MalformedFileError("Invalid encrypted metadata") from exc
        if not isinstance(metadata, dict):
            raise MalformedFileError("Invalid metadata object")
        return metadata

    def encrypt_file(
        self,
        input_path: Path,
        output_path: Path,
        password: str,
        preserve_name: bool = True,
        kdf: str = "Argon2id",
        verify_sha256: bool = False,
    ) -> bool:
        with self._operation_lock:
            self._reset_cancel()
            input_path = Path(input_path)
            output_path = Path(output_path)
            temp_path: Optional[Path] = None
            temp_file: Optional[BinaryIO] = None
            try:
                if not input_path.is_file():
                    raise FileNotFoundError(f"Input file not found: {input_path}")
                if input_path.resolve() == output_path.resolve():
                    raise ValueError("Input and output files must be different")

                password_bytes = self._password_bytes(password)
                kdf_id = int(KDF.ARGON2ID) if kdf.lower() == "argon2id" else int(KDF.PBKDF2) if kdf.lower() == "pbkdf2" else None
                if kdf_id is None:
                    raise UnsupportedKDFError(f"Unsupported KDF: {kdf}")
                kdf_params = KDFManager.default_params(kdf_id)
                KDFManager.validate(kdf_id, kdf_params)

                file_size = input_path.stat().st_size
                total_chunks = math.ceil(file_size / self.chunk_size) if file_size else 0
                if total_chunks > MAX_CHUNKS:
                    raise ValueError("File is too large for this container format")

                sha256_value = self._calculate_file_sha256(input_path) if verify_sha256 else None
                original_name = self._safe_filename(input_path.name) if preserve_name else ""

                metadata = {
                    "format": "SECURE02",
                    "original_name": original_name,
                    "timestamp": int(time.time()),
                    "file_size": file_size,
                    "chunk_size": self.chunk_size,
                    "sha256": sha256_value,
                }
                metadata_bytes = json.dumps(
                    metadata, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
                if len(metadata_bytes) > MAX_METADATA_SIZE - AEAD_TAG_SIZE:
                    raise ValueError("Metadata is too large")

                salt = secrets.token_bytes(SALT_SIZE)
                key = self._derive_key(password_bytes, salt, kdf_id, kdf_params)
                cipher = self._create_cipher(key, self.algorithm_id)
                metadata_nonce = secrets.token_bytes(NONCE_SIZE)
                metadata_length = len(metadata_bytes) + AEAD_TAG_SIZE
                header = self._create_header(
                    self.algorithm_id, kdf_id, salt, kdf_params,
                    metadata_length, total_chunks, file_size
                )
                encrypted_metadata = self._encrypt_metadata(
                    cipher, metadata_bytes, metadata_nonce, header
                )
                if len(encrypted_metadata) != metadata_length:
                    raise EncryptionError("Internal metadata length error")

                output_path.parent.mkdir(parents=True, exist_ok=True)
                temp_file = tempfile.NamedTemporaryFile(
                    mode="wb", dir=str(output_path.parent), prefix=".tmp_encrypt_", delete=False
                )
                temp_path = Path(temp_file.name)

                temp_file.write(header)
                temp_file.write(metadata_nonce)
                temp_file.write(encrypted_metadata)

                processed = 0
                with input_path.open("rb") as source:
                    for index in range(total_chunks):
                        self._check_cancelled()
                        plaintext = source.read(self.chunk_size)
                        if not plaintext:
                            raise TruncatedFileError("Input changed while encryption was running")
                        nonce = secrets.token_bytes(NONCE_SIZE)
                        ciphertext_len = len(plaintext) + AEAD_TAG_SIZE
                        aad = self._chunk_aad(header, index, len(plaintext), ciphertext_len)
                        ciphertext = cipher.encrypt(nonce, plaintext, aad)
                        self._write_chunk_record(
                            temp_file, index, len(plaintext), nonce, ciphertext, header
                        )
                        processed += len(plaintext)
                        self._update_progress(processed, file_size)

                temp_file.flush()
                os.fsync(temp_file.fileno())
                temp_file.close()
                temp_file = None
                self._check_cancelled()
                os.replace(temp_path, output_path)
                temp_path = None
                self._status("Encryption completed successfully.")
                return True
            except CancelledError:
                self._status("Encryption cancelled.", True)
                raise
            except Exception as exc:
                self._status("Encryption failed.", True)
                if isinstance(exc, EncryptionError):
                    raise
                raise EncryptionError(f"Encryption failed: {exc}") from exc
            finally:
                if temp_file is not None:
                    try:
                        temp_file.close()
                    except Exception:
                        pass
                if temp_path is not None:
                    try:
                        temp_path.unlink(missing_ok=True)
                    except Exception:
                        pass

    def decrypt_file(self, input_path: Path, output_path: Path, password: str) -> bool:
        with self._operation_lock:
            self._reset_cancel()
            input_path = Path(input_path)
            output_path = Path(output_path)
            temp_path: Optional[Path] = None
            temp_file: Optional[BinaryIO] = None
            try:
                if not input_path.is_file():
                    raise FileNotFoundError(f"Input file not found: {input_path}")
                if input_path.resolve() == output_path.resolve():
                    raise ValueError("Input and output files must be different")
                password_bytes = self._password_bytes(password)

                with input_path.open("rb") as source:
                    header = self._parse_header(source)
                    key = self._derive_key(
                        password_bytes, header.salt, header.kdf_id, header.kdf_params
                    )
                    cipher = self._create_cipher(key, header.algorithm_id)
                    metadata = self._decrypt_metadata(cipher, source, header)

                    if metadata.get("format") != "SECURE02":
                        raise MalformedFileError("Invalid metadata format")
                    if int(metadata.get("file_size", -1)) != header.file_size:
                        raise IntegrityError("Header and metadata file size mismatch")
                    chunk_size = int(metadata.get("chunk_size", 0))
                    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
                        raise MalformedFileError("Invalid stored chunk size")
                    if header.file_size == 0:
                        if header.total_chunks != 0:
                            raise IntegrityError("Invalid empty-file chunk count")
                    else:
                        expected_min = math.ceil(header.file_size / chunk_size)
                        if header.total_chunks != expected_min:
                            raise IntegrityError("Chunk count does not match file size")

                    stored_name = metadata.get("original_name", "")
                    if stored_name:
                        stored_name = self._safe_filename(stored_name)

                    stored_hash = metadata.get("sha256")
                    if stored_hash is not None:
                        if not isinstance(stored_hash, str) or len(stored_hash) != 64:
                            raise MalformedFileError("Invalid stored SHA-256")
                        try:
                            int(stored_hash, 16)
                        except ValueError as exc:
                            raise MalformedFileError("Invalid stored SHA-256") from exc

                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    temp_file = tempfile.NamedTemporaryFile(
                        mode="wb", dir=str(output_path.parent), prefix=".tmp_decrypt_", delete=False
                    )
                    temp_path = Path(temp_file.name)

                    processed = 0
                    for index in range(header.total_chunks):
                        self._check_cancelled()
                        record = self._read_chunk_record(source, index, header.file_size)
                        aad = self._chunk_aad(
                            header.raw,
                            index,
                            record["plaintext_len"],
                            record["ciphertext_len"],
                        )
                        try:
                            plaintext = cipher.decrypt(
                                record["nonce"], record["ciphertext"], aad
                            )
                        except Exception as exc:
                            raise IntegrityError(
                                f"Authentication failed for chunk {index}; file may be corrupted or tampered with"
                            ) from exc
                        if len(plaintext) != record["plaintext_len"]:
                            raise IntegrityError(f"Plaintext length mismatch in chunk {index}")
                        temp_file.write(plaintext)
                        processed += len(plaintext)
                        self._update_progress(processed, header.file_size)

                    # No trailing bytes are allowed. This catches concatenated/corrupted containers.
                    if source.read(1):
                        raise MalformedFileError("Unexpected trailing data after final chunk")

                    if processed != header.file_size:
                        raise IntegrityError(
                            f"File size mismatch: expected {header.file_size}, got {processed}"
                        )

                    temp_file.flush()
                    os.fsync(temp_file.fileno())

                    if stored_hash:
                        actual_hash = self._calculate_file_sha256(temp_path)
                        if not secrets.compare_digest(actual_hash, stored_hash):
                            raise SHA256VerificationError("SHA-256 verification failed")

                    temp_file.close()
                    temp_file = None
                    self._check_cancelled()
                    os.replace(temp_path, output_path)
                    temp_path = None

                    self._status("Decryption completed successfully.")
                    return True
            except CancelledError:
                self._status("Decryption cancelled.", True)
                raise
            except Exception:
                self._status("Decryption failed.", True)
                raise
            finally:
                if temp_file is not None:
                    try:
                        temp_file.close()
                    except Exception:
                        pass
                if temp_path is not None:
                    try:
                        temp_path.unlink(missing_ok=True)
                    except Exception:
                        pass

    def inspect_file(self, file_path: Path) -> EncryptedFileInfo:
        file_path = Path(file_path)
        try:
            if not file_path.is_file():
                return EncryptedFileInfo(False)
            with file_path.open("rb") as f:
                header = self._parse_header(f)
            return EncryptedFileInfo(
                is_encrypted=True,
                version=header.version,
                algorithm=self._algorithm_name(header.algorithm_id),
                kdf=self._kdf_name(header.kdf_id),
                file_size=file_path.stat().st_size,
                has_metadata=header.metadata_length > AEAD_TAG_SIZE,
            )
        except EncryptionError:
            return EncryptedFileInfo(False)
        except (OSError, ValueError):
            return EncryptedFileInfo(False)


class GUIWorker:
    def __init__(self, app: "EncryptionGUI", encryptor: SecureEncryptor):
        self.app = app
        self.encryptor = encryptor
        self.queue: queue.Queue = queue.Queue()
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def start_operation(self, operation: Callable, *args, **kwargs) -> bool:
        if self.running:
            return False
        self.running = True
        self.thread = threading.Thread(
            target=self._run_operation, args=(operation, args, kwargs), daemon=True
        )
        self.thread.start()
        return True

    def _run_operation(self, operation: Callable, args, kwargs) -> None:
        try:
            result = operation(*args, **kwargs)
            self.queue.put(("success", result))
        except Exception as exc:
            self.queue.put(("error", str(exc)))
        finally:
            self.running = False
            self.queue.put(("done", None))

    def cancel(self) -> None:
        self.encryptor.cancel()

    def report_progress(self, current: int, total: int) -> None:
        self.queue.put(("progress", (current, total)))

    def report_status(self, message: str, is_error: bool = False) -> None:
        self.queue.put(("status", (message, is_error)))

    def update_gui(self) -> None:
        while True:
            try:
                kind, data = self.queue.get_nowait()
            except queue.Empty:
                break
            if kind == "progress":
                self.app.update_progress(*data)
            elif kind == "status":
                self.app.update_status(data)
            elif kind == "success":
                self.app.operation_success(data)
            elif kind == "error":
                self.app.operation_error(data)
            elif kind == "done":
                self.app.operation_done()


if HAS_DND:
    BaseTk = TkinterDnD.Tk
else:
    BaseTk = tk.Tk


class EncryptionGUI:
    def __init__(self):
        self.root = BaseTk()
        self.root.title("Secure File Encryption Tool v2.1")
        self.root.geometry("920x760")
        self.root.minsize(820, 620)
        self.root.protocol("WM_DELETE_WINDOW", self.on_exit)

        self.encryptor = SecureEncryptor()
        self.worker = GUIWorker(self, self.encryptor)

        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.password = tk.StringVar()
        self.mode = tk.StringVar(value="encrypt")
        self.algorithm = tk.StringVar(value="AES-256-GCM")
        self.kdf = tk.StringVar(value="Argon2id")
        self.preserve_name = tk.BooleanVar(value=True)
        self.verify_sha256 = tk.BooleanVar(value=False)
        self.show_password = tk.BooleanVar(value=False)

        self.setup_gui()
        self.root.after(100, self.process_queue)

    def setup_gui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main = ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(6, weight=1)

        op = ttk.LabelFrame(main, text="Operation", padding=8)
        op.grid(row=0, column=0, sticky="ew", pady=4)
        ttk.Radiobutton(op, text="Encrypt", variable=self.mode, value="encrypt", command=self.update_mode).grid(row=0, column=0, padx=6)
        ttk.Radiobutton(op, text="Decrypt", variable=self.mode, value="decrypt", command=self.update_mode).grid(row=0, column=1, padx=6)
        ttk.Label(op, text="Algorithm:").grid(row=0, column=2, padx=(20, 4))
        ttk.Combobox(op, textvariable=self.algorithm, values=["AES-256-GCM", "ChaCha20-Poly1305"], state="readonly", width=19).grid(row=0, column=3, padx=4)
        ttk.Label(op, text="KDF:").grid(row=0, column=4, padx=(12, 4))
        ttk.Combobox(op, textvariable=self.kdf, values=["Argon2id", "PBKDF2"], state="readonly", width=12).grid(row=0, column=5, padx=4)

        inp = ttk.LabelFrame(main, text="Input File", padding=8)
        inp.grid(row=1, column=0, sticky="ew", pady=4)
        inp.columnconfigure(0, weight=1)
        ttk.Entry(inp, textvariable=self.input_file).grid(row=0, column=0, sticky="ew", padx=4)
        ttk.Button(inp, text="Browse...", command=self.browse_input).grid(row=0, column=1, padx=4)
        ttk.Button(inp, text="Inspect", command=self.inspect_file).grid(row=0, column=2, padx=4)

        out = ttk.LabelFrame(main, text="Output File", padding=8)
        out.grid(row=2, column=0, sticky="ew", pady=4)
        out.columnconfigure(0, weight=1)
        ttk.Entry(out, textvariable=self.output_file).grid(row=0, column=0, sticky="ew", padx=4)
        ttk.Button(out, text="Browse...", command=self.browse_output).grid(row=0, column=1, padx=4)

        pw = ttk.LabelFrame(main, text="Password", padding=8)
        pw.grid(row=3, column=0, sticky="ew", pady=4)
        self.password_entry = ttk.Entry(pw, textvariable=self.password, show="•", width=45)
        self.password_entry.grid(row=0, column=0, padx=4)
        ttk.Button(pw, text="Toggle Show", command=self.toggle_password_visibility).grid(row=0, column=1, padx=4)
        self.strength_label = ttk.Label(pw, text="Password strength: --")
        self.strength_label.grid(row=0, column=2, padx=8)
        self.password.trace_add("write", lambda *_: self.update_strength())

        opts = ttk.LabelFrame(main, text="Options", padding=8)
        opts.grid(row=4, column=0, sticky="ew", pady=4)
        ttk.Checkbutton(opts, text="Preserve original filename", variable=self.preserve_name).grid(row=0, column=0, padx=8)
        ttk.Checkbutton(opts, text="Verify SHA-256", variable=self.verify_sha256).grid(row=0, column=1, padx=8)

        prog = ttk.LabelFrame(main, text="Progress", padding=8)
        prog.grid(row=5, column=0, sticky="ew", pady=4)
        prog.columnconfigure(0, weight=1)
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(prog, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=0, column=0, sticky="ew", padx=4)
        self.progress_label = ttk.Label(prog, text="0.0%")
        self.progress_label.grid(row=0, column=1, padx=6)

        status = ttk.LabelFrame(main, text="Status", padding=8)
        status.grid(row=6, column=0, sticky="nsew", pady=4)
        status.rowconfigure(0, weight=1)
        status.columnconfigure(0, weight=1)
        self.status_text = scrolledtext.ScrolledText(status, height=9)
        self.status_text.grid(row=0, column=0, sticky="nsew")
        self.status_text.tag_config("error", foreground="red")
        self.status_text.tag_config("success", foreground="green")
        self.status_text.tag_config("info", foreground="blue")

        buttons = ttk.Frame(main)
        buttons.grid(row=7, column=0, pady=8)
        self.action_button = ttk.Button(buttons, text="Encrypt", command=self.execute_operation, width=16)
        self.action_button.grid(row=0, column=0, padx=4)
        ttk.Button(buttons, text="Cancel", command=self.cancel_operation, width=16).grid(row=0, column=1, padx=4)
        ttk.Button(buttons, text="Clear", command=self.clear_fields, width=16).grid(row=0, column=2, padx=4)
        ttk.Button(buttons, text="Exit", command=self.on_exit, width=16).grid(row=0, column=3, padx=4)

        self.setup_drag_drop()
        self.update_mode()

    def setup_drag_drop(self):
        if not HAS_DND:
            return
        try:
            self.root.drop_target_register("DND_Files")
            self.root.dnd_bind("<<Drop>>", self.on_drop)
        except (tk.TclError, AttributeError):
            pass

    def on_drop(self, event):
        try:
            files = self.root.tk.splitlist(event.data)
            if files:
                self.input_file.set(files[0])
                self.auto_set_output()
        except (tk.TclError, ValueError):
            self.log_message("Could not read dropped file.", "error")

    def update_mode(self):
        if self.mode.get() == "encrypt":
            self.action_button.config(text="Encrypt")
            self.root.title("Secure File Encryption Tool v2.1 - Encrypt")
        else:
            self.action_button.config(text="Decrypt")
            self.root.title("Secure File Encryption Tool v2.1 - Decrypt")
        self.auto_set_output()

    def browse_input(self):
        filename = filedialog.askopenfilename(title="Select Input File", filetypes=[("All files", "*.*")])
        if filename:
            self.input_file.set(filename)
            self.auto_set_output()

    def browse_output(self):
        if self.mode.get() == "encrypt":
            filename = filedialog.asksaveasfilename(
                title="Select Output File",
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
                defaultextension=".enc",
            )
        else:
            filename = filedialog.asksaveasfilename(title="Select Output File", filetypes=[("All files", "*.*")])
        if filename:
            self.output_file.set(filename)

    def auto_set_output(self):
        raw = self.input_file.get().strip()
        if not raw:
            return
        p = Path(raw)
        if not p.exists():
            return
        if self.mode.get() == "encrypt":
            self.output_file.set(str(p.with_suffix(p.suffix + ".enc")))
        else:
            # Extension is only a GUI convenience. Decryption itself never depends on it.
            if p.suffix == ".enc":
                self.output_file.set(str(p.with_suffix("")))
            else:
                self.output_file.set(str(p.with_name(p.name + ".decrypted")))

    def toggle_password_visibility(self):
        self.show_password.set(not self.show_password.get())
        self.password_entry.config(show="" if self.show_password.get() else "•")

    def update_strength(self):
        p = self.password.get()
        score = 0
        if len(p) >= 12: score += 1
        if len(p) >= 16: score += 1
        if any(c.islower() for c in p): score += 1
        if any(c.isupper() for c in p): score += 1
        if any(c.isdigit() for c in p): score += 1
        if any(not c.isalnum() for c in p): score += 1
        labels = ["Very weak", "Weak", "Fair", "Good", "Strong", "Very strong", "Very strong"]
        self.strength_label.config(text=f"Password strength: {labels[score]}")

    def inspect_file(self):
        path = Path(self.input_file.get().strip())
        if not path.is_file():
            messagebox.showerror("Error", "Input file does not exist")
            return
        info = self.encryptor.inspect_file(path)
        if not info.is_encrypted:
            self.log_message("✗ File is not a valid Secure02 encrypted container.", "error")
            return
        self.log_message("✓ File is a Secure02 encrypted container.", "success")
        self.log_message(f"  Version: {info.version}", "info")
        self.log_message(f"  Algorithm: {info.algorithm}", "info")
        self.log_message(f"  KDF: {info.kdf}", "info")
        self.log_message(f"  Container size: {info.file_size:,} bytes", "info")
        self.log_message(f"  Encrypted metadata: {'yes' if info.has_metadata else 'no'}", "info")

    def execute_operation(self):
        if self.worker.running:
            return
        input_path = Path(self.input_file.get().strip())
        output_path = Path(self.output_file.get().strip())
        if not input_path.is_file():
            messagebox.showerror("Error", "Input file does not exist")
            return
        if not str(output_path):
            messagebox.showerror("Error", "Choose an output file")
            return
        if input_path.resolve() == output_path.resolve():
            messagebox.showerror("Error", "Input and output must be different")
            return
        if not output_path.parent.exists():
            messagebox.showerror("Error", "Output directory does not exist")
            return
        password = self.password.get()
        if not password:
            messagebox.showerror("Error", "Password cannot be empty")
            return
        if self.mode.get() == "encrypt" and len(password) < 8:
            messagebox.showerror("Error", "Use at least 8 characters; a long passphrase is strongly recommended.")
            return
        if output_path.exists():
            if not messagebox.askyesno("Confirm Overwrite", f"Output already exists:\n{output_path.name}\n\nOverwrite only after successful verification?"):
                return

        self.action_button.config(state="disabled")
        self.progress_var.set(0)
        self.progress_label.config(text="0.0%")
        self.encryptor = SecureEncryptor(self.algorithm.get(), DEFAULT_CHUNK_SIZE)
        self.encryptor.set_progress_callback(self.worker.report_progress)
        self.encryptor.set_status_callback(self.worker.report_status)
        self.worker.encryptor = self.encryptor

        if self.mode.get() == "encrypt":
            self.worker.start_operation(
                self.encryptor.encrypt_file,
                input_path, output_path, password,
                self.preserve_name.get(), self.kdf.get(), self.verify_sha256.get()
            )
            self.log_message(f"Encrypting: {input_path.name}", "info")
        else:
            self.worker.start_operation(self.encryptor.decrypt_file, input_path, output_path, password)
            self.log_message(f"Decrypting: {input_path.name}", "info")

    def cancel_operation(self):
        if self.worker.running:
            self.worker.cancel()
            self.log_message("Cancellation requested...", "info")

    def clear_fields(self):
        if self.worker.running:
            return
        self.input_file.set("")
        self.output_file.set("")
        self.password.set("")
        self.status_text.delete("1.0", tk.END)
        self.progress_var.set(0)
        self.progress_label.config(text="0.0%")

    def process_queue(self):
        self.worker.update_gui()
        self.root.after(100, self.process_queue)

    def update_progress(self, current: int, total: int):
        percent = (current / total * 100) if total else 100
        self.progress_var.set(percent)
        self.progress_label.config(text=f"{percent:.1f}%")

    def update_status(self, data):
        message, is_error = data
        self.log_message(message, "error" if is_error else "info")

    def operation_success(self, _result):
        self.log_message("✓ Operation completed successfully!", "success")

    def operation_error(self, message):
        self.log_message(f"✗ Operation failed: {message}", "error")
        messagebox.showerror("Operation failed", message)

    def operation_done(self):
        self.action_button.config(state="normal")

    def log_message(self, message: str, tag: str = ""):
        self.status_text.insert(tk.END, message + "\n", tag)
        self.status_text.see(tk.END)

    def on_exit(self):
        if self.worker.running:
            if not messagebox.askyesno("Exit", "An operation is running. Cancel it and exit?"):
                return
            self.worker.cancel()
            self.root.after(100, self._finish_exit_when_done)
        else:
            self.root.destroy()

    def _finish_exit_when_done(self):
        if self.worker.running:
            self.root.after(100, self._finish_exit_when_done)
        else:
            self.root.destroy()

    def run(self):
        self.root.mainloop()


def cli_main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Secure File Encryption Tool v2.1")
    parser.add_argument("input", help="Input file path")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-p", "--password", help="Password (prefer prompt for better privacy)")
    parser.add_argument("-m", "--mode", choices=["encrypt", "decrypt", "inspect"], default="encrypt")
    parser.add_argument("-a", "--algorithm", choices=["AES-256-GCM", "ChaCha20-Poly1305"], default="AES-256-GCM")
    parser.add_argument("-k", "--kdf", choices=["Argon2id", "PBKDF2"], default="Argon2id")
    parser.add_argument("--preserve-name", action="store_true", help="Store original filename in encrypted metadata")
    parser.add_argument("--verify", action="store_true", help="Store/verify plaintext SHA-256")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    try:
        encryptor = SecureEncryptor(args.algorithm, args.chunk_size)
        if args.mode == "inspect":
            info = encryptor.inspect_file(Path(args.input))
            if not info.is_encrypted:
                print("✗ File is not a valid Secure02 encrypted container")
                return 1
            print("✓ File is encrypted")
            print(f"  Version: {info.version}")
            print(f"  Algorithm: {info.algorithm}")
            print(f"  KDF: {info.kdf}")
            print(f"  Container size: {info.file_size:,} bytes")
            print(f"  Encrypted metadata: {'yes' if info.has_metadata else 'no'}")
            return 0

        password = args.password
        if password is None:
            password = getpass.getpass("Enter password: ")
            if args.mode == "encrypt":
                confirm = getpass.getpass("Confirm password: ")
                if not secrets.compare_digest(password, confirm):
                    print("Error: passwords do not match")
                    return 1

        input_path = Path(args.input)
        if not input_path.is_file():
            print(f"Error: input file not found: {input_path}")
            return 1

        if args.mode == "encrypt":
            output_path = Path(args.output) if args.output else input_path.with_suffix(input_path.suffix + ".enc")
            print(f"Encrypting: {input_path.name}")
            print(f"Algorithm: {args.algorithm}")
            print(f"KDF: {args.kdf}")
            encryptor.set_progress_callback(lambda c, t: print(f"\rProgress: {(c/t*100 if t else 100):.1f}%", end="", flush=True))
            encryptor.encrypt_file(input_path, output_path, password, args.preserve_name, args.kdf, args.verify)
            print(f"\n✓ Encryption complete: {output_path}")
        else:
            if args.output:
                output_path = Path(args.output)
            elif input_path.suffix == ".enc":
                output_path = input_path.with_suffix("")
            else:
                output_path = input_path.with_name(input_path.name + ".decrypted")
            print(f"Decrypting: {input_path.name}")
            encryptor.set_progress_callback(lambda c, t: print(f"\rProgress: {(c/t*100 if t else 100):.1f}%", end="", flush=True))
            encryptor.decrypt_file(input_path, output_path, password)
            print(f"\n✓ Decryption complete: {output_path}")
        return 0
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 130
    except Exception as exc:
        print(f"\n✗ Error: {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


class TestSuite:
    @staticmethod
    def _roundtrip(algorithm: str, kdf: str, data: bytes, verify: bool = True):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "বাংলা file ✓.txt"
            enc = root / "random.xyz"
            out = root / "restored.bin"
            src.write_bytes(data)
            e = SecureEncryptor(algorithm, 64 * 1024)
            e.encrypt_file(src, enc, "Correct horse battery staple 123!", True, kdf, verify)
            e.decrypt_file(enc, out, "Correct horse battery staple 123!")
            assert out.read_bytes() == data

    @staticmethod
    def test_aes_argon2():
        TestSuite._roundtrip("AES-256-GCM", "Argon2id", b"hello" * 10000)

    @staticmethod
    def test_chacha_argon2():
        TestSuite._roundtrip("ChaCha20-Poly1305", "Argon2id", b"hello" * 10000)

    @staticmethod
    def test_aes_pbkdf2():
        TestSuite._roundtrip("AES-256-GCM", "PBKDF2", b"PBKDF2 test" * 5000)

    @staticmethod
    def test_rename():
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "photo.jpg"
            enc = root / "photo.enc"
            renamed = root / "anything.whatever"
            out = root / "restored.jpg"
            data = secrets.token_bytes(200_000)
            src.write_bytes(data)
            e = SecureEncryptor("AES-256-GCM", 32 * 1024)
            e.encrypt_file(src, enc, "rename-test-password", True, "Argon2id", True)
            enc.rename(renamed)
            e.decrypt_file(renamed, out, "rename-test-password")
            assert out.read_bytes() == data

    @staticmethod
    def test_wrong_password_and_no_output():
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "x.txt"
            enc = root / "x.bin"
            out = root / "out.txt"
            src.write_bytes(b"secret")
            out.write_bytes(b"existing")
            e = SecureEncryptor()
            e.encrypt_file(src, enc, "correct-password")
            try:
                e.decrypt_file(enc, out, "wrong-password")
                raise AssertionError("Wrong password unexpectedly succeeded")
            except AuthenticationError:
                pass
            assert out.read_bytes() == b"existing"

    @staticmethod
    def test_corruption():
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "x.bin"
            enc = root / "x.enc"
            out = root / "out.bin"
            src.write_bytes(secrets.token_bytes(300_000))
            e = SecureEncryptor("ChaCha20-Poly1305", 32 * 1024)
            e.encrypt_file(src, enc, "corruption-password", True, "Argon2id", True)
            data = bytearray(enc.read_bytes())
            # Flip a byte in the first ciphertext area after the fixed header + metadata record.
            data[-20] ^= 0x80
            enc.write_bytes(data)
            try:
                e.decrypt_file(enc, out, "corruption-password")
                raise AssertionError("Corruption was not detected")
            except (IntegrityError, SHA256VerificationError, AuthenticationError):
                pass
            assert not out.exists()

    @staticmethod
    def test_empty_file():
        TestSuite._roundtrip("AES-256-GCM", "Argon2id", b"")

    @staticmethod
    def test_inspect():
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "x.txt"
            enc = root / "x.random"
            src.write_bytes(b"inspect")
            e = SecureEncryptor()
            e.encrypt_file(src, enc, "inspect-password", True, "Argon2id", False)
            info = e.inspect_file(enc)
            assert info.is_encrypted and info.version == 2
            assert info.algorithm == "AES-256-GCM"
            assert info.kdf == "Argon2id"
            assert not e.inspect_file(src).is_encrypted

    @staticmethod
    def run_all_tests() -> bool:
        tests = [
            TestSuite.test_aes_argon2,
            TestSuite.test_chacha_argon2,
            TestSuite.test_aes_pbkdf2,
            TestSuite.test_rename,
            TestSuite.test_wrong_password_and_no_output,
            TestSuite.test_corruption,
            TestSuite.test_empty_file,
            TestSuite.test_inspect,
        ]
        passed = failed = 0
        print("=" * 70)
        print("SECURE FILE ENCRYPTION TOOL - TEST SUITE")
        print("=" * 70)
        for test in tests:
            try:
                test()
                print(f"✓ {test.__name__}: PASSED")
                passed += 1
            except Exception as exc:
                print(f"✗ {test.__name__}: FAILED - {exc}")
                failed += 1
        print("=" * 70)
        print(f"RESULTS: {passed} passed, {failed} failed")
        print("=" * 70)
        return failed == 0


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        raise SystemExit(0 if TestSuite.run_all_tests() else 1)
    if len(sys.argv) > 1:
        raise SystemExit(cli_main())
    try:
        app = EncryptionGUI()
        app.run()
    except tk.TclError as exc:
        print(f"GUI unavailable: {exc}")
        print("Use CLI mode instead. Run --help for usage.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
