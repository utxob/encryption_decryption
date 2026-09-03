# encryption_decryption# Secure File Encryption & Decryption Tool

A secure, modern, and user-friendly file encryption and decryption application built with Python.

The tool supports both **GUI and CLI**, strong password-based key derivation, authenticated encryption, large-file processing, integrity verification, and encrypted metadata.

---

## Features

### Encryption Algorithms

- **AES-256-GCM**
- **ChaCha20-Poly1305**

Both algorithms provide authenticated encryption, protecting files against unauthorized modification and tampering.

### Key Derivation Functions

- **Argon2id** — Recommended
- **PBKDF2-HMAC-SHA256**

Each encrypted file stores the required KDF parameters so that it can be decrypted correctly in the future.

### Security Features

- 256-bit encryption keys
- Random cryptographic salts
- Unique random nonce for every encrypted record/chunk
- Authenticated Encryption with Associated Data (AEAD)
- Encrypted metadata
- Password-based key derivation
- SHA-256 integrity verification
- Tamper/corruption detection
- Wrong-password detection
- Truncated-file detection
- Safe temporary-file handling
- Atomic output replacement
- No password storage
- No hardcoded decryption backdoor

### File Handling

- Large-file streaming support
- Configurable chunk size
- Original filename preservation
- Unicode filename support
- Encrypted files can be renamed freely
- File extension is not used to identify encrypted files
- Internal container header is used for file detection
- Protection against unsafe/path-traversal filenames

### User Interface

The application provides two interfaces:

- **Graphical User Interface (GUI)**
- **Command-Line Interface (CLI)**

The GUI includes:

- File selection
- Password input
- Password confirmation
- Encryption algorithm selection
- KDF selection
- Progress reporting
- Operation cancellation
- Drag-and-drop support
- File inspection
- Error reporting

---

# Requirements

- Python 3.9 or newer
- `cryptography`
- `argon2-cffi`

Optional:

- `tkinterdnd2` — required for drag-and-drop support

---

# Installation

Clone or download the project:

```bash
git clone https://github.com/utxob/encryption_decryption.git
python3 -m venv venv
source venv/bin/activate

pip install cryptography argon2-cffi
pip install tkinterdnd2       
python secure_file_encryption_tool_v2_1.py  
```
