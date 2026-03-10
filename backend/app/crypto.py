"""Fernet-based encryption helpers for API keys and CF tokens."""

import hashlib
import os
import secrets
import string

from cryptography.fernet import Fernet

_FERNET_KEY = os.getenv("FERNET_KEY", "")
_fernet: Fernet | None = None

API_KEY_PREFIX = "dk7_"
API_KEY_RANDOM_LENGTH = 24
API_KEY_ALPHABET = string.ascii_letters + string.digits


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        if not _FERNET_KEY:
            raise RuntimeError(
                "FERNET_KEY env var is not set. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        _fernet = Fernet(_FERNET_KEY.encode() if isinstance(_FERNET_KEY, str) else _FERNET_KEY)
    return _fernet


def encrypt_value(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    return _get_fernet().decrypt(ciphertext.encode()).decode()


def hash_api_key(plaintext_key: str) -> str:
    return hashlib.sha256(plaintext_key.encode()).hexdigest()


def generate_api_key() -> str:
    random_part = "".join(secrets.choice(API_KEY_ALPHABET) for _ in range(API_KEY_RANDOM_LENGTH))
    return f"{API_KEY_PREFIX}{random_part}"
