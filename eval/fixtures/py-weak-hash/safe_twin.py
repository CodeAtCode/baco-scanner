# eval/fixtures/py-weak-hash/safe_twin.py
# BACO Eval Fixture: Weak hash safe twin - salted PBKDF2-HMAC-SHA256 (CWE-327)

import hashlib
import os


def hash_password(password: str) -> str:
    """
    Hash a password for storage.

    SECURE: PBKDF2-HMAC-SHA256 with a random per-password salt and a
    high iteration count makes offline brute-force expensive.
    """
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return digest.hex()
