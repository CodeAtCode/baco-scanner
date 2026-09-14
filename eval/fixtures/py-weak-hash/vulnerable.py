# eval/fixtures/py-weak-hash/vulnerable.py
# BACO Eval Fixture: Weak hash (MD5) for password storage (CWE-327)
# The vulnerability is on line 15 - MD5 used to hash passwords

import hashlib


def hash_password(password: str) -> str:
    """
    Hash a password for storage.

    VULNERABLE: MD5 is cryptographically broken and fast to brute-force.
    An attacker who steals the digest can recover the password.
    """
    digest = hashlib.md5(password.encode()).hexdigest()
    return digest
