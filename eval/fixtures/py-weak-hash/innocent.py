# eval/fixtures/py-weak-hash/innocent.py
# BACO Eval Fixture: innocent file - strong hash for a non-secret checksum

import hashlib


def artifact_checksum(data: bytes) -> str:
    """Checksum for build-artifact deduplication. No secrets involved."""
    return hashlib.sha256(data).hexdigest()
