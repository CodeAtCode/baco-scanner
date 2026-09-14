# eval/fixtures/py-cmdi/innocent.py
# BACO Eval Fixture: innocent file - filesystem check, no command execution

import socket


def host_reachable(host: str) -> bool:
    """Resolve a hostname. No shell commands are executed."""
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False
