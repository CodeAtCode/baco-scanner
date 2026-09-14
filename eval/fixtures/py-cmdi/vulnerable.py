# eval/fixtures/py-cmdi/vulnerable.py
# BACO Eval Fixture: Command injection via os.system (CWE-78)
# The vulnerability is on line 16 - user input concatenated into shell command

import os


def ping_host(host: str) -> str:
    """
    Ping a host requested by the user.

    VULNERABLE: the host string is concatenated into a shell command.
    An attacker can supply "8.8.8.8; rm -rf /" to run arbitrary commands.
    """
    command = "ping -c 1 " + host
    exit_code = os.system(command)
    return f"ping exited with {exit_code}"
