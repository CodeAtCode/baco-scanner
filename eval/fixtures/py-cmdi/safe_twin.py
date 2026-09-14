# eval/fixtures/py-cmdi/safe_twin.py
# BACO Eval Fixture: Command injection safe twin - subprocess with argument list (CWE-78)

import subprocess


def ping_host(host: str) -> str:
    """
    Ping a host requested by the user.

    SECURE: subprocess receives an argument list with shell=False, so
    the host value can never be interpreted as shell syntax.
    """
    completed = subprocess.run(
        ["ping", "-c", "1", "--", host],
        capture_output=True,
        shell=False,
        check=False,
    )
    return f"ping exited with {completed.returncode}"
