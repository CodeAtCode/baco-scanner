# eval/fixtures/py-sqli/vulnerable.py
# BACO Eval Fixture: SQL Injection via f-string (CWE-89)
# The vulnerability is on line 15 - f-string interpolation in SQL query

from typing import Optional

def get_user_by_id(user_id: int) -> Optional[dict]:
    """
    Fetch user from database by ID.
    
    VULNERABLE: Uses f-string interpolation in SQL query.
    An attacker can inject arbitrary SQL via the user_id parameter.
    """
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    # Execute the query (mock implementation)
    # In production, this would connect to a real database
    print(f"Executing: {query}")
    
    return None


def delete_user(user_id: int) -> bool:
    """
    Delete a user by ID.
    
    VULNERABLE: Same f-string SQL injection pattern.
    """
    query = f"DELETE FROM users WHERE id = {user_id}"
    print(f"Executing: {query}")
    return True