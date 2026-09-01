# eval/fixtures/py-sqli/safe_twin.py
# BACO Eval Fixture: Secure SQL twin (parameterized query)
# This is the SECURE version - any finding here is a false positive

from typing import Optional

def get_user_by_id(user_id: int) -> Optional[dict]:
    """
    Fetch user from database by ID.
    
    SECURE: Uses parameterized query to prevent SQL injection.
    The parameter is passed separately, preventing any injection.
    """
    query = "SELECT * FROM users WHERE id = %s"
    params = (user_id,)
    
    # Execute the query with parameters (mock implementation)
    print(f"Executing: {query} with params: {params}")
    
    return None


def delete_user(user_id: int) -> bool:
    """
    Delete a user by ID.
    
    SECURE: Uses parameterized query.
    """
    query = "DELETE FROM users WHERE id = %s"
    params = (user_id,)
    print(f"Executing: {query} with params: {params}")
    return True