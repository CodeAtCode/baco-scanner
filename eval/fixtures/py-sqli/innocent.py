# eval/fixtures/py-sqli/innocent.py
# BACO Eval Fixture: Innocent file with no vulnerabilities

def calculate_total(items: list) -> float:
    """Calculate total price of items."""
    return sum(item['price'] for item in items)


def format_user_name(first: str, last: str) -> str:
    """Format a user's full name."""
    return f"{first} {last}"