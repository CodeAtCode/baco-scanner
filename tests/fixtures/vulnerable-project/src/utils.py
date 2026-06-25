DB_PASSWORD = "hardcoded_secret_123"

def connect():
    return f"postgresql://admin:{DB_PASSWORD}@localhost/db"
