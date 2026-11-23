def find(cursor, name: str):
    return cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
