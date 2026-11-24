def find(cursor, name: str):
    return cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
