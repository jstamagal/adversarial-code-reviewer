"""Test file with SQL injection vulnerability."""


def vulnerable_function(user_input):
    """Function with SQL injection vulnerability."""
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchall()


def another_vulnerable_function(username):
    """Another SQL injection using f-string."""
    query = f"SELECT * FROM users WHERE username='{username}'"
    cursor.execute(query)
    return cursor.fetchall()


def secure_function(user_input):
    """Secure version using parameterized query."""
    query = "SELECT * FROM users WHERE name = %s"
    cursor.execute(query, (user_input,))
    return cursor.fetchall()
