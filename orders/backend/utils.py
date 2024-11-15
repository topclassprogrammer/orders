import bcrypt


def hash_password(value):
    password_bytes = value.encode()
    password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    password = password.decode()
    return password


