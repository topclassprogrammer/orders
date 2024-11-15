import bcrypt


def hash_password(value):
    password_bytes = value.encode()
    password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    password = password.decode()
    return password


def check_hashed_passwords(password, stored_hash):
    password = password.encode()
    stored_hash = stored_hash.encode()
    return bcrypt.checkpw(password, stored_hash)


