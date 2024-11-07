#!/usr/bin/env python3
"""
password encryption
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ Returns a hashed password,a byte string """
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """uses bcrypt to Validate provided password matches the hashed password """
    valid = False
    encoded = password.encode()
    if bcrypt.checkpw(encoded, hashed_password):
        valid = True
    return valid
