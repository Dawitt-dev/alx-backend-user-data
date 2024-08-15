#!/usr/bin/env python3
"""
Auth module for handling authentication operations.
"""

import bcrypt


def _hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt and returns the hashed password as bytes.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The salted, hashed password.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed
