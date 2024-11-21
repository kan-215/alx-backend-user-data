#!/usr/bin/env python3
""" Authentication Module """

import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from typing import Optional
from user import User
from uuid import uuid4


def _hash_password(password: str) -> str:
    """
    Returns a salted hash of the input password.

    Args:
        password (str): The password to be hashed.

    Returns:
        str: The hashed password as a string.
    """
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed.decode('utf-8')  # Convert bytes to string


def _generate_uuid() -> str:
    """
    Generates a new UUID as a string.

    Returns:
        str: A unique UUID as a string.
    """
    UUID = uuid4()
    return str(UUID)


class Auth:
    """
    Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initializes the Auth class with a DB instance."""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user in the database if email does not exist.

        Args:
            email (str): The email of the user to register.
            password (str): The password of the user.

        Returns:
            User: The created user object.

        Raises:
            ValueError: If a user with the given email already exists.
        """
        try:
            user = self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates if the provided email and password match a registered user.

        Args:
            email (str): The email of the user.
            password (str): The password of the user.

        Returns:
            bool: True if the login is valid, otherwise False.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        user_password = user.hashed_password
        encoded_password = password.encode()

        return bcrypt.checkpw(encoded_password, user_password)

    def create_session(self, email: str) -> str:
        """
        Creates a session for a valid user.

        Args:
            email (str): The email of the user.

        Returns:
            str: The session ID.

        Raises:
            ValueError: If no user exists with the provided email.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError(f"No user found with email {email}")

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Optional[User]:
        """
        Retrieves the user associated with the given session ID.

        Args:
            session_id (str): The session ID.

        Returns:
            Optional[User]: The user associated with the session, or None if not found.
        """
        if not session_id:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """
        Destroys the session for the user with the given ID.

        Args:
            user_id (int): The ID of the user whose session is to be destroyed.
        """
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None

        self._db.update_user(user.id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """
        Generates a reset password token if the user with the given email exists.

        Args:
            email (str): The email address of the user requesting a reset.

        Returns:
            str: A unique reset token.

        Raises:
            ValueError: If no user exists with the provided email.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError(f"No account associated with the email {email}")

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Updates the password for a user using the provided reset token.

        Args:
            reset_token (str): The reset token to validate the password change.
            password (str): The new password to be set.

        Raises:
            ValueError: If the reset token is invalid.
        """
        if not reset_token or not password:
            return None

        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token")

        hashed_password = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed_password, reset_token=None)
