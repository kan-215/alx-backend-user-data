#!/usr/bin/env python3
""" User Authentication Module """

import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from typing import Union
from user import User
from uuid import uuid4


def _hash_password(password: str) -> str:
    """
    Returns a salted hash of the input password.

    Args:
        password (str): plain text password to be hashed.

    Returns:
        str: hashed password.
    """
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed


def _generate_uuid() -> str:
    """
    Returns a string representation of a new UUID.

    Returns:
        str: newly generated UUID.
    """
    UUID = uuid4()
    return str(UUID)


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        """
        Initializes the Auth class and sets up the database connection.

        Attributes:
            _db (DB): An instance of the DB class to interact with the database
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a user in the database.

        Args:
            email (str): email of the user to be registered.
            password (str): user password.

        Returns:
            User: User object created and added to the database.

        Raises:
            ValueError: If the email is already registered.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)
            return user
        else:
            raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates the login credentials for a user.

        Args:
            email (str): email of the user trying to log in.
            password (str): password entered by the user.

        Returns:
            bool: True if the login details are valid, False otherwise
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        user_password = user.hashed_password
        encoded_password = password.encode()

        if bcrypt.checkpw(encoded_password, user_password):
            return True

        return False

    def create_session(self, email: str) -> str:
        """
        Creates a session for a user and returns the session ID.

        Args:
            email (str): The email of the user to create a session for.

        Returns:
            str: session ID for the user, None if the user does not exist
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[str, None]:
        """
        Gets a user by their session ID.

        Args:
            session_id (str): User ID session.

        Returns:
            Union[str, None]: The user object if found, None if no user exists
                              with the provided session ID.
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """
        Destroys the session for a user by setting their session ID to None.

        Args:
            user_id (int): The ID of the user to destroy the session for.
        """
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None

        self._db.update_user(user.id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """
        Generates a reset password token for a user if they exist.

        Args:
            email (str): The email of the user requesting a password reset.

        Returns:
            str: The reset password token.

        Raises:
            ValueError: If the email is not registered.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError("Email not registered")

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
        self._db.update_user(user.id, hashed_password=hashed_password,
                             reset_token=None)
