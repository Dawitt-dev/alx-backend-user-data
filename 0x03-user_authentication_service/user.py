#!/usr/bin/env python3
"""
This module defines a SQLAlchemy model for users.
"""

from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    """
    This class defines the User model which is used to represent
    the users table in the database.
    """
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)


# Create an engine and metadata (optional but useful for testing)
engine = create_engine('sqlite:///user.db')
Base.metadata.create_all(engine)
