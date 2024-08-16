#!/usr/bin/env python3
"""
Main file
"""
import requests  # Ensure you're using the requests module
from flask import jsonify

BASE_URL = "http://0.0.0.0:5000"

def register_user(email: str, password: str) -> None:
    """Register a user"""
    url = f"{BASE_URL}/users"
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "user created"}
    
    response = requests.post(url, data=data)
    assert response.status_code == 400
    assert response.json() == {"message": "email already registered"}

def log_in_wrong_password(email: str, wrong_password: str) -> None:
    """Log in with wrong password"""
    url = f"{BASE_URL}/sessions"
    data = {"email": email, "password": wrong_password}
    response = requests.post(url, data=data)
    assert response.status_code == 401

def profile_unlogged() -> None:
    """Test profile unlogged"""
    url = f"{BASE_URL}/profile"
    response = requests.get(url)
    assert response.status_code == 403

def profile_logged(session_id: str) -> None:
    """Test profile logged"""
    url = f"{BASE_URL}/profile"
    response = requests.get(url, cookies={"session_id": session_id})
    assert response.status_code == 200
    assert "email" in response.json()

def log_out(session_id: str) -> None:
    """Test log out"""
    url = f"{BASE_URL}/sessions"
    response = requests.delete(url, cookies={"session_id": session_id})
    assert response.status_code == 200
    assert response.json() == {"message": "Bienvenue"}

def reset_password_token(email: str) -> str:
    """Reset password token"""
    url = f"{BASE_URL}/reset_password"
    data = {"email": email}
    response = requests.post(url, data=data)
    assert response.status_code == 200
    return response.json().get("reset_token")

def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Update password"""
    url = f"{BASE_URL}/reset_password"
    data = {"email": email, "reset_token": reset_token, "new_password": new_password}
    response = requests.put(url, data=data)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "Password updated"}

def log_in(email: str, password: str) -> str:
    """Log in"""
    url = f"{BASE_URL}/sessions"
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)
    assert response.status_code == 200
    return response.json().get("session_id")


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"

if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
