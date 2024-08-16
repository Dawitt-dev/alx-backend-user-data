#!/usr/bin/env python3
"""
Flask app for handling authentication
"""
from auth import Auth
from flask import Flask, jsonify, request, abort, redirect, url_for
from sqlalchemy.exc import InvalidRequestError

app = Flask(__name__)

AUTH = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def hello() -> str:
    """GET /
    Return:
      - welcome message
    """
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
