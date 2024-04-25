#!/usr/bin/env python3
"""Basic Flask App"""
from flask import Flask, jsonify, request, abort
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/", strict_slashes=False)
def index():
    """The index method"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users/", methods=["POST"], strict_slashes=False)
def users():
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        AUTH.register_user(email=email, password=password)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400
    else:
        return jsonify({"email": email, "message": "user created"})


@app.route("/sessions/", methods=["POST"], strict_slashes=False)
def login():
    """Performs user login"""
    email = request.form.get("email")
    password = request.form.get("password")

    if not AUTH.valid_login(email=email, password=password):
        abort(401)

    session_id = AUTH.create_session(email)

    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie("session_id", session_id)

    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
