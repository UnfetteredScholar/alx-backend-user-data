#!/usr/bin/env python3
""" Module of Session Auth views
"""
import os
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User


@app_views.route("/auth_session/login", methods=["POST"], strict_slashes=False)
def session_login():
    """Perfroms session login"""

    email = request.form.get("email")
    if email is None or email == "":
        return jsonify({"error": "email missing"}), 400
    password = request.form.get("password")
    if password is None or password == "":
        return jsonify({"error": "password missing"}), 400

    users = User.search({"email": email})
    if len(users) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    if not users[0].is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    from api.v1.app import auth

    session_id = auth.create_session(users[0].id)

    response = jsonify(users[0].to_json())
    response.set_cookie(os.getenv("SESSION_NAME"), session_id)

    return response


@app_views.route(
    "/auth_session/logout", methods=["DELETE"], strict_slashes=False
)
def session_logout():
    """Closes a session"""

    from api.v1.app import auth

    if not auth.destroy_session(request):
        abort(404)

    return jsonify({}), 200
