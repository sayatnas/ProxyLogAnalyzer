"""Authentication: password hashing, JWT issuing, verification."""
import logging
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")
JWT_ALGORITHM = "HS256"
TOKEN_HOURS = 8

log = logging.getLogger(__name__)

# Single demo account, provisioned from environment.
# For production, store accounts in a database with real provisioning.
USERS: dict[str, str] = {}


def hash_password(password: str) -> str:
    """Salted scrypt hash. The password itself is never stored or logged."""
    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, password)


def ensure_demo_user() -> None:
    username = os.environ.get("DEMO_USER", "analyst")
    password = os.environ.get("DEMO_PASSWORD", "analyst")
    USERS[username] = hash_password(password)


def authenticate(username: str, password: str) -> bool:
    """True when the username exists and the password matches its stored hash."""
    stored = USERS.get(username)
    if stored is None:
        return False
    return verify_password(password, stored)


def create_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(hours=TOKEN_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict | None:
    """Return the payload, or None if the token is missing, forged or expired.

    Callers get one undifferentiated failure so a client cannot learn WHY a
    token was rejected; the reason is logged server-side instead.
    """
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        log.debug("token rejected: %s", exc)
        return None


def require_auth(f):
    """Reject the request unless it carries a valid token.

    Applied UNDER @app.route so Flask registers the wrapped function:

        @app.route("/api/upload", methods=["POST"])
        @require_auth
        def upload():
            ...  # g.username is set
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "missing token"}), 401
        payload = decode_token(header[7:])
        if payload is None:
            return jsonify({"error": "invalid or expired token"}), 401
        g.username = payload["sub"]
        return f(*args, **kwargs)
    return wrapper
