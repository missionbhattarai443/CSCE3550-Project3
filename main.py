import argparse
import base64
import datetime
import json
import os
import sqlite3
import time
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import jwt
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_FILE = "totally_not_my_privateKeys.db"
HOST = "localhost"
PORT = 8080
PASSWORD_HASHER = PasswordHasher(
    time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16
)


def encryption_key():
    """Read a 32-byte AES key, encoded as 64 hexadecimal characters."""
    value = os.environ.get("NOT_MY_KEY", "")
    try:
        key = bytes.fromhex(value)
    except ValueError:
        raise ValueError("NOT_MY_KEY must be 64 hexadecimal characters") from None
    if len(value) != 64 or len(key) != 32:
        raise ValueError("NOT_MY_KEY must be 64 hexadecimal characters")
    return key


def encrypt_pem(pem):
    """Store a fresh 96-bit nonce followed by AES-GCM ciphertext and tag."""
    nonce = os.urandom(12)
    return nonce + AESGCM(encryption_key()).encrypt(nonce, pem, None)


def decrypt_pem(blob):
    """Authenticate and decrypt a nonce-prefixed database key BLOB."""
    return AESGCM(encryption_key()).decrypt(blob[:12], blob[12:], None)


class RateLimiter:
    """A sliding one-second window, shared by all /auth requests."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.requests = deque()

    def allow(self):
        """Admit at most ten requests in the trailing second."""
        now = self.clock()
        while self.requests and self.requests[0] <= now - 1:
            self.requests.popleft()
        if len(self.requests) >= 10:
            return False
        self.requests.append(now)
        return True


def initialize_database():
    """Create assignment tables, migrate PEM rows, and validate encrypted keys."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)

        conn.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")
        # Upgrade existing Project 2 PEM rows in one transaction.
        for kid, blob in conn.execute("SELECT kid, key FROM keys").fetchall():
            if blob.startswith(b"-----BEGIN PRIVATE KEY-----"):
                conn.execute(
                    "UPDATE keys SET key=? WHERE kid=?", (encrypt_pem(blob), kid)
                )
            else:
                decrypt_pem(blob)  # Fail startup for a wrong key or corrupt DB.


def save_key(private_key, expiration):
    """Encrypt a PKCS8 PEM key before inserting it with parameterized SQL."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypt_pem(pem), expiration)
        )
        return cursor.lastrowid


def generate_key(expiration):
    """Generate and store a new RSA private key."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return save_key(private_key, expiration)


def ensure_keys():
    """Ensure at least one valid and one expired key exist."""
    now = int(datetime.datetime.now(datetime.UTC).timestamp())

    with sqlite3.connect(DB_FILE) as conn:
        valid_count = conn.execute(
            "SELECT COUNT(*) FROM keys WHERE exp > ?", (now,)
        ).fetchone()[0]
        expired_count = conn.execute(
            "SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,)
        ).fetchone()[0]

    if not valid_count:
        generate_key(now + 3600)

    if not expired_count:
        generate_key(now - 3600)


def get_key(expired=False):
    """Read and deserialize a key from SQLite."""
    now = int(datetime.datetime.now(datetime.UTC).timestamp())

    operator = "<=" if expired else ">"

    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute(
            f"SELECT kid, key, exp FROM keys WHERE exp {operator} ? "
            "ORDER BY exp DESC LIMIT 1",
            (now,),
        ).fetchone()

    if row is None:
        return None

    kid, pem, expiration = row
    private_key = serialization.load_pem_private_key(decrypt_pem(pem), password=None)
    return kid, private_key, expiration


def int_to_base64(value):
    """Convert an integer to base64url format."""
    length = (value.bit_length() + 7) // 8
    data = value.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def public_key_to_jwk(private_key, kid):
    """Convert an RSA public key to a JWK."""
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": str(kid),
        "n": int_to_base64(numbers.n),
        "e": int_to_base64(numbers.e),
    }


def get_jwks():
    """Read all unexpired public keys from the database."""
    now = int(datetime.datetime.now(datetime.UTC).timestamp())

    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute(
            "SELECT kid, key FROM keys WHERE exp > ?", (now,)
        ).fetchall()

    keys = []
    for kid, pem in rows:
        private_key = serialization.load_pem_private_key(
            decrypt_pem(pem), password=None
        )
        keys.append(public_key_to_jwk(private_key, kid))

    return {"keys": keys}


class JWKSHandler(BaseHTTPRequestHandler):
    """Handle JWKS and authentication requests."""

    def log_message(self, format, *args):
        # Keep request bodies and generated passwords out of access logs.
        pass

    def respond(self, status, body, content_type="application/json"):
        data = (
            json.dumps(body) if content_type == "application/json" else body
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if status == 429:
            self.send_header("Retry-After", "1")
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 <= length <= 16384:
            raise ValueError("Invalid body length")
        data = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(data, dict):
            raise TypeError("Expected JSON object")
        return data

    def register(self, data):
        """Return a one-time UUIDv4 password and persist only its Argon2id hash."""
        username, email = data.get("username"), data.get("email")
        if (
            not isinstance(username, str)
            or not username.strip()
            or not isinstance(email, str)
            or not email.strip()
        ):
            self.respond(400, {"error": "username and email are required strings"})
            return
        password = str(uuid.uuid4())
        password_hash = PASSWORD_HASHER.hash(password)
        try:
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute(
                    "INSERT INTO users(username, password_hash, email) VALUES(?,?,?)",
                    (username, password_hash, email),
                )
        except sqlite3.IntegrityError:
            self.respond(409, {"error": "Username or email already registered"})
            return
        self.respond(201, {"password": password})

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/.well-known/jwks.json":
            response = json.dumps(get_jwks()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            return

        if parsed.path in ("/auth", "/register"):
            self.send_response(405)
        else:
            self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path in ("/auth", "/register"):
            if parsed.path == "/auth" and not self.server.rate_limiter.allow():
                self.respond(429, {"error": "Too Many Requests"})
                return
            try:
                data = self.read_json()
            except (ValueError, TypeError, UnicodeDecodeError):
                self.respond(400, {"error": "Invalid JSON request body"})
                return
            if parsed.path == "/register":
                self.register(data)
                return
            username = data.get("username", "fake_user")
            if not isinstance(username, str):
                self.respond(400, {"error": "username must be a string"})
                return

        if parsed.path != "/auth":
            self.send_response(405 if parsed.path == "/.well-known/jwks.json" else 404)
            self.end_headers()
            return

        params = parse_qs(parsed.query, keep_blank_values=True)
        expired = "expired" in params

        # Authentication is mocked, as required by the assignment.
        key_data = get_key(expired=expired)
        if key_data is None:
            self.send_error(500, "No suitable RSA key")
            return

        kid, private_key, _expiration = key_data

        now = int(datetime.datetime.now(datetime.UTC).timestamp())

        token_expiration = now - 3600 if expired else now + 3600

        payload = {"user": username, "exp": token_expiration}

        token = jwt.encode(
            payload, private_key, algorithm="RS256", headers={"kid": str(kid)}
        )

        # Project 2 authentication remains mocked. Unknown users have NULL IDs.
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            row = conn.execute(
                "SELECT id FROM users WHERE username=?", (username,)
            ).fetchone()
            user_id = row[0] if row else None
            conn.execute(
                "INSERT INTO auth_logs(request_ip, user_id) VALUES(?,?)",
                (self.client_address[0], user_id),
            )
            if user_id is not None:
                conn.execute(
                    "UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?",
                    (user_id,),
                )
        self.respond(200, token, "text/plain")

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()

    encryption_key()
    initialize_database()
    ensure_keys()

    server = HTTPServer((HOST, args.port), JWKSHandler)
    server.rate_limiter = RateLimiter()
    print(f"JWKS server running at http://{HOST}:{args.port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
