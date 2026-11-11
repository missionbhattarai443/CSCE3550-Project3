"""Security, persistence, registration and HTTP integration tests."""

import sqlite3
import threading
import uuid
from http.server import HTTPServer

import jwt
import pytest
import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import main


@pytest.fixture
def api():
    server = HTTPServer(("127.0.0.1", 0), main.JWKSHandler)
    server.rate_limiter = main.RateLimiter()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", server
    server.shutdown()
    thread.join()
    server.server_close()


def rows(table):
    with sqlite3.connect(main.DB_FILE) as db:
        return db.execute(f"SELECT * FROM {table}").fetchall()


def test_registration_hash_and_constraints(api):
    url, _ = api
    response = requests.post(
        url + "/register", json={"username": "mission", "email": "mission@example.test"}
    )
    assert response.status_code == 201
    password = response.json()["password"]
    assert uuid.UUID(password).version == 4
    user = rows("users")[0]
    assert user[1] == "mission" and user[3] == "mission@example.test"
    assert user[4] is not None and user[5] is None
    assert password not in user[2] and user[2].startswith("$argon2id$")
    assert main.PASSWORD_HASHER.verify(user[2], password)
    for data in (
        {"username": "mission", "email": "other@example.test"},
        {"username": "other", "email": "mission@example.test"},
    ):
        assert requests.post(url + "/register", json=data).status_code == 409
    assert len(rows("users")) == 1


@pytest.mark.parametrize(
    "body",
    [
        "{",
        "[]",
        '{"username":null}',
        "{}",
        '{"username":" ","email":"a"}',
        '{"username":"a","email":3}',
    ],
)
def test_invalid_registration(api, body):
    assert requests.post(api[0] + "/register", data=body).status_code == 400
    assert rows("users") == []


def test_auth_links_username_ip_timestamp(api):
    url, _ = api
    requests.post(
        url + "/register", json={"username": "mission", "email": "m@example.test"}
    )
    response = requests.post(
        url + "/auth", json={"username": "mission", "password": "mock"}
    )
    assert response.status_code == 200
    assert (
        jwt.decode(response.text, main.get_key()[1].public_key(), algorithms=["RS256"])[
            "user"
        ]
        == "mission"
    )
    log = rows("auth_logs")[0]
    assert log[1] == "127.0.0.1" and log[2] is not None
    assert log[3] == rows("users")[0][0]
    assert rows("users")[0][5] is not None


def test_unknown_user_still_works_for_project2(api):
    assert (
        requests.post(api[0] + "/auth", json={"username": "unknown"}).status_code == 200
    )
    assert rows("auth_logs")[0][3] is None


def test_rate_limit_and_logging(api):
    url, server = api
    server.rate_limiter = main.RateLimiter(clock=lambda: 50)
    responses = [requests.post(url + "/auth") for _ in range(12)]
    assert [r.status_code for r in responses] == [200] * 10 + [429] * 2
    assert responses[-1].headers["Retry-After"] == "1"
    assert len(rows("auth_logs")) == 10
    assert requests.get(url + "/.well-known/jwks.json").status_code == 200
    assert (
        requests.post(
            url + "/register", json={"username": "m", "email": "m"}
        ).status_code
        == 201
    )


def test_sliding_window_boundary():
    clock = [0.0]
    limiter = main.RateLimiter(lambda: clock[0])
    assert all(limiter.allow() for _ in range(10))
    clock[0] = 0.999
    assert not limiter.allow()
    clock[0] = 1.0
    assert limiter.allow()


def test_aes_storage_nonce_and_tamper(monkeypatch):
    blob = rows("keys")[0][1]
    pem = main.decrypt_pem(blob)
    assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert b"PRIVATE KEY" not in blob
    assert main.encrypt_pem(pem) != main.encrypt_pem(pem)
    with pytest.raises(InvalidTag):
        main.decrypt_pem(blob[:-1] + bytes([blob[-1] ^ 1]))
    monkeypatch.setenv("NOT_MY_KEY", "02" * 32)
    with pytest.raises(InvalidTag):
        main.get_key()


@pytest.mark.parametrize("key", [None, "", "secret", "gg" * 32, "01" * 16])
def test_invalid_encryption_configuration(monkeypatch, key):
    if key is None:
        monkeypatch.delenv("NOT_MY_KEY")
    else:
        monkeypatch.setenv("NOT_MY_KEY", key)
    with pytest.raises(ValueError, match="NOT_MY_KEY"):
        main.encryption_key()


def test_upgrade_plaintext_database(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_FILE", str(tmp_path / "old.db"))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with sqlite3.connect(main.DB_FILE) as db:
        db.execute(
            "CREATE TABLE keys(kid INTEGER PRIMARY KEY AUTOINCREMENT,key BLOB NOT NULL,exp INTEGER NOT NULL)"
        )
        db.execute("INSERT INTO keys(key,exp) VALUES(?,?)", (pem, 9999999999))
    main.initialize_database()
    assert rows("keys")[0][1] != pem
    assert main.get_key()[1].private_numbers() == key.private_numbers()
    main.initialize_database()
    assert main.get_key() is not None


@pytest.mark.parametrize("body", ["[]", "{", '{"username":2}'])
def test_invalid_auth_not_logged(api, body):
    assert requests.post(api[0] + "/auth", data=body).status_code == 400
    assert rows("auth_logs") == []


def test_get_register_not_allowed(api):
    assert requests.get(api[0] + "/register").status_code == 405


def test_no_key_failure_not_logged(api):
    with sqlite3.connect(main.DB_FILE) as db:
        db.execute("DELETE FROM keys")
    assert requests.post(api[0] + "/auth").status_code == 500
    assert rows("auth_logs") == []


def test_oversize_body(api):
    assert requests.post(api[0] + "/register", data="x" * 16385).status_code == 400


def test_main_startup(monkeypatch):
    class FakeServer:
        def __init__(self, address, handler):
            self.closed = False

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            self.closed = True

    monkeypatch.setattr(main, "HTTPServer", FakeServer)
    monkeypatch.setattr("sys.argv", ["main.py", "--port", "0"])
    main.main()
