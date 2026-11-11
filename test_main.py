import datetime
import threading
import time
from http.server import HTTPServer

import jwt
import pytest
import requests

from main import (
    HOST,
    PORT,
    JWKSHandler,
    RateLimiter,
    get_key,
)

BASE_URL = f"http://{HOST}:{PORT}"


@pytest.fixture(scope="function")
def server():
    """Start the JWKS server for the test suite."""
    httpd = HTTPServer((HOST, 0), JWKSHandler)
    httpd.rate_limiter = RateLimiter()
    global BASE_URL
    BASE_URL = f"http://{HOST}:{httpd.server_port}"
    thread = threading.Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()

    time.sleep(0.2)

    yield httpd

    httpd.shutdown()
    thread.join()
    httpd.server_close()


def test_jwks_endpoint(server):
    """JWKS endpoint should return the valid public key."""
    response = requests.get(
        f"{BASE_URL}/.well-known/jwks.json",
        timeout=5,
    )

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/json"

    data = response.json()

    assert "keys" in data
    assert len(data["keys"]) == 1

    key = data["keys"][0]

    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert "kid" in key
    assert "n" in key
    assert "e" in key


def test_valid_authentication(server):
    """Normal /auth request should return a valid JWT."""
    response = requests.post(
        f"{BASE_URL}/auth",
        timeout=5,
    )

    assert response.status_code == 200

    token = response.text
    assert len(token.split(".")) == 3

    header = jwt.get_unverified_header(token)
    jwks = requests.get(
        f"{BASE_URL}/.well-known/jwks.json",
        timeout=5,
    ).json()

    valid_jwk = jwks["keys"][0]

    assert header["kid"] == valid_jwk["kid"]

    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(valid_jwk)

    payload = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
    )

    assert payload["user"] == "fake_user"
    assert payload["exp"] > datetime.datetime.now(datetime.UTC).timestamp()


def test_expired_authentication(server):
    """Expired request should use the expired key and expiration."""
    response = requests.post(
        f"{BASE_URL}/auth?expired=true",
        timeout=5,
    )

    assert response.status_code == 200

    token = response.text
    header = jwt.get_unverified_header(token)

    assert "kid" in header

    expired_public_key = get_key(expired=True)[1].public_key()

    payload = jwt.decode(
        token,
        expired_public_key,
        algorithms=["RS256"],
        options={"verify_exp": False},
    )

    assert payload["exp"] < datetime.datetime.now(datetime.UTC).timestamp()


def test_expired_key_not_in_jwks(server):
    """Expired key must not be returned by JWKS."""
    response = requests.get(
        f"{BASE_URL}/.well-known/jwks.json",
        timeout=5,
    )

    kids = [key["kid"] for key in response.json()["keys"]]

    expired_key_data = get_key(expired=True)
    assert expired_key_data is not None
    assert str(expired_key_data[0]) not in kids


def test_get_auth_not_allowed(server):
    """GET is not allowed on /auth."""
    response = requests.get(
        f"{BASE_URL}/auth",
        timeout=5,
    )

    assert response.status_code == 405


def test_post_jwks_not_allowed(server):
    """POST is not allowed on the JWKS endpoint."""
    response = requests.post(
        f"{BASE_URL}/.well-known/jwks.json",
        timeout=5,
    )

    assert response.status_code == 405


def test_invalid_endpoint(server):
    """Unknown endpoints should not be accepted."""
    response = requests.get(
        f"{BASE_URL}/not-a-real-endpoint",
        timeout=5,
    )

    assert response.status_code == 404


def test_put_not_allowed(server):
    response = requests.put(
        f"{BASE_URL}/auth",
        timeout=5,
    )
    assert response.status_code == 405


def test_delete_not_allowed(server):
    response = requests.delete(
        f"{BASE_URL}/auth",
        timeout=5,
    )
    assert response.status_code == 405


def test_patch_not_allowed(server):
    response = requests.patch(
        f"{BASE_URL}/auth",
        timeout=5,
    )
    assert response.status_code == 405


def test_head_not_allowed(server):
    response = requests.head(
        f"{BASE_URL}/auth",
        timeout=5,
    )
    assert response.status_code == 405


def test_unknown_post_endpoint(server):
    response = requests.post(
        f"{BASE_URL}/not-a-real-endpoint",
        timeout=5,
    )
    assert response.status_code == 404


def test_get_key_returns_none_when_missing(monkeypatch, tmp_path):
    import main

    monkeypatch.setattr(main, "DB_FILE", str(tmp_path / "empty.db"))
    main.initialize_database()

    assert main.get_key() is None
    assert main.get_key(expired=True) is None


def test_ensure_keys_creates_missing_keys(monkeypatch, tmp_path):
    import main

    monkeypatch.setattr(main, "DB_FILE", str(tmp_path / "keys.db"))
    main.initialize_database()
    main.ensure_keys()

    assert main.get_key() is not None
    assert main.get_key(expired=True) is not None
