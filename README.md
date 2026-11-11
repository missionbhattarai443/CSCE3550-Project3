# CSCE 3550 Project 3 — Bulking up our JWKS server

Author: Mission Bhattarai (`missionbhattarai443`)

This extends my Project 2 Python/SQLite JWKS server with AES-encrypted private
keys, UUIDv4 registration passwords hashed with Argon2id, authentication logging,
and a sliding-window rate limiter.

## Setup and run

Requires Python 3.11 or later.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
# Generate the secret in your shell; do not paste it into source control.
export NOT_MY_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python main.py --port 8080
```

`NOT_MY_KEY` must contain 64 hexadecimal characters representing 32 random bytes.
Keep the same secret securely between runs when retaining the database. Missing,
invalid, or incorrect keys cause startup to fail. A new secret cannot decrypt an
existing database. Secrets and local database files are excluded by `.gitignore`.

The server listens on localhost. The default database is
`totally_not_my_privateKeys.db`. Startup creates both valid and expired RSA keys
when needed. Existing Project 2 plaintext PEM rows are encrypted transactionally
on startup. SQLite may retain historical plaintext in free pages or backups;
use a fresh database for this project if you do not need old development keys.

## Endpoints

| Endpoint | Behavior |
| --- | --- |
| `GET /.well-known/jwks.json` | Returns only unexpired RSA public keys. |
| `POST /register` | Accepts `{"username":"mission","email":"mission@example.test"}`; responds 201 with `{"password":"<generated UUIDv4>"}`. |
| `POST /auth` | Returns a signed RS256 JWT; accepts a JSON username for log association. |
| `POST /auth?expired=true` | Returns an expired JWT signed with an expired key, preserving Project 2 behavior. |

Registration stores only the Argon2id hash, never the generated password. Argon2
settings are time cost 3, memory cost 65,536 KiB, parallelism 4, hash length 32,
and random salt length 16 bytes. Duplicate usernames/emails return 409; invalid
JSON, missing fields, and non-string fields return 400. Bodies are limited to
16 KiB. Unsupported methods return 405; unknown routes return 404.

As in Project 2, `/auth` is a **mock token issuer**, not a production password
verification service. The assignment asks to add registration and request
logging without specifying a change to that behavior. The submitted username
is looked up to associate the log with `users.id`; unknown or omitted users
have a NULL `user_id`, preserving Gradebot and Project 2 compatibility. A known
user's `last_login` is updated on successful token issuance. Do not deploy this
mock server as real authentication.

## Security and database design

- The `keys.key` BLOB contains a random 12-byte nonce followed by AES-256-GCM
  ciphertext and its 16-byte authentication tag. A fresh nonce is generated for
  each encryption. Private keys are decrypted only in memory for signing and
  public-key extraction. Tampered data or a wrong secret fails authentication.
- `users` and `auth_logs` use the exact schemas specified in the assignment.
  Parameterized SQL handles all user-supplied values.
- Each successful `/auth` records the direct client IP, SQLite timestamp, and
  resolved user ID. Forwarded IP headers are not trusted.
- A global sliding one-second window permits 10 `/auth` requests and rejects
  subsequent requests with 429 and `Retry-After: 1`. Rejected and failed requests
  are not logged. JWKS and registration requests do not consume that window.
- The standard-library HTTP server processes requests serially; the in-memory
  limiter is scoped to one running process and resets on restart.

## Tests and evidence

```sh
python -m pytest --cov=main --cov-branch --cov-report=term-missing --cov-report=html -q
ruff check main.py test_main.py test_project3.py conftest.py
ruff format --check main.py test_main.py test_project3.py conftest.py
```

Tests create isolated temporary databases and a public, deterministic **test-only**
AES key. They start HTTP servers on available ports, verify JWT signatures and
expiration, Argon2 hashes, uniqueness constraints, encryption/tampering/wrong
keys, legacy migration, logging, malformed inputs, and the exact rate-limit
window boundary. No previously started server or database is needed.

Verified November 11, 2026: **39 tests passed; 99% branch-inclusive coverage**.
The remaining uncovered line is the script entry-point guard. See
`Test_Coverage.png` and the unmodified `test-results.txt` output.

Download the appropriate Gradebot executable from the instructor's releases:
<https://github.com/jh125486/CSCE3550/releases>
Then, with the same `NOT_MY_KEY` configured in the shell:

```sh
/path/to/gradebot project-3 --dir . --run '.venv/bin/python main.py' --code-dir .
```

Gradebot v1.1.2 passed every functional criterion and reported **99.21%** overall
(4.25/5 for its quality category). See `Gradebot_Result.png` and
`gradebot-results.txt`. This is the observed client result, not an instructor's
final grade. Gradebot's optional results-submission prompt was not accepted.

## Requirement checklist

- [x] AES encryption with `NOT_MY_KEY`; no committed secrets.
- [x] Exact `users` schema, registration JSON, UUIDv4 response, Argon2 hash.
- [x] Exact `auth_logs` schema and successful authentication request logging.
- [x] Optional 10 requests/second limiter with 429 responses.
- [x] Automated test suite, coverage evidence, and lint checks.
- [x] Gradebot output and screenshots with identifying information.

## Library references

- AES-GCM API: <https://cryptography.io/en/latest/hazmat/primitives/aead/>
- Argon2 PasswordHasher API: <https://argon2-cffi.readthedocs.io/en/stable/api.html>
