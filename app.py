"""
WebAuthn / Touch ID Authentication Server
Deploys on Hugging Face Spaces (Docker SDK)
"""

import json
import os
import secrets
import sqlite3
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from contextlib import contextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# HF Spaces provides SPACE_HOST env var, otherwise fall back for local dev
SPACE_HOST = os.getenv("SPACE_HOST", "")
if SPACE_HOST:
    RP_ID = SPACE_HOST.split(":")[0]            # e.g. "your-space.hf.space"
    ORIGIN = f"https://{SPACE_HOST}"
else:
    RP_ID = "localhost"
    ORIGIN = "http://localhost:7860"

RP_NAME = "Touch ID Auth Demo"
DB_PATH = Path(os.getenv("DB_PATH", "/data/webauthn.db"))  # /data is persistent on HF Spaces

# Fall back to local path if /data doesn't exist (local dev)
if not DB_PATH.parent.exists():
    DB_PATH = Path("webauthn.db")


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id          TEXT PRIMARY KEY,
                username    TEXT UNIQUE NOT NULL,
                created_at  REAL NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                credential_id   TEXT PRIMARY KEY,
                user_id         TEXT NOT NULL,
                public_key      TEXT NOT NULL,
                sign_count      INTEGER NOT NULL DEFAULT 0,
                created_at      REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        db.commit()


@contextmanager
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# In-memory challenge store (short-lived, per-session)
# ---------------------------------------------------------------------------

challenges: dict[str, bytes] = {}   # session_id -> challenge


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="WebAuthn Touch ID Demo")


@app.on_event("startup")
def startup():
    init_db()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class RegisterStartRequest(BaseModel):
    username: str

class RegisterFinishRequest(BaseModel):
    username: str
    credential: dict

class LoginStartRequest(BaseModel):
    username: str

class LoginFinishRequest(BaseModel):
    username: str
    credential: dict


# ---------------------------------------------------------------------------
# Helper – session cookie
# ---------------------------------------------------------------------------

def get_or_create_session(request: Request, response: Response) -> str:
    session_id = request.cookies.get("session_id")
    if not session_id:
        session_id = secrets.token_hex(16)
        response.set_cookie("session_id", session_id, httponly=True, samesite="strict")
    return session_id


# ---------------------------------------------------------------------------
# Registration endpoints
# ---------------------------------------------------------------------------

@app.post("/api/register/start")
async def register_start(body: RegisterStartRequest, request: Request, response: Response):
    session_id = get_or_create_session(request, response)
    username = body.username.strip().lower()

    if not username:
        raise HTTPException(400, "Username required")

    # Check if username already taken
    with get_db() as db:
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            raise HTTPException(409, "Username already registered. Try logging in instead.")

    user_id = secrets.token_hex(16)

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id.encode(),
        user_name=username,
        user_display_name=username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )

    # Store challenge for verification
    challenges[session_id] = options.challenge

    # Store pending user_id so we can use it in finish
    challenges[f"{session_id}_user_id"] = user_id.encode()
    challenges[f"{session_id}_username"] = username.encode()

    # Serialize options to JSON-compatible dict
    options_json = json.loads(options_to_json(options))

    return {"options": options_json}


@app.post("/api/register/finish")
async def register_finish(body: RegisterFinishRequest, request: Request, response: Response):
    session_id = get_or_create_session(request, response)

    challenge = challenges.pop(session_id, None)
    user_id = challenges.pop(f"{session_id}_user_id", None)
    username = challenges.pop(f"{session_id}_username", None)

    if not challenge or not user_id:
        raise HTTPException(400, "No pending registration. Start over.")

    user_id = user_id.decode() if isinstance(user_id, bytes) else user_id
    username = username.decode() if isinstance(username, bytes) else username

    try:
        credential = body.credential
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )
    except Exception as e:
        raise HTTPException(400, f"Registration verification failed: {e}")

    # Store user + credential
    cred_id = urlsafe_b64encode(verification.credential_id).decode()
    pub_key = urlsafe_b64encode(verification.credential_public_key).decode()

    with get_db() as db:
        db.execute(
            "INSERT INTO users (id, username, created_at) VALUES (?, ?, ?)",
            (user_id, username, time.time()),
        )
        db.execute(
            "INSERT INTO credentials (credential_id, user_id, public_key, sign_count, created_at) VALUES (?, ?, ?, ?, ?)",
            (cred_id, user_id, pub_key, verification.sign_count, time.time()),
        )
        db.commit()

    return {"status": "ok", "username": username}


# ---------------------------------------------------------------------------
# Authentication endpoints
# ---------------------------------------------------------------------------

@app.post("/api/login/start")
async def login_start(body: LoginStartRequest, request: Request, response: Response):
    session_id = get_or_create_session(request, response)
    username = body.username.strip().lower()

    with get_db() as db:
        user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found. Register first.")

        creds = db.execute(
            "SELECT credential_id FROM credentials WHERE user_id = ?", (user["id"],)
        ).fetchall()

    allow_credentials = [
        PublicKeyCredentialDescriptor(
            id=urlsafe_b64decode(c["credential_id"] + "==")
        )
        for c in creds
    ]

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    challenges[session_id] = options.challenge
    challenges[f"{session_id}_username"] = username.encode()

    options_json = json.loads(options_to_json(options))
    return {"options": options_json}


@app.post("/api/login/finish")
async def login_finish(body: LoginFinishRequest, request: Request, response: Response):
    session_id = get_or_create_session(request, response)

    challenge = challenges.pop(session_id, None)
    username_bytes = challenges.pop(f"{session_id}_username", None)

    if not challenge:
        raise HTTPException(400, "No pending login. Start over.")

    username = username_bytes.decode() if username_bytes else body.username.strip().lower()

    with get_db() as db:
        user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found.")

        # Find the credential used
        credential = body.credential
        raw_id_b64 = credential.get("rawId") or credential.get("id", "")
        # Normalize padding
        padded = raw_id_b64 + "=" * (-len(raw_id_b64) % 4)

        cred_row = db.execute(
            "SELECT credential_id, public_key, sign_count FROM credentials WHERE user_id = ?",
            (user["id"],),
        ).fetchone()

        if not cred_row:
            raise HTTPException(400, "No credentials found for user.")

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=urlsafe_b64decode(cred_row["public_key"] + "=="),
            credential_current_sign_count=cred_row["sign_count"],
        )
    except Exception as e:
        raise HTTPException(400, f"Authentication failed: {e}")

    # Update sign count
    with get_db() as db:
        db.execute(
            "UPDATE credentials SET sign_count = ? WHERE credential_id = ?",
            (verification.new_sign_count, cred_row["credential_id"]),
        )
        db.commit()

    # Set an authenticated session cookie
    response.set_cookie("authed_user", username, httponly=True, samesite="strict")

    return {"status": "ok", "username": username}


# ---------------------------------------------------------------------------
# Session / user info
# ---------------------------------------------------------------------------

@app.get("/api/me")
async def me(request: Request):
    username = request.cookies.get("authed_user")
    if not username:
        raise HTTPException(401, "Not authenticated")
    return {"username": username}


@app.post("/api/logout")
async def logout(response: Response):
    response.delete_cookie("authed_user")
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Serve frontend
# ---------------------------------------------------------------------------

app.mount("/", StaticFiles(directory="static", html=True), name="static")
