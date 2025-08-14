from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from db import ping, pool
from psycopg import sql
from psycopg.errors import UniqueViolation
from crypto_utils import hash_password, verify_password 
import re
from pydantic import BaseModel, Field, field_validator

ALLOWED_ORIGINS = ["https://rps9.github.io"]

USERNAME_RE = re.compile(r"^(?![._-])(?!.*[._-]{2})[a-z0-9._-]+(?<![._-])$")
# Covers all ASCII but space
PASSWORD_RE = re.compile(r"^[\x21-\x7E]+$")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

class UserCreds(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=64)

    @field_validator("username", mode="before")
    @classmethod
    def _normalize_username(cls, username_value: str) -> str:
        return (username_value or "").strip().lower()

    @field_validator("username")
    @classmethod
    def _validate_username(cls, username_value: str) -> str:
        if not USERNAME_RE.fullmatch(username_value):
            raise ValueError("username may contain a-z, 0-9, dot, underscore, hyphen; cannot start/end with . _ - or contain repeats like '..'")
        return username_value

    @field_validator("password")
    @classmethod
    def _validate_password(cls, password_value: str) -> str:
        if not PASSWORD_RE.fullmatch(password_value):
            raise ValueError("password must be 8-64 chars, visible ASCII (no spaces)")
        return password_value

@app.get("/api/db/health")
def db_health():
    ok = False
    try:
        ok = ping()
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {"ok": ok}

@app.post("/api/auth/signup", status_code=status.HTTP_201_CREATED)
def sign_up(body: UserCreds):
    try:
        pwd_hash = hash_password(body.password)
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (body.username, pwd_hash),
            )
        return {"ok": True, "message": "account created"}

    except UniqueViolation:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username already exists")

    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="signup failed")
    
@app.post("/api/auth/signin", status_code=status.HTTP_200_OK)
def sign_in(body: UserCreds):
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE username = %s", (body.username,))
            row = cur.fetchone()

        # Do not reveal if username exists
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

        stored_hash = row[0]
        if not verify_password(body.password, stored_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

        return {"ok": True, "message": "signed in"}

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="signin failed")