import re, json, hashlib, hmac, jwt
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from db import ping, pool
from psycopg.errors import UniqueViolation
from crypto_utils import hash_password, verify_password 
from pydantic import BaseModel, Field, field_validator
from jwt_utils import create_access_token, current_user, current_admin, current_owner, ACCESS_TOKEN_EXPIRE_MINUTES
from open_ai_manager import chatManager
from email_manager import EmailClient, issue_email_verification_link
from datetime import datetime, timedelta, timezone
from fastapi.responses import RedirectResponse
from spotify import router as spotify_router

ALLOWED_ORIGINS = [
    "https://rps9.net",
    "https://www.rps9.net",
    "https://rps9.github.io",
    "http://localhost:5173"
]

USERNAME_RE = re.compile(r"^(?![._-])(?!.*[._-]{2})[a-z0-9._-]+(?<![._-])$")
PASSWORD_RE = re.compile(r"^[\x21-\x7E]+$") # Covers all ASCII but space

security = HTTPBearer(auto_error=False)

app = FastAPI()
app.include_router(spotify_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

class SignUpCreds(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=64)
    email: str # had some issues with pydantic's EmailStr so I'm just gonna keep it simple

    @field_validator("username", mode="before")
    @classmethod
    def _normalize_username(cls, username: str) -> str:
        return username.strip().lower()

    @field_validator("username")
    @classmethod
    def _validate_username(cls, username: str) -> str:
        if not USERNAME_RE.fullmatch(username):
            raise ValueError("username may contain a-z, 0-9, dot, underscore, hyphen; cannot start/end with . _ - or contain repeats like '..'")
        return username

    @field_validator("password")
    @classmethod
    def _validate_password(cls, password: str) -> str:
        if not PASSWORD_RE.fullmatch(password):
            raise ValueError("password must be 8-64 chars, visible ASCII (no spaces)")
        return password
    
    @field_validator("email", mode="before")
    @classmethod
    def _normalize_email(cls, email: str):
        if email is None:
            raise ValueError("email is required")
        email = str(email).strip().lower()

        if "@" not in email or "." not in email.split("@")[-1]:
            raise ValueError("invalid email format")
        return email

class SignInCreds(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=64)

    @field_validator("username", mode="before")
    @classmethod
    def _normalize_username(cls, username: str) -> str:
        return username.strip().lower()

    @field_validator("username")
    @classmethod
    def _validate_username(cls, username: str) -> str:
        if not USERNAME_RE.fullmatch(username):
            raise ValueError("username may contain a-z, 0-9, dot, underscore, hyphen; cannot start/end with . _ - or contain repeats like '..'")
        return username

    @field_validator("password")
    @classmethod
    def _validate_password(cls, password: str) -> str:
        if not PASSWORD_RE.fullmatch(password):
            raise ValueError("password must be 8-64 chars, visible ASCII (no spaces)")
        return password
    

@app.get("/api/db/health", dependencies=[Depends(current_admin)])
def db_health():
    ok = False
    try:
        ok = ping()
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {"ok": ok}

@app.post("/api/auth/signup", status_code=status.HTTP_201_CREATED)
def sign_up(body: SignUpCreds):
    try:
        pwd_hash = hash_password(body.password)
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, email, email_verified, password_hash) VALUES (%s, %s, FALSE, %s) RETURNING id",
                (body.username, body.email, pwd_hash),
            )
            user_id = cur.fetchone()[0]

        verify_url = issue_email_verification_link(user_id)
        EmailClient().send_verification(body.email, verify_url)
        print(verify_url)
                                        
        # role is user by default, so no need to check the db for role
        token = create_access_token(username=body.username, role="user") 
        expires_at = jwt.decode(token, options={"verify_signature": False})["exp"]
        return {"ok": True, "message": "account created", "access_token": token, "token_type": "bearer", "expires_at": expires_at, "role": "user"}

    except UniqueViolation:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username already exists")

    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Sign Ups not working right now. Have to find a new API provider that won't block port 587...")
    
@app.post("/api/auth/signin", status_code=status.HTTP_200_OK)
def sign_in(body: SignInCreds):
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT password_hash, role, email_verified FROM users WHERE username = %s", (body.username,))
            row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

        stored_hash = row[0]
        role = row[1]
        email_verified = row[2]

        if not verify_password(body.password, stored_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
        if not email_verified:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="email not verified")
        
        token = create_access_token(username=body.username, role=role)
        expires_at = jwt.decode(token, options={"verify_signature": False})["exp"]
        return {"access_token": token, "token_type": "bearer", "expires_at": expires_at, "role": role}

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="signin failed")

@app.get("/api/auth/verify-email")
def verify_email(token_id: str, token: str):
    now = datetime.now(timezone.utc)

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT user_id, token_hash, expires_at, used_at FROM email_verifications WHERE id = %s",
            (token_id,)
        )
        row = cur.fetchone()

        if not row:
            return RedirectResponse(url="https://rps9.github.io/verify/invalid.html", status_code=302)

        user_id = row[0]
        token_hash = row[1]
        expires_at = row[2]
        used_at = row[3]

        if used_at is not None or now > expires_at:
            return RedirectResponse(url="https://rps9.github.io/verify/expired.html", status_code=302)

        presented = hashlib.sha256(token.encode()).hexdigest()
        if not hmac.compare_digest(token_hash, presented):
            return RedirectResponse(url="https://rps9.github.io/verify/invalid.html", status_code=302)

        cur.execute("UPDATE users SET email_verified = TRUE WHERE id = %s", (user_id,))
        cur.execute("UPDATE email_verifications SET used_at = %s WHERE id = %s", (now, token_id,))

    return RedirectResponse(url="https://rps9.github.io/verify/success.html", status_code=302)


class SongInput(BaseModel):
    song_input: list[str]
    additional_instructions: str

    @field_validator("song_input")
    @classmethod
    def _check_not_empty(cls, song_input):
        if not song_input:
            raise ValueError("song_input must have at least one song")
        return song_input
    

@app.post("/api/admin/songrecs", dependencies=[Depends(current_admin)], status_code=status.HTTP_200_OK)
def get_recs(body: SongInput):
    try:
        song_list = body.song_input
        seeds = "\n".join(f"- {s}" for s in song_list)

        prompt = (
            "You are a helpful music recommendation assistant.\n"
            "Task: Recommend 10 songs similar in vibe to the seed list.\n\n"
            f"Seeds:\n{seeds}\n\n"
            "Output format (strict JSON):\n"
            '[{"title":"...", "artist":"...", "why":"one short sentence"}, {"title":"...", "artist":"...", "why":"..."}]\n'
            "Rules: Do not include any of the seed songs in the output. Return exactly 10 items. No prose—JSON only."
        )

        if body.additional_instructions:
            prompt += f"Additional instructions: {body.additional_instructions}"

        gptAgent = chatManager(model="gpt-5-nano")
        raw_text_recommendations = gptAgent.chat(prompt=prompt)

        try:
            json_recommendations = json.loads(raw_text_recommendations)
        except:
            json_recommendations = "it failed ]:" # has yet to fail but we'll see 

        return {"recommendations": json_recommendations}
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="songrecs failed")

class BestowRoleBody(BaseModel):
    username: str
    role: str

    @field_validator("username", mode="before")
    @classmethod
    def _normalize_username(cls, username: str) -> str:
        return str(username).strip().lower()

@app.post("/api/owner/bestow-role", dependencies=[Depends(current_owner)], status_code=status.HTTP_200_OK)
def bestow_admin(body: BestowRoleBody):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET role = %s WHERE username = %s AND role <> %s",
            (body.role, body.username, body.role),
        )
        if cur.rowcount == 0:
            cur.execute("SELECT role FROM users WHERE username = %s", (body.username,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
            if row[0] == body.role:
                return {"ok": True, "message": f"user is already role: {body.role}"}
        return {"ok": True, "message": f"{body.username} is now role: {body.role}"}