import os
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from db import pool

SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

security = HTTPBearer(auto_error=False)

def create_access_token(*, username: str, role: str) -> str:
	now = datetime.now(timezone.utc)
	payload = {
		"sub": username,
		"role": role,
		"iat": int(now.timestamp()),
		"exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
	}
	return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

'''
3 Roles:
	• user
	• admin
	• owner
'''
def current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
	if not credentials or credentials.scheme.lower() != "bearer":
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing credentials")
	try:
		data = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
	except jwt.PyJWTError:
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired token")

	username = data.get("sub")
	if not username:
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")

	with pool.connection() as conn, conn.cursor() as cur:
		cur.execute("SELECT role, email_verified FROM users WHERE username = %s", (username,))
		row = cur.fetchone()
	if not row:
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="user not found")
	
	email_verified = row[1]
	if not email_verified:
		raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="email not verified")

	return {"username": username, "role": row[0]}

def current_admin(user = Depends(current_user)):
	if user["role"] != "admin" or user["role"] != "owner":
		raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin only")
	return user

def current_owner(user = Depends(current_user)):
	if user["role"] != "owner":
		raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="owner only")
	return user

