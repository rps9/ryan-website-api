import os, base64, hashlib, hmac

ITERATIONS = 150_000

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def _db64(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS, dklen=32)
    return f"pbkdf2$sha256${ITERATIONS}${_b64(salt)}${_b64(dk)}"

def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, algo, iters, salt_b64, hash_b64 = stored.split("$")
        if scheme != "pbkdf2" or algo != "sha256":
            return False
        iterations = int(iters)
        salt = _db64(salt_b64)
        expected = _db64(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False
