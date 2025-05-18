"""
🔐 JWT Token Management & Security Logic
----------------------------------------------------------
This module centralizes all authentication and token-related
security logic using JWT (JSON Web Tokens).

Functions Included:
- create_jwt_token(user_id):
    Generates a short-lived access token (JWT) with user_id as payload.
    
- create_refresh_token(user_id):
    Generates a long-lived refresh token used to reissue JWTs.

- decode_jwt_token(token: str):
    Dependency function to validate and decode JWTs for protected routes.

Planned Enhancements:
- Add token expiry checks and auto-blacklisting using Redis.
- Implement token revocation and refresh rotation.

Security Notes:
- Tokens are signed using a secret key and validated on every request.
- Always validate token structure, expiry, and blacklist status.
"""


from datetime import datetime, timedelta
import jwt
from uuid import UUID

SECRET_KEY = "your-secret-key" # Change this to a secure secret key, preferably stored in an environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def create_jwt_token(user_id: UUID):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),  
        "exp": expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(user_id: UUID):
    expire = datetime.utcnow() + timedelta(days=7)
    payload = {
        "sub": str(user_id),
        "exp": expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
