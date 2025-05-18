"""
🚧 NOTE: This authentication module is NOT complete yet.
Use strictly for **testing and development purposes only**.

----------------------------------------------------------
Authentication Routes Overview
----------------------------------------------------------
Currently Implemented:
- /register        : Register a new user
- /login           : Login a user and return an access token (set cookies)

Planned Features:
- /refresh         : Refresh a user's access token
- /logout          : Logout a user and clear cookies
- /reset-password  : Send reset link or OTP to reset password
- /forgot-password : Initiate forgot password flow
- /change-password : Authenticated password change
- /social-login    : OAuth-based login using providers (Google, GitHub, etc.)

----------------------------------------------------------
This module will be marked complete once all features are
implemented and thoroughly tested for production readiness.
"""



from fastapi import Depends, HTTPException, status, APIRouter, Response
from app.db.session import SessionLocal, get_db #import your db session
from app.db.models import User #import your user model
from app.core.security import create_jwt_token,decode_jwt_token,create_refresh_token #import your security module
from app.utils.cookies import set_auth_cookies
from app.db.schemas import UserCreate, UserLogin #import your user schema(pydantic model)
from werkzeug.security import generate_password_hash, check_password_hash

router = APIRouter()

@router.post("/register")
def register(user: UserCreate, db: SessionLocal = Depends(get_db)):
    #query database for email
    db_user = db.query(User).filter(User.email == user.email).first()
    #if email exists
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    #check if username exists
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")
    #hash password
    user.password = generate_password_hash(user.password)
    #create user
    db_user = User(**user.dict())
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user #return user details

@router.post("/login")
def login(user: UserLogin, db: SessionLocal = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not check_password_hash(db_user.password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid username or password")

    jwt_token = create_jwt_token(db_user.id)
    refresh_token = create_refresh_token(db_user.id)

    response = Response()  # create a response object to set cookies on
    set_auth_cookies(response, jwt_token, refresh_token)  # your helper should set both cookies securely

    # Return user info or minimal info + tokens if needed, but response object is needed to send cookies
    response.status_code = status.HTTP_200_OK
    response.content = '{"message": "Login successful"}'  # optional JSON message
    response.media_type = "application/json"
    #return response  # return the response object with cookies set
    # If you want to return data along with the response, you can add it to the response body
    return {"message": "Login successful", "data": {"user_id": db_user.id, "username": db_user.username, "email": db_user.email, "jwt_token": jwt_token, "refresh_token": refresh_token}}

#This is a protected route that requires a valid jwt token to access
@router.get("/me") 
#This route is used to get the user's profile
#The user_id is passed in as a dependency from the decode_jwt_token function
#The user_id is then used to query the database for the user's profile
#The user's profile is then returned to the client as a json object
def read_user_profile(user_id: str = Depends(decode_jwt_token)):
    return {"user_id": user_id, "message": "This is protected data"}
