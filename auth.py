#This module contains the authentication routes for the application.
#It includes the following routes:
# - /register: Register a new user
#Over time this module will be expanded to include the following routes:
# - /login: Login a user
# - /logout: Logout a user
# - /refresh: Refresh a user's access token
# - /reset-password: Reset a user's password
# - /forgot-password: Forgot a user's password
# - /change-password: Change a user's password

#I will mark it if updates are closed to completion for this module.


from fastapi import Depends, HTTPException, status, APIRouter
from app.db.session import SessionLocal, get_db #import your db session
from app.db.models import User #import your user model
from app.db.schemas import UserCreate #import your user schema(pydantic model)
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
