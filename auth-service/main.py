from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import logging

app = FastAPI()

# Setup logging
logging.basicConfig(level=logging.INFO)

# Fake database for demonstration
fake_users_db = {}

# OAuth2 password bearer token auth scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
    username: str
    email: str
    disabled: bool = None

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str


def fake_hash_password(password: str):
    return "fakehashed" + password

@app.post("/signup", response_model=User)
async def signup(user: User):
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already registered")
    fake_users_db[user.username] = UserInDB(**user.dict(), hashed_password=fake_hash_password("examplepassword"))
    logging.info(f"New user signed up: {user.username}")
    return user

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not (user.hashed_password == fake_hash_password(form_data.password)):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    logging.info(f"User logged in: {form_data.username}")
    return {"access_token": user.username, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(token: str = Depends(oauth2_scheme)):
    username = token  # In a real application, you'd decode the token to get the username
    user = fake_users_db.get(username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    logging.info(f"User info accessed: {username}")
    return user

@app.post("/refresh")
async def refresh_token(token: str = Depends(oauth2_scheme)):
    # This would usually involve validating the token and generating a new one
    return {"access_token": token, "token_type": "bearer"}