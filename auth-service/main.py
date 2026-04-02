import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv

from models import SignupRequest, LoginRequest, AuthResponse, VerifyTokenRequest, TokenResponse
from database import init_db, query_db_single, execute_db
from utils import hash_password, verify_password, create_token, verify_token

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting auth-service...")
    try:
        init_db()
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
    yield
    logger.info("Shutting down auth-service...")

app = FastAPI(title="Auth Service", lifespan=lifespan)

app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000", "http://localhost:8000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/signup", response_model=AuthResponse)
async def signup(request: SignupRequest):
    try:
        existing_user = query_db_single("SELECT id FROM users WHERE email = %s", (request.email,))
        if existing_user:
            logger.warning(f"Signup attempt with existing email: {request.email}")
            raise HTTPException(status_code=400, detail="Email already registered")
        password_hash = hash_password(request.password)
        import psycopg2
        conn = psycopg2.connect(os.getenv("DATABASE_URL"))
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id", (request.email, password_hash))
            user_id = cursor.fetchone()[0]
            conn.commit()
            logger.info(f"User created: {request.email}")
        finally:
            cursor.close()
            conn.close()
        token = create_token(user_id, request.email)
        return AuthResponse(token=token, user_id=user_id, email=request.email)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signup error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/login", response_model=AuthResponse)
async def login(request: LoginRequest):
    try:
        user = query_db_single("SELECT id, email, password_hash FROM users WHERE email = %s", (request.email,))
        if not user:
            logger.warning(f"Login attempt with non-existent email: {request.email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if not verify_password(request.password, user['password_hash']):
            logger.warning(f"Failed login attempt for: {request.email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = create_token(user['id'], user['email'])
        logger.info(f"User logged in: {request.email}")
        return AuthResponse(token=token, user_id=user['id'], email=user['email'])
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/verify-token", response_model=TokenResponse)
async def verify_token_endpoint(request: VerifyTokenRequest):
    try:
        payload = verify_token(request.token)
        if not payload:
            return TokenResponse(valid=False)
        return TokenResponse(valid=True, user_id=payload.get('user_id'))
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return TokenResponse(valid=False)

@app.post("/refresh")
async def refresh_token(request: VerifyTokenRequest):
    try:
        payload = verify_token(request.token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        new_token = create_token(payload['user_id'], payload['email'])
        logger.info(f"Token refreshed for user {payload['user_id']}")
        return {"token": new_token}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)