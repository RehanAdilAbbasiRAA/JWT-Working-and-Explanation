from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import (
    HTTPBearer, HTTPAuthorizationCredentials,
    OAuth2PasswordBearer, OAuth2PasswordRequestForm
)
from fastapi.openapi.utils import get_openapi
from jose import JWTError, jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv()

app = FastAPI()

# 🔐 Secret key + algorithm
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 🔐 Admin credentials from .env
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# 🛡️ In-memory fake user DB
fake_users_db = {
    "rehan": {
        "username": "rehan",
        "password": "123",
        "email": "rehan@gmail.com",
    },
    "john": {
        "username": "john",
        "password": "222",
        "email": "john@example.com",
    }
}

# ✅ Bearer token for regular auth
token_auth_scheme = HTTPBearer()

# ✅ OAuth2 for Swagger UI
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 📦 Create JWT token
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# 👮 Validate JWT (used by all protected routes)
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("name") or payload.get("sub")  # support both keys
        email = payload.get("email", "")

        # If admin
        if username == ADMIN_USERNAME:
            return {"username": ADMIN_USERNAME, "email": email or "admin@example.com"}

        # If normal user
        if not username or username not in fake_users_db:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return fake_users_db[username]

    except JWTError as e:
        raise HTTPException(status_code=401, detail="Token verification failed")

# 🔐 User login route (non-admin)
@app.post("/login")
def login(name: str, password: str):
    user = fake_users_db.get(name)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token_data = {"name": user["username"], "email": user["email"]}
    token = create_access_token(
        data=token_data,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {
        "success": True,
        "access_token": token,
        "token_type": "bearer",
        "name": name,
        "password": "*******"
    }

# 🔐 Admin login via Swagger UI (OAuth2 password flow)
@app.post("/token")
def admin_token(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != ADMIN_USERNAME or form_data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    token_data = {"sub": ADMIN_USERNAME}
    token = create_access_token(
        data=token_data,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": token, "token_type": "bearer"}

# 👤 Get current user
@app.get("/whoami")
def read_users_me(current_user: dict = Depends(get_current_user)):
    return {
        "user": current_user["username"],
        "email": current_user["email"]
    }

# 🔒 Protected route
@app.get("/secret")
def protected_route(current_user: dict = Depends(get_current_user)):
    return {
        "message": f"Welcome {current_user['username']}, you have access to the secret route."
    }

# 🔧 Swagger UI config: enable both HTTPBearer + OAuth2
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="JWT Auth Demo",
        version="1.0.0",
        description="JWT Authentication with Swagger UI Admin Login",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        # "BearerAuth": {
        #     "type": "http",
        #     "scheme": "bearer",
        #     "bearerFormat": "JWT"
        # },
        "OAuth2Password": {
            "type": "oauth2",
            "flows": {
                "password": {
                    "tokenUrl": "/token",
                    "scopes": {}
                }
            }
        }
    }

    for path, path_item in openapi_schema["paths"].items():
        for method in path_item.values():
            if path == "/login":
                continue
            method["security"] = [{"OAuth2Password": []}]
            # method["security"] = [{"BearerAuth": []}, {"OAuth2Password": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
