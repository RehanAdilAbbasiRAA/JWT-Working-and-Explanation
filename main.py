from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordRequestForm
from fastapi.openapi.utils import get_openapi
from jose import JWTError, jwt
from datetime import datetime, timedelta

app = FastAPI()

# 🔐 Secret key + algorithm
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

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

# ✅ Use HTTPBearer instead of OAuth2PasswordBearer for better Swagger behavior
token_auth_scheme = HTTPBearer()

# 📦 Create JWT token
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# 👮 Decode JWT and return user
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    print(token_auth_scheme)
    print("🔐 Received token:", credentials.credentials)  # Debug print
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print("📦 Decoded payload:", payload,type(payload))  # Debug print
        username: str = payload.get("name")
        # email: str = payload.get("email")
        if not username or username not in fake_users_db:
            print("🚫 Invalid username:", username)  # Debug print
            raise HTTPException(status_code=401, detail="Invalid credentials")
        print("✅ Authenticated user:", username)  # Debug print
        print(type(fake_users_db[username]))
        return fake_users_db[username]
    except JWTError as e:
        print("❌ JWT Error:", str(e))  # Debug print
        raise HTTPException(status_code=401, detail="Token verification failed")


# 🔐 Login endpoint
@app.post("/login")
def login(name:str,password:str):
    print(name,password)
    user = fake_users_db.get(name)
    if not user or user["password"]!=password:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token_data = {"name": user["username"],"email":user["email"]}
    token = create_access_token(
        data=token_data,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    ) 
    return {"sucess":True, "access_token": token, "token_type": "bearer","name":name,"password":"*******"}

# 👤 Get current user
@app.get("/whoami")
def read_users_me(current_user: dict = Depends(get_current_user)):
    return {"user": current_user["username"],"email":current_user["email"]}

# 🔒 Protected route
@app.get("/secret")
def protected_route(current_user: dict = Depends(get_current_user)):
    return {"message": f"Welcome {current_user['username']}, you have access to the secret route."}

# 🔧 Swagger UI Bearer Token Auth
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="JWT Auth Demo",
        version="1.0.0",
        description="Simple JWT Authentication using FastAPI",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path, path_item in openapi_schema["paths"].items():
        if path == "/login":
            continue  # ✅ Skip adding auth to /login
        for method in path_item.values():
            method["security"] = [{"BearerAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi