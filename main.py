from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
import os
import uvicorn

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))  
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)


fake_db = {}

SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


app = FastAPI(title="SANTHOSH",description="santhosh")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# User Model
class User(BaseModel):
    email: str
    password: str

# Token Response Model
class Token(BaseModel):
    access_token: str
    token_type: str

# Hash Password
def get_password_hash(password: str):
    return password_context.hash(password)

# Verify Password
def verify_password(plain_password, hashed_password):
    return password_context.verify(plain_password, hashed_password)

# Create JWT Token
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Authenticate User
def authenticate_user(email: str, password: str):
    user = fake_db.get(email)
    if not user or not verify_password(password, user["password"]):
        return False
    return user

# Get Current User
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None or email not in fake_db:
            raise credentials_exception
        return fake_db[email]
    except JWTError:
        raise credentials_exception

# Register User
@app.post("/register")
def register(user: User):
    if user.email in fake_db:
        raise HTTPException(status_code=400, detail="User already exists")
    fake_db[user.email] = {"email": user.email, "password": get_password_hash(user.password)}
    return {"msg": "User registered successfully"}

# Login and Generate Token
@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token({"sub": form_data.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

# Get Users (Protected Route)
@app.get("/users", dependencies=[Depends(get_current_user)])
def get_users():
    return fake_db
