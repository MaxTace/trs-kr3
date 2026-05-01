from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os
import secrets
from models import *
from databases import get_db_connection
from passlib.context import CryptContext
import jwt
import datetime
from typing import List, Optional

load_dotenv()

app = FastAPI()
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

MODE = os.getenv("MODE", "DEV")
DOCS_USER = os.getenv("DOCS_USER", "admin")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "admin123")
SECRET_KEY = os.getenv("SECRET_KEY", "secret-key") 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def authenticate_user(username: str, password: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, hashed_password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
    if not user:
        return False
    
    if not pwd_context.verify(password, user["hashed_password"]):
        return False
    
    return dict(user)

def get_user_from_db(username: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, hashed_password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
    
    return dict(user) if user else None

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"sub": username, "role": role}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_role(required_roles: List[UserRole]):
    def role_checker(user_data: dict = Depends(verify_token)):
        user_role = user_data.get("role")
        if user_role not in [role.value for role in required_roles]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return user_data
    return role_checker

def verify_docs_auth(credentials: HTTPBasicCredentials = Depends(HTTPBearer(auto_error=False))):
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    correct_username = secrets.compare_digest(credentials.username, DOCS_USER)
    correct_password = secrets.compare_digest(credentials.password, DOCS_PASSWORD)
    
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials

if MODE == "PROD":
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    
    @app.get("/docs", include_in_schema=False)
    @app.get("/redoc", include_in_schema=False)
    @app.get("/openapi.json", include_in_schema=False)
    async def not_found():
        raise HTTPException(status_code=404, detail="Not Found")
        
elif MODE == "DEV":
    @app.get("/docs", include_in_schema=False)
    async def get_docs(auth: HTTPBasicCredentials = Depends(verify_docs_auth)):
        return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")
    
    @app.get("/openapi.json", include_in_schema=False)
    async def get_openapi_endpoint(auth: HTTPBasicCredentials = Depends(verify_docs_auth)):
        return get_openapi(title="My API", version="1.0", routes=app.routes)
    
    @app.get("/redoc", include_in_schema=False)
    async def redoc_hidden():
        raise HTTPException(status_code=404, detail="Not Found")
        
else:
    raise ValueError(f"Invalid MODE value: {MODE}. Use DEV or PROD")

@app.get("/secret")
def give_secret_message(user: dict = Depends(verify_token)):
    return {"message": f"You got my secret, welcome {user.get('sub')}"}

@app.post("/register")
@limiter.limit("1/minute")
def register(request: Request, user: UserRegister):  
    if get_user_from_db(user.username):
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_password = pwd_context.hash(user.password)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, hashed_password) VALUES (?, ?)",
                (user.username, hashed_password)
            )
            conn.commit()
        except Exception as e:
            raise HTTPException(status_code=400, detail="Registration failed")
    
    return {"message": "User registered successfully"}

@app.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(request: Request, login_data: LoginRequest):  
    user = authenticate_user(login_data.username, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    role = "user"
    if login_data.username == "admin":
        role = "admin"
    
    access_token = create_access_token(data={"sub": login_data.username, "role": role})
    return TokenResponse(access_token=access_token)

@app.get("/protected_resource")
def protected_resource(user: dict = Depends(require_role([UserRole.ADMIN, UserRole.USER]))):
    return {"message": f"Access granted for {user.get('sub')} with role {user.get('role')}"}

@app.post("/todos", status_code=201)
def create_todo(
    todo: TodoCreate,
    user: dict = Depends(require_role([UserRole.ADMIN, UserRole.USER]))
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO todos (title, description, owner_username) VALUES (?, ?, ?)",
            (todo.title, todo.description, user.get('sub'))
        )
        todo_id = cursor.lastrowid
        
        cursor.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,))
        result = cursor.fetchone()
    
    return dict(result)

@app.get("/todos/{todo_id}")
def read_todo(
    todo_id: int,
    user: dict = Depends(require_role([UserRole.ADMIN, UserRole.USER, UserRole.GUEST]))
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,))
        result = cursor.fetchone()
    
    if not result:
        raise HTTPException(status_code=404, detail="Todo not found")
    
    return dict(result)

@app.get("/todos")
def get_all_todos(user: dict = Depends(verify_token)):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, description, completed, owner_username FROM todos")
        results = cursor.fetchall()
    
    return [dict(row) for row in results]

@app.put("/todos/{todo_id}")
def update_todo(
    todo_id: int,
    todo_update: TodoUpdate,
    user: dict = Depends(require_role([UserRole.ADMIN, UserRole.USER]))
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, owner_username FROM todos WHERE id = ?", (todo_id,))
        todo = cursor.fetchone()
        
        if not todo:
            raise HTTPException(status_code=404, detail="Todo not found")
        
        if user.get('role') != 'admin' and todo['owner_username'] != user.get('sub'):
            raise HTTPException(status_code=403, detail="Not enough permissions")
        
        cursor.execute(
            "UPDATE todos SET title = ?, description = ?, completed = ? WHERE id = ?",
            (todo_update.title, todo_update.description, todo_update.completed, todo_id)
        )
        
        cursor.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,))
        result = cursor.fetchone()
    
    return dict(result)

@app.delete("/todos/{todo_id}")
def delete_todo(
    todo_id: int,
    user: dict = Depends(require_role([UserRole.ADMIN]))
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM todos WHERE id = ?", (todo_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Todo not found")
        
        cursor.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    
    return {"message": "Todo deleted successfully"}

@app.get("/admin/users")
def list_users(user: dict = Depends(require_role([UserRole.ADMIN]))):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users")
        users = cursor.fetchall()
    
    return {"users": [dict(u) for u in users]}