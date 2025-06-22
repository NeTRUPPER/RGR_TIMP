from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks, status, Form, Body
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional
import nmap
import dns.resolver
import subprocess
import json
import os
import uuid
from app.models import Base, User, Scan
from app.database import SessionLocal, engine
from app.schemas import UserCreate, Token, ScanRequest
from app.auth import (
    create_access_token, 
    get_current_user, 
    verify_password, 
    get_password_hash,
    get_db,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

app = FastAPI()

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Templates
templates = Jinja2Templates(directory="app/templates")

# Create database tables
Base.metadata.create_all(bind=engine)

# Create default user if not exists
def create_default_user():
    db = SessionLocal()
    try:
        default_user = db.query(User).filter(User.username == "admin").first()
        if not default_user:
            hashed_password = get_password_hash("admin")
            default_user = User(
                username="admin",
                email="admin@example.com",
                hashed_password=hashed_password,
                is_active=True
            )
            db.add(default_user)
            db.commit()
    finally:
        db.close()

# Initialize default user
create_default_user()

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

@app.get("/favicon.ico")
async def favicon():
    favicon_path = "app/static/favicon.ico"
    if os.path.exists(favicon_path):
        return FileResponse(favicon_path)
    else:
        return Response(status_code=404)

@app.get("/.well-known/appspecific/com.chrome.devtools.json")
async def chrome_devtools():
    return {"error": "Not found"}, 404

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "current_user": current_user
    })

@app.get("/aviation-security", response_class=HTMLResponse)
async def aviation_security(request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("aviation_security.html", {
        "request": request,
        "current_user": current_user
    })

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    current_user = await get_current_user(request)
    if current_user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": None
    })

@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Неверное имя пользователя или пароль"
        })
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    return response

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    current_user = await get_current_user(request)
    if current_user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("register.html", {
        "request": request,
        "error": None
    })

@app.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check if username already exists
    if db.query(User).filter(User.username == username).first():
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Пользователь с таким именем уже существует"
        })
    
    # Check if email already exists
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Пользователь с таким email уже существует"
        })
    
    # Create new user
    hashed_password = get_password_hash(password)
    db_user = User(
        username=username,
        email=email,
        hashed_password=hashed_password,
        is_active=True
    )
    db.add(db_user)
    db.commit()
    
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response

@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("scan.html", {
        "request": request,
        "current_user": current_user
    })

@app.get("/scan/{scan_id}")
async def get_scan_results(scan_id: str, request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    db = SessionLocal()
    try:
        db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not db_scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if db_scan.status == "completed":
            return {
                "status": db_scan.status,
                "results": db_scan.results if db_scan.results else []
            }
        elif db_scan.status == "failed":
            return {
                "status": db_scan.status,
                "error": db_scan.results.get("error") if db_scan.results else "Unknown error"
            }
        else:
            return {"status": db_scan.status}
    finally:
        db.close()

@app.post("/scan")
async def start_scan(
    background_tasks: BackgroundTasks,
    request: Request,
    scan_request: ScanRequest = Body(...)
):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    scan_id = str(uuid.uuid4())
    
    # Create scan in database
    db = SessionLocal()
    try:
        db_scan = Scan(
            scan_id=scan_id,
            user_id=current_user.id,
            network=scan_request.network,
            status="running",
            results=None
        )
        db.add(db_scan)
        db.commit()
        
        # Start scan in background
        background_tasks.add_task(run_scan, scan_id, scan_request.network)
        
        return {"scan_id": scan_id}
    finally:
        db.close()

async def run_scan(scan_id: str, network: str):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            return

        try:
            # Используем наш расширенный сканер
            from app.scanner import NetworkScanner
            scanner = NetworkScanner()
            
            # Выполняем полное сканирование сети
            results = scanner.scan_network(network)
            
            # Update scan status and results
            scan.status = 'completed'
            scan.results = results
            db.commit()
            
        except Exception as e:
            scan.status = 'failed'
            scan.results = {'error': f'Scan error: {str(e)}'}
            db.commit()
            
    except Exception as e:
        if scan:
            scan.status = 'failed'
            scan.results = {'error': f'Database error: {str(e)}'}
            db.commit()
    finally:
        db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 