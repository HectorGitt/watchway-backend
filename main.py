from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
import models, schemas, auth, database
from database import engine
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from pydantic import EmailStr, BaseModel
import os
from dotenv import load_dotenv
import secrets

load_dotenv()

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Email Config
conf = ConnectionConfig(
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'user@example.com'),
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'password'),
    MAIL_FROM = os.getenv('MAIL_FROM', 'noreply@watchway.ng'),
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587)),
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_STARTTLS = False,
    MAIL_SSL_TLS = True,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = True
)

# CORS
origins = ["*"] # Allow all for dev debugging
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Authenticate by Email (username field in form_data contains email in our frontend logic)
    # Or strict check: user might send email in 'username' field of OAuth2 form
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_verified:
         raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Please check your inbox.",
        )

    if user.is_suspended:
         raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account suspended by administrator.",
        )

    access_token_expires = auth.timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email}, # Sub is now email
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

async def send_verification_email(email: EmailStr, token: str):
    message = MessageSchema(
        subject="Verify your WatchWay Account",
        recipients=[email],
        body=f"Click the following link to verify your account:\n\nhttp://localhost:3000/verify/{token}\n\nIf you did not request this, please ignore this email.",
        subtype=MessageType.plain
    )
    fm = FastMail(conf)
    try:
        await fm.send_message(message)
    except Exception as e:
        print(f"Email failed: {e}")

@app.post("/users/", response_model=schemas.User)
async def create_user(user: schemas.UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = auth.get_password_hash(user.password)
    # Default username to email prefix if not provided
    uname = user.username if user.username else user.email.split("@")[0]
    
    db_user = models.User(
        email=user.email, 
        username=uname, 
        hashed_password=hashed_password,
        is_verified=False, # Enforce verification
        civic_points=5 # Sign up bonus
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    # Send Verification Email (Mock token using same auth logic for MVP simplicity)
    # In real app, make a separate expiry token
    verification_token = auth.create_access_token(data={"sub": user.email}, expires_delta=auth.timedelta(hours=24))
    background_tasks.add_task(send_verification_email, user.email, verification_token)

    return db_user

@app.get("/verify/{token}")
async def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = auth.jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
             raise HTTPException(status_code=400, detail="Invalid token")
    except auth.JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
         raise HTTPException(status_code=404, detail="User not found")
    
    if user.is_verified:
        return {"message": "Email already verified"}

    user.is_verified = True
    user.civic_points += 2 # Verification bonus
    db.commit()
    return {"message": "Email verified successfully! You can now login."}

@app.post("/resend-verification")
async def resend_verification(
    email: str, 
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_verified:
        raise HTTPException(status_code=400, detail="User already verified")

    # Generate new token
    verification_token = auth.create_access_token(data={"sub": user.email}, expires_delta=auth.timedelta(hours=24))
    background_tasks.add_task(send_verification_email, user.email, verification_token)
    
    return {"message": "Verification email resent"}

@app.get("/users/me/", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(auth.get_current_user)):
    return current_user

@app.put("/users/me/", response_model=schemas.User)
async def update_user_me(
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    # Check if username is taken
    if user_update.username:
        existing_user = db.query(models.User).filter(models.User.username == user_update.username).first()
        if existing_user and existing_user.id != current_user.id:
            raise HTTPException(status_code=400, detail="Username already taken")
        current_user.username = user_update.username
    
    db.commit()
    db.refresh(current_user)
    return current_user

class UserPasswordUpdate(BaseModel):
    old_password: str
    new_password: str

@app.put("/users/me/password")
async def update_user_password(
    password_update: UserPasswordUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    if not auth.verify_password(password_update.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect old password")
    
    current_user.hashed_password = auth.get_password_hash(password_update.new_password)
    db.commit()
    return {"message": "Password updated successfully"}

@app.post("/reports/", response_model=schemas.Report)
def create_report(
    report: schemas.ReportCreate, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    # Auto-determine jurisdiction (simplified logic for backend)
    jurisdiction = "UNKNOWN"
    if "Expressway" in report.address:
        jurisdiction = "FEDERAL"
    else:
        jurisdiction = "STATE"

    db_report = models.Report(
        id=secrets.token_hex(4), # Generates 8-char random ID
        **report.dict(), 
        jurisdiction=jurisdiction, 
        status="unverified",
        reporter_id=current_user.id,
        severity_level=5,
        is_verified=False
    )
    db.add(db_report)
    
    # Award Civic Points for reporting
    current_user.civic_points += 3
    
    db.commit()
    db.refresh(db_report)
    return db_report

@app.get("/reports/", response_model=List[schemas.Report])
def read_reports(
    skip: int = 0, 
    limit: int = 100, 
    status: Optional[str] = None,
    state: Optional[str] = None,
    hazard_type: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(models.Report)
    
    if status is not None and status != "all":
        query = query.filter(models.Report.status == status)
    
    if state is not None and state != "all":
        query = query.filter(models.Report.state == state)

    if hazard_type is not None and hazard_type != "all":
        query = query.filter(models.Report.title == hazard_type)
        
    if search:
        search_term = f"%{search}%"
        query = query.filter(models.Report.description.ilike(search_term))
        
    return query.offset(skip).limit(limit).all()

@app.get("/reports/{report_id}", response_model=schemas.Report)
def read_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report

import math

def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371  # Earth radius in km
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (math.sin(d_lat / 2) * math.sin(d_lat / 2) +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(d_lon / 2) * math.sin(d_lon / 2))
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

class VerifySchema(BaseModel):
    lat: Optional[float] = None
    lng: Optional[float] = None

@app.post("/reports/{report_id}/verify", response_model=schemas.Report)
def verify_report(
    report_id: str, 
    verify_data: VerifySchema,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    if report.reporter_id == current_user.id:
        raise HTTPException(status_code=400, detail="Start your own verification? You submitted this! Let others verify it.")

    if report.status == "verified" or report.status == "resolved":
        raise HTTPException(status_code=400, detail="Report is already verified")

    # Coordinator Logic: Instant Verify, No location needed
    if current_user.role == "coordinator" or current_user.role == "admin":
        report.status = "verified"
        report.is_verified = True
        report.verification_count += 3 # Boost count
        
        # Award points
        current_user.civic_points += 2
        reporter = db.query(models.User).filter(models.User.id == report.reporter_id).first()
        if reporter:
             reporter.civic_points += 10
             
        db.commit()
        db.refresh(report)
        return report

    # Citizen Logic: Proximity Check required
    if not verify_data.lat or not verify_data.lng:
        raise HTTPException(status_code=400, detail="GPS location required for citizen verification")
        
    dist = calculate_distance(verify_data.lat, verify_data.lng, report.lat, report.lng)
    if dist > 0.5: # 500 meters
        raise HTTPException(status_code=400, detail=f"You are too far away ({dist:.2f}km). Get closer to verify.")

    # Increment verification count
    report.verification_count += 1
    
    # Auto-verify threshold logic
    if report.verification_count >= 3:
        report.status = "verified"
        report.is_verified = True
        
        # Award points to reporter for confirmed hazard
        reporter = db.query(models.User).filter(models.User.id == report.reporter_id).first()
        if reporter:
            reporter.civic_points += 10
            
    # Award points to verifier
    current_user.civic_points += 1
    
    db.commit()
    db.refresh(report)
    return report

class ResolveSchema(BaseModel):
    after_image_url: Optional[str] = None
    lat: Optional[float] = None
    lng: Optional[float] = None

@app.post("/reports/{report_id}/resolve", response_model=schemas.Report)
def resolve_report(
    report_id: str,
    resolve_data: ResolveSchema,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Coordinator/Admin Logic (Instant Resolve)
    if current_user.role == "coordinator" or current_user.role == "admin":
         # Check assignment if coordinator
        if current_user.role == "coordinator" and current_user.state_assigned != report.state:
             raise HTTPException(status_code=403, detail=f"You are only authorized for {current_user.state_assigned}")
        
        report.status = "resolved"
        if resolve_data.after_image_url:
            report.after_image_url = resolve_data.after_image_url
        
        # Award points
        current_user.civic_points += 50
        if report.reporter:
            report.reporter.civic_points += 20
        
        db.commit()
        db.refresh(report)
        return report

    # Citizen Logic
    if not resolve_data.lat or not resolve_data.lng:
        raise HTTPException(status_code=400, detail="GPS location required for citizen resolution")

    dist = calculate_distance(resolve_data.lat, resolve_data.lng, report.lat, report.lng)
    if dist > 0.5:
        raise HTTPException(status_code=400, detail=f"Too far away ({dist:.2f}km).")

    # Path 1: Reporting the fix (Needs photo)
    if report.status == "verified":
        if not resolve_data.after_image_url:
             raise HTTPException(status_code=400, detail="Live photo required to report a fix")
        
        report.status = "fix_pending"
        report.after_image_url = resolve_data.after_image_url
        current_user.civic_points += 15
        
        db.commit()
        db.refresh(report)
        return report
        
    # Path 2: Confirming the fix (Status is already fix_pending)
    if report.status == "fix_pending":
        # Ensure it's not the same person who reported the fix (simplified: check if user provided prev image? 
        # For now, just check simply. In real app we'd track 'fix_reporter_id')
        
        report.status = "resolved"
        current_user.civic_points += 20
        if report.reporter:
             report.reporter.civic_points += 20 # Original reporter gets points too
             
        db.commit()
        db.refresh(report)
        return report

    raise HTTPException(status_code=400, detail="Report validation logic unhandled")

# --- Admin Endpoints ---

@app.get("/users/", response_model=List[schemas.User])
def read_users(
    skip: int = 0, 
    limit: int = 100, 
    role: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    query = db.query(models.User)
    if role:
        query = query.filter(models.User.role == role)
        
    return query.offset(skip).limit(limit).all()

@app.put("/users/{user_id}/role", response_model=schemas.User)
def update_user_role(
    user_id: int, 
    role: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
        
    if role not in ["citizen", "coordinator", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")
        
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    user.role = role
    db.commit()
    db.refresh(user)
    return user

@app.put("/users/{user_id}/suspend", response_model=schemas.User)
def suspend_user(
    user_id: int, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
        
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Toggle suspension
    user.is_suspended = not user.is_suspended
    
    db.commit()
    db.refresh(user)
    return user
