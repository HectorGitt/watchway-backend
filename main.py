from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
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
    print(f"DEBUG: read_users_me called for {current_user.email}")
    print(f"DEBUG: Returning user role: {current_user.role}")
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

@app.post("/users/apply-coordinator", response_model=schemas.User)
def apply_coordinator(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    if current_user.role != "citizen":
        raise HTTPException(status_code=400, detail="Only citizens can apply")
        
    if current_user.coordinator_application_status == "PENDING":
        raise HTTPException(status_code=400, detail="Application already pending")
    
    if current_user.coordinator_application_status == "APPROVED":
         raise HTTPException(status_code=400, detail="You are already a coordinator")

    current_user.coordinator_application_status = "PENDING"
    db.commit()
    db.refresh(current_user)
    return current_user

@app.post("/reports/", response_model=schemas.Report)
def create_report(
    report: schemas.ReportCreate, 
    x_device_id: Optional[str] = Header(None),
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
        severity_level=report.severity_level or 1, # Default to 1 if not provided
        is_verified=False,
        device_id=x_device_id
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
    x_device_id: Optional[str] = Header(None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    # 1. Self-Verification Block
    if report.reporter_id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot verify your own report. A different Citizen must confirm this from their location")

    # 2. Sybil Checker (Device ID Binding)
    # If the device that submitted the report tries to verify it (even with diff account) -> BLOCK
    if x_device_id and report.device_id and x_device_id == report.device_id:
        raise HTTPException(status_code=400, detail="Security Alert: You cannot verify a report from the same device used to submit it.")

    # 3. Double-Voting Checker
    # Check if this User OR this Device has already verified this report
    query = db.query(models.ReportVerification).filter(models.ReportVerification.report_id == report.id)
    if x_device_id:
        query = query.filter((models.ReportVerification.user_id == current_user.id) | (models.ReportVerification.device_id == x_device_id))
    else:
        query = query.filter(models.ReportVerification.user_id == current_user.id)
        
    existing_vote = query.first()
    if existing_vote:
        raise HTTPException(status_code=400, detail="You have already verified this report.")

    if report.status == "verified" or report.status == "resolved":
        raise HTTPException(status_code=400, detail="Report is already verified")

    # Record the verification logic attempt
    # Coordinator Logic: Instant Verify, No location needed
    if current_user.role == "coordinator" or current_user.role == "admin":
        report.status = "verified"
        report.is_verified = True
        report.verification_count += 3 # Boost count
        
        # Trigger X Alert if auto-post enabled
        if get_auto_post_x(db):
            trigger_x_alert(report)
        
        # Award points
        current_user.civic_points += 2
        reporter = db.query(models.User).filter(models.User.id == report.reporter_id).first()
        if reporter:
             reporter.civic_points += 10
             
        # Log Verification
        new_verify = models.ReportVerification(report_id=report.id, user_id=current_user.id, device_id=x_device_id)
        db.add(new_verify)
             
        db.commit()
        db.refresh(report)
        return report

    # Citizen Logic: Proximity Check required
    if not verify_data.lat or not verify_data.lng:
        raise HTTPException(status_code=400, detail="GPS location required for citizen verification")
        
    dist = calculate_distance(verify_data.lat, verify_data.lng, report.lat, report.lng)
    
    max_radius = get_proximity_radius(db)
    
    if dist > max_radius:
        raise HTTPException(status_code=400, detail=f"You are too far away ({dist:.2f}km). Max allowed: {max_radius}km")

    # Increment verification count
    report.verification_count += 1
    
    # Log Verification
    new_verify = models.ReportVerification(report_id=report.id, user_id=current_user.id, device_id=x_device_id)
    db.add(new_verify)
    
    # Dynamic Severity Increase
    # Mechanism: For every 5 verifications, increase severity by 1, up to max 5
    # This crowdsources urgency
    if report.verification_count % 5 == 0 and report.severity_level < 5:
        report.severity_level += 1
        
    # Auto-verify threshold logic
    if report.verification_count >= 3:
        report.status = "verified"
        report.is_verified = True
        
        # Trigger X Alert
        trigger_x_alert(report)
        
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
    
    max_radius = get_proximity_radius(db)
    
    if dist > max_radius:
        raise HTTPException(status_code=400, detail=f"Too far away ({dist:.2f}km). Max allowed: {max_radius}km")

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
        
        # Trigger X Alert if auto-post enabled
        if get_auto_post_x(db):
            trigger_x_alert(report)

        db.commit()
        db.refresh(report)
        return report

    raise HTTPException(status_code=400, detail="Report validation logic unhandled")

# --- System Settings & Admin ---

class SystemSettingSchema(BaseModel):
    key: str
    value: str
    description: Optional[str] = None

@app.get("/admin/settings", response_model=List[SystemSettingSchema])
def get_system_settings(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    settings = db.query(models.SystemSetting).all()
    # Ensure default exists if not found
    if not any(s.key == "proximity_radius_km" for s in settings):
        default_prox = models.SystemSetting(key="proximity_radius_km", value="0.5", description="Max radius (km) for verification")
        db.add(default_prox)
        db.commit()
        settings.append(default_prox)
        
    if not any(s.key == "auto_post_x" for s in settings):
        default_auto = models.SystemSetting(key="auto_post_x", value="false", description="Auto-post verified reports to X")
        db.add(default_auto)
        db.commit()
        settings.append(default_auto)
        
    return settings

@app.post("/admin/settings", response_model=SystemSettingSchema)
def update_system_setting(
    setting: SystemSettingSchema,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
        
    db_setting = db.query(models.SystemSetting).filter(models.SystemSetting.key == setting.key).first()
    if not db_setting:
        db_setting = models.SystemSetting(key=setting.key, value=setting.value, description=setting.description)
        db.add(db_setting)
    else:
        db_setting.value = setting.value
        if setting.description:
            db_setting.description = setting.description
            
    db.commit()
    db.refresh(db_setting)
    return db_setting

def get_proximity_radius(db: Session) -> float:
    setting = db.query(models.SystemSetting).filter(models.SystemSetting.key == "proximity_radius_km").first()
    if setting:
        try:
            return float(setting.value)
        except:
            return 0.5
    return 0.5

def get_auto_post_x(db: Session) -> bool:
    setting = db.query(models.SystemSetting).filter(models.SystemSetting.key == "auto_post_x").first()
    if setting:
        return setting.value.lower() == "true"
    return False

# --- Integrations ---
import tweepy

def get_twitter_client():
    api_key = os.getenv("TWITTER_API_KEY")
    api_secret = os.getenv("TWITTER_API_SECRET")
    access_token = os.getenv("TWITTER_ACCESS_TOKEN")
    access_secret = os.getenv("TWITTER_ACCESS_SECRET")
    
    if not all([api_key, api_secret, access_token, access_secret]):
        print("TWITTER: Missing credentials")
        return None

    try:
        client = tweepy.Client(
            consumer_key=api_key,
            consumer_secret=api_secret,
            access_token=access_token,
            access_token_secret=access_secret
        )
        return client
    except Exception as e:
        print(f"TWITTER: Client init failed - {e}")
        return None

def format_tweet(report: models.Report) -> str:
    status_emoji = "🚧"
    if report.status == "resolved": status_emoji = "✅"
    elif report.status == "verified": status_emoji = "⚠️"
    
    tweet = f"{status_emoji} Road Hazard Alert!\n\n"
    tweet += f"📍 {report.address[:40]}...\n"
    tweet += f"🏙️ {report.state} ({report.jurisdiction})\n"
    tweet += f"⚠️ Severity: {report.severity_level}/5\n"
    tweet += f"ℹ️ {report.title}\n"
    tweet += f"🔗 View Report: https://watchway.ng/report/{report.id}\n\n"
    tweet += f"#WatchWay #{report.state.replace(' ', '')} #RoadSafety"
    return tweet

def trigger_x_alert(report: models.Report):
    client = get_twitter_client()
    if not client:
        # Fallback to mock if no creds
        post_id = f"mock_x_{secrets.token_hex(4)}"
        print(f"TRIGGER_X_ALERT (Mock): {format_tweet(report)}")
        report.x_post_id = post_id
        return

    try:
        tweet_text = format_tweet(report)
        response = client.create_tweet(text=tweet_text)
        post_id = response.data['id']
        print(f"TRIGGER_X_ALERT: Posted {post_id}")
        report.x_post_id = post_id
    except Exception as e:
        print(f"TRIGGER_X_ALERT: Failed to post - {e}")

@app.post("/reports/{report_id}/x-post")
def manual_trigger_x_post(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
        
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    client = get_twitter_client()
    if not client:
        # Mock Post
        report.x_post_id = f"mock_x_{secrets.token_hex(4)}"
        print(f"MANUAL_X_POST (Mock): {format_tweet(report)}")
        db.commit()
        return {"message": "Posted to X (Mock)", "x_post_id": report.x_post_id}

    try:
        tweet_text = format_tweet(report)
        response = client.create_tweet(text=tweet_text)
        post_id = response.data['id']
        report.x_post_id = post_id
        db.commit()
        return {"message": "Posted to X", "x_post_id": post_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to post to X: {str(e)}")

@app.get("/admin/analytics", dependencies=[Depends(get_db)])
def get_analytics(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
        
    # 1. Status Distribution
    status_counts = db.query(models.Report.status, func.count(models.Report.id)).group_by(models.Report.status).all()
    status_data = [{"name": s[0], "value": s[1]} for s in status_counts]
    
    # 2. Jurisdiction Distribution
    jur_counts = db.query(models.Report.jurisdiction, func.count(models.Report.id)).group_by(models.Report.jurisdiction).all()
    jur_data = [{"name": j[0], "value": j[1]} for j in jur_counts]
    
    # 3. Growth (Mocked for now as SQLite date truncate is tricky/verbose, in Prod use Postgres date_trunc)
    # In a real app we'd do a daily query. For now, let's return some mock trend data based on actual counts
    # total_users = db.query(models.User).count()
    # total_reports = db.query(models.Report).count()
    
    # Mock last 7 days
    growth_data = [
        {"date": "Day 1", "users": 10, "reports": 5},
        {"date": "Day 2", "users": 15, "reports": 8},
        {"date": "Day 3", "users": 22, "reports": 15},
        {"date": "Day 4", "users": 30, "reports": 25},
        {"date": "Day 5", "users": 35, "reports": 40},
        {"date": "Day 6", "users": 42, "reports": 55},
        {"date": "Today", "users": db.query(models.User).count(), "reports": db.query(models.Report).count()},
    ]
    
    return {
        "status": status_data,
        "distribution": jur_data,
        "growth": growth_data
    }

# --- Admin Endpoints ---

@app.get("/users/", response_model=List[schemas.User])
def read_users(
    skip: int = 0, 
    limit: int = 100, 
    role: Optional[str] = None,
    sort_by: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    query = db.query(models.User)
    
    if role and role != "all":
        query = query.filter(models.User.role == role)
        
    if sort_by == "civic_points":
        query = query.order_by(models.User.civic_points.desc())
    else:
        query = query.order_by(models.User.id.asc())
        
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

@app.get("/admin/stats")
def get_admin_stats(
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(auth.get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    total_users = db.query(models.User).count()
    total_reports = db.query(models.Report).count()
    active_hazards = db.query(models.Report).filter(models.Report.status != "resolved").count()
    pending_coordinators = db.query(models.User).filter(models.User.coordinator_application_status == "PENDING").count()
    
    recent_reports = db.query(models.Report).order_by(models.Report.created_at.desc()).limit(5).all()
    
    return {
        "total_users": total_users,
        "total_reports": total_reports,
        "active_hazards": active_hazards,
        "pending_coordinators": pending_coordinators,
        "recent_reports": recent_reports
    }
