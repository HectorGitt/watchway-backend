from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserBase(BaseModel):
    email: str
    username: Optional[str] = None

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    username: Optional[str] = None

class User(UserBase):
    id: int
    is_active: bool
    is_verified: bool
    is_suspended: bool = False
    coordinator_application_status: str
    role: str
    state_assigned: Optional[str] = None
    civic_points: int
    reports: List["Report"] = []

    class Config:
        from_attributes = True

class ReportBase(BaseModel):
    title: str
    description: str
    lat: float
    lng: float
    address: str
    state: str
    live_image_url: str
    after_image_url: Optional[str] = None

class ReportCreate(ReportBase):
    severity_level: Optional[int] = 5

class Report(ReportBase):
    id: str
    jurisdiction: str
    status: str
    severity_level: int
    verification_count: int
    
    created_at: datetime
    reporter_id: int
    x_post_id: Optional[str] = None

    class Config:
        from_attributes = True

User.update_forward_refs()
