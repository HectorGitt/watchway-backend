from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Float, DateTime
from sqlalchemy.orm import relationship
from database import Base
import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="citizen") # citizen, coordinator, admin
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_suspended = Column(Boolean, default=False) # Admin Ban
    
    # Coordinator Application
    coordinator_application_status = Column(String, default="NONE") # NONE, PENDING, APPROVED, REJECTED
    
    state_assigned = Column(String, nullable=True) # For coordinators
    civic_points = Column(Integer, default=0)

    reports = relationship("Report", back_populates="reporter")

class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    
    # Location
    lat = Column(Float)
    lng = Column(Float)
    address = Column(String)
    state = Column(String, index=True)
    
    jurisdiction = Column(String) # FEDERAL, STATE
    severity_level = Column(Integer)
    status = Column(String, default="unverified") # unverified, verified, fixed
    
    # Trust Protocol
    live_image_url = Column(String)
    after_image_url = Column(String, nullable=True)
    verification_count = Column(Integer, default=0)
    is_verified = Column(Boolean, default=False)
    
    # Social Media
    x_post_id = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    reporter_id = Column(Integer, ForeignKey("users.id"))

    reporter = relationship("User", back_populates="reports")

class SystemSetting(Base):
    __tablename__ = "system_settings"

    key = Column(String, primary_key=True, index=True)
    value = Column(String) # Stored as string, cast as needed
    description = Column(String, nullable=True)
