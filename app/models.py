from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    scans = relationship("Scan", back_populates="user")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    network = Column(String)
    status = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    results = Column(JSON, nullable=True)
    user = relationship("User", back_populates="scans") 