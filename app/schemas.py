from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class ScanRequest(BaseModel):
    network: str

class ScanResult(BaseModel):
    scan_id: str
    network: str
    status: str
    results: Optional[Dict[str, Any]] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True 