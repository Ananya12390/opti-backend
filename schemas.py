from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

class RoleOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    permissions: List[str]
    class Config:
        from_attributes = True

class UserOut(BaseModel):
    id: int
    name: str
    email: str
    username: str
    is_active: bool
    avatar_url: Optional[str]
    role: RoleOut
    created_at: Optional[datetime]
    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    username: str
    password: str
    role_id: int

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserOut

class AssetOut(BaseModel):
    id: int
    name: str
    category: str
    serial_number: str
    status: str
    condition: str
    assigned_to: Optional[int]
    assignee: Optional[UserOut]
    purchase_date: Optional[str]
    notes: Optional[str]
    created_at: Optional[datetime]
    class Config:
        from_attributes = True

class AssetCreate(BaseModel):
    name: str
    category: str
    serial_number: str
    status: str = "available"
    condition: str = "good"
    assigned_to: Optional[int] = None
    purchase_date: Optional[str] = None
    notes: Optional[str] = None

class AssetUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    status: Optional[str] = None
    condition: Optional[str] = None
    assigned_to: Optional[int] = None
    notes: Optional[str] = None
