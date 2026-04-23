from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, JSON, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String)
    permissions = Column(JSON, default=[])  # list of permission strings
    users = relationship("User", back_populates="role")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    avatar_url = Column(String, nullable=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    role = relationship("Role", back_populates="users")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    assets = relationship("Asset", back_populates="assignee", foreign_keys="Asset.assigned_to")

class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    category = Column(String, nullable=False)  # Laptop, Phone, Monitor, Peripheral
    serial_number = Column(String, unique=True, nullable=False)
    status = Column(String, default="available")  # available, assigned, maintenance, retired
    condition = Column(String, default="good")  # new, good, fair, poor
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    assignee = relationship("User", back_populates="assets", foreign_keys=[assigned_to])
    purchase_date = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
