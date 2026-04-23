from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
import os

# ✅ Use environment variable (Render will provide this)
DATABASE_URL = os.getenv("DATABASE_URL")

# ✅ Fallback for local development
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./vaultguard.db"

# ✅ Fix for Supabase (Postgres SSL)
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    connect_args = {"sslmode": "require"}  # 🔥 IMPORTANT for Supabase

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
