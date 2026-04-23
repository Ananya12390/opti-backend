from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from contextlib import asynccontextmanager
from database import engine, Base, get_db
from sqlalchemy.orm import Session
import models, schemas, auth

# ── Lifespan ─────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title="VaultGuard API",
    version="1.0.0",
    lifespan=lifespan
)

# ── ✅ FIXED CORS ─────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 🔥 allow all (fixes Vercel issue)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth ─────────────────────────────
@app.post("/auth/login", response_model=schemas.TokenResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = auth.create_access_token({"sub": str(user.id)})

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": schemas.UserOut.from_orm(user)
    }

@app.get("/auth/me", response_model=schemas.UserOut)
def get_me(current_user=Depends(auth.get_current_user)):
    return current_user

# ── Users ────────────────────────────
@app.get("/users", response_model=list[schemas.UserOut])
def list_users(
    db: Session = Depends(get_db),
    _=Depends(auth.RequirePrivilege("view:all_users"))
):
    return db.query(models.User).all()

@app.post("/users", response_model=schemas.UserOut)
def create_user(
    payload: schemas.UserCreate,
    db: Session = Depends(get_db),
    _=Depends(auth.RequirePrivilege("manage:users"))
):
    return auth.create_user(db, payload)

@app.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    _=Depends(auth.RequirePrivilege("manage:users"))
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    db.delete(user)
    db.commit()

# ── Assets ───────────────────────────
@app.get("/assets", response_model=list[schemas.AssetOut])
def list_assets(
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user)
):
    if auth.user_has_privilege(current_user, "view:all_assets"):
        return db.query(models.Asset).all()

    return db.query(models.Asset).filter(
        models.Asset.assigned_to == current_user.id
    ).all()
