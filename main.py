from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from contextlib import asynccontextmanager
from database import engine, Base, get_db
from sqlalchemy.orm import Session
import models, schemas, auth, seed

# ── Lifespan (DB init + seeding) ─────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = next(get_db())
    seed.seed_database(db)
    yield

# ── App Init ─────────────────────────────────────────────────
app = FastAPI(
    title="VaultGuard API",
    description="RBAC-powered Asset Management System",
    version="1.0.0",
    lifespan=lifespan
)

# ── ✅ FIXED CORS (IMPORTANT) ─────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # local
        "https://opti-frontend-23zw-c733vcu77-ananyacs2703-4453s-projects.vercel.app"  # deployed frontend
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth routes ──────────────────────────────────────────────
@app.post("/auth/login", response_model=schemas.TokenResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    token = auth.create_access_token({"sub": str(user.id)})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": schemas.UserOut.from_orm(user)
    }

@app.get("/auth/me", response_model=schemas.UserOut)
def get_me(current_user=Depends(auth.get_current_user)):
    return current_user

# ── Users routes ─────────────────────────────────────────────
@app.get("/users", response_model=list[schemas.UserOut])
def list_users(
    db: Session = Depends(get_db),
    _=Depends(auth.RequirePrivilege("view:all_users"))
):
    return db.query(models.User).all()

@app.post("/users", response_model=schemas.UserOut, status_code=201)
def create_user(
    payload: schemas.UserCreate,
    db: Session = Depends(get_db),
    _=Depends(auth.RequirePrivilege("manage:users"))
):
    return auth.create_user(db, payload)

@app.delete("/users/{user_id}", status_code=204)
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

# ── Assets routes ─────────────────────────────────────────────
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

@app.get("/assets/{asset_id}", response_model=schemas.AssetOut)
def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user)
):
    asset = db.query(models.Asset).filter(
        models.Asset.id == asset_id
    ).first()

    if not asset:
        raise HTTPException(404, "Asset not found")

    if not auth.user_has_privilege(current_user, "view:all_assets") and asset.assigned_to != current_user.id:
        raise HTTPException(403, "Access denied")

    return asset

@app.post("/assets", response_model=schemas.AssetOut, status_code=201)
def create_asset(
    payload: schemas.AssetCreate,
    db: Session = Depends(get_db),
    _=Depends(auth.RequirePrivilege("manage:inventory"))
):
    asset = models.Asset(**payload.dict())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset

@app.put("/assets/{asset_id}", response_model=schemas.AssetOut)
def update_asset(
    asset_id: int,
    payload: schemas.AssetUpdate,
    db: Session = Depends(get_db),
    _=Depends(auth.RequirePrivilege("manage:inventory"))
):
    asset = db.query(models.Asset).filter(
        models.Asset.id == asset_id
    ).first()

    if not asset:
        raise HTTPException(404, "Asset not found")

    for k, v in payload.dict(exclude_unset=True).items():
        setattr(asset, k, v)

    db.commit()
    db.refresh(asset)
    return asset

@app.delete("/assets/{asset_id}", status_code=204)
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    _=Depends(auth.RequirePrivilege("delete:asset"))
):
    asset = db.query(models.Asset).filter(
        models.Asset.id == asset_id
    ).first()

    if not asset:
        raise HTTPException(404, "Asset not found")

    db.delete(asset)
    db.commit()

# ── Roles ────────────────────────────────────────────────────
@app.get("/roles", response_model=list[schemas.RoleOut])
def list_roles(
    db: Session = Depends(get_db),
    _=Depends(auth.RequirePrivilege("view:all_users"))
):
    return db.query(models.Role).all()

# ── Stats ────────────────────────────────────────────────────
@app.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    _=Depends(auth.RequirePrivilege("view:all_assets"))
):
    total_assets = db.query(models.Asset).count()
    total_users = db.query(models.User).count()
    assigned = db.query(models.Asset).filter(
        models.Asset.assigned_to != None
    ).count()
    unassigned = total_assets - assigned

    by_category = {}
    for a in db.query(models.Asset).all():
        by_category[a.category] = by_category.get(a.category, 0) + 1

    return {
        "total_assets": total_assets,
        "total_users": total_users,
        "assigned_assets": assigned,
        "unassigned_assets": unassigned,
        "by_category": by_category,
    }
