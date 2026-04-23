from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware


from database import engine, Base, get_db
import models, schemas, auth

# ─────────────────────────────────────────────
# DB INIT
# ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title="VaultGuard API",
    version="1.0.0",
    lifespan=lifespan
)

# ─────────────────────────────────────────────
# CORS (PRODUCTION FIXED)
# ─────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://opti-frontend-o12t-qy5f55bcc-ananyacs2703-4453s-projects.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────
@app.get("/")
def root():
    return {"message": "VaultGuard API running 🚀"}

# ─────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────
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

# ─────────────────────────────────────────────
# USERS
# ─────────────────────────────────────────────
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
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()

# ─────────────────────────────────────────────
# ASSETS
# ─────────────────────────────────────────────
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
