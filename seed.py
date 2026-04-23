from sqlalchemy.orm import Session
import models
from auth import hash_password
from datetime import date

# ── Permissions ───────────────────────
ADMIN_PERMISSIONS = [
    "view:all_users",
    "manage:users",
    "view:all_assets",
    "manage:inventory",
    "delete:asset",
    "view:reports",
    "manage:settings",
]

MANAGER_PERMISSIONS = [
    "view:all_users",
    "view:all_assets",
    "manage:inventory",
    "view:reports",
]

EMPLOYEE_PERMISSIONS = [
    "view:my_gear",
]

# ── Seed Function ─────────────────────
def seed_database(db: Session):
    # ✅ FIX 1: Prevent duplicate seeding
    if db.query(models.User).first():
        return

    # ── Roles ─────────────────────────
    admin_role = models.Role(
        name="Admin",
        description="Full system access",
        permissions=ADMIN_PERMISSIONS
    )
    manager_role = models.Role(
        name="Manager",
        description="Inventory oversight",
        permissions=MANAGER_PERMISSIONS
    )
    employee_role = models.Role(
        name="Employee",
        description="View own assets only",
        permissions=EMPLOYEE_PERMISSIONS
    )

    db.add_all([admin_role, manager_role, employee_role])
    db.commit()   # ✅ FIX 2: Commit to generate IDs
    db.refresh(admin_role)
    db.refresh(manager_role)
    db.refresh(employee_role)

    # ── Users ─────────────────────────
    users = [
        models.User(
            name="Admin User",
            email="admin@vaultguard.io",
            username="admin",
            hashed_password=hash_password("admin123"),
            role_id=admin_role.id,
            avatar_url="https://api.dicebear.com/7.x/avataaars/svg?seed=admin"
        ),
        models.User(
            name="Manager User",
            email="manager@vaultguard.io",
            username="manager",
            hashed_password=hash_password("manager123"),
            role_id=manager_role.id,
            avatar_url="https://api.dicebear.com/7.x/avataaars/svg?seed=manager"
        ),
        models.User(
            name="Ben",
            email="ben@vaultguard.io",
            username="ben",
            hashed_password=hash_password("ben123"),
            role_id=employee_role.id,
            avatar_url="https://api.dicebear.com/7.x/avataaars/svg?seed=ben"
        ),
    ]

    db.add_all(users)
    db.commit()   # ✅ FIX 3: Save users before using IDs
    for user in users:
        db.refresh(user)

    ben = users[2]

    # ── Assets ─────────────────────────
    assets = [
        models.Asset(
            name="MacBook Pro 16\"",
            category="Laptop",
            serial_number="MBP-2024-001",
            status="assigned",
            condition="new",
            assigned_to=ben.id,
            purchase_date=date(2024, 1, 15)   # ✅ FIX 4: Use proper date
        ),
        models.Asset(
            name="iPhone 15 Pro",
            category="Phone",
            serial_number="IPH-2024-001",
            status="assigned",
            condition="new",
            assigned_to=ben.id,
            purchase_date=date(2024, 2, 1)
        ),
    ]

    db.add_all(assets)
    db.commit()

    print("✅ Database seeded successfully")
