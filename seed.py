from sqlalchemy.orm import Session
import models
from auth import hash_password

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

def seed_database(db: Session):
    # ✅ FIX: Check USERS instead of roles
    if db.query(models.User).count() > 0:
        return  # already seeded

    # ── Roles ─────────────────────────────
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
    db.flush()  # get IDs

    # ── Users ─────────────────────────────
    users = [
        models.User(
            name="Ananya",
            email="admin@vaultguard.io",
            username="admin",
            hashed_password=hash_password("admin123"),
            role_id=admin_role.id,
            avatar_url="https://api.dicebear.com/7.x/avataaars/svg?seed=Aalishan"
        ),
        models.User(
            name="Sarah",
            email="manager@vaultguard.io",
            username="manager",
            hashed_password=hash_password("manager123"),
            role_id=manager_role.id,
            avatar_url="https://api.dicebear.com/7.x/avataaars/svg?seed=Sarah"
        ),
        models.User(
            name="Ben",
            email="ben@vaultguard.io",
            username="ben",
            hashed_password=hash_password("ben123"),
            role_id=employee_role.id,
            avatar_url="https://api.dicebear.com/7.x/avataaars/svg?seed=Ben"
        ),
        models.User(
            name="Priya",
            email="priya@vaultguard.io",
            username="priya",
            hashed_password=hash_password("priya123"),
            role_id=employee_role.id,
            avatar_url="https://api.dicebear.com/7.x/avataaars/svg?seed=Priya"
        ),
        models.User(
            name="James",
            email="james@vaultguard.io",
            username="james",
            hashed_password=hash_password("james123"),
            role_id=employee_role.id,
            avatar_url="https://api.dicebear.com/7.x/avataaars/svg?seed=James"
        ),
    ]

    db.add_all(users)
    db.flush()

    ben = users[2]
    priya = users[3]
    james = users[4]

    # ── Assets ─────────────────────────────
    assets = [
        models.Asset(
            name="MacBook Pro 16\"",
            category="Laptop",
            serial_number="MBP-2024-001",
            status="assigned",
            condition="new",
            assigned_to=ben.id,
            purchase_date="2024-01-15"
        ),
        models.Asset(
            name="MacBook Air M2",
            category="Laptop",
            serial_number="MBA-2023-002",
            status="assigned",
            condition="good",
            assigned_to=priya.id,
            purchase_date="2023-09-10"
        ),
        models.Asset(
            name="Dell XPS 15",
            category="Laptop",
            serial_number="DEL-2023-003",
            status="assigned",
            condition="good",
            assigned_to=james.id,
            purchase_date="2023-06-20"
        ),
        models.Asset(
            name="iPhone 15 Pro",
            category="Phone",
            serial_number="IPH-2024-001",
            status="assigned",
            condition="new",
            assigned_to=ben.id,
            purchase_date="2024-02-01"
        ),
        models.Asset(
            name="Samsung Galaxy S24",
            category="Phone",
            serial_number="SAM-2024-002",
            status="available",
            condition="new",
            purchase_date="2024-03-01"
        ),
    ]

    db.add_all(assets)
    db.commit()

    print("✅ Database seeded successfully")
