# VaultGuard Backend — FastAPI + RBAC

## Quick Start

```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

API docs: http://localhost:8000/docs

## Demo Accounts

| Username | Password    | Role     |
|----------|-------------|----------|
| admin    | admin123    | Admin    |
| manager  | manager123  | Manager  |
| ben      | ben123      | Employee |
| priya    | priya123    | Employee |

## RBAC Architecture

Roles have a `permissions` JSON array of privilege strings. The `RequirePrivilege` dependency checks them:

```python
@app.delete("/assets/{asset_id}")
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    _=Depends(auth.RequirePrivilege("delete:asset"))  # ← RBAC gate
):
    ...
```

### Permissions by Role

| Permission        | Admin | Manager | Employee |
|-------------------|-------|---------|----------|
| view:all_users    | ✅    | ✅      | ❌       |
| manage:users      | ✅    | ❌      | ❌       |
| view:all_assets   | ✅    | ✅      | ❌       |
| manage:inventory  | ✅    | ✅      | ❌       |
| delete:asset      | ✅    | ❌      | ❌       |
| view:reports      | ✅    | ✅      | ❌       |
| manage:settings   | ✅    | ❌      | ❌       |
| view:my_gear      | ✅    | ✅      | ✅       |
