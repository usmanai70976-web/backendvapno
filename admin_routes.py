from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import uuid
from motor.motor_asyncio import AsyncIOMotorClient
import os

# Admin Router
admin_router = APIRouter(prefix="/api/admin")

# Security
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ADMIN_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ==================== MODELS ====================

# Admin User Models
class AdminUser(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    password_hash: str
    role: str = "super_admin"
    is_active: bool = True
    last_login: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AdminLogin(BaseModel):
    email: EmailStr
    password: str

class AdminResponse(BaseModel):
    id: str
    email: str
    role: str
    is_active: bool
    last_login: Optional[datetime]

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    admin: AdminResponse

# Server Models
class ServerUpdate(BaseModel):
    name: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    public_key: Optional[str] = None
    protocol: Optional[str] = None
    capacity: Optional[int] = None
    is_premium: Optional[bool] = None
    is_active: Optional[bool] = None

# AdMob Config Models
class AdMobConfig(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    app_id: str
    banner_unit_id: str
    interstitial_unit_id: str
    rewarded_unit_id: Optional[str] = None
    test_mode: bool = True
    banner_enabled: bool = True
    banner_position: str = "bottom"  # "top" or "bottom"
    interstitial_enabled: bool = True
    interstitial_cooldown_minutes: int = 5
    banner_refresh_seconds: int = 30
    max_ads_per_session: int = 5
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class AdMobConfigUpdate(BaseModel):
    app_id: Optional[str] = None
    banner_unit_id: Optional[str] = None
    interstitial_unit_id: Optional[str] = None
    rewarded_unit_id: Optional[str] = None
    test_mode: Optional[bool] = None
    banner_enabled: Optional[bool] = None
    banner_position: Optional[str] = None
    interstitial_enabled: Optional[bool] = None
    interstitial_cooldown_minutes: Optional[int] = None
    banner_refresh_seconds: Optional[int] = None
    max_ads_per_session: Optional[int] = None

# App Settings Models
class AppSettings(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    app_name: str = "VPN Shield"
    app_version: str = "1.0.0"
    force_update: bool = False
    minimum_version: str = "1.0.0"
    maintenance_mode: bool = False
    maintenance_message: str = "App is under maintenance. Please try again later."
    
    # Feature flags
    kill_switch_enabled: bool = True
    split_tunneling_enabled: bool = False
    
    # Premium settings
    monthly_price: str = "$9.99"
    yearly_price: str = "$79.99"
    yearly_discount: str = "33%"
    trial_enabled: bool = False
    trial_days: int = 7
    
    # Free user limits
    free_bandwidth_limit_enabled: bool = False
    free_daily_limit_mb: int = 1024  # 1GB
    free_monthly_limit_mb: int = 10240  # 10GB
    speed_throttling_enabled: bool = False
    free_max_speed_mbps: int = 10
    
    # Connection settings
    auto_connect: bool = True
    auto_reconnect: bool = True
    connection_timeout_seconds: int = 30
    keep_alive_interval_seconds: int = 25
    
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class AppSettingsUpdate(BaseModel):
    app_name: Optional[str] = None
    app_version: Optional[str] = None
    force_update: Optional[bool] = None
    minimum_version: Optional[str] = None
    maintenance_mode: Optional[bool] = None
    maintenance_message: Optional[str] = None
    kill_switch_enabled: Optional[bool] = None
    split_tunneling_enabled: Optional[bool] = None
    monthly_price: Optional[str] = None
    yearly_price: Optional[str] = None
    yearly_discount: Optional[str] = None
    trial_enabled: Optional[bool] = None
    trial_days: Optional[int] = None
    free_bandwidth_limit_enabled: Optional[bool] = None
    free_daily_limit_mb: Optional[int] = None
    free_monthly_limit_mb: Optional[int] = None
    speed_throttling_enabled: Optional[bool] = None
    free_max_speed_mbps: Optional[int] = None
    auto_connect: Optional[bool] = None
    auto_reconnect: Optional[bool] = None
    connection_timeout_seconds: Optional[int] = None
    keep_alive_interval_seconds: Optional[int] = None

# ==================== HELPER FUNCTIONS ====================

def get_db():
    mongo_url = os.environ['MONGO_URL']
    client = AsyncIOMotorClient(mongo_url)
    return client[os.environ['DB_NAME']]

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_admin_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ADMIN_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "admin"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        if payload.get("type") != "admin":
            raise HTTPException(status_code=403, detail="Not an admin token")
        
        admin_id: str = payload.get("sub")
        if admin_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    
    db = get_db()
    admin = await db.admin_users.find_one({"id": admin_id})
    if admin is None or not admin.get("is_active"):
        raise HTTPException(status_code=401, detail="Admin not found or inactive")
    
    return AdminResponse(**admin)

# ==================== ADMIN AUTH ROUTES ====================

@admin_router.post("/auth/login", response_model=TokenResponse)
async def admin_login(login_data: AdminLogin):
    db = get_db()
    admin = await db.admin_users.find_one({"email": login_data.email})
    
    if not admin or not verify_password(login_data.password, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    if not admin.get("is_active"):
        raise HTTPException(status_code=403, detail="Admin account is inactive")
    
    # Update last login
    await db.admin_users.update_one(
        {"id": admin["id"]},
        {"$set": {"last_login": datetime.utcnow()}}
    )
    
    access_token = create_admin_token(data={"sub": admin["id"]})
    admin_response = AdminResponse(**admin)
    
    return TokenResponse(access_token=access_token, admin=admin_response)

@admin_router.get("/auth/me", response_model=AdminResponse)
async def get_current_admin_info(current_admin: AdminResponse = Depends(get_current_admin)):
    return current_admin

@admin_router.post("/auth/init")
async def initialize_admin():
    """Create initial super admin if none exists"""
    db = get_db()
    existing_admin = await db.admin_users.find_one({})
    
    if existing_admin:
        return {"message": "Admin already exists"}
    
    # Create default admin
    admin = AdminUser(
        email="admin@vpnshield.com",
        password_hash=get_password_hash("admin123"),
        role="super_admin"
    )
    
    await db.admin_users.insert_one(admin.dict())
    
    return {
        "message": "Super admin created successfully",
        "email": "admin@vpnshield.com",
        "password": "admin123",
        "warning": "Please change the password immediately!"
    }

# ==================== DASHBOARD ROUTES ====================

@admin_router.get("/dashboard/stats")
async def get_dashboard_stats(current_admin: AdminResponse = Depends(get_current_admin)):
    db = get_db()
    
    # Get counts
    total_servers = await db.servers.count_documents({})
    active_servers = await db.servers.count_documents({"is_active": True})
    premium_servers = await db.servers.count_documents({"is_premium": True})
    
    # Get active connections
    active_connections = await db.connections.count_documents({"is_active": True})
    
    # Get today's connections
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_connections = await db.connections.count_documents({
        "started_at": {"$gte": today_start}
    })
    
    # Calculate average server load
    servers = await db.servers.find({"is_active": True}).to_list(100)
    avg_load = 0
    if servers:
        total_load = sum(s.get("current_load", 0) / s.get("capacity", 1) * 100 for s in servers)
        avg_load = int(total_load / len(servers))
    
    # Get user counts (if tracking)
    total_users = await db.users.count_documents({})
    premium_users = await db.users.count_documents({"is_premium": True})
    
    return {
        "servers": {
            "total": total_servers,
            "active": active_servers,
            "premium": premium_servers
        },
        "connections": {
            "active": active_connections,
            "today": today_connections
        },
        "users": {
            "total": total_users,
            "premium": premium_users,
            "free": total_users - premium_users,
            "premium_percentage": round(premium_users / total_users * 100, 1) if total_users > 0 else 0
        },
        "performance": {
            "avg_server_load": avg_load
        }
    }

@admin_router.get("/dashboard/recent-activity")
async def get_recent_activity(current_admin: AdminResponse = Depends(get_current_admin), limit: int = 10):
    db = get_db()
    
    # Get recent connections
    recent_connections = await db.connections.find().sort("started_at", -1).limit(limit).to_list(limit)
    
    activities = []
    for conn in recent_connections:
        server = await db.servers.find_one({"id": conn["server_id"]})
        server_name = server["name"] if server else "Unknown Server"
        
        activities.append({
            "type": "connection",
            "message": f"User connected to {server_name}",
            "timestamp": conn["started_at"],
            "status": "active" if conn.get("is_active") else "ended"
        })
    
    return activities

# ==================== SERVER MANAGEMENT ROUTES ====================

@admin_router.get("/servers")
async def get_all_servers(current_admin: AdminResponse = Depends(get_current_admin)):
    db = get_db()
    servers = await db.servers.find().sort("created_at", -1).to_list(100)
    
    # Calculate load percentage for each
    for server in servers:
        server["load_percentage"] = int((server.get("current_load", 0) / server.get("capacity", 1)) * 100)
    
    return servers

@admin_router.post("/servers")
async def create_server(server_data: dict, current_admin: AdminResponse = Depends(get_current_admin)):
    db = get_db()
    
    from datetime import datetime
    import uuid
    
    server = {
        "id": str(uuid.uuid4()),
        "name": server_data["name"],
        "country": server_data["country"],
        "country_code": server_data["country_code"],
        "city": server_data["city"],
        "ip_address": server_data["ip_address"],
        "port": server_data.get("port", 51820),
        "public_key": server_data["public_key"],
        "protocol": server_data.get("protocol", "WireGuard"),
        "capacity": server_data.get("capacity", 100),
        "current_load": 0,
        "ping": server_data.get("ping", 0),
        "is_premium": server_data.get("is_premium", False),
        "is_active": server_data.get("is_active", True),
        "created_at": datetime.utcnow()
    }
    
    await db.servers.insert_one(server)
    
    return {"message": "Server created successfully", "server": server}

@admin_router.put("/servers/{server_id}")
async def update_server(server_id: str, server_data: ServerUpdate, current_admin: AdminResponse = Depends(get_current_admin)):
    db = get_db()
    
    # Find server
    server = await db.servers.find_one({"id": server_id})
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    # Update fields
    update_data = {k: v for k, v in server_data.dict().items() if v is not None}
    
    if update_data:
        await db.servers.update_one(
            {"id": server_id},
            {"$set": update_data}
        )
    
    updated_server = await db.servers.find_one({"id": server_id})
    return {"message": "Server updated successfully", "server": updated_server}

@admin_router.delete("/servers/{server_id}")
async def delete_server(server_id: str, current_admin: AdminResponse = Depends(get_current_admin)):
    db = get_db()
    
    result = await db.servers.delete_one({"id": server_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Server not found")
    
    return {"message": "Server deleted successfully"}

@admin_router.patch("/servers/{server_id}/toggle")
async def toggle_server_status(server_id: str, current_admin: AdminResponse = Depends(get_current_admin)):
    db = get_db()
    
    server = await db.servers.find_one({"id": server_id})
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    new_status = not server.get("is_active", True)
    
    await db.servers.update_one(
        {"id": server_id},
        {"$set": {"is_active": new_status}}
    )
    
    return {"message": f"Server {'activated' if new_status else 'deactivated'}", "is_active": new_status}

# ==================== ADMOB CONFIG ROUTES ====================

@admin_router.get("/admob")
async def get_admob_config(current_admin: AdminResponse = Depends(get_current_admin)):
    db = get_db()
    config = await db.admob_config.find_one()
    
    if not config:
        # Return default config
        return {
            "app_id": "",
            "banner_unit_id": "",
            "interstitial_unit_id": "",
            "rewarded_unit_id": "",
            "test_mode": True,
            "banner_enabled": True,
            "banner_position": "bottom",
            "interstitial_enabled": True,
            "interstitial_cooldown_minutes": 5,
            "banner_refresh_seconds": 30,
            "max_ads_per_session": 5
        }
    
    return config

@admin_router.put("/admob")
async def update_admob_config(config_data: AdMobConfigUpdate, current_admin: AdminResponse = Depends(get_current_admin)):
    db = get_db()
    
    existing_config = await db.admob_config.find_one()
    
    update_data = {k: v for k, v in config_data.dict().items() if v is not None}
    update_data["updated_at"] = datetime.utcnow()
    
    if existing_config:
        await db.admob_config.update_one(
            {"id": existing_config["id"]},
            {"$set": update_data}
        )
    else:
        new_config = AdMobConfig(**update_data)
        await db.admob_config.insert_one(new_config.dict())
    
    updated_config = await db.admob_config.find_one()
    return {"message": "AdMob configuration updated successfully", "config": updated_config}

# ==================== APP SETTINGS ROUTES ====================

@admin_router.get("/settings")
async def get_app_settings(current_admin: AdminResponse = Depends(get_current_admin)):
    db = get_db()
    settings = await db.app_settings.find_one()
    
    if not settings:
        # Return default settings
        default_settings = AppSettings()
        await db.app_settings.insert_one(default_settings.dict())
        return default_settings.dict()
    
    return settings

@admin_router.put("/settings")
async def update_app_settings(settings_data: AppSettingsUpdate, current_admin: AdminResponse = Depends(get_current_admin)):
    db = get_db()
    
    existing_settings = await db.app_settings.find_one()
    
    update_data = {k: v for k, v in settings_data.dict().items() if v is not None}
    update_data["updated_at"] = datetime.utcnow()
    
    if existing_settings:
        await db.app_settings.update_one(
            {"id": existing_settings["id"]},
            {"$set": update_data}
        )
    else:
        new_settings = AppSettings(**update_data)
        await db.app_settings.insert_one(new_settings.dict())
    
    updated_settings = await db.app_settings.find_one()
    return {"message": "App settings updated successfully", "settings": updated_settings}

# ==================== ANALYTICS ROUTES ====================

@admin_router.get("/analytics/connections")
async def get_connection_analytics(current_admin: AdminResponse = Depends(get_current_admin), days: int = 7):
    db = get_db()
    
    # Get connections for last N days
    start_date = datetime.utcnow() - timedelta(days=days)
    connections = await db.connections.find({
        "started_at": {"$gte": start_date}
    }).to_list(1000)
    
    # Group by date
    daily_stats = {}
    for conn in connections:
        date_key = conn["started_at"].strftime("%Y-%m-%d")
        if date_key not in daily_stats:
            daily_stats[date_key] = {"date": date_key, "connections": 0, "total_duration": 0}
        
        daily_stats[date_key]["connections"] += 1
        if conn.get("duration_seconds"):
            daily_stats[date_key]["total_duration"] += conn["duration_seconds"]
    
    # Convert to list and sort
    chart_data = sorted(daily_stats.values(), key=lambda x: x["date"])
    
    # Calculate totals
    total_connections = len(connections)
    avg_duration = sum(c.get("duration_seconds", 0) for c in connections) / len(connections) if connections else 0
    
    return {
        "chart_data": chart_data,
        "total_connections": total_connections,
        "avg_duration_seconds": int(avg_duration)
    }

@admin_router.get("/analytics/servers")
async def get_server_analytics(current_admin: AdminResponse = Depends(get_current_admin)):
    db = get_db()
    
    servers = await db.servers.find({"is_active": True}).to_list(100)
    
    server_stats = []
    for server in servers:
        # Get connection count for this server
        conn_count = await db.connections.count_documents({"server_id": server["id"]})
        
        load_percentage = int((server.get("current_load", 0) / server.get("capacity", 1)) * 100)
        
        server_stats.append({
            "name": server["name"],
            "country": server["country"],
            "connections": conn_count,
            "load_percentage": load_percentage,
            "is_premium": server.get("is_premium", False)
        })
    
    # Sort by connections
    server_stats.sort(key=lambda x: x["connections"], reverse=True)
    
    return server_stats

@admin_router.get("/analytics/users")
async def get_user_analytics(current_admin: AdminResponse = Depends(get_current_admin), days: int = 30):
    db = get_db()
    
    # Get user counts
    total_users = await db.users.count_documents({})
    premium_users = await db.users.count_documents({"is_premium": True})
    free_users = total_users - premium_users
    
    # Get new users over time
    start_date = datetime.utcnow() - timedelta(days=days)
    users = await db.users.find({
        "created_at": {"$gte": start_date}
    }).to_list(10000)
    
    # Group by date
    daily_users = {}
    for user in users:
        date_key = user["created_at"].strftime("%Y-%m-%d")
        if date_key not in daily_users:
            daily_users[date_key] = {"date": date_key, "new_users": 0}
        daily_users[date_key]["new_users"] += 1
    
    chart_data = sorted(daily_users.values(), key=lambda x: x["date"])
    
    return {
        "total_users": total_users,
        "premium_users": premium_users,
        "free_users": free_users,
        "conversion_rate": round(premium_users / total_users * 100, 2) if total_users > 0 else 0,
        "chart_data": chart_data
    }
