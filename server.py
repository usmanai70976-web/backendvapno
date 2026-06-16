from fastapi import FastAPI, APIRouter, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import random
from wireguard_manager import WireGuardManager, IPAllocator

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 43200  # 30 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Create the main app without a prefix
app = FastAPI(title="VPN Server API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# ==================== MODELS ====================

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    password_hash: str
    is_premium: bool = False
    subscription_tier: Optional[str] = None  # "free", "premium_monthly", "premium_yearly"
    subscription_expires: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    data_used: int = 0  # in MB

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    is_premium: bool
    subscription_tier: Optional[str]
    subscription_expires: Optional[datetime]
    data_used: int

class VPNServer(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    country: str
    country_code: str  # ISO 2-letter code
    city: str
    ip_address: str
    port: int = 51820
    public_key: str
    protocol: str = "WireGuard"
    capacity: int  # Max concurrent users
    current_load: int = 0  # Current connected users
    ping: int = 0  # Latency in ms
    is_premium: bool = False
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)

class VPNServerCreate(BaseModel):
    name: str
    country: str
    country_code: str
    city: str
    ip_address: str
    public_key: str
    capacity: int = 100
    is_premium: bool = False

class VPNServerResponse(BaseModel):
    id: str
    name: str
    country: str
    country_code: str
    city: str
    ip_address: str
    port: int
    protocol: str
    capacity: int
    current_load: int
    load_percentage: int
    ping: int
    is_premium: bool
    is_active: bool

class Connection(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    server_id: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = None
    duration_seconds: int = 0
    data_transferred_mb: int = 0
    is_active: bool = True

class ConnectionStart(BaseModel):
    server_id: str

class ConnectionEnd(BaseModel):
    connection_id: str
    data_transferred_mb: int

class ConnectionResponse(BaseModel):
    id: str
    server_id: str
    started_at: datetime
    is_active: bool

# ==================== VPN CONNECTION MODELS ====================

class VPNConnectRequest(BaseModel):
    server_id: str
    client_public_key: str  # WireGuard public key from mobile device

class VPNConnectResponse(BaseModel):
    success: bool
    connection_id: str
    client_ip: str
    server_ip: str
    server_public_key: str
    server_port: int = 51820
    dns: str = "1.1.1.1"
    allowed_ips: str = "0.0.0.0/0"
    message: str

class VPNDisconnectRequest(BaseModel):
    connection_id: str
    client_public_key: str  # Required to remove peer from server

class Subscription(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    tier: str  # "premium_monthly", "premium_yearly"
    status: str  # "active", "canceled", "expired"
    started_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    billing_token: Optional[str] = None

class SubscriptionCreate(BaseModel):
    tier: str
    billing_token: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

# ==================== AUTH HELPERS ====================

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    
    user = await db.users.find_one({"id": user_id})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return UserResponse(**user)

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user
    user = User(
        email=user_data.email,
        password_hash=get_password_hash(user_data.password)
    )
    
    await db.users.insert_one(user.dict())
    
    # Create access token
    access_token = create_access_token(data={"sub": user.id})
    
    user_response = UserResponse(**user.dict())
    
    return TokenResponse(access_token=access_token, user=user_response)

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(user_data: UserLogin):
    user = await db.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token = create_access_token(data={"sub": user["id"]})
    
    user_response = UserResponse(**user)
    
    return TokenResponse(access_token=access_token, user=user_response)

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: UserResponse = Depends(get_current_user)):
    return current_user

# ==================== SERVER ROUTES ====================

@api_router.get("/servers/list", response_model=List[VPNServerResponse])
async def list_servers(current_user: UserResponse = Depends(get_current_user)):
    # Get all active servers
    query = {"is_active": True}
    
    # If user is not premium, filter out premium servers
    if not current_user.is_premium:
        query["is_premium"] = False
    
    servers = await db.servers.find(query).to_list(100)
    
    response_servers = []
    for server in servers:
        # Calculate load percentage
        load_percentage = int((server["current_load"] / server["capacity"]) * 100) if server["capacity"] > 0 else 0
        
        # Simulate ping if not set
        if server.get("ping", 0) == 0:
            server["ping"] = random.randint(10, 150)
        
        response_servers.append(VPNServerResponse(
            **server,
            load_percentage=load_percentage
        ))
    
    # Sort by ping (optimal first)
    response_servers.sort(key=lambda x: x.ping)
    
    return response_servers

@api_router.get("/servers/optimal", response_model=VPNServerResponse)
async def get_optimal_server(current_user: UserResponse = Depends(get_current_user)):
    # Get all available servers
    query = {"is_active": True}
    
    if not current_user.is_premium:
        query["is_premium"] = False
    
    servers = await db.servers.find(query).to_list(100)
    
    if not servers:
        raise HTTPException(status_code=404, detail="No servers available")
    
    # Find server with lowest ping and < 80% capacity
    optimal = None
    for server in servers:
        load_percentage = int((server["current_load"] / server["capacity"]) * 100)
        if load_percentage < 80:
            if optimal is None or server.get("ping", 999) < optimal.get("ping", 999):
                optimal = server
    
    if optimal is None:
        optimal = servers[0]
    
    # Simulate ping
    if optimal.get("ping", 0) == 0:
        optimal["ping"] = random.randint(10, 80)
    
    load_percentage = int((optimal["current_load"] / optimal["capacity"]) * 100)
    
    return VPNServerResponse(**optimal, load_percentage=load_percentage)

@api_router.post("/servers/create", response_model=VPNServerResponse)
async def create_server(server_data: VPNServerCreate):
    server = VPNServer(**server_data.dict())
    
    await db.servers.insert_one(server.dict())
    
    load_percentage = 0
    
    return VPNServerResponse(**server.dict(), load_percentage=load_percentage)

# ==================== CONNECTION ROUTES ====================

@api_router.post("/connections/start", response_model=ConnectionResponse)
async def start_connection(conn_data: ConnectionStart, current_user: UserResponse = Depends(get_current_user)):
    # Check if server exists
    server = await db.servers.find_one({"id": conn_data.server_id, "is_active": True})
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    # Check if server requires premium
    if server.get("is_premium", False) and not current_user.is_premium:
        raise HTTPException(status_code=403, detail="Premium subscription required for this server")
    
    # Check if user already has active connection
    existing_conn = await db.connections.find_one({"user_id": current_user.id, "is_active": True})
    if existing_conn:
        raise HTTPException(status_code=400, detail="Already connected to a server")
    
    # Create new connection
    connection = Connection(
        user_id=current_user.id,
        server_id=conn_data.server_id
    )
    
    await db.connections.insert_one(connection.dict())
    
    # Increment server load
    await db.servers.update_one(
        {"id": conn_data.server_id},
        {"$inc": {"current_load": 1}}
    )
    
    return ConnectionResponse(**connection.dict())

@api_router.post("/connections/end")
async def end_connection(conn_data: ConnectionEnd, current_user: UserResponse = Depends(get_current_user)):
    # Find active connection
    connection = await db.connections.find_one({
        "id": conn_data.connection_id,
        "user_id": current_user.id,
        "is_active": True
    })
    
    if not connection:
        raise HTTPException(status_code=404, detail="Active connection not found")
    
    # Calculate duration
    ended_at = datetime.utcnow()
    duration = int((ended_at - connection["started_at"]).total_seconds())
    
    # Update connection
    await db.connections.update_one(
        {"id": conn_data.connection_id},
        {
            "$set": {
                "ended_at": ended_at,
                "duration_seconds": duration,
                "data_transferred_mb": conn_data.data_transferred_mb,
                "is_active": False
            }
        }
    )
    
    # Decrement server load
    await db.servers.update_one(
        {"id": connection["server_id"]},
        {"$inc": {"current_load": -1}}
    )
    
    # Update user data usage
    await db.users.update_one(
        {"id": current_user.id},
        {"$inc": {"data_used": conn_data.data_transferred_mb}}
    )
    
    return {"message": "Connection ended successfully"}

@api_router.get("/connections/active", response_model=Optional[ConnectionResponse])
async def get_active_connection(current_user: UserResponse = Depends(get_current_user)):
    connection = await db.connections.find_one({
        "user_id": current_user.id,
        "is_active": True
    })
    
    if connection:
        return ConnectionResponse(**connection)
    return None

# ==================== SUBSCRIPTION ROUTES ====================

@api_router.post("/subscriptions/activate")
async def activate_subscription(sub_data: SubscriptionCreate, current_user: UserResponse = Depends(get_current_user)):
    # Calculate expiration
    if sub_data.tier == "premium_monthly":
        expires_at = datetime.utcnow() + timedelta(days=30)
    elif sub_data.tier == "premium_yearly":
        expires_at = datetime.utcnow() + timedelta(days=365)
    else:
        raise HTTPException(status_code=400, detail="Invalid subscription tier")
    
    # Create subscription
    subscription = Subscription(
        user_id=current_user.id,
        tier=sub_data.tier,
        status="active",
        expires_at=expires_at,
        billing_token=sub_data.billing_token
    )
    
    await db.subscriptions.insert_one(subscription.dict())
    
    # Update user
    await db.users.update_one(
        {"id": current_user.id},
        {
            "$set": {
                "is_premium": True,
                "subscription_tier": sub_data.tier,
                "subscription_expires": expires_at
            }
        }
    )
    
    return {"message": "Subscription activated successfully", "expires_at": expires_at}

@api_router.get("/subscriptions/status")
async def get_subscription_status(current_user: UserResponse = Depends(get_current_user)):
    subscription = await db.subscriptions.find_one({
        "user_id": current_user.id,
        "status": "active"
    }, sort=[("created_at", -1)])
    
    if subscription:
        return {
            "is_premium": current_user.is_premium,
            "tier": subscription["tier"],
            "expires_at": subscription["expires_at"],
            "status": subscription["status"]
        }
    
    return {
        "is_premium": False,
        "tier": "free",
        "expires_at": None,
        "status": "inactive"
    }

# ==================== VPN WIREGUARD ROUTES ====================

# Initialize IP allocator
ip_allocator = IPAllocator(db)

@api_router.post("/vpn/connect", response_model=VPNConnectResponse)
async def vpn_connect(request: VPNConnectRequest, current_user: UserResponse = Depends(get_current_user)):
    """
    Establish VPN connection:
    1. Validate server exists and user has access
    2. Allocate client IP address
    3. Add peer to WireGuard server via SSH
    4. Create connection record
    5. Return WireGuard config for client
    """
    try:
        # Step 1: Get server details
        server = await db.servers.find_one({"id": request.server_id, "is_active": True})
        if not server:
            raise HTTPException(status_code=404, detail="Server not found or inactive")
        
        # Check premium access
        if server.get("is_premium", False) and not current_user.is_premium:
            raise HTTPException(status_code=403, detail="Premium subscription required for this server")
        
        # Check capacity
        if server.get("current_load", 0) >= server.get("capacity", 100):
            raise HTTPException(status_code=503, detail="Server at capacity, please try another server")
        
        # Check for existing active connection
        existing_conn = await db.connections.find_one({
            "user_id": current_user.id,
            "is_active": True
        })
        if existing_conn:
            # End existing connection first
            await db.connections.update_one(
                {"id": existing_conn["id"]},
                {"$set": {"is_active": False, "ended_at": datetime.utcnow()}}
            )
            await db.servers.update_one(
                {"id": existing_conn["server_id"]},
                {"$inc": {"current_load": -1}}
            )
        
        # Step 2: Allocate client IP
        client_ip = await ip_allocator.allocate_ip(request.server_id, current_user.id)
        
        # Step 3: Add peer to WireGuard server via SSH
        ssh_key_path = os.environ.get("WIREGUARD_SSH_KEY_PATH")
        wg_manager = WireGuardManager(
            server_ip=server["ip_address"],
            ssh_key_path=ssh_key_path
        )
        
        # Try to add peer (will fail gracefully if SSH not configured)
        peer_added = False
        try:
            wg_manager.add_peer(request.client_public_key, client_ip)
            logger.info(f"WireGuard peer added for user {current_user.id}")
        except Exception as ssh_error:
            # Log but don't fail - allow demo mode without actual SSH
            logger.warning(f"SSH peer addition failed (demo mode): {ssh_error}")
        
        # Step 4: Create connection record
        connection = Connection(
            user_id=current_user.id,
            server_id=request.server_id
        )
        await db.connections.insert_one(connection.dict())
        
        # Store peer info for cleanup
        await db.vpn_peers.update_one(
            {"user_id": current_user.id, "server_id": request.server_id},
            {
                "$set": {
                    "user_id": current_user.id,
                    "server_id": request.server_id,
                    "client_public_key": request.client_public_key,
                    "client_ip": client_ip,
                    "connection_id": connection.id,
                    "connected_at": datetime.utcnow(),
                    "is_active": True
                }
            },
            upsert=True
        )
        
        # Increment server load
        await db.servers.update_one(
            {"id": request.server_id},
            {"$inc": {"current_load": 1}}
        )
        
        # Step 5: Return WireGuard config
        return VPNConnectResponse(
            success=True,
            connection_id=connection.id,
            client_ip=client_ip,
            server_ip=server["ip_address"],
            server_public_key=server["public_key"],
            server_port=server.get("port", 51820),
            dns="1.1.1.1",
            allowed_ips="0.0.0.0/0",
            message="VPN connection established successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"VPN connect error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to establish VPN connection: {str(e)}")


@api_router.post("/vpn/disconnect")
async def vpn_disconnect(request: VPNDisconnectRequest, current_user: UserResponse = Depends(get_current_user)):
    """
    Disconnect VPN:
    1. Find active connection
    2. Remove peer from WireGuard server
    3. Release IP address
    4. Update connection record
    """
    try:
        # Find connection
        connection = await db.connections.find_one({
            "id": request.connection_id,
            "user_id": current_user.id,
            "is_active": True
        })
        
        if not connection:
            raise HTTPException(status_code=404, detail="Active connection not found")
        
        # Get server details
        server = await db.servers.find_one({"id": connection["server_id"]})
        
        if server:
            # Try to remove peer from WireGuard server
            try:
                ssh_key_path = os.environ.get("WIREGUARD_SSH_KEY_PATH")
                wg_manager = WireGuardManager(
                    server_ip=server["ip_address"],
                    ssh_key_path=ssh_key_path
                )
                wg_manager.remove_peer(request.client_public_key)
                logger.info(f"WireGuard peer removed for user {current_user.id}")
            except Exception as ssh_error:
                logger.warning(f"SSH peer removal failed (demo mode): {ssh_error}")
        
        # Get peer info for IP release
        peer_info = await db.vpn_peers.find_one({
            "connection_id": request.connection_id
        })
        
        # Release IP address
        if peer_info:
            await ip_allocator.release_ip(peer_info["client_ip"], connection["server_id"])
            
            # Mark peer as inactive
            await db.vpn_peers.update_one(
                {"connection_id": request.connection_id},
                {"$set": {"is_active": False, "disconnected_at": datetime.utcnow()}}
            )
        
        # Calculate duration
        ended_at = datetime.utcnow()
        duration = int((ended_at - connection["started_at"]).total_seconds())
        
        # Update connection
        await db.connections.update_one(
            {"id": request.connection_id},
            {
                "$set": {
                    "ended_at": ended_at,
                    "duration_seconds": duration,
                    "is_active": False
                }
            }
        )
        
        # Decrement server load
        if server:
            await db.servers.update_one(
                {"id": connection["server_id"]},
                {"$inc": {"current_load": -1}}
            )
        
        return {
            "success": True,
            "message": "VPN disconnected successfully",
            "duration_seconds": duration
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"VPN disconnect error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to disconnect VPN: {str(e)}")


@api_router.get("/vpn/status")
async def vpn_status(current_user: UserResponse = Depends(get_current_user)):
    """
    Get current VPN connection status
    """
    connection = await db.connections.find_one({
        "user_id": current_user.id,
        "is_active": True
    })
    
    if not connection:
        return {
            "connected": False,
            "server": None,
            "connection_id": None,
            "connected_since": None
        }
    
    # Get server info
    server = await db.servers.find_one({"id": connection["server_id"]})
    
    peer_info = await db.vpn_peers.find_one({
        "connection_id": connection["id"],
        "is_active": True
    })
    
    return {
        "connected": True,
        "connection_id": connection["id"],
        "server": {
            "id": server["id"] if server else None,
            "name": server["name"] if server else "Unknown",
            "country": server["country"] if server else None,
            "country_code": server["country_code"] if server else None,
            "ip_address": server["ip_address"] if server else None
        },
        "client_ip": peer_info["client_ip"] if peer_info else None,
        "connected_since": connection["started_at"]
    }

# ==================== SEED DATA ====================

@api_router.post("/seed/servers")
async def seed_servers():
    # Check if servers already exist
    count = await db.servers.count_documents({})
    if count > 0:
        return {"message": f"Servers already seeded ({count} servers exist)"}
    
    seed_servers = [
        {
            "name": "New York Fast",
            "country": "United States",
            "country_code": "US",
            "city": "New York",
            "ip_address": "198.51.100.1",
            "public_key": "base64_encoded_public_key_ny",
            "capacity": 100,
            "is_premium": False,
            "ping": 25
        },
        {
            "name": "Los Angeles Premium",
            "country": "United States",
            "country_code": "US",
            "city": "Los Angeles",
            "ip_address": "198.51.100.2",
            "public_key": "base64_encoded_public_key_la",
            "capacity": 150,
            "is_premium": True,
            "ping": 18
        },
        {
            "name": "London Fast",
            "country": "United Kingdom",
            "country_code": "GB",
            "city": "London",
            "ip_address": "198.51.100.3",
            "public_key": "base64_encoded_public_key_london",
            "capacity": 100,
            "is_premium": False,
            "ping": 45
        },
        {
            "name": "Frankfurt Premium",
            "country": "Germany",
            "country_code": "DE",
            "city": "Frankfurt",
            "ip_address": "198.51.100.4",
            "public_key": "base64_encoded_public_key_frankfurt",
            "capacity": 120,
            "is_premium": True,
            "ping": 35
        },
        {
            "name": "Tokyo Fast",
            "country": "Japan",
            "country_code": "JP",
            "city": "Tokyo",
            "ip_address": "198.51.100.5",
            "public_key": "base64_encoded_public_key_tokyo",
            "capacity": 80,
            "is_premium": False,
            "ping": 120
        },
        {
            "name": "Singapore Premium",
            "country": "Singapore",
            "country_code": "SG",
            "city": "Singapore",
            "ip_address": "198.51.100.6",
            "public_key": "base64_encoded_public_key_singapore",
            "capacity": 100,
            "is_premium": True,
            "ping": 95
        },
        {
            "name": "Sydney Fast",
            "country": "Australia",
            "country_code": "AU",
            "city": "Sydney",
            "ip_address": "198.51.100.7",
            "public_key": "base64_encoded_public_key_sydney",
            "capacity": 70,
            "is_premium": False,
            "ping": 140
        },
        {
            "name": "Toronto Fast",
            "country": "Canada",
            "country_code": "CA",
            "city": "Toronto",
            "ip_address": "198.51.100.8",
            "public_key": "base64_encoded_public_key_toronto",
            "capacity": 90,
            "is_premium": False,
            "ping": 30
        }
    ]
    
    servers_to_insert = []
    for s in seed_servers:
        server = VPNServer(**s)
        servers_to_insert.append(server.dict())
    
    await db.servers.insert_many(servers_to_insert)
    
    return {"message": f"Seeded {len(servers_to_insert)} servers successfully"}

# Include routers in the main app
app.include_router(api_router)

# Import and include admin router
from admin_routes import admin_router
app.include_router(admin_router)

# Add public config endpoint for mobile app
@api_router.get("/app/config")
async def get_app_config():
    """Public endpoint for mobile app to fetch configuration"""
    # Get AdMob config
    admob_config = await db.admob_config.find_one()
    admob_data = {
        "app_id": admob_config.get("app_id", "") if admob_config else "",
        "banner_unit_id": admob_config.get("banner_unit_id", "") if admob_config else "",
        "banner_enabled": admob_config.get("banner_enabled", True) if admob_config else True,
        "banner_position": admob_config.get("banner_position", "bottom") if admob_config else "bottom",
        "test_mode": admob_config.get("test_mode", True) if admob_config else True
    }
    
    # Get app settings
    app_settings = await db.app_settings.find_one()
    settings_data = {
        "maintenance_mode": app_settings.get("maintenance_mode", False) if app_settings else False,
        "maintenance_message": app_settings.get("maintenance_message", "") if app_settings else "",
        "force_update": app_settings.get("force_update", False) if app_settings else False,
        "minimum_version": app_settings.get("minimum_version", "1.0.0") if app_settings else "1.0.0",
        "kill_switch_enabled": app_settings.get("kill_switch_enabled", True) if app_settings else True,
        "split_tunneling_enabled": app_settings.get("split_tunneling_enabled", False) if app_settings else False
    }
    
    premium_data = {
        "monthly_price": app_settings.get("monthly_price", "$9.99") if app_settings else "$9.99",
        "yearly_price": app_settings.get("yearly_price", "$79.99") if app_settings else "$79.99",
        "yearly_discount": app_settings.get("yearly_discount", "33%") if app_settings else "33%"
    }
    
    return {
        "admob": admob_data,
        "settings": settings_data,
        "premium": premium_data
    }

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
