"""
WireGuard Peer Management Module
Handles automatic peer registration and cleanup
"""
import paramiko
import os
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class WireGuardManager:
    """
    Manages WireGuard peer operations on remote Vultr servers
    Uses SSH with key-based authentication for security
    """
    
    def __init__(self, server_ip: str, ssh_key_path: str = None, username: str = "root"):
        self.server_ip = server_ip
        self.username = username
        self.ssh_key_path = ssh_key_path or os.environ.get("WIREGUARD_SSH_KEY_PATH")
        
    def _execute_ssh_command(self, command: str) -> str:
        """
        Execute command on remote server via SSH
        Uses key-based authentication for security
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Use SSH key for authentication (more secure than password)
            if self.ssh_key_path and os.path.exists(self.ssh_key_path):
                key = paramiko.RSAKey.from_private_key_file(self.ssh_key_path)
                ssh.connect(
                    self.server_ip, 
                    username=self.username, 
                    pkey=key, 
                    timeout=10
                )
            else:
                # Fallback to password (NOT recommended for production)
                # Only for development/testing
                logger.warning(f"SSH key not found at {self.ssh_key_path}, using password auth")
                password = os.environ.get("WIREGUARD_SSH_PASSWORD")
                if not password:
                    raise Exception("No SSH key or password configured")
                ssh.connect(
                    self.server_ip,
                    username=self.username,
                    password=password,
                    timeout=10
                )
            
            stdin, stdout, stderr = ssh.exec_command(command)
            error = stderr.read().decode().strip()
            
            if error and "warning" not in error.lower():
                logger.error(f"SSH command error: {error}")
                raise Exception(f"SSH Remote Error: {error}")
            
            output = stdout.read().decode().strip()
            logger.info(f"SSH command executed successfully: {command[:50]}...")
            return output
            
        except Exception as e:
            logger.error(f"SSH connection failed: {str(e)}")
            raise
        finally:
            ssh.close()
    
    def add_peer(self, client_public_key: str, client_ip: str) -> bool:
        """
        Add peer to WireGuard dynamically without restarting service
        Uses runtime wg set command + persistent config update
        """
        try:
            # Step 1: Add peer at runtime (doesn't disconnect existing users)
            runtime_command = (
                f"sudo wg set wg0 peer {client_public_key} "
                f"allowed-ips {client_ip}/32"
            )
            self._execute_ssh_command(runtime_command)
            logger.info(f"Added peer {client_public_key[:16]}... at runtime")
            
            # Step 2: Make it persistent (survives server reboot)
            persist_command = (
                f"echo -e '\\n[Peer]\\n"
                f"PublicKey = {client_public_key}\\n"
                f"AllowedIPs = {client_ip}/32' | sudo tee -a /etc/wireguard/wg0.conf > /dev/null"
            )
            self._execute_ssh_command(persist_command)
            logger.info(f"Persisted peer {client_public_key[:16]}... to config")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to add peer: {str(e)}")
            return False
    
    def remove_peer(self, client_public_key: str) -> bool:
        """
        Remove peer from WireGuard (runtime + persistent)
        """
        try:
            # Step 1: Remove from runtime
            runtime_command = f"sudo wg set wg0 peer {client_public_key} remove"
            self._execute_ssh_command(runtime_command)
            logger.info(f"Removed peer {client_public_key[:16]}... from runtime")
            
            # Step 2: Remove from config file
            # Using sed to remove the [Peer] block
            remove_command = (
                f"sudo sed -i '/^\\[Peer\\]/,/^$/{{/PublicKey = {client_public_key}/,/^$/d}}' "
                f"/etc/wireguard/wg0.conf"
            )
            self._execute_ssh_command(remove_command)
            logger.info(f"Removed peer {client_public_key[:16]}... from config")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove peer: {str(e)}")
            return False
    
    def get_server_public_key(self) -> str:
        """
        Retrieve server's WireGuard public key
        """
        try:
            command = "sudo cat /etc/wireguard/server_public.key"
            return self._execute_ssh_command(command)
        except Exception as e:
            logger.error(f"Failed to get server public key: {str(e)}")
            raise
    
    def get_active_peers(self) -> list:
        """
        Get list of currently active peers
        """
        try:
            command = "sudo wg show wg0 peers"
            output = self._execute_ssh_command(command)
            peers = output.split('\n') if output else []
            return [p for p in peers if p]
        except Exception as e:
            logger.error(f"Failed to get active peers: {str(e)}")
            return []
    
    def cleanup_inactive_peers(self, active_public_keys: list) -> int:
        """
        Remove peers that are no longer active
        Returns count of cleaned up peers
        """
        try:
            current_peers = self.get_active_peers()
            cleaned = 0
            
            for peer in current_peers:
                if peer not in active_public_keys:
                    if self.remove_peer(peer):
                        cleaned += 1
            
            logger.info(f"Cleaned up {cleaned} inactive peers")
            return cleaned
            
        except Exception as e:
            logger.error(f"Peer cleanup failed: {str(e)}")
            return 0


class IPAllocator:
    """
    Manages IP address allocation for VPN clients
    Uses MongoDB to track allocated IPs
    """
    
    def __init__(self, db):
        self.db = db
        self.base_ip = "10.0.0"
        self.min_host = 2  # .1 is server
        self.max_host = 254
    
    async def allocate_ip(self, server_id: str, user_id: str) -> str:
        """
        Allocate next available IP address for a user on a specific server
        """
        # Get all allocated IPs for this server
        allocated = await self.db.ip_allocations.find(
            {"server_id": server_id, "is_active": True}
        ).to_list(300)
        
        # Extract host numbers
        used_hosts = set()
        for alloc in allocated:
            ip = alloc["ip_address"]
            host = int(ip.split('.')[-1])
            used_hosts.add(host)
        
        # Find next available
        for host in range(self.min_host, self.max_host + 1):
            if host not in used_hosts:
                ip_address = f"{self.base_ip}.{host}"
                
                # Record allocation
                await self.db.ip_allocations.insert_one({
                    "server_id": server_id,
                    "user_id": user_id,
                    "ip_address": ip_address,
                    "is_active": True,
                    "allocated_at": datetime.utcnow()
                })
                
                logger.info(f"Allocated IP {ip_address} to user {user_id}")
                return ip_address
        
        raise Exception("No available IP addresses on this server")
    
    async def release_ip(self, ip_address: str, server_id: str):
        """
        Release an IP address back to the pool
        """
        result = await self.db.ip_allocations.update_one(
            {"server_id": server_id, "ip_address": ip_address},
            {"$set": {"is_active": False, "released_at": datetime.utcnow()}}
        )
        
        if result.modified_count > 0:
            logger.info(f"Released IP {ip_address}")
        
        return result.modified_count > 0
    
    async def get_user_ip(self, server_id: str, user_id: str) -> str:
        """
        Get user's allocated IP for a server (if exists)
        """
        allocation = await self.db.ip_allocations.find_one({
            "server_id": server_id,
            "user_id": user_id,
            "is_active": True
        })
        
        return allocation["ip_address"] if allocation else None
