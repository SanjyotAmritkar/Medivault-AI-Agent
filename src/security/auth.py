"""
Authentication and Authorization Module
Simple role-based access control for local deployment.
"""

import os
import hashlib
import logging
import secrets
from typing import Optional, List, Dict
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class Role(str, Enum):
    """User roles"""
    ADMIN = "admin"
    PROVIDER = "provider"
    STAFF = "staff"
    READONLY = "readonly"


@dataclass
class User:
    """User account"""
    username: str
    password_hash: str
    roles: List[Role]
    enabled: bool = True


class AuthManager:
    """
    Simple authentication manager for local deployment.
    
    For production deployment, integrate with:
    - OAuth 2.0 / OIDC
    - SAML
    - Multi-factor authentication
    - Enterprise directory (LDAP/AD)
    
    HIPAA Compliance:
    - Addresses: 164.312(a)(2)(i) Unique User Identification
    - Addresses: 164.312(d) Person or Entity Authentication
    """
    
    def __init__(self):
        # In-memory user store (production would use database)
        self.users: Dict[str, User] = {}
        self._create_default_user()
    
    def _create_default_user(self):
        """
        Create the default admin user from environment variables.

        Credentials are read from ADMIN_USERNAME / ADMIN_PASSWORD so that no
        secret is ever committed to source control. If ADMIN_PASSWORD is not
        set, a random one-time password is generated and logged to the console
        for first-time setup.
        """
        username = os.getenv("ADMIN_USERNAME", "admin")
        password = os.getenv("ADMIN_PASSWORD")

        if not password:
            password = secrets.token_urlsafe(16)
            logger.warning(
                "ADMIN_PASSWORD not set; generated a temporary admin password "
                "for user '%s': %s  (set ADMIN_USERNAME/ADMIN_PASSWORD in your "
                "environment to override).",
                username,
                password,
            )

        self.create_user(username, password, [Role.ADMIN])
    
    def hash_password(self, password: str) -> str:
        """Hash password with salt"""
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}${pwd_hash.hex()}"
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            salt, hash_value = password_hash.split('$')
            pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return pwd_hash.hex() == hash_value
        except:
            return False
    
    def create_user(self, username: str, password: str, roles: List[Role]) -> User:
        """Create new user"""
        password_hash = self.hash_password(password)
        user = User(username=username, password_hash=password_hash, roles=roles)
        self.users[username] = user
        return user
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate user.
        
        Returns:
            User object if authenticated, None otherwise
        """
        user = self.users.get(username)
        if not user:
            return None
        
        if not user.enabled:
            return None
        
        if self.verify_password(password, user.password_hash):
            return user
        
        return None
    
    def has_role(self, user: User, required_role: Role) -> bool:
        """Check if user has required role"""
        return required_role in user.roles or Role.ADMIN in user.roles
    
    def authorize(self, user: User, action: str, resource: str) -> bool:
        """
        Authorize user action on resource.
        
        Args:
            user: User object
            action: Action to perform (read, write, delete, etc.)
            resource: Resource being accessed
            
        Returns:
            True if authorized
        """
        # Admin can do anything
        if Role.ADMIN in user.roles:
            return True
        
        # Simple permission model
        if action == "read":
            return True  # All authenticated users can read
        
        if action in ["write", "update"]:
            return Role.PROVIDER in user.roles or Role.STAFF in user.roles
        
        if action == "delete":
            return Role.PROVIDER in user.roles
        
        return False


# Global auth manager
_auth_manager = None


def get_auth_manager() -> AuthManager:
    """Get or create global auth manager"""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager
