#!/usr/bin/env python3
"""
Authentication System for BWF Toolkit
Handles user registration, login, and session management
"""

import os
import json
import sqlite3
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class User:
    """User data structure"""
    user_id: str
    username: str
    email: str
    full_name: str
    password_hash: str
    role: str = "user"  # user, admin
    is_active: bool = True
    created_at: str = None
    last_login: str = None
    login_attempts: int = 0
    locked_until: str = None

@dataclass
class Session:
    """Session data structure"""
    session_id: str
    user_id: str
    username: str
    created_at: str
    expires_at: str
    ip_address: str = None
    user_agent: str = None

class AuthSystem:
    """Authentication system for user management"""
    
    def __init__(self, db_path: str = 'auth.db'):
        self.db_path = db_path
        self.session_timeout = 24 * 60 * 60  # 24 hours
        self.max_login_attempts = 5
        self.lockout_duration = 30 * 60  # 30 minutes
        self._init_database()
    
    def _init_database(self):
        """Initialize authentication database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    is_active BOOLEAN DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_login TEXT,
                    login_attempts INTEGER DEFAULT 0,
                    locked_until TEXT
                )
            """)
            
            # Sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                )
            """)
            
            # Login attempts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    ip_address TEXT,
                    success BOOLEAN NOT NULL,
                    timestamp TEXT NOT NULL,
                    user_agent TEXT
                )
            """)
            
            conn.commit()
            logger.info("Authentication database initialized")
            
            # Create default admin user if no users exist
            self._create_default_admin()
            
        except Exception as e:
            logger.error(f"Error initializing auth database: {e}")
        finally:
            conn.close()
    
    def _create_default_admin(self):
        """Create default admin user if no users exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            
            if user_count == 0:
                # Create default admin user
                admin_user = User(
                    user_id="admin_001",
                    username="admin",
                    email="admin@bwftoolkit.com",
                    full_name="System Administrator",
                    password_hash=self._hash_password("admin123"),
                    role="admin",
                    created_at=datetime.now().isoformat()
                )
                
                cursor.execute("""
                    INSERT INTO users 
                    (user_id, username, email, full_name, password_hash, role, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    admin_user.user_id,
                    admin_user.username,
                    admin_user.email,
                    admin_user.full_name,
                    admin_user.password_hash,
                    admin_user.role,
                    admin_user.created_at
                ))
                
                conn.commit()
                logger.info("Default admin user created (username: admin, password: admin123)")
                
        except Exception as e:
            logger.error(f"Error creating default admin: {e}")
        finally:
            conn.close()
    
    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-256 with salt"""
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}:{password_hash}"
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            salt, hash_part = password_hash.split(':')
            return hashlib.sha256((password + salt).encode()).hexdigest() == hash_part
        except:
            return False
    
    def _is_user_locked(self, user: User) -> bool:
        """Check if user account is locked"""
        if not user.locked_until:
            return False
        
        try:
            locked_until = datetime.fromisoformat(user.locked_until)
            return datetime.now() < locked_until
        except:
            return False
    
    def _lock_user(self, user_id: str):
        """Lock user account"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            locked_until = datetime.now() + timedelta(seconds=self.lockout_duration)
            cursor.execute("""
                UPDATE users 
                SET locked_until = ?, login_attempts = login_attempts + 1
                WHERE user_id = ?
            """, (locked_until.isoformat(), user_id))
            conn.commit()
        except Exception as e:
            logger.error(f"Error locking user: {e}")
        finally:
            conn.close()
    
    def _reset_login_attempts(self, user_id: str):
        """Reset login attempts for user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                UPDATE users 
                SET login_attempts = 0, locked_until = NULL
                WHERE user_id = ?
            """, (user_id,))
            conn.commit()
        except Exception as e:
            logger.error(f"Error resetting login attempts: {e}")
        finally:
            conn.close()
    
    def register_user(self, username: str, email: str, full_name: str, password: str) -> Dict[str, Any]:
        """Register a new user"""
        try:
            # Validate input
            if not username or not email or not full_name or not password:
                return {"success": False, "message": "All fields are required"}
            
            if len(password) < 6:
                return {"success": False, "message": "Password must be at least 6 characters"}
            
            # Check if username or email already exists
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT user_id FROM users WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                conn.close()
                return {"success": False, "message": "Username or email already exists"}
            
            # Create new user
            user_id = f"user_{secrets.token_hex(8)}"
            user = User(
                user_id=user_id,
                username=username,
                email=email,
                full_name=full_name,
                password_hash=self._hash_password(password),
                created_at=datetime.now().isoformat()
            )
            
            cursor.execute("""
                INSERT INTO users 
                (user_id, username, email, full_name, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                user.user_id,
                user.username,
                user.email,
                user.full_name,
                user.password_hash,
                user.created_at
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"New user registered: {username}")
            return {"success": True, "message": "User registered successfully", "user_id": user_id}
            
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            return {"success": False, "message": "Registration failed"}
    
    def login_user(self, username: str, password: str, ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
        """Authenticate user login"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get user by username
            cursor.execute("""
                SELECT user_id, username, email, full_name, password_hash, role, 
                       is_active, login_attempts, locked_until
                FROM users WHERE username = ?
            """, (username,))
            
            row = cursor.fetchone()
            if not row:
                conn.close()
                self._log_login_attempt(username, ip_address, False, user_agent)
                return {"success": False, "message": "Invalid username or password"}
            
            user = User(
                user_id=row[0],
                username=row[1],
                email=row[2],
                full_name=row[3],
                password_hash=row[4],
                role=row[5],
                is_active=bool(row[6]),
                login_attempts=row[7],
                locked_until=row[8]
            )
            
            # Check if user is active
            if not user.is_active:
                conn.close()
                return {"success": False, "message": "Account is deactivated"}
            
            # Check if user is locked
            if self._is_user_locked(user):
                conn.close()
                return {"success": False, "message": "Account is temporarily locked"}
            
            # Verify password
            if not self._verify_password(password, user.password_hash):
                self._lock_user(user.user_id)
                conn.close()
                self._log_login_attempt(username, ip_address, False, user_agent)
                return {"success": False, "message": "Invalid username or password"}
            
            # Reset login attempts on successful login
            self._reset_login_attempts(user.user_id)
            
            # Create session
            session = self._create_session(user, ip_address, user_agent)
            
            # Update last login
            cursor.execute("""
                UPDATE users SET last_login = ? WHERE user_id = ?
            """, (datetime.now().isoformat(), user.user_id))
            
            conn.commit()
            conn.close()
            
            self._log_login_attempt(username, ip_address, True, user_agent)
            logger.info(f"User logged in: {username}")
            
            return {
                "success": True,
                "message": "Login successful",
                "session_id": session.session_id,
                "user": {
                    "user_id": user.user_id,
                    "username": user.username,
                    "email": user.email,
                    "full_name": user.full_name,
                    "role": user.role
                }
            }
            
        except Exception as e:
            logger.error(f"Error during login: {e}")
            return {"success": False, "message": "Login failed"}
    
    def _create_session(self, user: User, ip_address: str = None, user_agent: str = None) -> Session:
        """Create a new session for user"""
        session_id = secrets.token_urlsafe(32)
        now = datetime.now()
        expires_at = now + timedelta(seconds=self.session_timeout)
        
        session = Session(
            session_id=session_id,
            user_id=user.user_id,
            username=user.username,
            created_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO sessions 
                (session_id, user_id, username, created_at, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                session.session_id,
                session.user_id,
                session.username,
                session.created_at,
                session.expires_at,
                session.ip_address,
                session.user_agent
            ))
            
            conn.commit()
        except Exception as e:
            logger.error(f"Error creating session: {e}")
        finally:
            conn.close()
        
        return session
    
    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Validate session and return user info"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT s.session_id, s.user_id, s.username, s.expires_at,
                       u.email, u.full_name, u.role, u.is_active
                FROM sessions s
                JOIN users u ON s.user_id = u.user_id
                WHERE s.session_id = ?
            """, (session_id,))
            
            row = cursor.fetchone()
            if not row:
                conn.close()
                return None
            
            # Check if session is expired
            expires_at = datetime.fromisoformat(row[3])
            if datetime.now() > expires_at:
                # Clean up expired session
                cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                conn.commit()
                conn.close()
                return None
            
            # Check if user is still active
            if not row[7]:  # is_active
                conn.close()
                return None
            
            conn.close()
            
            return {
                "session_id": row[0],
                "user_id": row[1],
                "username": row[2],
                "email": row[4],
                "full_name": row[5],
                "role": row[6]
            }
            
        except Exception as e:
            logger.error(f"Error validating session: {e}")
            return None
    
    def logout_user(self, session_id: str) -> bool:
        """Logout user by removing session"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            return False
    
    def _log_login_attempt(self, username: str, ip_address: str, success: bool, user_agent: str = None):
        """Log login attempt"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO login_attempts (username, ip_address, success, timestamp, user_agent)
                VALUES (?, ?, ?, ?, ?)
            """, (username, ip_address, success, datetime.now().isoformat(), user_agent))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error logging login attempt: {e}")
    
    def get_user_stats(self) -> Dict[str, Any]:
        """Get user statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total users
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            
            # Active users
            cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
            active_users = cursor.fetchone()[0]
            
            # Recent logins (last 24 hours)
            yesterday = (datetime.now() - timedelta(days=1)).isoformat()
            cursor.execute("SELECT COUNT(*) FROM users WHERE last_login > ?", (yesterday,))
            recent_logins = cursor.fetchone()[0]
            
            # Active sessions
            cursor.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > ?", (datetime.now().isoformat(),))
            active_sessions = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                "total_users": total_users,
                "active_users": active_users,
                "recent_logins": recent_logins,
                "active_sessions": active_sessions
            }
            
        except Exception as e:
            logger.error(f"Error getting user stats: {e}")
            return {
                "total_users": 0,
                "active_users": 0,
                "recent_logins": 0,
                "active_sessions": 0
            }

# Global auth system instance
_auth_system = None

def get_auth_system() -> AuthSystem:
    """Get global auth system instance"""
    global _auth_system
    if _auth_system is None:
        _auth_system = AuthSystem()
    return _auth_system

if __name__ == "__main__":
    # Test the auth system
    auth = AuthSystem()
    
    # Test registration
    result = auth.register_user("testuser", "test@example.com", "Test User", "password123")
    print("Registration:", result)
    
    # Test login
    result = auth.login_user("testuser", "password123")
    print("Login:", result)
    
    # Test stats
    stats = auth.get_user_stats()
    print("Stats:", stats)

