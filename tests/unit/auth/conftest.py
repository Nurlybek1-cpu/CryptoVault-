"""
Pytest fixtures for authentication module tests.

This module provides reusable test fixtures for testing the authentication
module, including test data, mock database connections, and initialized
AuthModule instances.
"""

import pytest  # type: ignore
from unittest.mock import Mock, MagicMock
from datetime import datetime

from src.auth.auth_module import AuthModule


@pytest.fixture
def test_username():
    """Fixture providing a valid test username."""
    return "testuser123"


@pytest.fixture
def test_password():
    """Fixture providing a valid strong test password."""
    return "MySecureP@ssw0rd!"


@pytest.fixture
def test_weak_password():
    """Fixture providing a weak test password (too short)."""
    return "weak"


@pytest.fixture
def mock_database():
    """
    Fixture providing a mock database connection.
    
    The mock database supports:
    - execute() method that returns a mock cursor
    - commit() method for transactions
    - Stores mock data in memory for testing
    """
    db = MagicMock()
    
    # Mock data storage
    users_data = {}
    sessions_data = {}
    
    def mock_execute(query, params=None):
        """Mock execute method that simulates database operations."""
        cursor = MagicMock()
        
        # Handle user queries
        if "SELECT" in query.upper() and "users" in query.upper():
            if params and "username = ?" in query:
                username = params[0]
                user = users_data.get(username)
                if user and "user_id, username, password_hash, account_locked" in query:
                    # Return data matching the login query order
                    cursor.fetchone.return_value = (
                        user[0], user[1], user[2], user[3], user[4],
                        user[5], user[6], user[7], user[8]
                    )
                else:
                    cursor.fetchone.return_value = user
            elif params and "user_id = ?" in query:
                user_id = params[0]
                # Find user by user_id
                user = next((u for u in users_data.values() if u[0] == user_id), None)
                if user:
                    # Handle different SELECT queries
                    if "failed_login_attempts" in query and "FROM users" in query:
                        # Return just the failed_login_attempts value
                        cursor.fetchone.return_value = (user[5],)  # failed_login_attempts is at index 5
                    elif "account_locked, account_locked_until" in query:
                        # Return account lock fields
                        cursor.fetchone.return_value = (user[3], user[4])  # account_locked, account_locked_until
                    else:
                        cursor.fetchone.return_value = user
                else:
                    cursor.fetchone.return_value = None
            else:
                cursor.fetchone.return_value = None
        
        # Handle session queries
        elif "SELECT" in query.upper() and "sessions" in query.upper():
            if params and "session_token = ?" in query:
                token = params[0]
                session = sessions_data.get(token)
                cursor.fetchone.return_value = session
            else:
                cursor.fetchone.return_value = None
        
        # Handle INSERT operations
        elif "INSERT" in query.upper() and "users" in query.upper():
            if params:
                # INSERT order: user_id, username, password_hash, totp_secret, totp_enabled,
                #               backup_codes_hash, failed_login_attempts, account_locked,
                #               account_locked_until, created_at, last_login, email
                user_id = params[0]
                username = params[1]
                password_hash = params[2]
                totp_secret = params[3]
                totp_enabled = params[4]
                backup_codes_hash = params[5]
                failed_login_attempts = params[6]
                account_locked = params[7]
                account_locked_until = params[8]
                created_at = params[9]
                last_login = params[10]
                email = params[11]
                
                # Store in tuple matching SELECT query order from login:
                # user_id, username, password_hash, account_locked, account_locked_until,
                # failed_login_attempts, totp_enabled, totp_secret, backup_codes_hash
                users_data[username] = (
                    user_id, username, password_hash, account_locked, account_locked_until,
                    failed_login_attempts, totp_enabled, totp_secret, backup_codes_hash
                )
        
        elif "INSERT" in query.upper() and "sessions" in query.upper():
            if params:
                session_token = params[0]
                user_id = params[1]
                created_at = params[2]
                expires_at = params[3]
                ip_hash = params[4]
                user_agent_hash = params[5]
                
                sessions_data[session_token] = (
                    session_token, user_id, created_at, expires_at,
                    ip_hash, user_agent_hash, True  # is_valid
                )
        
        # Handle UPDATE operations
        elif "UPDATE" in query.upper() and "users" in query.upper():
            if params:
                # Find user by username or user_id based on WHERE clause
                if "username = ?" in query:
                    username = params[-1]  # Last param is username
                    if username in users_data:
                        user_data = list(users_data[username])
                        # Update fields based on query
                        # Tuple structure: user_id(0), username(1), password_hash(2), account_locked(3),
                        #                  account_locked_until(4), failed_login_attempts(5), totp_enabled(6),
                        #                  totp_secret(7), backup_codes_hash(8)
                        if "account_locked = ?" in query:
                            user_data[3] = params[0]  # account_locked
                            if len(params) > 1:
                                user_data[4] = params[1]  # account_locked_until
                        elif "failed_login_attempts = ?" in query:
                            user_data[5] = params[0]
                        elif "totp_enabled = ?" in query:
                            if len(params) >= 3:
                                user_data[6] = params[0]  # totp_enabled
                                user_data[7] = params[1]  # totp_secret
                            else:
                                user_data[6] = params[0]  # totp_enabled
                        elif "backup_codes_hash = ?" in query:
                            user_data[8] = params[0]
                        
                        users_data[username] = tuple(user_data)
                
                elif "user_id = ?" in query:
                    user_id = params[-1]
                    # Find user by user_id and update
                    for username, user_data in users_data.items():
                        if user_data[0] == user_id:
                            user_data_list = list(user_data)
                            # Tuple structure: user_id(0), username(1), password_hash(2), account_locked(3),
                            #                  account_locked_until(4), failed_login_attempts(5), totp_enabled(6),
                            #                  totp_secret(7), backup_codes_hash(8)
                            if "account_locked = ?" in query:
                                user_data_list[3] = params[0]  # account_locked
                                if len(params) > 1:
                                    user_data_list[4] = params[1]  # account_locked_until
                                if len(params) > 3:
                                    user_data_list[5] = params[3]  # failed_login_attempts
                            elif "failed_login_attempts = ?" in query:
                                user_data_list[5] = params[0]
                            users_data[username] = tuple(user_data_list)
                            break
        
        elif "UPDATE" in query.upper() and "sessions" in query.upper():
            if params:
                session_token = params[-1] if "session_token = ?" in query else None
                if session_token and session_token in sessions_data:
                    session_data = list(sessions_data[session_token])
                    if "is_valid = ?" in query:
                        session_data[6] = params[0]
                    sessions_data[session_token] = tuple(session_data)
        
        return cursor
    
    db.execute = mock_execute
    db.commit = MagicMock()
    
    # Store data references for test access
    db._users_data = users_data
    db._sessions_data = sessions_data
    
    return db


@pytest.fixture
def auth_module(mock_database):
    """
    Fixture providing an initialized AuthModule instance.
    
    Uses the mock_database fixture and initializes AuthModule with
    default password policy and TOTP settings.
    """
    return AuthModule(
        db=mock_database,
        password_policy={
            'min_length': 12,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_numbers': True,
            'require_special': True,
        },
        totp_settings={
            'digits': 6,
            'interval': 30,
            'issuer': 'CryptoVault',
        }
    )

