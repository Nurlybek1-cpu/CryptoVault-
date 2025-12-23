from datetime import datetime, timedelta, UTC

import pytest  # type: ignore

from tests.unit.auth import conftest as auth_conftest  # Reuse mock DB logic
from src.auth.auth_module import AuthModule
from src.auth.totp import TOTPManager
from src.auth.backup_codes import BackupCodesManager
from src.exceptions import AuthenticationError, AccountLockedError, RateLimitError


class CryptoVault:
    """
    High-level orchestrator for authentication flows used in integration tests.

    This is a lightweight wrapper around AuthModule that exposes a simpler
    interface for end-to-end flows (registration, login, MFA, sessions).
    """

    def __init__(self) -> None:
        # Use the same in-memory mock database implementation as unit tests
        db_gen = auth_conftest.mock_database.__wrapped__()  # type: ignore[attr-defined]
        self._db_gen = db_gen
        self.db = next(db_gen)

        self.auth = AuthModule(db=self.db)
        self.totp_manager: TOTPManager = self.auth.totp_manager
        self.backup_codes_manager: BackupCodesManager = self.auth.backup_codes_manager

    def close(self) -> None:
        """Clean up underlying mock database generator."""
        try:
            next(self._db_gen)
        except StopIteration:
            pass

    # ------------------------------------------------------------------ #
    # Core auth flows
    # ------------------------------------------------------------------ #

    def register(self, username: str, password: str) -> dict:
        return self.auth.register(username, password)

    def login(
        self,
        username: str,
        password: str,
        totp_code: str | None = None,
        backup_code: str | None = None,
    ) -> dict:
        return self.auth.login(
            username=username,
            password=password,
            totp_code=totp_code,
            backup_code=backup_code,
        )

    # ------------------------------------------------------------------ #
    # Session helpers
    # ------------------------------------------------------------------ #

    def verify_session(self, session_token: str) -> bool:
        """Return True if session exists and is not expired."""
        # Use underlying mock sessions store when available
        now = datetime.now(UTC)
        if hasattr(self.db, "_sessions_data"):
            for token, _user_id, _created_at, expires_at, _ip_hash, _ua_hash, is_valid in self.db._sessions_data.values():  # type: ignore[attr-defined]
                if token == session_token and is_valid and (expires_at is None or expires_at > now):
                    return True
            return False

        # Fallback SQL path for real database connections
        cursor = self.db.execute(
            "SELECT expires_at FROM sessions WHERE session_token = ?",
            (session_token,),
        )
        row = cursor.fetchone()
        if row is None:
            return False
        expires_at = row[0]
        return expires_at is None or expires_at > now

    def expire_session_immediately(self, session_token: str) -> None:
        """Force a session to be expired (for testing expiration handling)."""
        past = datetime.now(UTC) - timedelta(hours=1)
        if hasattr(self.db, "_sessions_data"):
            # Update in-memory session store
            data = self.db._sessions_data  # type: ignore[attr-defined]
            if session_token in data:
                token, user_id, created_at, _expires_at, ip_hash, ua_hash, is_valid = data[session_token]
                data[session_token] = (token, user_id, created_at, past, ip_hash, ua_hash, is_valid)
        else:
            self.db.execute(
                "UPDATE sessions SET expires_at = ? WHERE session_token = ?",
                (past, session_token),
            )
            if hasattr(self.db, "commit"):
                self.db.commit()

    def get_user_sessions(self, username: str) -> list[tuple]:
        """Return list of sessions for a given username."""
        cursor = self.db.execute(
            "SELECT user_id FROM users WHERE username = ?",
            (username,),
        )
        row = cursor.fetchone()
        if row is None:
            return []
        user_id = row[0]
        if hasattr(self.db, "_sessions_data"):
            sessions = []
            for token, s_user_id, _created_at, expires_at, _ip_hash, _ua_hash, is_valid in self.db._sessions_data.values():  # type: ignore[attr-defined]
                if s_user_id == user_id and is_valid:
                    sessions.append((token, expires_at))
            return sessions

        cursor = self.db.execute(
            "SELECT session_token, expires_at FROM sessions WHERE user_id = ?",
            (user_id,),
        )
        return cursor.fetchall() or []

    def logout_session(self, session_token: str) -> None:
        """Invalidate a single session by removing it."""
        if hasattr(self.db, "_sessions_data"):
            data = self.db._sessions_data  # type: ignore[attr-defined]
            if session_token in data:
                del data[session_token]
        else:
            self.db.execute(
                "DELETE FROM sessions WHERE session_token = ?",
                (session_token,),
            )
            if hasattr(self.db, "commit"):
                self.db.commit()


# ============================================================================ #
# Fixtures
# ============================================================================ #


@pytest.fixture
def vault() -> CryptoVault: # type: ignore
    vault = CryptoVault()
    try:
        yield vault
    finally:
        vault.close()


@pytest.fixture
def test_user_data() -> dict:
    return {
        "username": "integration_user",
        "password": "MySecureP@ssw0rd!",
    }


class TestAuthenticationFlow:
    # ------------------------------------------------------------------ #
    # Complete registration & login
    # ------------------------------------------------------------------ #

    def test_complete_registration_and_login(self, vault: CryptoVault, test_user_data: dict):
        # Register
        reg_result = vault.register(**test_user_data)
        assert reg_result["success"] is True

        # Login
        login_result = vault.login(test_user_data["username"], test_user_data["password"])
        assert login_result["success"] is True
        session_token = login_result["session_token"]

        # Use session
        assert vault.verify_session(session_token) is True

        # Expire session and verify it is no longer valid
        vault.expire_session_immediately(session_token)
        assert vault.verify_session(session_token) is False

    # ------------------------------------------------------------------ #
    # MFA / TOTP flows
    # ------------------------------------------------------------------ #

    def test_registration_with_mfa_setup(self, vault: CryptoVault, test_user_data: dict):
        import pyotp  # type: ignore

        # Register user and get TOTP secret
        reg_result = vault.register(**test_user_data)
        assert reg_result["success"] is True
        totp_secret = reg_result["totp_secret"]
        user_id = reg_result["user_id"]

        # Generate TOTP code from secret
        totp = pyotp.TOTP(totp_secret)
        code = totp.now()

        # Enable TOTP via manager
        enabled = vault.totp_manager.enable_totp(user_id, totp_secret, code)
        assert enabled is True

        # "Logout" is implicit: we just don't keep any active sessions here

    def test_login_with_mfa(self, vault: CryptoVault, test_user_data: dict):
        import pyotp  # type: ignore

        # Register user
        reg_result = vault.register(**test_user_data)
        totp_secret = reg_result["totp_secret"]
        user_id = reg_result["user_id"]

        # Enable TOTP
        totp = pyotp.TOTP(totp_secret)
        code = totp.now()
        vault.totp_manager.enable_totp(user_id, totp_secret, code)

        # First login without TOTP should request MFA
        login_result = vault.login(test_user_data["username"], test_user_data["password"])
        assert login_result["success"] is False
        assert login_result["status"] == "AWAITING_MFA"

        # Login with TOTP code should succeed
        login_result = vault.login(
            test_user_data["username"],
            test_user_data["password"],
            totp_code=totp.now(),
        )
        assert login_result["success"] is True

    # ------------------------------------------------------------------ #
    # Backup codes
    # ------------------------------------------------------------------ #

    def test_backup_code_usage(self, vault: CryptoVault, test_user_data: dict):
        import pyotp  # type: ignore

        # Register user and get backup codes
        reg_result = vault.register(**test_user_data)
        backup_codes = reg_result["backup_codes"]
        assert len(backup_codes) == 10
        first_code = backup_codes[0]

        totp_secret = reg_result["totp_secret"]
        user_id = reg_result["user_id"]

        # Enable TOTP for the user
        totp = pyotp.TOTP(totp_secret)
        vault.totp_manager.enable_totp(user_id, totp_secret, totp.now())

        # First login with backup code (no TOTP)
        login_result = vault.login(
            test_user_data["username"],
            test_user_data["password"],
            backup_code=first_code,
        )
        assert login_result["success"] is True

        # Backup code should now be single-use: using it again should fail
        with pytest.raises(Exception):
            vault.login(
                test_user_data["username"],
                test_user_data["password"],
                backup_code=first_code,
            )

    # ------------------------------------------------------------------ #
    # Security flows: lockout & rate limiting
    # ------------------------------------------------------------------ #

    def test_failed_login_attempts_lockout(self, vault: CryptoVault, test_user_data: dict):
        # Register
        vault.register(**test_user_data)

        # 5 failed attempts with wrong password
        for _ in range(5):
            with pytest.raises(AuthenticationError):
                vault.login(test_user_data["username"], "WrongPassword123!")

        # 6th attempt with correct password should raise AccountLockedError
        with pytest.raises(AccountLockedError):
            vault.login(test_user_data["username"], test_user_data["password"])

    def test_rate_limiting(self, vault: CryptoVault, test_user_data: dict):
        # Register
        vault.register(**test_user_data)

        # 5 failed attempts
        for _ in range(5):
            with pytest.raises(AuthenticationError):
                vault.login(test_user_data["username"], "WrongPassword123!")

        # Next attempt should raise RateLimitError
        with pytest.raises(RateLimitError):
            vault.login(test_user_data["username"], "WrongPassword123!")

        # Simulate waiting 15+ minutes by clearing internal rate limiter state
        vault.auth.rate_limiter.reset_attempts(test_user_data["username"])

        # Now we can attempt again (still wrong password, so AuthenticationError)
        with pytest.raises(AuthenticationError):
            vault.login(test_user_data["username"], "WrongPassword123!")

    # ------------------------------------------------------------------ #
    # Password reset flow (high level behaviour – token generation assumed)
    # ------------------------------------------------------------------ #

    @pytest.mark.skip(reason="Password reset orchestration not fully implemented yet")
    def test_password_reset_flow(self, vault: CryptoVault, test_user_data: dict):
        """
        Placeholder for full password reset flow once password_reset module is complete.
        """
        pass

    # ------------------------------------------------------------------ #
    # Session security
    # ------------------------------------------------------------------ #

    def test_session_hijacking_prevention(self, vault: CryptoVault, test_user_data: dict):
        # Register two users
        user_a = {"username": "user_a", "password": test_user_data["password"]}
        user_b = {"username": "user_b", "password": test_user_data["password"]}
        vault.register(**user_a)
        vault.register(**user_b)

        # Login as user A and get session
        login_a = vault.login(user_a["username"], user_a["password"])
        session_a = login_a["session_token"]
        assert vault.verify_session(session_a) is True

        # Attempt to "use" user A's session as user B: here we model this as
        # checking that sessions are bound to user IDs in the DB.
        cursor = vault.db.execute(
            "SELECT user_id FROM users WHERE username = ?",
            (user_b["username"],),
        )
        user_b_row = cursor.fetchone()
        assert user_b_row is not None
        user_b_id = user_b_row[0]

        cursor = vault.db.execute(
            "SELECT user_id FROM sessions WHERE session_token = ?",
            (session_a,),
        )
        session_row = cursor.fetchone()
        assert session_row is not None
        user_id_for_session = session_row[1]

        # Session token for A must not be usable as B (different user_ids)
        assert user_id_for_session != user_b_id

    def test_concurrent_sessions(self, vault: CryptoVault, test_user_data: dict):
        # Register user and login from two "devices"
        vault.register(**test_user_data)

        login1 = vault.login(test_user_data["username"], test_user_data["password"])
        login2 = vault.login(test_user_data["username"], test_user_data["password"])

        session1 = login1["session_token"]
        session2 = login2["session_token"]
        assert session1 != session2

        sessions = vault.get_user_sessions(test_user_data["username"])
        assert len(sessions) >= 2

        # Logout first session
        vault.logout_session(session1)
        assert vault.verify_session(session1) is False
        assert vault.verify_session(session2) is True


