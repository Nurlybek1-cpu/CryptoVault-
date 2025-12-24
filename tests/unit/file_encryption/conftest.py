"""
Pytest fixtures for file encryption module tests.

Provides reusable fixtures for testing file encryption functionality.
"""

import os
import tempfile
import pytest
from pathlib import Path

from src.file_encryption.file_encryption_module import FileEncryptionModule
from src.file_encryption.key_derivation import KeyDerivation


@pytest.fixture
def file_encryption_module():
    """Initialized FileEncryptionModule instance."""
    return FileEncryptionModule(user_id="test_user")


@pytest.fixture
def test_password():
    """Sample strong password for testing."""
    return "TestPassword123!@#"


@pytest.fixture
def test_username():
    """Sample username for testing."""
    return "testuser"


@pytest.fixture
def test_file():
    """Temporary test file with small content (~1KB)."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        # Write sample content
        f.write("This is a test file for encryption testing.\n" * 50)
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def test_large_file():
    """Temporary large test file (~10MB for streaming tests)."""
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.bin') as f:
        # Write 10MB of data
        chunk_size = 1024 * 1024  # 1MB
        for i in range(10):
            f.write(b'x' * chunk_size)
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def test_file_content():
    """Sample file content for testing."""
    return "Test file content\n" * 100


@pytest.fixture
def test_file_with_content(test_file_content):
    """Temporary file with specific content."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(test_file_content)
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def key_derivation():
    """Initialized KeyDerivation instance."""
    return KeyDerivation()


@pytest.fixture
def master_key():
    """Generated 32-byte master key."""
    return os.urandom(32)


@pytest.fixture
def file_encryption_key():
    """Generated 32-byte File Encryption Key."""
    return os.urandom(32)


@pytest.fixture
def salt():
    """Generated 32-byte salt for key derivation."""
    return os.urandom(32)


@pytest.fixture
def nonce():
    """Generated 12-byte nonce for AES-GCM."""
    return os.urandom(12)


@pytest.fixture
def temp_dir():
    """Temporary directory for test files."""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    
    # Cleanup - remove all files in directory
    import shutil
    if os.path.exists(temp_path):
        shutil.rmtree(temp_path)


@pytest.fixture
def cleanup_files():
    """Fixture to track and cleanup generated files."""
    files_to_cleanup = []
    
    yield files_to_cleanup
    
    # Cleanup
    for filepath in files_to_cleanup:
        if os.path.exists(filepath):
            os.unlink(filepath)
