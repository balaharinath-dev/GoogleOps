import pytest
import sys
import os
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import warnings

# Fix for Python 3.14 bcrypt compatibility
if sys.version_info >= (3, 14):
    warnings.filterwarnings('ignore', message='.*bcrypt.*')
    warnings.filterwarnings('ignore', category=UserWarning)


# CRITICAL: Add backend directory to path for imports
# In a real CI/CD, this path would be more deterministic.
backend_path = os.environ.get('CODEBASE_BACKEND_PATH')
if not backend_path:
    # Search upward from test file location
    _current_dir = os.path.dirname(os.path.abspath(__file__))
    # Heuristic to find the directory containing 'app.py'
    for i in range(5):  # Search up to 5 levels
        candidate = os.path.join(_current_dir, *(['..'] * i))
        if os.path.exists(candidate) and os.path.isfile(os.path.join(candidate, 'app.py')):
            backend_path = os.path.abspath(candidate)
            break

# If found, add it to the path.
if backend_path and backend_path not in sys.path:
    sys.path.insert(0, backend_path)
elif not backend_path:
    # If we still haven't found it, try adding the current dir as a last resort.
    if os.path.isfile('app.py'):
        sys.path.insert(0, os.path.abspath('.'))


# Now, attempt to import application components
try:
    # The new file is app.py, not main.py
    from app import app, read_root
    # The following imports are kept for future tests, even if not used by app.py
    # from database import Base, get_db
    # from models import User, Item, Order
    # from auth import get_password_hash
except ImportError as e:
    print(f"CRITICAL: Failed to import application components. sys.path: {sys.path}")
    print(f"Error: {e}")
    # Exit pytest if core components can't be imported.
    pytest.exit("Could not import the main FastAPI app from app.py. Check PYTHONPATH and file locations.", 1)

# Since app.py is simple and has no database, we can simplify the fixtures.
# The full DB setup is kept commented for when the app grows.

# @pytest.fixture(scope="function")
# def db_session(reset_db):
#     '''Provide a clean database session for each test.'''
#     # ... implementation ...

@pytest.fixture(scope="function")
def test_client():
    '''Provide a TestClient instance for the application.'''
    with TestClient(app) as client:
        yield client

# The following fixtures are not needed for the current app.py but are good placeholders
# for a production environment, ready for when auth is added.

@pytest.fixture(scope="function")
def test_user():
    '''Placeholder for a standard test user fixture.'''
    # In a real scenario with a DB:
    # from auth import get_password_hash
    # from models import User
    # return User(username="testuser", email="test@example.com", hashed_password=get_password_hash("TestPass123"))
    return {"username": "testuser"}


@pytest.fixture(scope="function")
def admin_user():
    '''Placeholder for an admin user fixture.'''
    # In a real scenario with a DB:
    # from auth import get_password_hash
    # from models import User
    # return User(username="admin", email="admin@example.com", hashed_password=get_password_hash("AdminPass123"), is_admin=True)
    return {"username": "admin", "is_admin": True}


@pytest.fixture(scope="function")
def auth_headers():
    '''Placeholder for auth_headers fixture.'''
    # This would typically involve calling a login endpoint to get a real token.
    return {"Authorization": "Bearer fake-user-token-for-testing"}


@pytest.fixture(scope="function")
def admin_headers():
    '''Placeholder for admin_headers fixture.'''
    return {"Authorization": "Bearer fake-admin-token-for-testing"}