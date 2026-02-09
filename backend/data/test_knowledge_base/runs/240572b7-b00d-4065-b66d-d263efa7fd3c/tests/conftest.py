import pytest
import sys
import os
from fastapi.testclient import TestClient
import warnings
from datetime import datetime, timezone

# Fix for Python 3.14 compatibility
if sys.version_info >= (3, 14):
    warnings.filterwarnings('ignore', message='.*bcrypt.*')
    warnings.filterwarnings('ignore', category=UserWarning)

# CRITICAL: Add backend directory to path for imports
# This assumes the tests are run from a directory within the project root.
# The user's file structure is /.../codebase/app.py. We'll add 'codebase' to the path.
_current_dir = os.path.dirname(os.path.abspath(__file__))
# Start search from the current directory of the conftest.py file
search_dir = _current_dir
backend_path = None
# Search up to 5 levels for a directory named 'codebase' containing 'app.py'
for i in range(5):
    candidate_path = os.path.join(search_dir, 'codebase')
    if os.path.isdir(candidate_path) and os.path.isfile(os.path.join(candidate_path, 'app.py')):
        backend_path = os.path.abspath(candidate_path)
        break
    # Move one level up in the directory hierarchy
    search_dir = os.path.dirname(search_dir)

if backend_path and backend_path not in sys.path:
    sys.path.insert(0, backend_path)
elif not backend_path:
    # Fallback for simpler structures if 'codebase' is not found
    backend_path = os.path.abspath(os.path.join(_current_dir, '..'))
    if backend_path not in sys.path:
        sys.path.insert(0, backend_path)


# Import application components and in-memory stores
# The application uses global dictionaries as an in-memory database.
# We import them here to control their state during testing.
try:
    from app import app
    from utils import hash_password
except ImportError as e:
    print(f"CRITICAL: Failed to import from app or utils. Check that the 'codebase' directory is in the PYTHONPATH.", file=sys.stderr)
    print(f"PYTHONPATH: {sys.path}", file=sys.stderr)
    raise e


@pytest.fixture(scope="function", autouse=True)
def reset_in_memory_dbs():
    """
    Fixture to reset the state of the in-memory databases before each test.
    This ensures test isolation. It directly manipulates the global variables
    in the 'app' module.
    """
    # Import the module itself to modify its global variables
    import app as app_module
    app_module.user_id_counter = 1
    app_module.item_id_counter = 1
    app_module.users_db.clear()
    app_module.items_db.clear()
    yield


@pytest.fixture(scope="function")
def test_client(reset_in_memory_dbs):
    """
    Provide a TestClient instance for making requests to the application.
    Depends on `reset_in_memory_dbs` to ensure a clean state for each test.
    """
    with TestClient(app) as client:
        yield client


@pytest.fixture(scope="function")
def created_user(test_client):
    """
    Fixture to create a standard user via the API and return its data.
    This is useful for tests that require a pre-existing user.
    """
    user_data = {"username": "testuser", "email": "test@example.com", "password": "TestPass123"}
    response = test_client.post("/users/", json=user_data)
    assert response.status_code == 200, f"Fixture setup failed: Could not create user. Response: {response.text}"
    return response.json()

@pytest.fixture(scope="function")
def created_user_in_db():
    """
    Fixture to create a user directly in the in-memory db, including the hash.
    Useful for unit-testing components that rely on the internal user structure.
    """
    import app as app_module
    user_id = app_module.user_id_counter
    app_module.user_id_counter += 1
    user_record = {
        "id": user_id,
        "username": "directuser",
        "email": "direct@example.com",
        "password_hash": hash_password("DirectPass123"),
        "is_active": True
    }
    app_module.users_db[user_id] = user_record
    return user_record