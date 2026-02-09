import pytest
import sys
import os
from fastapi.testclient import TestClient
import warnings

# Fix for Python 3.14 bcrypt compatibility
if sys.version_info >= (3, 14):
    warnings.filterwarnings('ignore', message='.*bcrypt.*')
    warnings.filterwarnings('ignore', category=UserWarning)


# CRITICAL: Add backend directory to path for imports
# Use environment variable if set, otherwise search for codebase
backend_path = os.environ.get('CODEBASE_BACKEND_PATH')
if not backend_path:
    # Search upward from test file location
    _current_dir = os.path.dirname(os.path.abspath(__file__))
    # Adjust path to find the 'codebase' directory where app.py lives
    candidate = os.path.join(_current_dir, '..', 'codebase')
    if os.path.exists(candidate) and os.path.isfile(os.path.join(candidate, 'app.py')):
        backend_path = os.path.abspath(candidate)

if backend_path and backend_path not in sys.path:
    sys.path.insert(0, backend_path)


# Import application components using absolute imports
# This setup is tailored to the provided code which uses in-memory dicts in app.py
try:
    from app import app, users_db, items_db
    import app as app_module
    from utils import hash_password
except ImportError as e:
    print(f"FATAL: Could not import application modules. Check PYTHONPATH and file locations.", file=sys.stderr)
    print(f"Error: {e}", file=sys.stderr)
    print(f"Current sys.path: {sys.path}", file=sys.stderr)
    sys.exit(1)


@pytest.fixture(scope="function", autouse=True)
def reset_in_memory_db():
    """
    Reset in-memory data stores and counters before each test for complete isolation.
    This is the correct approach for the provided application code.
    """
    users_db.clear()
    items_db.clear()
    # Reset counters by modifying the module's global variables
    app_module.user_id_counter = 1
    app_module.item_id_counter = 1
    yield


@pytest.fixture(scope="session")
def test_client_session():
    """
    Provide a TestClient instance that persists across a session to avoid setup overhead.
    """
    with TestClient(app) as client:
        yield client

@pytest.fixture(scope="function")
def test_client(test_client_session, reset_in_memory_db):
    """
    Provide a TestClient instance with a clean in-memory state for each test.
    """
    return test_client_session


@pytest.fixture(scope="function")
def created_user(test_client):
    """
    Creates a standard test user via the API endpoint and returns its full data.
    This is a reusable component for tests that require an existing user.
    """
    user_data = {"username": "testuser", "email": "test@example.com", "password": "TestPassword123"}
    response = test_client.post("/users/", json=user_data)
    assert response.status_code == 200, f"Fixture 'created_user' failed: {response.text}"
    return response.json()

@pytest.fixture(scope="function")
def created_item(test_client, created_user):
    """
    Creates a sample item owned by the 'created_user' fixture.
    This is useful for tests involving item retrieval, update, or deletion.
    """
    item_data = {"name": "Test Item", "description": "A test item from fixture", "price": 99.99}
    owner_id = created_user['id']
    response = test_client.post(f"/items/?owner_id={owner_id}", json=item_data)
    assert response.status_code == 200, f"Fixture 'created_item' failed: {response.text}"
    return response.json()