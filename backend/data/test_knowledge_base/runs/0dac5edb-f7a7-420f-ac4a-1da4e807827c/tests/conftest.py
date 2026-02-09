import pytest
import sys
import os
from fastapi.testclient import TestClient
import warnings

# Fix for Python 3.14 bcrypt compatibility (good practice, though not used in this project)
if sys.version_info >= (3, 14):
    warnings.filterwarnings('ignore', message='.*bcrypt.*')
    warnings.filterwarnings('ignore', category=UserWarning)

# CRITICAL: Add codebase directory to path for imports
# This logic is adapted from the prompt to fit the project structure.
codebase_path = os.environ.get('CODEBASE_PATH')
if not codebase_path:
    _current_dir = os.path.dirname(os.path.abspath(__file__))
    for i in range(10):  # Search up to 10 levels
        candidate = os.path.join(_current_dir, *(['..'] * i), 'codebase')
        if os.path.exists(candidate) and os.path.isfile(os.path.join(candidate, 'app.py')):
            codebase_path = os.path.abspath(candidate)
            break
if codebase_path and codebase_path not in sys.path:
    sys.path.insert(0, codebase_path)

# Import application components
# This is adapted for the target application which uses in-memory data.
from app import app
import app as app_module

@pytest.fixture(scope="function", autouse=True)
def reset_in_memory_state():
    """
    AUTOUSE FIXTURE: Resets the application's in-memory 'database' and counters
    before each test. This is CRITICAL for test isolation.
    """
    app_module.users_db.clear()
    app_module.items_db.clear()
    app_module.user_id_counter = 1
    app_module.item_id_counter = 1
    yield

@pytest.fixture(scope="function")
def test_client(reset_in_memory_state):
    """
    Provide a TestClient instance for making API requests.
    Depends on reset_in_memory_state to ensure a clean slate.
    """
    with TestClient(app) as client:
        yield client

@pytest.fixture(scope="function")
def created_user(test_client):
    """
    Fixture to create a standard user via the API and return its creation response data.
    Useful for tests that require a pre-existing user.
    """
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "ValidPassword123"
    }
    response = test_client.post("/users/", json=user_data)
    assert response.status_code == 200, f"Failed to create user for fixture: {response.text}"
    return response.json()

@pytest.fixture(scope="function")
def created_item(test_client, created_user):
    """
    Fixture to create a standard item via the API, owned by the created_user.
    Returns the item creation response data.
    """
    item_data = {
        "name": "Test Item",
        "description": "A description for the test item",
        "price": 99.99
    }
    owner_id = created_user["id"]
    response = test_client.post(f"/items/?owner_id={owner_id}", json=item_data)
    assert response.status_code == 200, f"Failed to create item for fixture: {response.text}"
    return response.json()