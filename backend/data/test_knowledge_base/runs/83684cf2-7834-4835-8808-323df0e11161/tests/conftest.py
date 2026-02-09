import pytest
import sys
import os
from fastapi.testclient import TestClient
import warnings

# Fix for Python 3.14 bcrypt compatibility (Good practice, though not used in this specific codebase)
if sys.version_info >= (3, 14):
    warnings.filterwarnings('ignore', message='.*bcrypt.*')
    warnings.filterwarnings('ignore', category=UserWarning)


# CRITICAL: Add backend directory to path for imports
# The user's codebase is in a directory that needs to be added to the path.
# Assuming the tests are run from a directory parallel to 'codebase'.
_current_dir = os.path.dirname(os.path.abspath(__file__))
backend_path = os.path.abspath(os.path.join(_current_dir, '..', 'codebase'))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)


# Import application components from the user's codebase
# Note: The application uses in-memory dicts, not a SQL database.
# The fixtures are adapted accordingly.
from app import app


@pytest.fixture(scope="function", autouse=True)
def reset_in_memory_storage():
    """
    Reset in-memory storage before each test for isolation.
    This is the equivalent of resetting a database for this application.
    """
    # Import the module and its global variables to reset them
    import app as app_module
    app_module.users_db.clear()
    app_module.items_db.clear()
    app_module.user_id_counter = 1
    app_module.item_id_counter = 1
    yield


@pytest.fixture(scope="function")
def test_client(reset_in_memory_storage):
    """Provide a TestClient instance with clean in-memory storage."""
    with TestClient(app) as client:
        yield client


@pytest.fixture(scope="function")
def created_user(test_client):
    """
    Fixture to create a standard test user via the API.
    Returns the created user's data from the API response.
    """
    response = test_client.post(
        "/users/",
        json={"username": "testuser", "email": "test@example.com", "password": "TestPass123"}
    )
    assert response.status_code == 200, f"Failed to create test user: {response.text}"
    return response.json()

@pytest.fixture(scope="function")
def created_user_and_item(test_client, created_user):
    """
    Fixture to create a test user and an item owned by that user.
    Returns a tuple of (user_data, item_data).
    """
    user_id = created_user["id"]
    item_payload = {
        "name": "Test Item",
        "description": "An item for testing",
        "price": 19.99
    }
    response = test_client.post(f"/items/?owner_id={user_id}", json=item_payload)
    assert response.status_code == 200, f"Failed to create test item: {response.text}"
    return created_user, response.json()