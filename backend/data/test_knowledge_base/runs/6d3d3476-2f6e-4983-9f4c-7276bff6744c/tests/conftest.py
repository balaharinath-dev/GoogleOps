import pytest
import sys
import os
from fastapi.testclient import TestClient

# Add the 'codebase' directory to the Python path to allow for absolute imports
# This assumes the test file is run from a directory sibling to 'codebase'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'codebase')))

# Now we can import from the application
from app import app
import app as app_module # Import the module itself to reset its state


@pytest.fixture(scope="function", autouse=True)
def reset_in_memory_state():
    """
    Ensures a clean slate for each test by resetting the in-memory data stores.
    This is critical for test isolation.
    """
    app_module.users_db.clear()
    app_module.items_db.clear()
    app_module.user_id_counter = 1
    app_module.item_id_counter = 1
    yield


@pytest.fixture(scope="function")
def client(reset_in_memory_state):
    """
    Provides a FastAPI TestClient for making requests to the application.
    """
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="function")
def created_user(client):
    """
    Fixture to create a user and return its creation response data.
    This is useful for tests that require a user to already exist.
    """
    user_payload = {"username": "testuser", "email": "test@example.com", "password": "a-secure-password"}
    response = client.post("/users/", json=user_payload)
    assert response.status_code == 200, f"Failed to create user for fixture: {response.text}"
    return response.json()