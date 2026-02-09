import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
import re

# Import functions and models to be tested
# Imports are absolute based on the path added in conftest.py
from utils import hash_password, verify_password, get_timestamp, validate_email
from models import UserCreate, Item

# ==============================================================================
# UNIT TESTS
# ==============================================================================

@pytest.mark.unit
@pytest.mark.parametrize("password", ["password123", "a_very_long_and_secure_password_!@#$%", ""])
def test_unit_hash_and_verify_password_success(password):
    """Unit Test for utils.py: hash_password & verify_password
    Tests that verify_password returns True for a correctly hashed password."""
    # This test covers utils.py
    hashed = hash_password(password)
    assert isinstance(hashed, str)
    assert len(hashed) == 64  # SHA256 hex digest length
    assert verify_password(password, hashed) is True

@pytest.mark.unit
def test_unit_verify_password_failure():
    """Unit Test for utils.py: verify_password
    Tests that verify_password returns False for an incorrect password."""
    # This test covers utils.py
    hashed = hash_password("correct_password")
    assert verify_password("wrong_password", hashed) is False

@pytest.mark.unit
def test_unit_hash_password_consistency():
    """Unit Test for utils.py: hash_password
    Tests that hashing the same password multiple times yields the same hash."""
    # This test covers utils.py
    password = "consistent_password"
    hash1 = hash_password(password)
    hash2 = hash_password(password)
    assert hash1 == hash2

@pytest.mark.unit
def test_unit_get_timestamp_format():
    """Unit Test for utils.py: get_timestamp
    Tests that the timestamp is a string in ISO 8601 format."""
    # This test covers utils.py
    ts = get_timestamp()
    assert isinstance(ts, str)
    iso_pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+$'
    assert re.match(iso_pattern, ts)

@pytest.mark.unit
@pytest.mark.parametrize("email, expected", [
    ("test@example.com", True),
    ("user.name+alias@domain.co.uk", True),
    ("invalid-email", False),
    ("user@.com", False),
    ("@domain.com", False),
    ("user@domain", False),
    ("", False)
])
def test_unit_validate_email(email, expected):
    """Unit Test for utils.py: validate_email
    Tests email validation logic with various valid and invalid formats."""
    # This test covers utils.py
    assert validate_email(email) == expected

@pytest.mark.unit
def test_unit_model_user_create_valid():
    """Unit Test for models.py: UserCreate
    Tests that a valid payload creates a UserCreate instance."""
    # This test covers models.py
    user = UserCreate(username="test", email="test@example.com", password="pwd")
    assert user.username == "test"
    assert user.email == "test@example.com"

@pytest.mark.unit
def test_unit_model_user_create_invalid_email():
    """Unit Test for models.py: UserCreate
    Tests that Pydantic raises a validation error for an invalid email."""
    # This test covers models.py
    with pytest.raises(ValidationError):
        UserCreate(username="test", email="not-an-email", password="pwd")

@pytest.mark.unit
def test_unit_model_item_valid():
    """Unit Test for models.py: Item
    Tests that a valid payload creates an Item instance."""
    # This test covers models.py
    item = Item(name="My Item", description="A thing", price=10.50)
    assert item.name == "My Item"
    assert item.price == 10.50

@pytest.mark.unit
def test_unit_model_item_invalid_price():
    """Unit Test for models.py: Item
    Tests that Pydantic raises a validation error for an invalid price type."""
    # This test covers models.py
    with pytest.raises(ValidationError):
        Item(name="My Item", price="ten dollars")

# ==============================================================================
# INTEGRATION, CONTRACT & SECURITY TESTS
# ==============================================================================

@pytest.mark.integration
def test_integration_read_root(test_client: TestClient):
    """Integration Test for app.py: GET /
    Tests the root endpoint."""
    # This test covers app.py
    response = test_client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the User and Item Management API"}

@pytest.mark.integration
def test_integration_create_user_success(test_client: TestClient):
    """Integration Test for app.py: POST /users/
    Tests successful user creation."""
    # This test covers app.py
    user_data = {"username": "newUser", "email": "new@example.com", "password": "a_secure_password"}
    response = test_client.post("/users/", json=user_data)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "newUser"
    assert data["email"] == "new@example.com"
    assert data["is_active"] is True
    assert "id" in data

@pytest.mark.security
def test_security_create_user_duplicate_username(test_client: TestClient, created_user):
    """Security Test for app.py: POST /users/
    Tests that creating a user with a duplicate username is rejected."""
    # This test covers app.py
    duplicate_data = {"username": "testuser", "email": "another@example.com", "password": "password123"}
    response = test_client.post("/users/", json=duplicate_data)
    assert response.status_code == 400
    assert response.json() == {"detail": "Username already exists"}

@pytest.mark.contract
@pytest.mark.parametrize("payload, expected_detail_part", [
    ({"username": "u", "password": "p"}, "email"),
    ({"email": "e@e.com", "password": "p"}, "username"),
    ({"username": "u", "email": "e@e.com"}, "password"),
    ({"username": "u", "email": "not-a-valid-email", "password": "p"}, "value is not a valid email address"),
])
def test_contract_create_user_invalid_payload(test_client: TestClient, payload, expected_detail_part):
    """Contract Test for app.py: POST /users/
    Tests API contract for invalid or incomplete payloads (expects 422)."""
    # This test covers app.py and models.py
    response = test_client.post("/users/", json=payload)
    assert response.status_code == 422
    assert expected_detail_part in str(response.json()["detail"])

@pytest.mark.security
def test_security_user_response_no_password(test_client: TestClient):
    """Security Test for app.py: POST /users/ & GET /users/{id}
    Ensures password hash is never returned in user API responses."""
    # This test covers app.py and models.py
    user_data = {"username": "secure_user", "email": "secure@example.com", "password": "some_password"}
    response = test_client.post("/users/", json=user_data)
    assert response.status_code == 200
    post_data = response.json()
    assert "password" not in post_data
    assert "password_hash" not in post_data

    user_id = post_data["id"]
    response = test_client.get(f"/users/{user_id}")
    assert response.status_code == 200
    get_data = response.json()
    assert "password" not in get_data
    assert "password_hash" not in get_data

@pytest.mark.integration
def test_integration_get_user_success(test_client: TestClient, created_user):
    """Integration Test for app.py: GET /users/{user_id}
    Tests retrieving an existing user successfully."""
    # This test covers app.py
    user_id = created_user["id"]
    response = test_client.get(f"/users/{user_id}")
    assert response.status_code == 200
    retrieved_user = response.json()
    assert retrieved_user["id"] == user_id
    assert retrieved_user["username"] == created_user["username"]

@pytest.mark.integration
def test_integration_get_user_not_found(test_client: TestClient):
    """Integration Test for app.py: GET /users/{user_id}
    Tests retrieving a non-existent user (expects 404)."""
    # This test covers app.py
    response = test_client.get("/users/9999")
    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

@pytest.mark.contract
def test_contract_get_user_schema(test_client: TestClient, created_user):
    """Contract Test for app.py: GET /users/{user_id}
    Verifies the response schema for getting a user."""
    # This test covers app.py and models.py
    user_id = created_user["id"]
    response = test_client.get(f"/users/{user_id}")
    assert response.status_code == 200
    data = response.json()
    assert list(data.keys()) == ["id", "username", "email", "is_active"]
    assert isinstance(data["id"], int)
    assert isinstance(data["username"], str)
    assert isinstance(data["email"], str)
    assert isinstance(data["is_active"], bool)

@pytest.mark.integration
def test_integration_create_item_success(test_client: TestClient, created_user):
    """Integration Test for app.py: POST /items/
    Tests successful item creation for an existing user."""
    # This test covers app.py
    owner_id = created_user["id"]
    item_data = {"name": "Shiny Sword", "description": "+5 to testing", "price": 100.0}
    response = test_client.post(f"/items/?owner_id={owner_id}", json=item_data)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Shiny Sword"
    assert data["price"] == 100.0
    assert data["owner_id"] == owner_id
    assert "id" in data

@pytest.mark.integration
def test_integration_create_item_owner_not_found(test_client: TestClient):
    """Integration Test for app.py: POST /items/
    Tests creating an item with a non-existent owner (expects 404)."""
    # This test covers app.py
    non_existent_owner_id = 9999
    item_data = {"name": "Orphan Item", "price": 10.0}
    response = test_client.post(f"/items/?owner_id={non_existent_owner_id}", json=item_data)
    assert response.status_code == 404
    assert response.json() == {"detail": "Owner not found"}

@pytest.mark.contract
def test_contract_create_item_invalid_payload(test_client: TestClient, created_user):
    """Contract Test for app.py: POST /items/
    Tests API contract for invalid item payload (expects 422)."""
    # This test covers app.py and models.py
    owner_id = created_user["id"]
    item_data = {"name": "Invalid Item", "price": "ninety-nine"}
    response = test_client.post(f"/items/?owner_id={owner_id}", json=item_data)
    assert response.status_code == 422
    assert "value is not a valid float" in str(response.json()["detail"])

@pytest.mark.integration
def test_integration_get_item_success(test_client: TestClient, created_item):
    """Integration Test for app.py: GET /items/{item_id}
    Tests retrieving an existing item successfully."""
    # This test covers app.py
    item_id = created_item["id"]
    response = test_client.get(f"/items/{item_id}")
    assert response.status_code == 200
    retrieved_item = response.json()
    assert retrieved_item["id"] == item_id
    assert retrieved_item["name"] == created_item["name"]

@pytest.mark.integration
def test_integration_get_item_not_found(test_client: TestClient):
    """Integration Test for app.py: GET /items/{item_id}
    Tests retrieving a non-existent item (expects 404)."""
    # This test covers app.py
    response = test_client.get("/items/9999")
    assert response.status_code == 404
    assert response.json() == {"detail": "Item not found"}

@pytest.mark.contract
def test_contract_get_item_schema(test_client: TestClient, created_item):
    """Contract Test for app.py: GET /items/{item_id}
    Verifies the response schema for getting an item."""
    # This test covers app.py and models.py
    item_id = created_item["id"]
    response = test_client.get(f"/items/{item_id}")
    assert response.status_code == 200
    data = response.json()
    assert set(data.keys()) == {"id", "name", "description", "price", "owner_id"}
    assert isinstance(data["id"], int)
    assert isinstance(data["name"], str)
    assert isinstance(data["price"], float)
    assert isinstance(data["owner_id"], int)

@pytest.mark.contract
@pytest.mark.parametrize("url", ["/users/999", "/items/999"])
def test_contract_error_response_schema(test_client: TestClient, url):
    """Contract Test for app.py: Error Responses
    Verifies that 404 errors return a JSON object with a 'detail' key."""
    # This test covers app.py
    response = test_client.get(url)
    assert response.status_code == 404
    data = response.json()
    assert list(data.keys()) == ["detail"]
    assert isinstance(data["detail"], str)

@pytest.mark.security
def test_security_password_is_actually_hashed_in_db(test_client: TestClient):
    """Security Test for app.py & utils.py
    Verifies the password stored in the in-memory db is not plaintext."""
    # This white-box test covers app.py and utils.py
    plain_password = "MyPlainPassword123"
    user_data = {"username": "hash_check_user", "email": "hash@example.com", "password": plain_password}
    response = test_client.post("/users/", json=user_data)
    assert response.status_code == 200
    user_id = response.json()["id"]

    from app import users_db
    stored_user = users_db[user_id]
    assert "password_hash" in stored_user
    assert stored_user["password_hash"] != plain_password
    assert stored_user["password_hash"] == hash_password(plain_password)