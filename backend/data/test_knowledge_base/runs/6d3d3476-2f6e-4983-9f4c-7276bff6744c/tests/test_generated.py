import pytest
import hashlib
import re
from fastapi.testclient import TestClient

# Unit tests for functions in: utils.py

@pytest.mark.unit
def test_hash_password_correctness():
    """Unit: Tests utils.hash_password for correctness against a known value."""
    password = "admin"
    expected_hash = hashlib.sha256(password.encode()).hexdigest()
    from utils import hash_password
    assert hash_password(password) == expected_hash

@pytest.mark.unit
def test_hash_password_is_deterministic():
    """Unit: Tests that utils.hash_password produces the same output for the same input."""
    from utils import hash_password
    assert hash_password("password123") == hash_password("password123")

@pytest.mark.unit
@pytest.mark.parametrize("plain_password,hashed_password,expected", [
    ("correct", hashlib.sha256("correct".encode()).hexdigest(), True),
    ("wrong", hashlib.sha256("correct".encode()).hexdigest(), False),
    ("", hashlib.sha256("".encode()).hexdigest(), True),
])
def test_verify_password(plain_password, hashed_password, expected):
    """Unit: Tests utils.verify_password for both correct and incorrect passwords."""
    from utils import verify_password
    assert verify_password(plain_password, hashed_password) is expected

@pytest.mark.unit
def test_get_timestamp_format():
    """Unit: Tests utils.get_timestamp format to be a valid ISO 8601 string."""
    from utils import get_timestamp
    ts = get_timestamp()
    assert isinstance(ts, str)
    # Regex for ISO 8601 format like 2024-01-01T12:00:00.123456
    assert re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+', ts)

@pytest.mark.unit
@pytest.mark.parametrize("email,expected", [
    ("test@example.com", True),
    ("test.user@domain.co.uk", True),
    ("invalid-email", False),
    ("test@.com", False),
    ("test@domain.", False),
    ("@domain.com", False),
])
def test_validate_email(email, expected):
    """Unit: Tests the simple utils.validate_email function."""
    from utils import validate_email
    assert validate_email(email) is expected

# Integration, Contract, and Security tests for: app.py and models.py

@pytest.mark.integration
def test_read_root(client: TestClient):
    """Integration: Tests the root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "timestamp" in data

@pytest.mark.integration
def test_create_user_success(client: TestClient):
    """Integration: Tests successful user creation."""
    # This test covers app.py (create_user endpoint) and models.py (UserCreate)
    response = client.post("/users/", json={"username": "newuser", "email": "new@user.com", "password": "password"})
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "new@user.com"
    assert data["is_active"] is True
    assert data["id"] == 1

@pytest.mark.security
def test_create_user_response_hides_password(client: TestClient):
    """Security: Ensures password hash is not returned on user creation."""
    # This test covers app.py (create_user response_model) and models.py (User model)
    response = client.post("/users/", json={"username": "secuser", "email": "sec@user.com", "password": "password"})
    assert response.status_code == 200
    data = response.json()
    assert "password" not in data
    assert "password_hash" not in data

@pytest.mark.integration
def test_create_user_duplicate_username(client: TestClient, created_user):
    """Integration: Tests that creating a user with a duplicate username fails."""
    # This test covers app.py (create_user duplicate check)
    response = client.post("/users/", json={"username": "testuser", "email": "another@email.com", "password": "password"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Username already exists"}

@pytest.mark.contract
@pytest.mark.parametrize("payload, expected_error_loc", [
    ({"username": "u", "email": "e@e.com"}, "password"), # Missing password
    ({"email": "e@e.com", "password": "p"}, "username"), # Missing username
    ({"username": "u", "password": "p"}, "email"), # Missing email
    ({"username": "u", "email": "not-an-email", "password": "p"}, "email"), # Invalid email
])
def test_create_user_validation_errors(client: TestClient, payload, expected_error_loc):
    """Contract: Tests Pydantic validation for the create_user endpoint."""
    # This test covers models.py (UserCreate model validation)
    response = client.post("/users/", json=payload)
    assert response.status_code == 422
    error_detail = response.json()["detail"][0]
    assert expected_error_loc in error_detail["loc"]

@pytest.mark.integration
def test_get_user_by_id_success(client: TestClient, created_user):
    """Integration: Tests retrieving a user by their ID."""
    # This test covers app.py (get_user endpoint)
    user_id = created_user["id"]
    response = client.get(f"/users/{user_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == user_id
    assert data["username"] == created_user["username"]

@pytest.mark.integration
def test_get_user_by_id_not_found(client: TestClient):
    """Integration: Tests retrieving a non-existent user returns 404."""
    # This test covers app.py (get_user not found case)
    response = client.get("/users/999")
    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

@pytest.mark.security
def test_get_user_hides_password(client: TestClient, created_user):
    """Security: Ensures password hash is not returned when getting a user."""
    # This test covers app.py (get_user response_model) and models.py (User model)
    user_id = created_user["id"]
    response = client.get(f"/users/{user_id}")
    assert response.status_code == 200
    assert "password" not in response.json()
    assert "password_hash" not in response.json()

@pytest.mark.integration
def test_create_item_success(client: TestClient, created_user):
    """Integration: Tests successful item creation for an existing user."""
    # This test covers app.py (create_item endpoint) and models.py (Item model)
    owner_id = created_user["id"]
    item_payload = {"name": "Test Item", "description": "A description", "price": 10.5}
    response = client.post(f"/items/?owner_id={owner_id}", json=item_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Test Item"
    assert data["price"] == 10.5
    assert data["owner_id"] == owner_id
    assert data["id"] == 1

@pytest.mark.integration
def test_create_item_owner_not_found(client: TestClient):
    """Integration: Tests that creating an item with a non-existent owner fails."""
    # This test covers app.py (create_item owner check)
    item_payload = {"name": "Test Item", "description": "A description", "price": 10.5}
    response = client.post("/items/?owner_id=999", json=item_payload)
    assert response.status_code == 404
    assert response.json() == {"detail": "Owner not found"}

@pytest.mark.contract
def test_create_item_validation_error(client: TestClient, created_user):
    """Contract: Tests Pydantic validation for item creation."""
    # This test covers models.py (Item model validation)
    owner_id = created_user["id"]
    # Missing 'name' and 'price'
    item_payload = {"description": "A description"}
    response = client.post(f"/items/?owner_id={owner_id}", json=item_payload)
    assert response.status_code == 422

@pytest.mark.integration
def test_get_item_by_id_success(client: TestClient, created_user):
    """Integration: Tests retrieving an item by its ID."""
    # This test covers app.py (get_item endpoint)
    owner_id = created_user["id"]
    item_payload = {"name": "Test Item", "description": "A description", "price": 10.5}
    create_response = client.post(f"/items/?owner_id={owner_id}", json=item_payload)
    item_id = create_response.json()["id"]

    get_response = client.get(f"/items/{item_id}")
    assert get_response.status_code == 200
    data = get_response.json()
    assert data["id"] == item_id
    assert data["name"] == "Test Item"

@pytest.mark.integration
def test_get_item_by_id_not_found(client: TestClient):
    """Integration: Tests retrieving a non-existent item returns 404."""
    # This test covers app.py (get_item not found case)
    response = client.get("/items/999")
    assert response.status_code == 404
    assert response.json() == {"detail": "Item not found"}

@pytest.mark.contract
def test_user_and_item_id_auto_increment(client: TestClient):
    """Contract: Verifies that user and item IDs auto-increment correctly."""
    # Covers app.py (user_id_counter, item_id_counter logic)
    # Create first user
    resp1 = client.post("/users/", json={"username": "user1", "email": "u1@e.com", "password": "p"})
    assert resp1.status_code == 200
    assert resp1.json()["id"] == 1
    owner_id_1 = resp1.json()["id"]

    # Create second user
    resp2 = client.post("/users/", json={"username": "user2", "email": "u2@e.com", "password": "p"})
    assert resp2.status_code == 200
    assert resp2.json()["id"] == 2

    # Create first item
    item_resp1 = client.post(f"/items/?owner_id={owner_id_1}", json={"name": "i1", "price": 1})
    assert item_resp1.status_code == 200
    assert item_resp1.json()["id"] == 1

    # Create second item
    item_resp2 = client.post(f"/items/?owner_id={owner_id_1}", json={"name": "i2", "price": 2})
    assert item_resp2.status_code == 200
    assert item_resp2.json()["id"] == 2

@pytest.mark.contract
def test_get_user_response_schema(client: TestClient, created_user):
    """Contract: Verifies the GET /users/{id} response schema."""
    # Covers models.py (User model)
    user_id = created_user["id"]
    response = client.get(f"/users/{user_id}")
    assert response.status_code == 200
    data = response.json()
    expected_keys = {"id", "username", "email", "is_active"}
    assert set(data.keys()) == expected_keys

@pytest.mark.contract
def test_get_item_response_schema(client: TestClient, created_user):
    """Contract: Verifies the GET /items/{id} response schema."""
    # Covers models.py (Item model)
    owner_id = created_user["id"]
    item_payload = {"name": "Schema Item", "price": 1.99}
    create_resp = client.post(f"/items/?owner_id={owner_id}", json=item_payload)
    item_id = create_resp.json()["id"]

    get_resp = client.get(f"/items/{item_id}")
    assert get_resp.status_code == 200
    data = get_resp.json()
    expected_keys = {"id", "name", "description", "price", "owner_id"}
    # Description is optional, so it might be None
    assert expected_keys.issubset(set(data.keys()))

@pytest.mark.security
def test_long_string_input(client: TestClient):
    """Security: Tests endpoints with very long string inputs."""
    # Covers app.py and models.py robustness
    long_string = "a" * 2000
    response = client.post("/users/", json={"username": long_string, "email": "long@string.com", "password": "p"})
    assert response.status_code == 200
    assert response.json()["username"] == long_string

@pytest.mark.security
def test_special_character_input(client: TestClient):
    """Security: Tests endpoints with special characters in inputs."""
    # Covers app.py and models.py robustness
    special_user = "user-`!@#$%^&*()_+-=[]{}|;':,./<>?"
    response = client.post("/users/", json={"username": special_user, "email": "special@chars.com", "password": "p"})
    assert response.status_code == 200
    assert response.json()["username"] == special_user

@pytest.mark.integration
def test_item_creation_with_optional_description(client: TestClient, created_user):
    """Integration: Tests item creation without the optional description field."""
    # Covers models.py (Item model with optional field)
    owner_id = created_user["id"]
    item_payload = {"name": "No Desc Item", "price": 50.0} # No description
    response = client.post(f"/items/?owner_id={owner_id}", json=item_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "No Desc Item"
    assert data["description"] is None # Pydantic should default it to None

@pytest.mark.integration
def test_item_creation_with_null_description(client: TestClient, created_user):
    """Integration: Tests item creation with an explicit null description."""
    # Covers models.py (Item model with optional field)
    owner_id = created_user["id"]
    item_payload = {"name": "Null Desc Item", "description": None, "price": 55.0}
    response = client.post(f"/items/?owner_id={owner_id}", json=item_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Null Desc Item"
    assert data["description"] is None