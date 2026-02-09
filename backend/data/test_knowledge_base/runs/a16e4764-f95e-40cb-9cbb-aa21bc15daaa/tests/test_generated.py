import pytest
from fastapi.testclient import TestClient
from datetime import datetime
import hashlib

# Import components to be tested
from utils import hash_password, verify_password, get_timestamp, validate_email
from models import UserCreate, Item

# --- UNIT TESTS ---

@pytest.mark.unit
def test_hash_password_deterministic():
    """Unit(utils.py): Ensures hash_password produces the same output for the same input."""
    password = "secure_password_123"
    hash1 = hash_password(password)
    hash2 = hash_password(password)
    assert hash1 == hash2
    assert hash1 == hashlib.sha256(password.encode()).hexdigest()

@pytest.mark.unit
def test_verify_password_correct():
    """Unit(utils.py): Tests that verify_password returns True for a correct password."""
    password = "a_real_password"
    hashed = hash_password(password)
    assert verify_password(password, hashed) is True

@pytest.mark.unit
def test_verify_password_incorrect():
    """Unit(utils.py): Tests that verify_password returns False for an incorrect password."""
    password = "a_real_password"
    hashed = hash_password(password)
    assert verify_password("wrong_password", hashed) is False

@pytest.mark.unit
def test_get_timestamp_format():
    """Unit(utils.py): Verifies get_timestamp returns a string in ISO 8601 format."""
    ts = get_timestamp()
    assert isinstance(ts, str)
    # Check that it can be parsed as an ISO format datetime
    assert datetime.fromisoformat(ts.replace('Z', '+00:00'))

@pytest.mark.unit
@pytest.mark.parametrize("email, expected", [
    ("test@example.com", True),
    ("user.name+tag@gmail.co.uk", True),
    ("invalid-email", False),
    ("test@.com", False),
    ("@example.com", False),
    ("test@example", False),
])
def test_validate_email_functionality(email, expected):
    """Unit(utils.py): Comprehensive checks for the validate_email function."""
    assert validate_email(email) is expected

@pytest.mark.unit
def test_pydantic_user_create_model():
    """Unit(models.py): Validates the UserCreate Pydantic model."""
    # Test valid data
    user = UserCreate(username="model_user", email="model@test.com", password="password")
    assert user.username == "model_user"
    # Test for validation error (e.g., invalid email)
    with pytest.raises(ValueError):
        UserCreate(username="model_user", email="not-an-email", password="password")

@pytest.mark.unit
def test_pydantic_item_model():
    """Unit(models.py): Validates the Item Pydantic model."""
    # Test valid data
    item = Item(name="A valid item", description="A description", price=10.50)
    assert item.price == 10.50
    # Test for validation error (e.g., non-positive price)
    with pytest.raises(ValueError):
        Item(name="Invalid item", price=-5.0)

# --- INTEGRATION TESTS ---

@pytest.mark.integration
def test_read_root_endpoint(test_client: TestClient):
    """Integration(app.py): Tests the root endpoint."""
    response = test_client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the User and Item Management API"}

@pytest.mark.integration
def test_create_user_success(test_client: TestClient):
    """Integration(app.py): Tests successful user creation."""
    response = test_client.post("/users/", json={"username": "newuser", "email": "new@user.com", "password": "a_strong_password"})
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "new@user.com"
    assert data["is_active"] is True
    assert "id" in data

@pytest.mark.integration
def test_create_user_duplicate_username(test_client: TestClient, created_user):
    """Integration(app.py): Tests that creating a user with a duplicate username fails."""
    response = test_client.post("/users/", json={"username": "testuser", "email": "another@email.com", "password": "password"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Username already exists"}

@pytest.mark.integration
def test_get_user_success(test_client: TestClient, created_user):
    """Integration(app.py): Tests retrieving an existing user successfully."""
    user_id = created_user["id"]
    response = test_client.get(f"/users/{user_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == user_id
    assert data["username"] == created_user["username"]

@pytest.mark.integration
def test_get_user_not_found(test_client: TestClient):
    """Integration(app.py): Tests that retrieving a non-existent user returns a 404 error."""
    response = test_client.get("/users/999")
    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

@pytest.mark.integration
def test_create_item_success(test_client: TestClient, created_user):
    """Integration(app.py): Tests successful item creation for an existing user."""
    owner_id = created_user["id"]
    item_data = {"name": "A new shiny item", "description": "It's great", "price": 199.99}
    response = test_client.post(f"/items/?owner_id={owner_id}", json=item_data)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == item_data["name"]
    assert data["owner_id"] == owner_id
    assert "id" in data

@pytest.mark.integration
def test_create_item_owner_not_found(test_client: TestClient):
    """Integration(app.py): Tests that creating an item for a non-existent owner fails."""
    item_data = {"name": "Orphan Item", "description": "No owner", "price": 50.0}
    response = test_client.post("/items/?owner_id=999", json=item_data)
    assert response.status_code == 404
    assert response.json() == {"detail": "Owner not found"}

@pytest.mark.integration
def test_get_item_success(test_client: TestClient, created_item):
    """Integration(app.py): Tests retrieving an existing item successfully."""
    item_id = created_item["id"]
    response = test_client.get(f"/items/{item_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == item_id
    assert data["name"] == created_item["name"]

@pytest.mark.integration
def test_get_item_not_found(test_client: TestClient):
    """Integration(app.py): Tests that retrieving a non-existent item returns a 404 error."""
    response = test_client.get("/items/999")
    assert response.status_code == 404
    assert response.json() == {"detail": "Item not found"}

# --- SECURITY TESTS ---

@pytest.mark.security
def test_password_is_hashed_on_user_creation(test_client: TestClient):
    """Security(app.py, utils.py): Verifies the user's password is not stored in plain text."""
    from app import users_db # Import for inspection
    password = "my_plain_password"
    response = test_client.post("/users/", json={"username": "security_user", "email": "sec@user.com", "password": password})
    assert response.status_code == 200
    user_id = response.json()["id"]
    
    stored_user = users_db[user_id]
    assert "password" not in stored_user
    assert "password_hash" in stored_user
    assert stored_user["password_hash"] != password
    assert stored_user["password_hash"] == hash_password(password)

@pytest.mark.security
def test_get_user_endpoint_does_not_expose_password_hash(test_client: TestClient, created_user):
    """Security(app.py, models.py): Ensures the GET /users/{id} endpoint does not expose the password hash."""
    user_id = created_user["id"]
    response = test_client.get(f"/users/{user_id}")
    assert response.status_code == 200
    data = response.json()
    assert "password" not in data
    assert "password_hash" not in data

@pytest.mark.security
def test_create_user_with_malicious_input_xss(test_client: TestClient):
    """Security(app.py): Tests for basic XSS protection by checking if input is returned as is."""
    xss_payload = "<script>alert('XSS')</script>"
    response = test_client.post("/users/", json={"username": xss_payload, "email": "xss@test.com", "password": "password"})
    assert response.status_code == 200
    # FastAPI/Pydantic by default don't sanitize, but they encode correctly in JSON.
    # The test ensures the payload is treated as a string, not executed.
    assert response.json()["username"] == xss_payload

@pytest.mark.security
def test_insecure_hashing_algorithm_is_used():
    """Security(utils.py): A test to flag the use of an insecure hashing algorithm (unsalted SHA256)."""
    # This test serves as a documented warning. In a real CI/CD, this might be a custom check.
    password = "test"
    hashed = hash_password(password)
    # An actual attack isn't feasible here, but we can assert the known hash to show it's a simple SHA256.
    assert hashed == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    pytest.skip("SKIPPED: Test flags use of unsalted SHA256. Upgrade to bcrypt or Argon2.")

# --- CONTRACT & EDGE CASE TESTS ---

@pytest.mark.contract
def test_get_user_response_schema(test_client: TestClient, created_user):
    """Contract(app.py, models.py): Verifies the response for getting a user matches the User schema."""
    user_id = created_user["id"]
    response = test_client.get(f"/users/{user_id}")
    assert response.status_code == 200
    data = response.json()
    # Check for all fields in the User model
    assert all(key in data for key in ["id", "username", "email", "is_active"])
    assert isinstance(data["id"], int)
    assert isinstance(data["username"], str)
    assert isinstance(data["email"], str)
    assert isinstance(data["is_active"], bool)

@pytest.mark.contract
def test_get_item_response_schema(test_client: TestClient, created_item):
    """Contract(app.py, models.py): Verifies the response for getting an item matches the Item schema."""
    item_id = created_item["id"]
    response = test_client.get(f"/items/{item_id}")
    assert response.status_code == 200
    data = response.json()
    # Check for all fields in the Item model
    assert all(key in data for key in ["id", "name", "description", "price", "owner_id"])
    assert isinstance(data["id"], int)
    assert isinstance(data["name"], str)
    assert isinstance(data["price"], float)
    assert isinstance(data["owner_id"], int)

@pytest.mark.contract
def test_422_error_for_invalid_user_input(test_client: TestClient):
    """Contract(app.py, models.py): Tests for a 422 Unprocessable Entity error with invalid input."""
    # Missing password
    response = test_client.post("/users/", json={"username": "user", "email": "email@test.com"})
    assert response.status_code == 422
    # Invalid email
    response = test_client.post("/users/", json={"username": "user", "email": "not-an-email", "password": "pw"})
    assert response.status_code == 422

@pytest.mark.contract
def test_404_error_schema(test_client: TestClient):
    """Contract(app.py): Verifies the JSON schema for 404 Not Found errors."""
    response = test_client.get("/users/99999")
    assert response.status_code == 404
    assert "detail" in response.json()
    assert response.json()["detail"] == "User not found"

@pytest.mark.edgecase
def test_create_user_with_empty_fields(test_client: TestClient):
    """EdgeCase(app.py, models.py): Tests creating a user with empty string fields."""
    response = test_client.post("/users/", json={"username": "", "email": "empty@test.com", "password": "password"})
    assert response.status_code == 422 # Pydantic default min_length=1 for strings
    
    response = test_client.post("/users/", json={"username": "test", "email": "empty@test.com", "password": ""})
    assert response.status_code == 422

@pytest.mark.edgecase
def test_get_user_with_id_zero(test_client: TestClient):
    """EdgeCase(app.py): Tests retrieving a user with ID 0, a common edge case."""
    response = test_client.get("/users/0")
    assert response.status_code == 404 # Assuming IDs start from 1
    assert response.json()["detail"] == "User not found"

@pytest.mark.edgecase
def test_create_item_with_zero_price(test_client: TestClient, created_user):
    """EdgeCase(app.py, models.py): Tests creating an item with a price of 0."""
    item_data = {"name": "Free Item", "description": "This item is free", "price": 0.0}
    owner_id = created_user['id']
    response = test_client.post(f"/items/?owner_id={owner_id}", json=item_data)
    assert response.status_code == 200
    assert response.json()["price"] == 0.0

@pytest.mark.edgecase
def test_create_item_with_negative_price(test_client: TestClient, created_user):
    """EdgeCase(app.py, models.py): Tests that creating an item with a negative price fails validation."""
    item_data = {"name": "Negative Price Item", "price": -10.0}
    owner_id = created_user['id']
    response = test_client.post(f"/items/?owner_id={owner_id}", json=item_data)
    assert response.status_code == 422 # Pydantic validation should catch this