import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone

# Import functions and models to be tested
# Imports are absolute based on the conftest.py path setup
from utils import hash_password, verify_password, get_timestamp, validate_email
from models import User, UserCreate, Item

# --- Unit Tests ---

# Covers: utils.py
@pytest.mark.unit
class TestUtils:
    """Unit tests for functions in utils.py"""

    def test_hash_password_consistency(self):
        """Unit: hash_password should be consistent for the same input."""
        assert hash_password("password123") == hash_password("password123")

    def test_hash_password_uniqueness(self):
        """Unit: hash_password should produce different hashes for different inputs."""
        assert hash_password("password123") != hash_password("Password123")

    def test_verify_password_correct(self):
        """Unit: verify_password should return True for a correct password."""
        hashed = hash_password("correct_password")
        assert verify_password("correct_password", hashed) is True

    def test_verify_password_incorrect(self):
        """Unit: verify_password should return False for an incorrect password."""
        hashed = hash_password("correct_password")
        assert verify_password("wrong_password", hashed) is False

    def test_verify_password_case_sensitive(self):
        """Unit: verify_password should be case-sensitive."""
        hashed = hash_password("MyPassword")
        assert verify_password("mypassword", hashed) is False

    def test_get_timestamp_format(self):
        """Unit: get_timestamp should return a string in ISO 8601 format."""
        ts = get_timestamp()
        assert isinstance(ts, str)
        # Check if it's a valid ISO 8601 timestamp
        parsed_ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        assert parsed_ts.tzinfo is not None

    @pytest.mark.parametrize("email", ["test@example.com", "user.name+tag@gmail.co.uk"])
    def test_validate_email_valid(self, email):
        """Unit: validate_email should return True for valid email formats."""
        assert validate_email(email) is True

    @pytest.mark.parametrize("email", ["plainaddress", "@missing-local-part.com", "user@.com", "user@domain."])
    def test_validate_email_invalid(self, email):
        """Unit: validate_email should return False for invalid email formats."""
        assert validate_email(email) is False

# --- Integration and Contract Tests ---

# Covers: app.py
@pytest.mark.integration
def test_read_root(test_client: TestClient):
    """Integration: Test the root endpoint."""
    response = test_client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the User and Item Management API"}

# Covers: app.py, models.py, utils.py
@pytest.mark.integration
class TestUserEndpoints:
    """Integration tests for user-related endpoints."""

    def test_create_user_success(self, test_client: TestClient):
        """Integration: Test successful user creation."""
        response = test_client.post(
            "/users/",
            json={"username": "newuser", "email": "new@example.com", "password": "a_secure_password"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "newuser"
        assert data["email"] == "new@example.com"
        assert data["is_active"] is True
        assert "id" in data and data["id"] == 1

    def test_create_user_duplicate_username(self, test_client: TestClient, created_user):
        """Integration: Test creating a user with a duplicate username fails."""
        response = test_client.post(
            "/users/",
            json={"username": "testuser", "email": "another@example.com", "password": "password123"}
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "Username already exists"}

    def test_get_user_success(self, test_client: TestClient, created_user):
        """Integration: Test retrieving an existing user."""
        user_id = created_user["id"]
        response = test_client.get(f"/users/{user_id}")
        assert response.status_code == 200
        data = response.json()
        assert data == created_user

    def test_get_user_not_found(self, test_client: TestClient):
        """Integration: Test retrieving a non-existent user returns 404."""
        response = test_client.get("/users/999")
        assert response.status_code == 404
        assert response.json() == {"detail": "User not found"}

# Covers: app.py, models.py
@pytest.mark.integration
class TestItemEndpoints:
    """Integration tests for item-related endpoints."""

    def test_create_item_success(self, test_client: TestClient, created_user):
        """Integration: Test successful item creation."""
        user_id = created_user["id"]
        item_data = {"name": "A new item", "description": "Details here", "price": 99.99}
        response = test_client.post(f"/items/?owner_id={user_id}", json=item_data)
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == item_data["name"]
        assert data["price"] == item_data["price"]
        assert data["owner_id"] == user_id
        assert "id" in data and data["id"] == 1

    def test_create_item_owner_not_found(self, test_client: TestClient):
        """Integration: Test creating an item with a non-existent owner fails."""
        item_data = {"name": "Orphan item", "description": "No owner", "price": 10.0}
        response = test_client.post("/items/?owner_id=999", json=item_data)
        assert response.status_code == 404
        assert response.json() == {"detail": "Owner not found"}

    def test_get_item_success(self, test_client: TestClient, created_user_and_item):
        """Integration: Test retrieving an existing item."""
        user, item = created_user_and_item
        item_id = item["id"]
        response = test_client.get(f"/items/{item_id}")
        assert response.status_code == 200
        assert response.json() == item

    def test_get_item_not_found(self, test_client: TestClient):
        """Integration: Test retrieving a non-existent item returns 404."""
        response = test_client.get("/items/999")
        assert response.status_code == 404
        assert response.json() == {"detail": "Item not found"}

# --- Security and Contract Tests ---

# Covers: app.py, models.py
@pytest.mark.security
class TestSecurity:
    """Security-focused tests."""

    def test_create_user_response_omits_password_hash(self, test_client: TestClient):
        """Security: Ensure password hash is not in the user creation response."""
        response = test_client.post(
            "/users/",
            json={"username": "secureuser", "email": "secure@example.com", "password": "a_secure_password"}
        )
        assert response.status_code == 200
        assert "password" not in response.json()
        assert "password_hash" not in response.json()

    def test_get_user_response_omits_password_hash(self, test_client: TestClient, created_user):
        """Security: Ensure password hash is not in the get user response."""
        user_id = created_user["id"]
        response = test_client.get(f"/users/{user_id}")
        assert response.status_code == 200
        assert "password" not in response.json()
        assert "password_hash" not in response.json()

    def test_create_user_with_long_inputs(self, test_client: TestClient):
        """Security: Test endpoint with very long input strings."""
        long_string = "a" * 1024
        response = test_client.post(
            "/users/",
            json={"username": long_string, "email": f"{long_string}@example.com", "password": long_string}
        )
        # Pydantic v2 will likely fail on email validation, but the goal is to ensure it doesn't crash
        assert response.status_code == 422 # Expecting validation error, not 500

# Covers: app.py, models.py
@pytest.mark.contract
class TestContracts:
    """API contract and validation tests."""

    @pytest.mark.parametrize("payload, expected_detail_part", [
        ({"username": "user", "password": "pw"}, "email"),  # Missing email
        ({"email": "e@e.com", "password": "pw"}, "username"), # Missing username
        ({"username": "user", "email": "e@e.com"}, "password"), # Missing password
    ])
    def test_create_user_missing_fields(self, test_client: TestClient, payload, expected_detail_part):
        """Contract: Test user creation with missing fields returns 422."""
        response = test_client.post("/users/", json=payload)
        assert response.status_code == 422
        assert any(expected_detail_part in err['loc'] for err in response.json()['detail'])

    def test_create_user_invalid_email(self, test_client: TestClient):
        """Contract: Test user creation with an invalid email format."""
        response = test_client.post(
            "/users/",
            json={"username": "bademailuser", "email": "not-an-email", "password": "password123"}
        )
        assert response.status_code == 422
        assert "value is not a valid email address" in response.text

    @pytest.mark.parametrize("price", [-10.50, "not-a-price", None])
    def test_create_item_invalid_price(self, test_client: TestClient, created_user, price):
        """Contract: Test item creation with invalid price types."""
        user_id = created_user["id"]
        item_data = {"name": "Invalid Price Item", "description": "desc", "price": price}
        response = test_client.post(f"/items/?owner_id={user_id}", json=item_data)
        assert response.status_code == 422

    def test_get_user_invalid_id_type(self, test_client: TestClient):
        """Contract: Test GET /users/ with non-integer ID."""
        response = test_client.get("/users/abc")
        assert response.status_code == 422
        assert "Input should be a valid integer" in response.text

    def test_get_item_invalid_id_type(self, test_client: TestClient):
        """Contract: Test GET /items/ with non-integer ID."""
        response = test_client.get("/items/abc")
        assert response.status_code == 422
        assert "Input should be a valid integer" in response.text

    def test_error_response_schema(self, test_client: TestClient):
        """Contract: Verify that 404 errors return a JSON object with a 'detail' field."""
        response = test_client.get("/users/999")
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data
        assert isinstance(data["detail"], str)