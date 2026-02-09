import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from datetime import datetime, timezone

# Import all necessary components from the application source
# These imports must be absolute as per the instructions
from utils import hash_password, verify_password, get_timestamp, validate_email
from models import User, UserCreate, Item
from app import app, users_db, items_db

# --- Unit Tests for utils.py ---

@pytest.mark.unit
def test_hash_password_consistency():
    """Unit(utils.py): Tests that hash_password produces a consistent hash for the same input."""
    password = "mysecretpassword"
    hash1 = hash_password(password)
    hash2 = hash_password(password)
    assert hash1 == hash2
    assert isinstance(hash1, str)
    assert len(hash1) == 64  # SHA-256 hex digest length

@pytest.mark.unit
def test_hash_password_is_different_for_different_passwords():
    """Unit(utils.py): Tests that different passwords produce different hashes."""
    assert hash_password("pass1") != hash_password("pass2")

@pytest.mark.unit
def test_verify_password_correct():
    """Unit(utils.py): Tests that verify_password returns True for a correct password."""
    password = "correct_password"
    hashed = hash_password(password)
    assert verify_password(password, hashed) is True

@pytest.mark.unit
def test_verify_password_incorrect():
    """Unit(utils.py): Tests that verify_password returns False for an incorrect password."""
    password = "correct_password"
    hashed = hash_password(password)
    assert verify_password("incorrect_password", hashed) is False

@pytest.mark.unit
def test_get_timestamp_format():
    """Unit(utils.py): Tests that get_timestamp returns a string in valid ISO 8601 format."""
    ts = get_timestamp()
    assert isinstance(ts, str)
    parsed_ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
    assert parsed_ts.tzinfo is not None

@pytest.mark.unit
@pytest.mark.parametrize("email", ["test@example.com", "user.name@domain.co.uk"])
def test_validate_email_valid(email):
    """Unit(utils.py): Tests validate_email with valid email formats."""
    assert validate_email(email) is True

@pytest.mark.unit
@pytest.mark.parametrize("email", ["plainaddress", "user@", "@domain.com", "user@.com"])
def test_validate_email_invalid(email):
    """Unit(utils.py): Tests validate_email with invalid email formats."""
    assert validate_email(email) is False

# --- Unit/Contract Tests for models.py ---

@pytest.mark.unit
def test_user_create_model_valid():
    """Unit(models.py): Tests successful creation of a UserCreate instance."""
    user_data = {"username": "modeluser", "email": "model@test.com", "password": "a_valid_password"}
    instance = UserCreate(**user_data)
    assert instance.username == user_data["username"]
    assert instance.email == user_data["email"]
    assert instance.password == user_data["password"]

@pytest.mark.unit
def test_user_create_model_invalid_email():
    """Unit(models.py): Tests that UserCreate raises a validation error for an invalid email."""
    with pytest.raises(ValidationError):
        UserCreate(username="test", email="not-an-email", password="password")

@pytest.mark.contract
def test_user_model_schema():
    """Contract(models.py): Ensures the User model has the correct fields and excludes password."""
    user_data = {"id": 1, "username": "test", "email": "test@test.com", "is_active": True}
    instance = User(**user_data)
    assert hasattr(instance, "id")
    assert not hasattr(instance, "password")
    assert not hasattr(instance, "password_hash")

@pytest.mark.unit
def test_item_model_invalid_price():
    """Unit(models.py): Tests that Item model raises a validation error for a non-float price."""
    with pytest.raises(ValidationError):
        Item(name="Test Item", description="Desc", price="not-a-price")

# --- Integration, Security, and Contract Tests for app.py ---

@pytest.mark.integration
def test_read_root(test_client: TestClient):
    """Integration(app.py): Tests the root endpoint for a successful response."""
    response = test_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "timestamp" in data

@pytest.mark.integration
def test_create_user_success(test_client: TestClient):
    """Integration(app.py): Tests successful user creation."""
    user_data = {"username": "newuser", "email": "new@example.com", "password": "StrongPassword123"}
    response = test_client.post("/users/", json=user_data)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "new@example.com"
    assert data["is_active"] is True
    # Verify user is in the 'database'
    assert 1 in users_db
    assert users_db[1]["username"] == "newuser"

@pytest.mark.security
def test_create_user_response_hides_password(test_client: TestClient):
    """Security(app.py): Verifies the user creation response does not include any password field."""
    user_data = {"username": "secuser", "email": "sec@example.com", "password": "MyPassword"}
    response = test_client.post("/users/", json=user_data)
    assert response.status_code == 200
    data = response.json()
    assert "password" not in data
    assert "password_hash" not in data

@pytest.mark.security
def test_create_user_stores_hashed_password(test_client: TestClient):
    """Security(app.py): Verifies the user's password is not stored in plaintext."""
    password = "PlaintextPassword"
    user_data = {"username": "hashuser", "email": "hash@example.com", "password": password}
    test_client.post("/users/", json=user_data)
    
    assert 1 in users_db
    stored_user = users_db[1]
    assert "password_hash" in stored_user
    assert stored_user["password_hash"] != password
    assert verify_password(password, stored_user["password_hash"])

@pytest.mark.integration
def test_create_user_duplicate_username(test_client: TestClient, created_user):
    """Integration(app.py): Tests that creating a user with a duplicate username fails."""
    duplicate_data = {"username": "testuser", "email": "another@example.com", "password": "anotherpassword"}
    response = test_client.post("/users/", json=duplicate_data)
    assert response.status_code == 400
    assert response.json() == {"detail": "Username already exists"}

@pytest.mark.contract
@pytest.mark.parametrize("payload, missing_field", [
    ({"email": "a@b.com", "password": "pw"}, "username"),
    ({"username": "user", "password": "pw"}, "email"),
    ({"username": "user", "email": "a@b.com"}, "password"),
])
def test_create_user_missing_fields(test_client: TestClient, payload, missing_field):
    """Contract(app.py): Tests for 422 error when required fields are missing for user creation."""
    response = test_client.post("/users/", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert data["detail"][0]["msg"] == "Field required"
    assert data["detail"][0]["loc"] == ["body", missing_field]

@pytest.mark.integration
def test_get_user_success(test_client: TestClient, created_user):
    """Integration(app.py): Tests successfully retrieving an existing user."""
    user_id = created_user["id"]
    response = test_client.get(f"/users/{user_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == user_id
    assert data["username"] == created_user["username"]

@pytest.mark.integration
def test_get_user_not_found(test_client: TestClient):
    """Integration(app.py): Tests retrieving a non-existent user results in a 404."""
    response = test_client.get("/users/999")
    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

@pytest.mark.contract
def test_get_user_invalid_id(test_client: TestClient):
    """Contract(app.py): Tests that a non-integer user ID results in a 422 error."""
    response = test_client.get("/users/abc")
    assert response.status_code == 422

@pytest.mark.integration
def test_create_item_success(test_client: TestClient, created_user):
    """Integration(app.py): Tests successful item creation for an existing user."""
    owner_id = created_user["id"]
    item_data = {"name": "Test Item", "description": "A cool item", "price": 19.99}
    response = test_client.post(f"/items/?owner_id={owner_id}", json=item_data)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == item_data["name"]
    assert data["price"] == item_data["price"]
    assert data["owner_id"] == owner_id
    assert 1 in items_db

@pytest.mark.integration
def test_create_item_owner_not_found(test_client: TestClient):
    """Integration(app.py): Tests that creating an item for a non-existent owner fails."""
    non_existent_owner_id = 999
    item_data = {"name": "Orphan Item", "price": 10.0}
    response = test_client.post(f"/items/?owner_id={non_existent_owner_id}", json=item_data)
    assert response.status_code == 404
    assert response.json() == {"detail": "Owner not found"}

@pytest.mark.contract
def test_create_item_invalid_payload(test_client: TestClient, created_user):
    """Contract(app.py): Tests for 422 error with invalid item data types."""
    owner_id = created_user["id"]
    item_data = {"name": "Invalid Item", "price": "not-a-number"}
    response = test_client.post(f"/items/?owner_id={owner_id}", json=item_data)
    assert response.status_code == 422

@pytest.mark.integration
def test_get_item_success(test_client: TestClient, created_user):
    """Integration(app.py): Tests successfully retrieving an existing item."""
    owner_id = created_user["id"]
    item_data = {"name": "My Item", "price": 50.0}
    create_response = test_client.post(f"/items/?owner_id={owner_id}", json=item_data)
    item_id = create_response.json()["id"]

    get_response = test_client.get(f"/items/{item_id}")
    assert get_response.status_code == 200
    data = get_response.json()
    assert data["id"] == item_id
    assert data["name"] == "My Item"

@pytest.mark.integration
def test_get_item_not_found(test_client: TestClient):
    """Integration(app.py): Tests retrieving a non-existent item results in a 404."""
    response = test_client.get("/items/999")
    assert response.status_code == 404
    assert response.json() == {"detail": "Item not found"}

@pytest.mark.security
@pytest.mark.parametrize("field, payload", [
    ("username", {"username": "' OR 1=1; --", "email": "a@b.com", "password": "pw"}),
    ("email", {"username": "test", "email": "' OR 1=1; --", "password": "pw"}),
])
def test_sql_injection_like_inputs_on_user_creation(test_client: TestClient, field, payload):
    """Security(app.py): Tests that SQLi-like strings in user creation are handled as literals."""
    response = test_client.post("/users/", json=payload)
    # Expect 200 OK because the app should create the user with the literal string
    # (or 422 if email validation catches it, which is also a pass)
    assert response.status_code in [200, 422]
    if response.status_code == 200:
        user_id = response.json()["id"]
        assert users_db[user_id][field] == payload[field]

@pytest.mark.security
def test_xss_payload_in_item_description(test_client: TestClient, created_user):
    """Security(app.py): Tests that XSS-like strings in item fields are handled as literals."""
    owner_id = created_user["id"]
    xss_payload = "<script>alert('XSS')</script>"
    item_data = {"name": "XSS Item", "description": xss_payload, "price": 1.0}
    response = test_client.post(f"/items/?owner_id={owner_id}", json=item_data)
    assert response.status_code == 200
    item_id = response.json()["id"]
    assert items_db[item_id]["description"] == xss_payload