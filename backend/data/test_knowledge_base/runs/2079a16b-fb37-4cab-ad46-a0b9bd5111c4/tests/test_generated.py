import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone

# Assuming conftest.py is in the same directory and sets up the path
# These imports will work because of the sys.path modification in conftest.py
from utils import hash_password, verify_password, get_timestamp, validate_email
from models import User, UserCreate, Item

# --- Unit Tests ---
# These tests focus on individual functions in isolation.

# Covers: utils.py
@pytest.mark.unit
def test_hash_password_is_deterministic():
    """Unit: Tests that hash_password function is deterministic (same input -> same output)."""
    assert hash_password("secure_pass_123") == hash_password("secure_pass_123")

# Covers: utils.py
@pytest.mark.unit
def test_hash_password_is_different_for_different_passwords():
    """Unit: Tests that different passwords produce different hashes."""
    assert hash_password("secure_pass_123") != hash_password("different_pass_456")

# Covers: utils.py
@pytest.mark.unit
def test_verify_password_correct_and_incorrect():
    """Unit: Tests verify_password for both correct and incorrect passwords."""
    password = "MyPassword"
    hashed = hash_password(password)
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword", hashed) is False

# Covers: utils.py
@pytest.mark.unit
def test_get_timestamp_format():
    """Unit: Tests that get_timestamp returns a valid ISO 8601 formatted string."""
    ts = get_timestamp()
    assert isinstance(ts, str)
    # Check if it can be parsed back to a datetime object
    parsed_ts = datetime.fromisoformat(ts)
    assert parsed_ts.tzinfo is not None

# Covers: utils.py
@pytest.mark.unit
@pytest.mark.parametrize("email, is_valid", [
    ("test@example.com", True),
    ("user.name@domain.co.uk", True),
    ("test.example.com", False),
    ("test@.com", False),
    ("@example.com", False),
    ("test@domain", False),
])
def test_validate_email(email, is_valid):
    """Unit: Tests the basic email validation logic with various cases."""
    assert validate_email(email) == is_valid

# Covers: models.py
@pytest.mark.unit
def test_pydantic_user_create_model():
    """Unit: Tests the UserCreate Pydantic model validation."""
    user_data = {"username": "test_user", "email": "test@example.com", "password": "password"}
    user = UserCreate(**user_data)
    assert user.username == "test_user"
    assert user.email == "test@example.com"
    assert user.password == "password"

# --- Integration and Contract Tests ---
# These tests check the behavior of the API endpoints.

# Covers: app.py
@pytest.mark.integration
def test_read_root(client: TestClient):
    """Integration: Test the root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the User and Item Management API"}

# Covers: app.py
@pytest.mark.integration
def test_create_user_success(client: TestClient):
    """Integration: Test successful user creation."""
    response = client.post("/users/", json={"username": "john_doe", "email": "john.doe@example.com", "password": "a_strong_password"})
    assert response.status_code == 200 # Per app.py, it returns 200, not 201
    data = response.json()
    assert data["username"] == "john_doe"
    assert data["email"] == "john.doe@example.com"
    assert data["is_active"] is True
    assert "password_hash" not in data
    assert "password" not in data

# Covers: app.py
@pytest.mark.integration
def test_create_user_duplicate_username(client: TestClient):
    """Integration: Test creating a user with a username that already exists."""
    client.post("/users/", json={"username": "jane_doe", "email": "jane.doe@example.com", "password": "password123"})
    response = client.post("/users/", json={"username": "jane_doe", "email": "another.email@example.com", "password": "password456"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Username already exists"}

# Covers: app.py
@pytest.mark.integration
def test_get_user_success(client: TestClient):
    """Integration: Test retrieving an existing user by ID."""
    create_response = client.post("/users/", json={"username": "test_user", "email": "test@example.com", "password": "password"})
    user_id = create_response.json()["id"]
    
    response = client.get(f"/users/{user_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == user_id
    assert data["username"] == "test_user"

# Covers: app.py
@pytest.mark.integration
def test_get_user_not_found(client: TestClient):
    """Integration: Test retrieving a non-existent user."""
    response = client.get("/users/999")
    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

# Covers: app.py
@pytest.mark.integration
def test_create_item_success(client: TestClient):
    """Integration: Test successful item creation for an existing user."""
    user_response = client.post("/users/", json={"username": "item_owner", "email": "owner@example.com", "password": "password"})
    owner_id = user_response.json()["id"]

    item_data = {"name": "Magic Wand", "description": "A wand of great power", "price": 199.99}
    response = client.post(f"/items/?owner_id={owner_id}", json=item_data)
    
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Magic Wand"
    assert data["price"] == 199.99
    assert data["owner_id"] == owner_id

# Covers: app.py
@pytest.mark.integration
def test_create_item_owner_not_found(client: TestClient):
    """Integration: Test creating an item with a non-existent owner ID."""
    item_data = {"name": "Orphaned Item", "description": "This item has no owner", "price": 10.0}
    response = client.post("/items/?owner_id=999", json=item_data)
    assert response.status_code == 404
    assert response.json() == {"detail": "Owner not found"}

# Covers: app.py
@pytest.mark.integration
def test_get_item_success(client: TestClient):
    """Integration: Test retrieving an existing item by ID."""
    user_response = client.post("/users/", json={"username": "item_owner_2", "email": "owner2@example.com", "password": "password"})
    owner_id = user_response.json()["id"]
    item_data = {"name": "Test Sword", "description": "A sharp sword", "price": 50.0}
    item_response = client.post(f"/items/?owner_id={owner_id}", json=item_data)
    item_id = item_response.json()["id"]

    response = client.get(f"/items/{item_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == item_id
    assert data["name"] == "Test Sword"

# Covers: app.py
@pytest.mark.integration
def test_get_item_not_found(client: TestClient):
    """Integration: Test retrieving a non-existent item."""
    response = client.get("/items/999")
    assert response.status_code == 404
    assert response.json() == {"detail": "Item not found"}

# Covers: app.py, models.py
@pytest.mark.contract
@pytest.mark.parametrize("payload", [
    {"username": "user1"}, # Missing email and password
    {"email": "user1@e.com", "password": "p"}, # Missing username
    {"username": "user1", "email": "not-an-email", "password": "p"}, # Invalid email
])
def test_create_user_invalid_payload(client: TestClient, payload):
    """Contract: Test user creation with invalid/incomplete payloads (422)."""
    response = client.post("/users/", json=payload)
    assert response.status_code == 422

# Covers: app.py, models.py
@pytest.mark.contract
@pytest.mark.parametrize("payload", [
    {"name": "Item1"}, # Missing price
    {"name": "Item1", "price": "not-a-float"}, # Invalid price type
])
def test_create_item_invalid_payload(client: TestClient, payload):
    """Contract: Test item creation with invalid/incomplete payloads (422)."""
    # Need a valid owner first
    user_response = client.post("/users/", json={"username": "owner3", "email": "owner3@example.com", "password": "password"})
    owner_id = user_response.json()["id"]
    
    response = client.post(f"/items/?owner_id={owner_id}", json=payload)
    assert response.status_code == 422

# Covers: app.py
@pytest.mark.contract
def test_user_response_schema(client: TestClient):
    """Contract: Verify the user response schema excludes sensitive data."""
    response = client.post("/users/", json={"username": "schema_user", "email": "schema@example.com", "password": "password"})
    assert response.status_code == 200
    data = response.json()
    assert list(data.keys()) == ["id", "username", "email", "is_active"]

# Covers: app.py
@pytest.mark.contract
def test_item_response_schema(client: TestClient):
    """Contract: Verify the item response schema."""
    user_response = client.post("/users/", json={"username": "schema_owner", "email": "schema_owner@example.com", "password": "password"})
    owner_id = user_response.json()["id"]
    item_data = {"name": "Schema Item", "description": "A test item", "price": 1.0}
    response = client.post(f"/items/?owner_id={owner_id}", json=item_data)
    assert response.status_code == 200
    data = response.json()
    assert list(data.keys()) == ["id", "name", "description", "price", "owner_id"]

# --- Security Tests ---
# These tests focus on potential security vulnerabilities.

# Covers: app.py
@pytest.mark.security
def test_security_password_hash_not_in_any_user_response(client: TestClient):
    """Security: Ensure password hash is NEVER returned by user endpoints."""
    create_response = client.post("/users/", json={"username": "secure_user", "email": "secure@example.com", "password": "a_very_secure_password"})
    assert "password_hash" not in create_response.json()
    assert "password" not in create_response.json()
    
    user_id = create_response.json()["id"]
    get_response = client.get(f"/users/{user_id}")
    assert "password_hash" not in get_response.json()
    assert "password" not in get_response.json()

# Covers: app.py
@pytest.mark.security
def test_security_no_authentication_required(client: TestClient):
    """Security: Confirm that critical endpoints are currently unprotected (vulnerability check)."""
    # This test confirms the current insecure design. It should fail once auth is added.
    user_response = client.post("/users/", json={"username": "unauth_user", "email": "unauth@example.com", "password": "password"})
    assert user_response.status_code == 200
    user_id = user_response.json()["id"]

    item_response = client.post(f"/items/?owner_id={user_id}", json={"name": "Unauth Item", "price": 0})
    assert item_response.status_code == 200

    get_user_response = client.get(f"/users/{user_id}")
    assert get_user_response.status_code == 200

# Covers: app.py
@pytest.mark.security
def test_security_user_id_enumeration(client: TestClient):
    """Security: Check for user ID enumeration vulnerability."""
    client.post("/users/", json={"username": "user_zero", "email": "zero@example.com", "password": "password"})
    client.post("/users/", json={"username": "user_one", "email": "one@example.com", "password": "password"})
    
    # Because IDs are sequential and predictable, anyone can guess them.
    response_zero = client.get("/users/0")
    assert response_zero.status_code == 200
    assert response_zero.json()["username"] == "user_zero"

    response_one = client.get("/users/1")
    assert response_one.status_code == 200
    assert response_one.json()["username"] == "user_one"

# Covers: app.py
@pytest.mark.security
@pytest.mark.parametrize("xss_string", ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"])
def test_security_xss_in_username(client: TestClient, xss_string):
    """Security: Test for XSS vulnerabilities in username field."""
    response = client.post("/users/", json={"username": xss_string, "email": "xss@example.com", "password": "password"})
    assert response.status_code == 200 # The app accepts it
    data = response.json()
    # FastAPI/Pydantic should escape this, but we verify the data is stored as sent.
    # The vulnerability would be on a frontend that renders this without escaping.
    assert data["username"] == xss_string

# Covers: app.py
@pytest.mark.security
@pytest.mark.parametrize("sql_injection_string", ["' OR 1=1; --", "admin'--"])
def test_security_sql_injection_in_username(client: TestClient, sql_injection_string):
    """Security: Test for SQL injection patterns in username (should be treated as literal string)."""
    # Since it's not a SQL DB, this just checks that the string is handled literally.
    response = client.post("/users/", json={"username": sql_injection_string, "email": "sqli@example.com", "password": "password"})
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == sql_injection_string