import pytest
from fastapi.testclient import TestClient
from backend.config import settings
from backend.auth import verify_password, get_password_hash

# ==================== UNIT TESTS ====================

@pytest.mark.unit
def test_config_loads_correct_version():
    """Test that the Settings class loads the new app_version correctly."""
    assert settings.app_version == "2.0.1"

@pytest.mark.unit
def test_config_loads_other_settings():
    """Test that other settings are loaded as expected."""
    assert settings.app_name == "My FastAPI App"
    assert settings.access_token_expire_minutes == 30

@pytest.mark.unit
def test_password_hashing_and_verification():
    """Test that password hashing and verification utilities work correctly."""
    password = "a_secure_password_123!"
    hashed_password = get_password_hash(password)
    assert hashed_password != password
    assert verify_password(password, hashed_password) is True
    assert verify_password("wrong_password", hashed_password) is False

# ==================== CONTRACT TESTS ====================

@pytest.mark.contract
def test_info_endpoint_returns_correct_version(test_client: TestClient):
    """Test the /info endpoint to verify it reports the correct app version."""
    response = test_client.get("/api/v1/info")
    assert response.status_code == 200
    data = response.json()
    assert data["app_version"] == "2.0.1"

@pytest.mark.contract
def test_info_endpoint_schema(test_client: TestClient):
    """Test the schema of the /info endpoint response."""
    response = test_client.get("/api/v1/info")
    assert response.status_code == 200
    data = response.json()
    assert "app_name" in data
    assert "app_version" in data
    assert "admin_email" in data
    assert isinstance(data["app_name"], str)
    assert isinstance(data["app_version"], str)

@pytest.mark.contract
def test_login_response_schema(test_client: TestClient, test_user):
    """Test that the login response schema is correct."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "testpass123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "token_type" in data
    assert data["token_type"] == "bearer"

# ==================== INTEGRATION TESTS ====================

@pytest.mark.integration
def test_app_startup_and_root_endpoint(test_client: TestClient):
    """Test that the application starts and the root endpoint is available."""
    response = test_client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "API is running"}

@pytest.mark.integration
def test_user_registration(test_client: TestClient):
    """Test the full user registration flow as a smoke test."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "SecurePassword123"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newuser"
    assert "hashed_password" not in data

@pytest.mark.integration
def test_get_current_user(test_client: TestClient, auth_headers, test_user):
    """Test the /auth/me endpoint to ensure authentication works."""
    response = test_client.get("/api/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == test_user.username
    assert data["email"] == test_user.email

@pytest.mark.integration
def test_get_items_public_endpoint(test_client: TestClient):
    """Test a public endpoint to ensure it remains accessible."""
    response = test_client.get("/api/v1/items")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

# ==================== SECURITY TESTS ====================

@pytest.mark.security
def test_access_protected_endpoint_without_token(test_client: TestClient):
    """Test that accessing a protected endpoint without a token fails."""
    response = test_client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

@pytest.mark.security
def test_access_protected_endpoint_with_invalid_token(test_client: TestClient):
    """Test that an invalid or malformed token is rejected."""
    headers = {"Authorization": "Bearer invalidtoken"}
    response = test_client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 401
    assert "Invalid authentication credentials" in response.json()["detail"]

@pytest.mark.security
def test_register_with_existing_username(test_client: TestClient, test_user):
    """Test that registering with a username that already exists fails."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={
            "username": "testuser",
            "email": "another@example.com",
            "password": "AnotherPassword123"
        }
    )
    assert response.status_code == 400
    assert "Username already registered" in response.json()["detail"]

@pytest.mark.security
def test_login_with_wrong_password(test_client: TestClient, test_user):
    """Test that login fails with an incorrect password."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert "Incorrect username or password" in response.json()["detail"]

@pytest.mark.security
def test_unauthorized_item_creation(test_client: TestClient, auth_headers):
    """Test that a non-admin user cannot create an item (assuming it's an admin-only action)."""
    response = test_client.post(
        "/api/v1/items",
        json={"name": "Forbidden Item", "price": 99.99},
        headers=auth_headers
    )
    # This assumes creating items is restricted to admins.
    # If not, the expected status code would be 201.
    assert response.status_code == 403
    assert "Not enough permissions" in response.json()["detail"]