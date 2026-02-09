import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

# Import application components to test them directly
from config import Settings
from auth import get_password_hash, verify_password, create_access_token
from models import User

# ==================== UNIT TESTS ====================

@pytest.mark.unit
def test_config_default_debug_is_false():
    """Test that the default value for debug in Settings is False."""
    settings = Settings()
    assert settings.debug is False

@pytest.mark.unit
def test_config_debug_can_be_set_true():
    """Test that the debug value in Settings can be set to True."""
    settings = Settings(debug=True)
    assert settings.debug is True

@pytest.mark.unit
def test_password_hashing_and_verification():
    """Test that password hashing and verification functions work correctly."""
    password = "a_very_secure_password"
    hashed_password = get_password_hash(password)
    assert hashed_password != password
    assert verify_password(password, hashed_password)
    assert not verify_password("wrong_password", hashed_password)

@pytest.mark.unit
def test_create_access_token_logic():
    """Test the logic of creating a JWT access token."""
    token = create_access_token(data={"sub": "testuser"})
    assert isinstance(token, str)
    assert len(token.split('.')) == 3

@pytest.mark.unit
def test_user_model_attributes():
    """Test the attributes of the User model after import refactoring."""
    user = User(username="test", email="test@test.com", hashed_password="abc")
    assert user.username == "test"
    assert user.is_admin is False

# ==================== INTEGRATION TESTS ====================

@pytest.mark.integration
def test_health_endpoint_dev_environment(test_client: TestClient):
    """Test the /health endpoint when debug is True (development)."""
    with patch('config.settings', Settings(debug=True, app_name="TestApp", app_version="0.1")):
        response = test_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["environment"] == "development"

@pytest.mark.integration
def test_health_endpoint_prod_environment(test_client: TestClient):
    """Test the /health endpoint when debug is False (production)."""
    with patch('config.settings', Settings(debug=False, app_name="TestApp", app_version="0.1")):
        response = test_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["environment"] == "production"

@pytest.mark.integration
def test_user_registration_and_login_flow(test_client: TestClient):
    """Smoke test for user registration and login to verify import refactoring."""
    # Register
    reg_response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "smokeuser", "email": "smoke@example.com", "password": "a_good_password"}
    )
    assert reg_response.status_code == 201
    assert reg_response.json()["username"] == "smokeuser"

    # Login
    login_response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "smokeuser", "password": "a_good_password"}
    )
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()

@pytest.mark.integration
def test_item_creation_and_retrieval_flow(test_client: TestClient, admin_headers: dict):
    """Smoke test for item creation to verify service/model imports."""
    item_data = {"name": "Test Item", "description": "A test item", "price": 9.99, "stock": 100}
    create_response = test_client.post("/api/v1/items", json=item_data, headers=admin_headers)
    assert create_response.status_code == 201
    created_item = create_response.json()
    assert created_item["name"] == item_data["name"]

    get_response = test_client.get(f"/api/v1/items/{created_item['id']}")
    assert get_response.status_code == 200
    assert get_response.json()["name"] == item_data["name"]

@pytest.mark.integration
def test_root_endpoint(test_client: TestClient):
    """Test the root endpoint to ensure the app is running."""
    response = test_client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the FastAPI E-commerce API"}

# ==================== SECURITY TESTS ====================

@pytest.mark.security
def test_health_endpoint_does_not_expose_secrets(test_client: TestClient):
    """Verify the /health endpoint does not expose sensitive configuration."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    sensitive_keys = ["database_url", "secret_key", "password", "token"]
    for key in data.keys():
        for sensitive in sensitive_keys:
            assert sensitive not in key.lower()

@pytest.mark.security
def test_unauthenticated_access_to_protected_route(test_client: TestClient):
    """Test that protected routes require authentication."""
    response = test_client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert "Not authenticated" in response.json()["detail"]

@pytest.mark.security
def test_regular_user_cannot_access_admin_route(test_client: TestClient, auth_headers: dict):
    """Test that admin-only routes are protected from regular users."""
    item_data = {"name": "Another Item", "price": 1.00, "stock": 1}
    response = test_client.post("/api/v1/items", json=item_data, headers=auth_headers)
    assert response.status_code == 403
    assert "Admin required" in response.json()["detail"]

@pytest.mark.security
def test_login_with_sql_injection_payload(test_client: TestClient):
    """Test login endpoint against a basic SQL injection attempt."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "admin' OR '1'='1", "password": "password"}
    )
    assert response.status_code == 401
    assert "Incorrect username or password" in response.json()["detail"]

# ==================== CONTRACT TESTS ====================

@pytest.mark.contract
def test_health_endpoint_contract(test_client: TestClient):
    """Verify the schema and data types of the /health endpoint response."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    
    expected_keys = {"status", "version", "app", "environment"}
    assert set(data.keys()) == expected_keys
    
    assert isinstance(data["status"], str)
    assert data["status"] == "healthy"
    assert isinstance(data["version"], str)
    assert isinstance(data["app"], str)
    assert isinstance(data["environment"], str)
    assert data["environment"] in ["development", "production"]

@pytest.mark.contract
def test_user_me_endpoint_contract(test_client: TestClient, auth_headers: dict):
    """Verify the schema of the /api/v1/auth/me endpoint."""
    response = test_client.get("/api/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    
    expected_keys = {"id", "username", "email", "is_active", "is_admin"}
    assert set(data.keys()) == expected_keys
    
    assert isinstance(data["id"], int)
    assert isinstance(data["username"], str)
    assert isinstance(data["email"], str)
    assert isinstance(data["is_active"], bool)
    assert isinstance(data["is_admin"], bool)

@pytest.mark.contract
def test_invalid_item_creation_contract(test_client: TestClient, admin_headers: dict):
    """Test the error contract for creating an item with invalid data."""
    # Missing 'price' field
    invalid_data = {"name": "Invalid Item", "stock": 10}
    response = test_client.post("/api/v1/items", json=invalid_data, headers=admin_headers)
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    assert isinstance(data["detail"], list)
    assert data["detail"][0]["msg"] == "Field required"
    assert "price" in data["detail"][0]["loc"]