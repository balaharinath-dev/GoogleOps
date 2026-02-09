import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from jose import jwt
from datetime import timedelta

# Import key components using absolute paths
from config import settings, Settings
from auth import (
    verify_password,
    get_password_hash,
    create_access_token,
    get_current_user,
    get_current_active_user,
    get_current_admin_user
)
from main import app
from models import User

# --- Test Categories ---
# - unit: Test individual functions or classes in isolation.
# - integration: Test how multiple components work together.
# - security: Test for vulnerabilities like auth bypass, data exposure.
# - contract: Test API request/response schemas and status codes.


# === Health Check & Config Tests (Primary Change) ===

@pytest.mark.integration
def test_health_check_endpoint_success(test_client: TestClient):
    """Integration: Test that the /health endpoint returns a 200 OK status."""
    response = test_client.get("/health")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

@pytest.mark.integration
def test_health_check_default_environment_is_production(test_client: TestClient):
    """Integration: Verify the 'environment' is 'production' by default."""
    # The default setting for debug is False
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["environment"] == "production", "Default environment should be production"

@pytest.mark.integration
def test_health_check_dev_environment_when_debug_is_true(test_client: TestClient):
    """Integration: Verify 'environment' is 'development' when debug is True."""
    with patch("main.settings.debug", True):
        response = test_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["environment"] == "development", "Environment should be development when debug is True"

@pytest.mark.contract
def test_health_check_response_schema(test_client: TestClient):
    """Contract: Validate the precise schema of the /health endpoint response."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    expected_keys = {"status", "version", "app", "environment"}
    assert set(data.keys()) == expected_keys, f"Response keys mismatch. Expected {expected_keys}, got {set(data.keys())}"

@pytest.mark.contract
def test_health_check_response_data_types(test_client: TestClient):
    """Contract: Validate the data types of the /health endpoint response fields."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["status"], str)
    assert isinstance(data["version"], str)
    assert isinstance(data["app"], str)
    assert isinstance(data["environment"], str)

@pytest.mark.security
def test_health_endpoint_does_not_expose_sensitive_config(test_client: TestClient):
    """Security: Ensure the /health endpoint does not leak sensitive information."""
    response = test_client.get("/health")
    data = response.json()
    sensitive_keys = {"database_url", "secret_key", "algorithm"}
    for key in sensitive_keys:
        assert key not in data, f"Sensitive key '{key}' found in /health response"

@pytest.mark.unit
def test_settings_model_defaults():
    """Unit: Test that the Pydantic Settings model has correct default values."""
    s = Settings()
    assert s.app_name == "My FastAPI App"
    assert s.debug is False, "Debug should be False by default"
    assert s.environment == "production", "Environment should be 'production' by default"

@pytest.mark.unit
def test_settings_model_environment_override(monkeypatch):
    """Unit: Test that settings can be overridden by environment variables."""
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("APP_NAME", "Test App")
    s = Settings()
    assert s.debug is True
    assert s.app_name == "Test App"
    assert s.environment == "development"


# === Auth and Service Smoke Tests (Verify Refactoring) ===

@pytest.mark.unit
def test_password_hashing_and_verification():
    """Unit: Test password hashing and verification functions."""
    password = "a_secure_password_123"
    hashed_password = get_password_hash(password)
    assert hashed_password != password, "Hashed password should not be the same as plain text"
    assert verify_password(password, hashed_password), "Verification should succeed with correct password"
    assert not verify_password("wrong_password", hashed_password), "Verification should fail with incorrect password"

@pytest.mark.integration
def test_user_registration_smoke_test(test_client: TestClient):
    """Integration (Smoke): Test user registration to ensure it's functional after refactoring."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "smoketestuser", "email": "smoke@test.com", "password": "aValidPassword123"}
    )
    assert response.status_code == 201, f"Registration smoke test failed: {response.text}"
    data = response.json()
    assert data["username"] == "smoketestuser"
    assert "hashed_password" not in data

@pytest.mark.integration
def test_user_login_smoke_test(test_client: TestClient, test_user):
    """Integration (Smoke): Test user login to ensure it's functional after refactoring."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "TestPass123"}
    )
    assert response.status_code == 200, f"Login smoke test failed: {response.text}"
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

@pytest.mark.integration
def test_get_items_smoke_test(test_client: TestClient, sample_item):
    """Integration (Smoke): Test fetching items to ensure item service is functional."""
    response = test_client.get("/api/v1/items/")
    assert response.status_code == 200, f"GET /items smoke test failed: {response.text}"
    assert len(response.json()) > 0

@pytest.mark.integration
def test_create_order_smoke_test(test_client: TestClient, auth_headers, sample_item):
    """Integration (Smoke): Test creating an order to ensure order service is functional."""
    response = test_client.post(
        "/api/v1/orders/",
        headers=auth_headers,
        json={"items": [{"item_id": sample_item.id, "quantity": 1}]}
    )
    assert response.status_code == 201, f"Create order smoke test failed: {response.text}"
    assert response.json()["total_price"] == sample_item.price


# === Comprehensive Security Tests ===

@pytest.mark.security
def test_access_protected_route_without_token(test_client: TestClient):
    """Security: Verify that accessing a protected route without a token fails."""
    response = test_client.get("/api/v1/users/me")
    assert response.status_code == 401, "Accessing protected route without token should be 401 Unauthorized"
    assert response.json()["detail"] == "Not authenticated"

@pytest.mark.security
def test_access_protected_route_with_invalid_token(test_client: TestClient):
    """Security: Verify that accessing a protected route with a malformed token fails."""
    headers = {"Authorization": "Bearer an-invalid-token"}
    response = test_client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401, "Accessing protected route with invalid token should be 401"

@pytest.mark.security
def test_access_protected_route_with_expired_token(test_client: TestClient, test_user):
    """Security: Verify that accessing a protected route with an expired token fails."""
    expired_token = create_access_token(
        data={"sub": test_user.username}, expires_delta=timedelta(minutes=-5)
    )
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = test_client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401, "Accessing protected route with expired token should be 401"
    assert "token has expired" in response.json()["detail"].lower()

@pytest.mark.security
def test_admin_route_access_by_regular_user(test_client: TestClient, auth_headers):
    """Security: Verify a regular user cannot access an admin-only route."""
    response = test_client.get("/api/v1/users/", headers=auth_headers)
    assert response.status_code == 403, "Regular user should get 403 Forbidden on admin routes"
    assert response.json()["detail"] == "The user doesn't have enough privileges"

@pytest.mark.security
def test_admin_route_access_by_admin_user(test_client: TestClient, admin_headers):
    """Security: Verify an admin user CAN access an admin-only route."""
    response = test_client.get("/api/v1/users/", headers=admin_headers)
    assert response.status_code == 200, "Admin user should be able to access admin routes"

@pytest.mark.security
@pytest.mark.parametrize("payload", ["' OR 1=1 --", "admin'--", "'; SELECT * FROM users; --"])
def test_sql_injection_in_login(test_client: TestClient, payload):
    """Security: Attempt basic SQL injection in login form."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": payload, "password": "password"}
    )
    # Expect authentication to fail, not a 500 server error
    assert response.status_code in [401, 404], f"SQLi attempt should not cause a server error. Got {response.status_code}"

@pytest.mark.security
def test_password_not_in_user_responses(test_client: TestClient, admin_headers, test_user):
    """Security: Ensure hashed_password is not returned from user endpoints."""
    # Test /users/me
    response_me = test_client.get("/api/v1/users/me", headers=admin_headers)
    assert response_me.status_code == 200
    assert "hashed_password" not in response_me.json(), "Hashed password exposed in /users/me"

    # Test /users/{user_id}
    response_id = test_client.get(f"/api/v1/users/{test_user.id}", headers=admin_headers)
    assert response_id.status_code == 200
    assert "hashed_password" not in response_id.json(), "Hashed password exposed in /users/{user_id}"


# === Edge Case and Failure Path Tests ===

@pytest.mark.integration
def test_register_duplicate_username(test_client: TestClient, test_user):
    """Integration: Test registering with a username that already exists."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "testuser", "email": "new@example.com", "password": "aValidPassword123"}
    )
    assert response.status_code == 400, "Should not be able to register with a duplicate username"
    assert "Username already registered" in response.json()["detail"]

@pytest.mark.integration
def test_register_duplicate_email(test_client: TestClient, test_user):
    """Integration: Test registering with an email that already exists."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "newuser", "email": "test@example.com", "password": "aValidPassword123"}
    )
    assert response.status_code == 400, "Should not be able to register with a duplicate email"
    assert "Email already registered" in response.json()["detail"]

@pytest.mark.integration
def test_login_with_inactive_user(test_client: TestClient, inactive_user):
    """Integration: Test that an inactive user cannot log in."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "inactive", "password": "InactPass123"}
    )
    assert response.status_code == 401, "Inactive user should not be able to log in"
    assert "Inactive user" in response.json()["detail"]

@pytest.mark.integration
def test_get_nonexistent_item(test_client: TestClient):
    """Integration: Test requesting an item that does not exist."""
    response = test_client.get("/api/v1/items/99999")
    assert response.status_code == 404, "Requesting a non-existent item should return 404 Not Found"
    assert "Item not found" in response.json()["detail"]

@pytest.mark.integration
def test_create_order_with_nonexistent_item(test_client: TestClient, auth_headers):
    """Integration: Test creating an order with an item ID that does not exist."""
    response = test_client.post(
        "/api/v1/orders/",
        headers=auth_headers,
        json={"items": [{"item_id": 99999, "quantity": 1}]}
    )
    assert response.status_code == 404, "Creating an order with a non-existent item should fail"
    assert "Item with id 99999 not found" in response.json()["detail"]

@pytest.mark.integration
def test_create_order_with_insufficient_stock(test_client: TestClient, auth_headers, sample_item):
    """Integration: Test creating an order for an item with insufficient stock."""
    response = test_client.post(
        "/api/v1/orders/",
        headers=auth_headers,
        json={"items": [{"item_id": sample_item.id, "quantity": sample_item.stock + 1}]}
    )
    assert response.status_code == 400, "Should not be able to order more items than are in stock"
    assert "Not enough stock" in response.json()["detail"]

@pytest.mark.parametrize("username, password, email, expected_status", [
    ("", "ValidPass123", "email@valid.com", 422),
    ("user", "", "email@valid.com", 422),
    ("user", "ValidPass123", "", 422),
    ("user", "ValidPass123", "not-an-email", 422),
    ("u", "ValidPass123", "email@valid.com", 422), # Username too short
    ("user", "short", "email@valid.com", 422), # Password too short
])
@pytest.mark.contract
def test_registration_input_validation(test_client: TestClient, username, password, email, expected_status):
    """Contract: Test server-side validation for user registration with various invalid inputs."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": username, "email": email, "password": password}
    )
    assert response.status_code == expected_status, f"Expected {expected_status} for invalid input but got {response.status_code}"