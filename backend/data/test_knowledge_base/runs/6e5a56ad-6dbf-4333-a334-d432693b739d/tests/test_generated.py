import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

# Imports from the application, assuming conftest.py handles path correctly
from main import health_check
from config import settings
from auth import get_password_hash, verify_password, create_access_token
from models import User

# 1. Unit Tests
@pytest.mark.unit
def test_unit_health_check_structure():
    """Unit: Test the direct output of the health_check function."""
    with patch('config.settings.debug', False):
        result = health_check()
        assert isinstance(result, dict)
        assert "status" in result
        assert "version" in result
        assert "app" in result
        assert "environment" in result

@pytest.mark.unit
@pytest.mark.parametrize("debug_mode, expected_env", [
    (True, "development"),
    (False, "production"),
])
def test_unit_health_check_environment_logic(debug_mode, expected_env):
    """Unit: Test the environment logic in health_check by mocking settings."""
    with patch('config.settings.debug', debug_mode):
        result = health_check()
        assert result["environment"] == expected_env, f"Failed for debug_mode={debug_mode}"

@pytest.mark.unit
def test_unit_password_hashing_and_verification():
    """Unit: Test password hashing and verification functions."""
    password = "StrongPassword123!"
    hashed_password = get_password_hash(password)
    assert isinstance(hashed_password, str)
    assert hashed_password != password
    assert verify_password(password, hashed_password)
    assert not verify_password("WrongPassword", hashed_password)

@pytest.mark.unit
def test_unit_create_access_token():
    """Unit: Test JWT access token creation."""
    token = create_access_token(data={"sub": "testuser"})
    assert isinstance(token, str)
    assert len(token.split('.')) == 3 # Standard JWT format

@pytest.mark.unit
def test_unit_config_settings_load():
    """Unit: Verify that configuration settings are loaded."""
    assert settings.app_name == "My FastAPI App"
    assert isinstance(settings.access_token_expire_minutes, int)


# 2. Contract Tests
@pytest.mark.contract
def test_contract_health_endpoint_schema(test_client: TestClient):
    """Contract: Validate the schema of the /health endpoint response."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    
    assert list(data.keys()) == ["status", "version", "app", "environment"]
    assert isinstance(data["status"], str)
    assert isinstance(data["version"], str)
    assert isinstance(data["app"], str)
    assert isinstance(data["environment"], str)

@pytest.mark.contract
def test_contract_validation_error_schema_422(test_client: TestClient):
    """Contract: Ensure 422 validation errors follow the expected FastAPI schema."""
    response = test_client.post("/api/v1/auth/register", json={"username": "u", "email": "not-an-email", "password": "p"})
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    assert isinstance(data["detail"], list)
    assert len(data["detail"]) > 0
    error = data["detail"][0]
    assert "loc" in error
    assert "msg" in error
    assert "type" in error

@pytest.mark.contract
def test_contract_user_registration_response_schema(test_client: TestClient):
    """Contract: Verify the response schema for a successful user registration."""
    response = test_client.post("/api/v1/auth/register", json={"username": "contractuser", "email": "contract@example.com", "password": "ValidPassword123"})
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert "username" in data
    assert "email" in data
    assert "is_active" in data
    assert "is_admin" in data
    assert "hashed_password" not in data, "Security risk: hashed_password should not be in the response."

@pytest.mark.contract
def test_contract_unauthorized_error_schema_401(test_client: TestClient):
    """Contract: Ensure 401 Unauthorized errors have the correct WWW-Authenticate header."""
    response = test_client.get("/api/v1/users/me")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == "Bearer"


# 3. Integration Tests
@pytest.mark.integration
def test_integration_health_endpoint_returns_200(test_client: TestClient):
    """Integration: Test that a GET request to /health returns 200 OK."""
    response = test_client.get("/health")
    assert response.status_code == 200

@pytest.mark.integration
def test_integration_root_endpoint_returns_200(test_client: TestClient):
    """Integration: Smoke test for the root endpoint to ensure the app is alive."""
    response = test_client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the API"}

@pytest.mark.integration
def test_integration_user_registration_and_login_flow(test_client: TestClient):
    """Integration: Test the full user registration and login workflow."""
    # Register
    reg_response = test_client.post("/api/v1/auth/register", json={"username": "flowuser", "email": "flow@example.com", "password": "FlowPassword123"})
    assert reg_response.status_code == 201
    
    # Login
    login_response = test_client.post("/api/v1/auth/login", data={"username": "flowuser", "password": "FlowPassword123"})
    assert login_response.status_code == 200
    token_data = login_response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"

@pytest.mark.integration
def test_integration_registration_fails_on_duplicate_username(test_client: TestClient, test_user):
    """Integration: Ensure registration fails if username is already taken."""
    response = test_client.post("/api/v1/auth/register", json={"username": "testuser", "email": "another@example.com", "password": "anotherpassword"})
    assert response.status_code == 400
    assert "Username already registered" in response.text

@pytest.mark.integration
def test_integration_registration_fails_on_duplicate_email(test_client: TestClient, test_user):
    """Integration: Ensure registration fails if email is already taken."""
    response = test_client.post("/api/v1/auth/register", json={"username": "anotheruser", "email": "test@example.com", "password": "anotherpassword"})
    assert response.status_code == 400
    assert "Email already registered" in response.text

@pytest.mark.integration
def test_integration_login_fails_for_inactive_user(test_client: TestClient, inactive_user):
    """Integration: Ensure an inactive user cannot log in."""
    response = test_client.post("/api/v1/auth/login", data={"username": "inactive", "password": "InactPass123"})
    assert response.status_code == 400
    assert "Inactive user" in response.text

@pytest.mark.integration
def test_integration_smoke_test_get_me(test_client: TestClient, auth_headers):
    """Integration: Smoke test for a protected endpoint after import refactor."""
    response = test_client.get("/api/v1/users/me", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"

@pytest.mark.integration
def test_integration_smoke_test_create_and_get_item(test_client: TestClient, admin_headers):
    """Integration: Smoke test for item service after import refactor."""
    # Create item
    create_response = test_client.post("/api/v1/items/", headers=admin_headers, json={"name": "Smoke Item", "description": "A test", "price": 10.0, "stock": 5})
    assert create_response.status_code == 201
    item_data = create_response.json()
    item_id = item_data["id"]

    # Get item
    get_response = test_client.get(f"/api/v1/items/{item_id}", headers=admin_headers)
    assert get_response.status_code == 200
    assert get_response.json()["name"] == "Smoke Item"

@pytest.mark.integration
def test_integration_smoke_test_create_order(test_client: TestClient, auth_headers, sample_item):
    """Integration: Smoke test for order service after import refactor."""
    response = test_client.post("/api/v1/orders/", headers=auth_headers, json={"items": [{"item_id": sample_item.id, "quantity": 1}]})
    assert response.status_code == 201
    order_data = response.json()
    assert order_data["owner_id"] == 1 # test_user ID
    assert len(order_data["items"]) == 1
    assert order_data["items"][0]["item_id"] == sample_item.id


# 4. Security Tests
@pytest.mark.security
def test_security_access_protected_route_without_token(test_client: TestClient):
    """Security: Deny access to protected routes without a token."""
    response = test_client.get("/api/v1/users/me")
    assert response.status_code == 401

@pytest.mark.security
def test_security_access_protected_route_with_invalid_token(test_client: TestClient):
    """Security: Deny access to protected routes with a malformed token."""
    headers = {"Authorization": "Bearer invalidtoken"}
    response = test_client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401

@pytest.mark.security
def test_security_regular_user_cannot_access_admin_routes(test_client: TestClient, auth_headers):
    """Security: Prevent non-admin users from accessing admin-only routes."""
    response = test_client.get("/api/v1/users/", headers=auth_headers)
    assert response.status_code == 403
    assert "not enough permissions" in response.text

@pytest.mark.security
def test_security_admin_user_can_access_admin_routes(test_client: TestClient, admin_headers):
    """Security: Allow admin users to access admin-only routes."""
    response = test_client.get("/api/v1/users/", headers=admin_headers)
    assert response.status_code == 200

@pytest.mark.security
def test_security_password_not_in_user_me_response(test_client: TestClient, auth_headers):
    """Security: Ensure hashed_password is not returned by the /users/me endpoint."""
    response = test_client.get("/api/v1/users/me", headers=auth_headers)
    assert response.status_code == 200
    assert "hashed_password" not in response.json()

@pytest.mark.security
def test_security_password_not_in_get_user_by_id_response(test_client: TestClient, admin_headers, test_user):
    """Security: Ensure hashed_password is not returned by the /users/{id} endpoint."""
    response = test_client.get(f"/api/v1/users/{test_user.id}", headers=admin_headers)
    assert response.status_code == 200
    assert "hashed_password" not in response.json()

@pytest.mark.security
@pytest.mark.parametrize("payload", [
    "' OR 1=1 --",
    "admin'--",
    "admin' OR '1'='1",
])
def test_security_sql_injection_attempt_on_login(test_client: TestClient, payload):
    """Security: Test for basic SQL injection on login form. Expect 401, not 500."""
    response = test_client.post("/api/v1/auth/login", data={"username": payload, "password": "anypassword"})
    # The ORM should prevent SQL injection. The user won't be found.
    assert response.status_code == 401
    assert "Incorrect username or password" in response.text

@pytest.mark.security
def test_security_health_endpoint_does_not_expose_secrets(test_client: TestClient):
    """Security: Verify the health endpoint does not leak sensitive information."""
    response = test_client.get("/health")
    data = response.json()
    sensitive_keys = ["secret", "password", "database", "token", "key"]
    for key in data.keys():
        for sensitive in sensitive_keys:
            assert sensitive not in key.lower()
    for value in data.values():
        if isinstance(value, str):
            for sensitive in sensitive_keys:
                assert sensitive not in value.lower()

@pytest.mark.security
def test_security_inactive_user_token_is_invalid(test_client: TestClient, db_session, inactive_user):
    """Security: Ensure a token generated for a user who is later deactivated is invalid."""
    # Manually create a token for the inactive user
    token = create_access_token(data={"sub": inactive_user.username})
    headers = {"Authorization": f"Bearer {token}"}
    
    # Attempt to access a protected route
    response = test_client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401
    assert "Inactive user" in response.text