import pytest
from unittest.mock import patch
from jose import jwt
from datetime import timedelta

from main import health_check
from config import settings
from auth import get_password_hash, verify_password, create_access_token, ALGORITHM, SECRET_KEY

# --- UNIT TESTS ---

@pytest.mark.unit
def test_get_password_hash():
    """Unit: Test that password hashing returns a non-plain-text string."""
    password = "plain_password"
    hashed = get_password_hash(password)
    assert hashed != password
    assert isinstance(hashed, str)

@pytest.mark.unit
def test_verify_password():
    """Unit: Test that password verification works for correct and incorrect passwords."""
    password = "a_secure_password"
    hashed = get_password_hash(password)
    assert verify_password(password, hashed) is True
    assert verify_password("wrong_password", hashed) is False

@pytest.mark.unit
def test_create_access_token():
    """Unit: Test JWT access token creation and content."""
    data = {"sub": "testuser@example.com"}
    token = create_access_token(data)
    decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert decoded_token["sub"] == "testuser@example.com"
    assert "exp" in decoded_token

@pytest.mark.unit
@patch('config.settings.debug', True)
def test_health_check_unit_development():
    """Unit: Test health_check function returns 'development' when debug is True."""
    response = health_check()
    assert response["environment"] == "development"
    assert response["status"] == "healthy"

@pytest.mark.unit
@patch('config.settings.debug', False)
def test_health_check_unit_production():
    """Unit: Test health_check function returns 'production' when debug is False."""
    response = health_check()
    assert response["environment"] == "production"
    assert response["status"] == "healthy"

@pytest.mark.unit
def test_settings_load_defaults():
    """Unit: Test that config settings load default values correctly."""
    assert settings.app_name == "My FastAPI App"
    assert settings.app_version == "0.1.0"
    assert isinstance(settings.debug, bool)

# --- INTEGRATION TESTS ---

@pytest.mark.integration
def test_health_endpoint_success(test_client):
    """Integration: Test that the /health endpoint returns a 200 OK status."""
    response = test_client.get("/health")
    assert response.status_code == 200

@pytest.mark.integration
def test_health_endpoint_response_body(test_client):
    """Integration: Test that the /health endpoint response body contains the new 'environment' field."""
    response = test_client.get("/health")
    data = response.json()
    assert "status" in data
    assert "version" in data
    assert "app" in data
    assert "environment" in data
    assert data["environment"] in ["development", "production"]

@pytest.mark.integration
def test_user_registration_success(test_client):
    """Integration: Test successful user registration."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "newuser", "email": "new@example.com", "password": "ValidPassword123"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "new@example.com"

@pytest.mark.integration
def test_user_registration_duplicate_username(test_client, test_user):
    """Integration: Test that registering with a duplicate username fails."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "testuser", "email": "another@example.com", "password": "ValidPassword123"}
    )
    assert response.status_code == 400
    assert "Username already registered" in response.json()["detail"]

@pytest.mark.integration
def test_full_auth_flow_and_regression_check(test_client, test_user, auth_headers):
    """Integration: Test full login flow and access a protected route to check for regressions."""
    response = test_client.get("/api/v1/users/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == test_user.username
    assert data["email"] == test_user.email

@pytest.mark.integration
def test_list_items_unauthenticated(test_client, sample_item):
    """Integration: Test that the public /items endpoint works without auth (regression check)."""
    response = test_client.get("/api/v1/items/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert data[0]["name"] == sample_item.name

@pytest.mark.integration
def test_create_order_as_user(test_client, auth_headers, sample_item):
    """Integration: Test creating an order as an authenticated user (regression check)."""
    order_data = {"items": [{"item_id": sample_item.id, "quantity": 1}]}
    response = test_client.post("/api/v1/orders/", headers=auth_headers, json=order_data)
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "pending"
    assert len(data["items"]) == 1
    assert data["items"][0]["item_id"] == sample_item.id

@pytest.mark.integration
def test_list_users_as_admin(test_client, admin_headers, multiple_users):
    """Integration: Test that an admin can list users (regression check)."""
    response = test_client.get("/api/v1/users/", headers=admin_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    # Total users = admin + 15 from fixture
    assert len(response.json()) >= 15

# --- SECURITY TESTS ---

@pytest.mark.security
def test_health_endpoint_no_sensitive_data_leak(test_client):
    """Security: Ensure the /health endpoint does not leak sensitive information."""
    response = test_client.get("/health")
    data = response.json()
    allowed_keys = {"status", "version", "app", "environment"}
    assert set(data.keys()) == allowed_keys, "Health endpoint is leaking unexpected data."

@pytest.mark.security
def test_access_admin_endpoint_as_non_admin(test_client, auth_headers, test_user):
    """Security: Test that a regular user cannot access an admin-only endpoint."""
    response = test_client.patch(f"/api/v1/users/{test_user.id}/make-admin", headers=auth_headers)
    assert response.status_code == 403
    assert "Admin privileges required" in response.json()["detail"]

@pytest.mark.security
def test_access_protected_endpoint_with_invalid_token(test_client):
    """Security: Test that an invalid JWT token is rejected."""
    headers = {"Authorization": "Bearer aninvalidtoken"}
    response = test_client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401
    assert "Invalid authentication credentials" in response.json()["detail"]

@pytest.mark.security
def test_access_protected_endpoint_with_expired_token(test_client, test_user):
    """Security: Test that an expired JWT token is rejected."""
    expired_token = create_access_token(
        data={"sub": test_user.email}, expires_delta=timedelta(minutes=-5)
    )
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = test_client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401
    assert "Token has expired" in response.json()["detail"]

@pytest.mark.security
def test_password_not_in_user_responses(test_client, admin_headers, test_user):
    """Security: Verify that password hashes are never returned from user endpoints."""
    # /register
    reg_response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "secureuser", "email": "secure@example.com", "password": "SecurePassword123"}
    )
    assert "hashed_password" not in reg_response.json()
    assert "password" not in reg_response.json()

    # /users/me
    me_response = test_client.get("/api/v1/users/me", headers=admin_headers)
    assert "hashed_password" not in me_response.json()

    # /users/{id}
    id_response = test_client.get(f"/api/v1/users/{test_user.id}", headers=admin_headers)
    assert "hashed_password" not in id_response.json()

@pytest.mark.security
@pytest.mark.parametrize("payload", ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"])
def test_xss_in_item_creation(test_client, admin_headers, payload):
    """Security: Test for XSS vulnerabilities in item creation."""
    item_data = {"name": payload, "description": "XSS test", "price": 10.0, "stock": 1}
    response = test_client.post("/api/v1/items/", headers=admin_headers, json=item_data)
    assert response.status_code == 201
    # In a real scenario, the response should be checked for escaped HTML.
    # For this test, we ensure it doesn't crash and the data is stored.
    # A more robust test would fetch the item and check the content.
    item_id = response.json()["id"]
    get_response = test_client.get(f"/api/v1/items/{item_id}")
    assert get_response.status_code == 200
    assert payload in get_response.json()["name"]
    assert "<" in get_response.json()["name"] # FastAPI/Pydantic doesn't auto-escape on input

@pytest.mark.security
def test_sql_injection_in_login(test_client):
    """Security: Test for basic SQL injection in login username field."""
    # This payload is a common simple SQLi check
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "' OR 1=1 --", "password": "fakepassword"}
    )
    # The correct behavior is to fail authentication, not crash or log in.
    assert response.status_code == 401
    assert "Incorrect username or password" in response.json()["detail"]

# --- CONTRACT TESTS ---

@pytest.mark.contract
def test_health_endpoint_response_schema(test_client):
    """Contract: Validate the exact schema of the /health endpoint response."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    expected_keys = {"status", "version", "app", "environment"}
    assert set(data.keys()) == expected_keys

@pytest.mark.contract
def test_health_endpoint_field_types(test_client):
    """Contract: Validate the data types of the /health endpoint response fields."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["status"], str)
    assert isinstance(data["version"], str)
    assert isinstance(data["app"], str)
    assert isinstance(data["environment"], str)

@pytest.mark.contract
def test_health_endpoint_environment_value(test_client):
    """Contract: Validate the value of the 'environment' field is one of the expected values."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["environment"] in ["development", "production"]

@pytest.mark.contract
def test_user_registration_response_schema_201(test_client):
    """Contract: Validate the response schema for a successful user registration."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "contractuser", "email": "contract@example.com", "password": "ContractPass123"}
    )
    assert response.status_code == 201
    data = response.json()
    expected_keys = {"id", "username", "email", "is_active", "is_admin"}
    assert set(data.keys()) == expected_keys
    assert isinstance(data["id"], int)
    assert isinstance(data["is_active"], bool)

@pytest.mark.contract
def test_validation_error_schema_422(test_client):
    """Contract: Validate the schema for a 422 Unprocessable Entity error."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "short", "email": "not-an-email", "password": "short"}
    )
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
def test_not_found_error_schema_404(test_client):
    """Contract: Validate the schema for a 404 Not Found error."""
    response = test_client.get("/api/v1/items/999999")
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Item not found"