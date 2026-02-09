import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

# ==================== UNIT TESTS ====================

@pytest.mark.unit
def test_password_hashing_and_verification():
    """Test that password hashing and verification functions work correctly."""
    from backend.auth import get_password_hash, verify_password
    password = "a_very_secure_password_123!"
    hashed_password = get_password_hash(password)
    assert hashed_password != password
    assert verify_password(password, hashed_password)
    assert not verify_password("wrong_password", hashed_password)

@pytest.mark.unit
def test_create_access_token():
    """Test the creation of a JWT access token."""
    from backend.auth import create_access_token
    from datetime import timedelta
    token = create_access_token(data={{"sub": "testuser"}}, expires_delta=timedelta(minutes=15))
    assert isinstance(token, str)
    assert len(token) > 50

# ==================== INTEGRATION TESTS ====================

@pytest.mark.integration
def test_health_check_endpoint_returns_200(test_client: TestClient):
    """Test that the /health-check endpoint is available and returns 200 OK."""
    response = test_client.get("/health-check")
    assert response.status_code == 200

@pytest.mark.integration
def test_user_registration_and_login_flow(test_client: TestClient, db_session):
    """Test the complete user registration and login workflow."""
    # Register a new user
    reg_response = test_client.post(
        "/api/v1/auth/register",
        json={{"username": "newuser", "email": "new@example.com", "password": "NewPassword123"}}
    )
    assert reg_response.status_code == 201
    assert reg_response.json()["username"] == "newuser"

    # Log in with the new user
    login_response = test_client.post(
        "/api/v1/auth/login",
        data={{"username": "newuser", "password": "NewPassword123"}}
    )
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()

@pytest.mark.integration
def test_admin_can_list_users(test_client: TestClient, admin_headers):
    """Test that an admin user can successfully list all users."""
    response = test_client.get("/api/v1/users/", headers=admin_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

@pytest.mark.integration
def test_regular_user_cannot_list_users(test_client: TestClient, auth_headers):
    """Test that a regular user is forbidden from listing all users."""
    response = test_client.get("/api/v1/users/", headers=auth_headers)
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required"

@pytest.mark.integration
def test_create_and_delete_item_as_admin(test_client: TestClient, admin_headers):
    """Test the full lifecycle of an item (create and delete) by an admin."""
    # Create item
    create_response = test_client.post(
        "/api/v1/items/",
        headers=admin_headers,
        json={{"name": "Test Gadget", "description": "A cool new gadget", "price": 99.99, "category": "Electronics", "inventory": 10}}
    )
    assert create_response.status_code == 201
    item_id = create_response.json()["id"]

    # Delete item
    delete_response = test_client.delete(f"/api/v1/items/{{item_id}}", headers=admin_headers)
    assert delete_response.status_code == 200
    assert delete_response.json()["message"] == "Item deleted successfully"

# ==================== SECURITY TESTS ====================

@pytest.mark.security
def test_login_sql_injection_attempt(test_client: TestClient):
    """Test that a basic SQL injection attempt in the username field fails."""
    malicious_username = "' OR 1=1 --"
    response = test_client.post(
        "/api/v1/auth/login",
        data={{"username": malicious_username, "password": "anypassword"}}
    )
    assert response.status_code == 401
    assert "access_token" not in response.json()

@pytest.mark.security
def test_unauthenticated_access_to_protected_route(test_client: TestClient):
    """Test that accessing a protected route without a token results in 401 Unauthorized."""
    response = test_client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

@pytest.mark.security
def test_regular_user_cannot_make_another_user_admin(test_client: TestClient, auth_headers, test_user):
    """Test that a regular user cannot escalate privileges of another user."""
    response = test_client.post(f"/api/v1/users/{{test_user.id}}/make-admin", headers=auth_headers)
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required"

@pytest.mark.security
def test_health_check_does_not_expose_sensitive_info(test_client: TestClient):
    """Test that the health check endpoint does not leak sensitive configuration."""
    response = test_client.get("/health-check")
    data = response.json()
    sensitive_keys = ["db_password", "secret_key", "database_url"]
    for key in sensitive_keys:
        assert key not in data

# ==================== CONTRACT TESTS ====================

@pytest.mark.contract
@patch("backend.config.settings.debug", True)
def test_health_check_contract_development(test_client: TestClient):
    """Test the health-check response schema and values in a development environment."""
    response = test_client.get("/health-check")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["environment"] == "development"
    assert "version" in data
    assert "app" in data
    assert isinstance(data["version"], str)
    assert isinstance(data["app"], str)

@pytest.mark.contract
@patch("backend.config.settings.debug", False)
def test_health_check_contract_production(test_client: TestClient):
    """Test the health-check response schema and values in a production environment."""
    response = test_client.get("/health-check")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["environment"] == "production"
    assert "version" in data
    assert "app" in data

@pytest.mark.contract
def test_get_me_response_schema(test_client: TestClient, auth_headers):
    """Verify the response schema for the /me endpoint."""
    response = test_client.get("/api/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert "username" in data
    assert "email" in data
    assert "is_active" in data
    assert "is_admin" in data
    assert isinstance(data["id"], int)
    assert isinstance(data["username"], str)
    assert isinstance(data["email"], str)
    assert isinstance(data["is_active"], bool)
    assert isinstance(data["is_admin"], bool)

@pytest.mark.contract
def test_not_found_error_schema(test_client: TestClient):
    """Test the standard schema for a 404 Not Found error."""
    response = test_client.get("/non-existent-endpoint")
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Not Found"

@pytest.mark.contract
def test_validation_error_schema(test_client: TestClient, admin_headers):
    """Test the schema for a 422 Unprocessable Entity validation error."""
    response = test_client.post(
        "/api/v1/items/",
        headers=admin_headers,
        json={{"name": "Incomplete Item", "price": "not-a-number"}} # Invalid data
    )
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    assert isinstance(data["detail"], list)
    assert "loc" in data["detail"][0]
    assert "msg" in data["detail"][0]
    assert "type" in data["detail"][0]