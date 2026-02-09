import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from backend.models import User
from backend.services.user_service import UserService
from backend.auth import get_password_hash

# ==================== UNIT TESTS ====================

@pytest.mark.unit
def test_health_check_in_development_mode():
    """Unit test: Verify health check reports 'development' when debug is True."""
    with patch('backend.main.settings', new_callable=lambda: type('Settings', (), {'debug': True, 'app_version': '1.0', 'app_name': 'TestApp'})):
        from backend.main import health_check
        response = health_check()
        assert response['environment'] == 'development'

@pytest.mark.unit
def test_health_check_in_production_mode():
    """Unit test: Verify health check reports 'production' when debug is False."""
    with patch('backend.main.settings', new_callable=lambda: type('Settings', (), {'debug': False, 'app_version': '1.0', 'app_name': 'TestApp'})):
        from backend.main import health_check
        response = health_check()
        assert response['environment'] == 'production'

@pytest.mark.unit
def test_create_user_with_invalid_email_raises_error(db_session):
    """Unit test: Verify user service rejects invalid email formats."""
    user_service = UserService(db_session)
    with pytest.raises(ValueError):
        user_service.create_user(username="test", email="not-an-email", password="password")

@pytest.mark.unit
def test_password_hashing_is_effective():
    """Unit test: Ensure password hashing function works as expected."""
    password = "a_very_secure_password_123!"
    hashed = get_password_hash(password)
    assert hashed != password
    from backend.auth import verify_password
    assert verify_password(password, hashed)

# ==================== INTEGRATION TESTS ====================

@pytest.mark.integration
def test_health_endpoint_returns_correct_data(test_client: TestClient):
    """Integration test: GET /health should return 200 and expected keys."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "version" in data
    assert "app" in data
    assert "environment" in data
    assert data["status"] == "healthy"

@pytest.mark.integration
def test_register_user_with_invalid_email_fails(test_client: TestClient):
    """Integration test: POST /register with invalid email should return 422."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "newuser", "email": "invalid-email", "password": "password123"}
    )
    assert response.status_code == 422

@pytest.mark.integration
def test_register_user_with_valid_email_succeeds(test_client: TestClient):
    """Integration test: POST /register with valid data should return 201."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "gooduser", "email": "good@email.com", "password": "ValidPassword123"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "gooduser"
    assert data["email"] == "good@email.com"

@pytest.mark.integration
def test_smoke_test_full_user_workflow(test_client: TestClient, db_session):
    """Integration test: Smoke test user registration, login, and profile access."""
    # Register
    reg_response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "workflow_user", "email": "workflow@test.com", "password": "Password123"}
    )
    assert reg_response.status_code == 201
    
    # Login
    login_response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "workflow_user", "password": "Password123"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    
    # Access protected route
    headers = {"Authorization": f"Bearer {token}"}
    me_response = test_client.get("/api/v1/auth/me", headers=headers)
    assert me_response.status_code == 200
    assert me_response.json()["email"] == "workflow@test.com"

@pytest.mark.integration
def test_item_and_order_endpoints_after_refactor(test_client: TestClient, auth_headers):
    """Integration test: Smoke test item and order endpoints after import refactoring."""
    # Create an item
    item_response = test_client.post(
        "/api/v1/items/",
        json={"name": "Test Item", "description": "A test item", "price": 9.99, "inventory": 10},
        headers=auth_headers
    )
    # This endpoint might require admin, let's check for non-404 errors
    assert item_response.status_code != 404
    
    # Get items
    get_items_response = test_client.get("/api/v1/items/", headers=auth_headers)
    assert get_items_response.status_code == 200
    assert get_items_response.status_code != 404

# ==================== SECURITY TESTS ====================

@pytest.mark.security
def test_health_endpoint_for_information_leakage(test_client: TestClient):
    """Security test: Ensure /health endpoint does not leak sensitive config."""
    response = test_client.get("/health")
    data = response.json()
    sensitive_keys = ["database_url", "secret_key", "password", "token"]
    for key in sensitive_keys:
        assert key not in data

@pytest.mark.security
def test_sql_injection_on_login_attempt(test_client: TestClient):
    """Security test: Attempt SQL injection on login form."""
    malicious_username = "' OR 1=1 --"
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": malicious_username, "password": "anypassword"}
    )
    assert response.status_code == 401  # Should fail authentication, not crash

@pytest.mark.security
def test_password_is_not_in_user_response(test_client: TestClient, auth_headers):
    """Security test: Ensure user endpoints do not return the password hash."""
    response = test_client.get("/api/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "password" not in data
    assert "hashed_password" not in data

@pytest.mark.security
def test_stored_password_is_hashed(db_session):
    """Security test: Verify that passwords stored in the database are hashed."""
    plain_password = "MySecurePassword123"
    user = User(
        username="secureuser",
        email="secure@example.com",
        hashed_password=get_password_hash(plain_password),
    )
    db_session.add(user)
    db_session.commit()
    
    retrieved_user = db_session.query(User).filter(User.username == "secureuser").one()
    assert retrieved_user.hashed_password != plain_password
    assert retrieved_user.hashed_password.startswith('$2b$') # bcrypt hash identifier

@pytest.mark.security
def test_non_admin_cannot_access_all_users(test_client: TestClient, auth_headers):
    """Security test: Verify authorization on admin-only user list endpoint."""
    response = test_client.get("/api/v1/users/", headers=auth_headers)
    assert response.status_code == 403 # Forbidden

# ==================== CONTRACT TESTS ====================

@pytest.mark.contract
def test_health_endpoint_response_schema(test_client: TestClient):
    """Contract test: Validate the schema of the /health endpoint response."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    
    assert isinstance(data, dict)
    assert list(data.keys()) == ["status", "version", "app", "environment"]
    assert isinstance(data["status"], str)
    assert isinstance(data["version"], str)
    assert isinstance(data["app"], str)
    assert isinstance(data["environment"], str)

@pytest.mark.contract
def test_user_registration_response_schema(test_client: TestClient):
    """Contract test: Validate the schema of the user registration response."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "contractuser", "email": "contract@test.com", "password": "Password123"}
    )
    assert response.status_code == 201
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
def test_validation_error_schema(test_client: TestClient):
    """Contract test: Validate the schema for a 422 Unprocessable Entity error."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "bad", "email": "bad-email", "password": "short"}
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
    assert isinstance(error["loc"], list)
    assert isinstance(error["msg"], str)
    assert isinstance(error["type"], str)