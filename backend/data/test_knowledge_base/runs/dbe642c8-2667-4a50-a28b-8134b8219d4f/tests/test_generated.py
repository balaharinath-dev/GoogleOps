import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from config import settings
from main import health_check
from auth import get_password_hash, verify_password

# ==================== UNIT TESTS ====================

@pytest.mark.unit
def test_health_check_development_environment():
    """Unit test for health_check function in a development environment."""
    with patch('config.settings.debug', True):
        response = health_check()
        assert response["environment"] == "development"
        assert response["status"] == "healthy"

@pytest.mark.unit
def test_health_check_production_environment():
    """Unit test for health_check function in a production environment."""
    with patch('config.settings.debug', False):
        response = health_check()
        assert response["environment"] == "production"
        assert response["status"] == "healthy"

@pytest.mark.unit
def test_password_hashing_and_verification():
    """Unit test for password hashing and verification logic in auth.py."""
    password = "a_very_secure_password_!@#"
    hashed_password = get_password_hash(password)
    assert hashed_password != password
    assert verify_password(password, hashed_password)
    assert not verify_password("wrongpassword", hashed_password)

@pytest.mark.unit
def test_config_settings_defaults():
    """Unit test to ensure config settings have expected default values."""
    assert settings.app_name == "My FastAPI App"
    assert isinstance(settings.debug, bool)

# ==================== INTEGRATION TESTS ====================

@pytest.mark.integration
def test_application_startup_and_health_endpoint(test_client: TestClient):
    """Integration test to ensure the app starts and the health endpoint is available."""
    response = test_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

@pytest.mark.integration
def test_user_registration_flow(test_client: TestClient):
    """Integration test for the full user registration and login flow to verify import refactoring."""
    # Register a new user
    reg_response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "newbie", "email": "newbie@example.com", "password": "a_strong_password"}
    )
    assert reg_response.status_code == 201
    assert reg_response.json()["username"] == "newbie"

    # Log in with the new user
    login_response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "newbie", "password": "a_strong_password"}
    )
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()

@pytest.mark.integration
def test_admin_can_create_item(test_client: TestClient, admin_headers: dict):
    """Integration test to verify item creation by an admin, testing item_service import."""
    item_data = {"name": "New Gadget", "description": "A shiny new gadget.", "price": 99.99, "stock": 100}
    response = test_client.post("/api/v1/items/", json=item_data, headers=admin_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == item_data["name"]
    assert data["price"] == item_data["price"]

@pytest.mark.integration
def test_user_can_create_order(test_client: TestClient, auth_headers: dict, db_session):
    """Integration test for order creation, verifying order_service import."""
    # First, create an item to order
    item = {"name": "Test Book", "description": "A book for testing.", "price": 10.0, "stock": 5}
    item_res = test_client.post("/api/v1/items/", json=item, headers=admin_headers(test_client, db_session.query(User).filter(User.is_admin).first())) # Need admin to create item
    item_id = item_res.json()["id"]

    # Now, create an order
    order_data = {"items": [{"item_id": item_id, "quantity": 1}]}
    response = test_client.post("/api/v1/orders/", json=order_data, headers=auth_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "pending"
    assert len(data["items"]) == 1
    assert data["items"][0]["item_id"] == item_id

@pytest.mark.integration
def test_get_all_users_as_admin(test_client: TestClient, admin_headers: dict, test_user):
    """Integration test to get all users, verifying user_service import."""
    response = test_client.get("/api/v1/users/", headers=admin_headers)
    assert response.status_code == 200
    users = response.json()
    assert isinstance(users, list)
    assert len(users) >= 2 # admin and test_user
    usernames = [u['username'] for u in users]
    assert 'admin' in usernames
    assert 'testuser' in usernames

# ==================== SECURITY TESTS ====================

@pytest.mark.security
def test_health_endpoint_does_not_expose_sensitive_info(test_client: TestClient):
    """Security test to ensure the /health endpoint does not leak sensitive config."""
    response = test_client.get("/health")
    data = response.json()
    assert "database_url" not in data
    assert "secret_key" not in data
    assert "algorithm" not in data

@pytest.mark.security
def test_access_protected_route_without_auth(test_client: TestClient):
    """Security test to ensure protected endpoints require authentication."""
    response = test_client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

@pytest.mark.security
def test_non_admin_cannot_access_admin_routes(test_client: TestClient, auth_headers: dict):
    """Security test to ensure admin routes are protected from non-admin users."""
    response = test_client.get("/api/v1/users/", headers=auth_headers)
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin required"

@pytest.mark.security
def test_sql_injection_on_login(test_client: TestClient):
    """Security test for SQL injection attempt on the login form."""
    malicious_username = "' OR 1=1 --"
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": malicious_username, "password": "anypassword"}
    )
    # Expects 401 because authentication should fail, not crash or be bypassed.
    assert response.status_code == 401

# ==================== CONTRACT TESTS ====================

@pytest.mark.contract
def test_health_check_response_schema(test_client: TestClient):
    """Contract test for the /health endpoint response schema."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    
    # Check for presence of all required keys
    assert "status" in data
    assert "version" in data
    assert "app" in data
    assert "environment" in data
    
    # Check data types
    assert isinstance(data["status"], str)
    assert isinstance(data["version"], str)
    assert isinstance(data["app"], str)
    assert isinstance(data["environment"], str)

@pytest.mark.contract
def test_user_schema_on_get_me(test_client: TestClient, auth_headers: dict):
    """Contract test for the /api/v1/auth/me endpoint response schema."""
    response = test_client.get("/api/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert "username" in data
    assert "email" in data
    assert "is_active" in data
    assert "is_admin" in data
    assert "hashed_password" not in data # Ensure password is not returned

@pytest.mark.contract
def test_item_list_schema(test_client: TestClient):
    """Contract test for the /api/v1/items/ endpoint response schema."""
    response = test_client.get("/api/v1/items/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if data:
        item = data[0]
        assert "id" in item
        assert "name" in item
        assert "price" in item
        assert isinstance(item["id"], int)
        assert isinstance(item["name"], str)
        assert isinstance(item["price"], float)

@pytest.mark.contract
def test_404_not_found_error_schema(test_client: TestClient):
    """Contract test for the standard 404 Not Found error response."""
    response = test_client.get("/a/path/that/does/not/exist")
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Not Found"