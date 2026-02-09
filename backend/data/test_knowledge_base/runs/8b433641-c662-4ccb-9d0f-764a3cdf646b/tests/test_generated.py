import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from backend.main import health_check
from backend.auth import get_password_hash, verify_password
from backend.services.user_service import UserService

# ==================== UNIT TESTS ====================

@pytest.mark.unit
def test_password_hashing_utility():
    """Test that password hashing and verification work correctly."""
    password = "SecurePassword123!"
    hashed_password = get_password_hash(password)
    assert hashed_password != password
    assert verify_password(password, hashed_password)
    assert not verify_password("WrongPassword", hashed_password)

@pytest.mark.unit
def test_health_check_logic_development(mock_settings_dev):
    """Unit test: Verify health_check returns 'development' when debug is True."""
    response = health_check()
    assert response["environment"] == "development"
    assert response["status"] == "healthy"

@pytest.mark.unit
def test_health_check_logic_production(mock_settings_prod):
    """Unit test: Verify health_check returns 'production' when debug is False."""
    response = health_check()
    assert response["environment"] == "production"
    assert response["status"] == "healthy"

@pytest.mark.unit
def test_create_user_service_logic(db_session):
    """Unit test: Test the user creation logic in the UserService."""
    user_data = {"username": "service_user", "email": "service@test.com", "password": "service_password"}
    user = UserService.create_user(db_session, user_data)
    assert user.username == user_data["username"]
    assert user.email == user_data["email"]
    assert user.id is not None

# ==================== INTEGRATION TESTS ====================

@pytest.mark.integration
def test_health_endpoint_liveness(test_client: TestClient):
    """Integration test: Ensure the /health endpoint is reachable and returns 200."""
    response = test_client.get("/health")
    assert response.status_code == 200

@pytest.mark.integration
def test_user_registration_and_login_flow(test_client: TestClient, db_session):
    """Integration test: Verify user registration and login workflow after import refactoring."""
    # Register
    reg_response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "flow_user", "email": "flow@example.com", "password": "FlowPassword123"}
    )
    assert reg_response.status_code == 201
    assert reg_response.json()["username"] == "flow_user"

    # Login
    login_response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "flow_user", "password": "FlowPassword123"}
    )
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()

@pytest.mark.integration
def test_create_item_as_admin_after_refactor(test_client: TestClient, admin_headers):
    """Integration test: Verify item creation works after service layer import refactoring."""
    response = test_client.post(
        "/api/v1/items",
        headers=admin_headers,
        json={"name": "New Gadget", "description": "A shiny new gadget.", "price": 99.99, "category": "Electronics"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "New Gadget"
    assert data["price"] == 99.99

@pytest.mark.integration
def test_create_order_as_user_after_refactor(test_client: TestClient, auth_headers, admin_headers):
    """Integration test: Verify order creation works after service layer import refactoring."""
    # Admin creates an item first
    item_res = test_client.post(
        "/api/v1/items",
        headers=admin_headers,
        json={"name": "Test Book", "description": "A book for testing.", "price": 10.0, "category": "Books"}
    )
    item_id = item_res.json()["id"]

    # User creates an order for that item
    order_res = test_client.post(
        "/api/v1/orders",
        headers=auth_headers,
        json={"items": [{"item_id": item_id, "quantity": 1}]}
    )
    assert order_res.status_code == 201
    data = order_res.json()
    assert data["status"] == "PENDING"
    assert len(data["items"]) == 1
    assert data["items"][0]["item_id"] == item_id

@pytest.mark.integration
def test_api_root_endpoint(test_client: TestClient):
    """Integration test: Check the root endpoint to ensure the app is running."""
    response = test_client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the FastAPI e-commerce backend!"}

# ==================== SECURITY TESTS ====================

@pytest.mark.security
def test_health_endpoint_no_sensitive_data(test_client: TestClient):
    """Security test: Ensure the /health endpoint does not leak sensitive information."""
    response = test_client.get("/health")
    data = response.json()
    sensitive_keys = ["password", "secret", "token", "dsn", "database_url"]
    for key in sensitive_keys:
        assert key not in data, f"Sensitive key '{key}' found in health check response"

@pytest.mark.security
def test_sql_injection_on_login(test_client: TestClient):
    """Security test: Attempt a basic SQL injection on the login endpoint."""
    malicious_username = "admin' OR '1'='1"
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": malicious_username, "password": "password"}
    )
    # Expect 401 Unauthorized, not 200 OK or 500 Internal Server Error
    assert response.status_code == 401

@pytest.mark.security
def test_access_protected_endpoint_without_auth(test_client: TestClient):
    """Security test: Ensure that accessing a protected endpoint without a token fails."""
    response = test_client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

@pytest.mark.security
def test_admin_endpoint_access_by_regular_user(test_client: TestClient, auth_headers):
    """Security test: Ensure a regular user cannot access an admin-only endpoint."""
    response = test_client.get("/api/v1/users", headers=auth_headers)
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin privileges required"

@pytest.mark.security
def test_admin_endpoint_access_by_admin(test_client: TestClient, admin_headers):
    """Security test: Verify that an admin user CAN access an admin-only endpoint."""
    response = test_client.get("/api/v1/users", headers=admin_headers)
    assert response.status_code == 200

# ==================== CONTRACT TESTS ====================

@pytest.mark.contract
def test_health_check_endpoint_contract(test_client: TestClient):
    """Contract test: Verify the schema and types of the /health endpoint response."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    
    # Check for presence of all keys
    expected_keys = {"status", "version", "app", "environment"}
    assert set(data.keys()) == expected_keys
    
    # Check types
    assert isinstance(data["status"], str)
    assert isinstance(data["version"], str)
    assert isinstance(data["app"], str)
    assert isinstance(data["environment"], str)
    assert data["environment"] in ["development", "production"]

@pytest.mark.contract
def test_user_registration_failure_contract(test_client: TestClient, test_user):
    """Contract test: Check the error response schema for a duplicate user registration."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "testuser", "email": "another@email.com", "password": "SomePassword123"}
    )
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert "Username already registered" in data["detail"]

@pytest.mark.contract
def test_item_schema_contract(test_client: TestClient, admin_headers):
    """Contract test: Verify the schema of a single item from the API."""
    # Create an item to fetch
    create_response = test_client.post(
        "/api/v1/items",
        headers=admin_headers,
        json={"name": "Contract Item", "description": "For schema testing.", "price": 12.34, "category": "Testing"}
    )
    item_id = create_response.json()["id"]

    # Fetch the item
    get_response = test_client.get(f"/api/v1/items/{item_id}")
    assert get_response.status_code == 200
    data = get_response.json()

    expected_keys = {"id", "name", "description", "price", "category", "is_available", "owner_id"}
    assert set(data.keys()) == expected_keys
    assert isinstance(data["id"], int)
    assert isinstance(data["name"], str)
    assert isinstance(data["price"], float)
    assert isinstance(data["is_available"], bool)

@pytest.mark.contract
def test_not_found_error_contract(test_client: TestClient):
    """Contract test: Verify the standard 404 Not Found error schema."""
    response = test_client.get("/api/v1/items/999999") # Assumes this item does not exist
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert "Item not found" in data["detail"]