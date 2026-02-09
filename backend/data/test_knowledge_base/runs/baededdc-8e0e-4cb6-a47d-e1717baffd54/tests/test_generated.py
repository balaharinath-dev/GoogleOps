import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from datetime import timedelta

# Import application components using absolute imports
from config import settings
from auth import create_access_token
from models import User

# --- Health Check Tests (Covering main.py, config.py changes) ---

@pytest.mark.integration
@pytest.mark.contract
def test_health_check_endpoint_success_and_schema(test_client: TestClient):
    """
    Integration & Contract: Test the /health endpoint for success and response schema.
    This directly tests the commit's primary change.
    """
    response = test_client.get("/health")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    
    # Contract validation
    expected_keys = {"status", "version", "app", "environment"}
    assert set(data.keys()) == expected_keys, f"Response keys mismatch. Expected {expected_keys}, got {set(data.keys())}"
    
    # Field type validation
    assert isinstance(data["status"], str)
    assert isinstance(data["version"], str)
    assert isinstance(data["app"], str)
    assert isinstance(data["environment"], str)
    
    assert data["status"] == "healthy"
    assert data["app"] == settings.app_name

@pytest.mark.unit
def test_health_check_environment_development(test_client: TestClient):
    """
    Unit: Test that /health reports 'development' when debug is True.
    """
    with patch("config.settings.debug", True):
        response = test_client.get("/health")
        assert response.status_code == 200
        assert response.json()["environment"] == "development"

@pytest.mark.unit
def test_health_check_environment_production(test_client: TestClient):
    """
    Unit: Test that /health reports 'production' when debug is False.
    """
    with patch("config.settings.debug", False):
        response = test_client.get("/health")
        assert response.status_code == 200
        assert response.json()["environment"] == "production"

@pytest.mark.security
def test_health_check_does_not_expose_sensitive_data(test_client: TestClient):
    """
    Security: Ensure the /health endpoint does not leak sensitive configuration.
    """
    response = test_client.get("/health")
    data = response.json()
    sensitive_keys = ["secret_key", "database_url", "password"]
    for key in sensitive_keys:
        assert key not in data, f"Sensitive key '{key}' found in /health response"

@pytest.mark.integration
@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_health_check_disallowed_methods(test_client: TestClient, method: str):
    """
    Integration: Ensure only GET is allowed on the /health endpoint.
    """
    response = test_client.request(method, "/health")
    assert response.status_code == 405, f"Method {method} should not be allowed on /health"

# --- Regression Tests for Import Refactoring ---

@pytest.mark.integration
@pytest.mark.regression
class TestAuthEndpointRegression:
    """A suite of tests to ensure auth endpoints work after import refactoring."""

    def test_user_registration_success(self, test_client: TestClient):
        """Regression: Test successful user registration."""
        response = test_client.post(
            "/api/v1/auth/register",
            json={"username": "newuser", "email": "new@example.com", "password": "NewPassword123"}
        )
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"
        assert data["email"] == "new@example.com"
        assert "hashed_password" not in data

    def test_user_registration_duplicate_username(self, test_client: TestClient, test_user: User):
        """Regression: Test registration with a duplicate username."""
        response = test_client.post(
            "/api/v1/auth/register",
            json={"username": "testuser", "email": "new@example.com", "password": "NewPassword123"}
        )
        assert response.status_code == 400
        assert "Username already registered" in response.text

    def test_user_registration_invalid_email(self, test_client: TestClient):
        """Regression: Test registration with an invalid email, implicitly testing email-validator."""
        response = test_client.post(
            "/api/v1/auth/register",
            json={"username": "emailuser", "email": "not-an-email", "password": "NewPassword123"}
        )
        assert response.status_code == 422 # pydantic validation error

    def test_user_login_success(self, test_client: TestClient, test_user: User):
        """Regression: Test successful user login."""
        response = test_client.post(
            "/api/v1/auth/login",
            data={"username": "testuser", "password": "TestPass123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_user_login_incorrect_password(self, test_client: TestClient, test_user: User):
        """Regression: Test login with an incorrect password."""
        response = test_client.post(
            "/api/v1/auth/login",
            data={"username": "testuser", "password": "WrongPassword"}
        )
        assert response.status_code == 401
        assert "Incorrect username or password" in response.text

    def test_get_current_user_success(self, test_client: TestClient, auth_headers: dict):
        """Regression: Test accessing a protected route (/users/me)."""
        response = test_client.get("/api/v1/users/me", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"

@pytest.mark.integration
@pytest.mark.regression
class TestServiceEndpointRegression:
    """A suite of tests for services (users, items, orders) to check for regressions."""

    def test_admin_can_view_all_users(self, test_client: TestClient, admin_headers: dict, multiple_users):
        """Regression: Verify admin can access user list after import changes."""
        response = test_client.get("/api/v1/users/", headers=admin_headers)
        assert response.status_code == 200
        assert len(response.json()) >= 5 # From the multiple_users fixture

    def test_admin_can_create_item(self, test_client: TestClient, admin_headers: dict):
        """Regression: Verify admin can create an item after item_service import changes."""
        response = test_client.post(
            "/api/v1/items/",
            headers=admin_headers,
            json={"name": "New Gadget", "description": "A shiny new gadget", "price": 199.99, "stock": 50}
        )
        assert response.status_code == 201
        assert response.json()["name"] == "New Gadget"

    def test_user_can_create_order(self, test_client: TestClient, auth_headers: dict, sample_item: Item):
        """Regression: Verify user can create an order after order_service import changes."""
        response = test_client.post(
            "/api/v1/orders/",
            headers=auth_headers,
            json={"items": [{"item_id": sample_item.id, "quantity": 1}]}
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "pending"
        assert len(data["items"]) == 1
        assert data["items"][0]["item_id"] == sample_item.id

    def test_create_order_insufficient_stock(self, test_client: TestClient, auth_headers: dict, sample_item: Item):
        """Regression: Test order creation failure due to insufficient stock."""
        response = test_client.post(
            "/api/v1/orders/",
            headers=auth_headers,
            json={"items": [{"item_id": sample_item.id, "quantity": 100}]} # stock is 10
        )
        assert response.status_code == 400
        assert "Insufficient stock" in response.text

# --- Security and Authorization Tests ---

@pytest.mark.security
def test_regular_user_cannot_access_admin_user_list(test_client: TestClient, auth_headers: dict):
    """Security: Ensure a regular user gets 403 Forbidden on an admin route."""
    response = test_client.get("/api/v1/users/", headers=auth_headers)
    assert response.status_code == 403, "Regular user should not be able to list all users."

@pytest.mark.security
def test_inactive_user_cannot_login(test_client: TestClient, inactive_user: User):
    """Security: Ensure an inactive user cannot get an access token."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "inactive", "password": "InactPass123"}
    )
    assert response.status_code == 401
    assert "Inactive user" in response.text

@pytest.mark.security
@pytest.mark.parametrize("payload", ["' OR 1=1 --", "admin'--"])
def test_sql_injection_attempt_on_login(test_client: TestClient, payload: str):
    """Security: Test for basic SQL injection vulnerabilities on login form."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": payload, "password": "password"}
    )
    # Expect 401 Unauthorized, not 200 OK or 500 Server Error
    assert response.status_code == 401

@pytest.mark.security
@pytest.mark.parametrize("token", ["invalidtoken", "Bearer invalid", ""])
def test_access_protected_route_with_invalid_token(test_client: TestClient, token: str):
    """Security: Test accessing a protected route with various invalid tokens."""
    response = test_client.get("/api/v1/users/me", headers={"Authorization": token})
    assert response.status_code == 401, f"Token '{token}' should be unauthorized"

@pytest.mark.security
def test_access_protected_route_with_expired_token(test_user: User, test_client: TestClient):
    """Security: Test that an expired token is rejected."""
    # Create a token that expires immediately
    expired_token = create_access_token(
        data={"sub": test_user.username}, expires_delta=timedelta(seconds=-1)
    )
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = test_client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401
    assert "Token has expired" in response.text

@pytest.mark.security
def test_password_hash_not_exposed_in_user_endpoints(test_client: TestClient, admin_headers: dict, test_user: User):
    """Security: Verify hashed_password is not present in user data responses."""
    # /users/me
    response_me = test_client.get("/api/v1/users/me", headers=admin_headers)
    assert "hashed_password" not in response_me.json()

    # /users/{user_id}
    response_id = test_client.get(f"/api/v1/users/{test_user.id}", headers=admin_headers)
    assert "hashed_password" not in response_id.json()

    # /users/
    response_list = test_client.get("/api/v1/users/", headers=admin_headers)
    for user in response_list.json():
        assert "hashed_password" not in user

# --- Edge Case and Contract Tests ---

@pytest.mark.contract
def test_get_nonexistent_item_returns_404(test_client: TestClient):
    """Contract: Test that requesting a non-existent item returns a 404 Not Found."""
    response = test_client.get("/api/v1/items/99999")
    assert response.status_code == 404
    assert "Item not found" in response.text

@pytest.mark.contract
def test_unauthenticated_access_to_protected_route(test_client: TestClient):
    """Contract: Test that unauthenticated access to a protected route returns 401."""
    response = test_client.get("/api/v1/users/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

@pytest.mark.edge_case
def test_create_order_with_empty_items_list(test_client: TestClient, auth_headers: dict):
    """Edge Case: Test creating an order with an empty list of items."""
    response = test_client.post(
        "/api/v1/orders/",
        headers=auth_headers,
        json={"items": []}
    )
    assert response.status_code == 400
    assert "Order must contain at least one item" in response.text

@pytest.mark.edge_case
def test_create_item_with_negative_price(test_client: TestClient, admin_headers: dict):
    """Edge Case: Test creating an item with a negative price."""
    response = test_client.post(
        "/api/v1/items/",
        headers=admin_headers,
        json={"name": "Freebie", "description": "A free item", "price": -10.0, "stock": 100}
    )
    assert response.status_code == 422 # Pydantic validation should catch this