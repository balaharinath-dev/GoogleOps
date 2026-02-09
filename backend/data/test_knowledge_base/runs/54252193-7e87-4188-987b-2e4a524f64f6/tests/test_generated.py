import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

# Import application components
from config import settings
from main import health_check
from auth import get_password_hash, verify_password, create_access_token, authenticate_user
from services.user_service import UserService
from schemas import UserCreate

# --- Health Check Tests (main.py, config.py) ---

@pytest.mark.integration
def test_health_endpoint_success_and_structure(test_client: TestClient):
    """
    Integration: Tests the /health endpoint for a successful response and correct structure.
    Covers: main.py, config.py
    """
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "version" in data
    assert "app" in data
    assert "environment" in data
    assert data["status"] == "healthy"

@pytest.mark.contract
def test_health_endpoint_contract_validation(test_client: TestClient):
    """
    Contract: Validates the data types and structure of the /health endpoint response.
    Covers: main.py, config.py
    """
    response = test_client.get("/health")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    data = response.json()
    assert isinstance(data["status"], str)
    assert isinstance(data["version"], str)
    assert isinstance(data["app"], str)
    assert isinstance(data["environment"], str)
    assert data["environment"] in ["production", "development"]

@pytest.mark.unit
def test_health_check_unit_development_environment(monkeypatch):
    """
    Unit: Tests the health_check function directly for 'development' environment.
    Covers: main.py, config.py
    """
    monkeypatch.setattr(settings, "debug", True)
    result = health_check()
    assert result["environment"] == "development"

@pytest.mark.unit
def test_health_check_unit_production_environment(monkeypatch):
    """
    Unit: Tests the health_check function directly for 'production' environment.
    Covers: main.py, config.py
    """
    monkeypatch.setattr(settings, "debug", False)
    result = health_check()
    assert result["environment"] == "production"

@pytest.mark.security
def test_health_endpoint_does_not_expose_sensitive_info(test_client: TestClient):
    """
    Security: Ensures the /health endpoint does not expose sensitive configuration.
    Covers: main.py, config.py
    """
    response = test_client.get("/health")
    data = response.json()
    sensitive_keys = ["secret_key", "database_url", "password", "token"]
    for key in data:
        for sensitive in sensitive_keys:
            assert sensitive not in key.lower()

# --- Regression Tests for Import Refactoring ---

@pytest.mark.integration
def test_user_registration_regression(test_client: TestClient):
    """
    Integration: Regression test for user registration to ensure import refactoring did not break it.
    Covers: main.py, auth.py, services/user_service.py
    """
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "newuser", "email": "new@example.com", "password": "NewPassword123"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "new@example.com"

@pytest.mark.integration
def test_user_login_regression(test_client: TestClient, test_user):
    """
    Integration: Regression test for user login.
    Covers: main.py, auth.py
    """
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "TestPass123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

@pytest.mark.integration
def test_get_items_regression(test_client: TestClient, sample_item):
    """
    Integration: Regression test for listing items.
    Covers: main.py, services/item_service.py
    """
    response = test_client.get("/api/v1/items/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert data[0]["name"] == sample_item.name

@pytest.mark.integration
def test_create_item_regression(test_client: TestClient, admin_headers):
    """
    Integration: Regression test for creating an item as admin.
    Covers: main.py, services/item_service.py, models.py
    """
    response = test_client.post(
        "/api/v1/items/",
        headers=admin_headers,
        json={"name": "New Gadget", "description": "A shiny new gadget", "price": 199.99, "stock": 50}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "New Gadget"
    assert data["stock"] == 50

@pytest.mark.integration
def test_create_order_regression(test_client: TestClient, auth_headers, sample_item):
    """
    Integration: Regression test for creating an order.
    Covers: main.py, services/order_service.py, models.py
    """
    response = test_client.post(
        "/api/v1/orders/",
        headers=auth_headers,
        json={"items": [{"item_id": sample_item.id, "quantity": 1}]}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "PENDING"
    assert len(data["items"]) == 1
    assert data["items"][0]["item_id"] == sample_item.id

# --- Unit Tests for Core Logic ---

@pytest.mark.unit
def test_password_hashing_and_verification():
    """
    Unit: Tests the password hashing and verification functions.
    Covers: auth.py
    """
    password = "SafePassword123!"
    hashed_password = get_password_hash(password)
    assert isinstance(hashed_password, str)
    assert hashed_password != password
    assert verify_password(password, hashed_password)
    assert not verify_password("WrongPassword", hashed_password)

@pytest.mark.unit
def test_authenticate_user_logic(db_session, test_user):
    """
    Unit: Tests the authenticate_user function directly.
    Covers: auth.py
    """
    # Successful authentication
    user = authenticate_user(db_session, "testuser", "TestPass123")
    assert user is not None
    assert user.username == "testuser"

    # Failed authentication (wrong password)
    user = authenticate_user(db_session, "testuser", "WrongPass")
    assert user is False

    # Failed authentication (user not found)
    user = authenticate_user(db_session, "nosuchuser", "anypass")
    assert user is False

@pytest.mark.unit
def test_user_service_create_user(db_session):
    """
    Unit: Tests the user creation logic in UserService.
    Covers: services/user_service.py
    """
    user_service = UserService(db_session)
    user_schema = UserCreate(username="serviceuser", email="service@user.com", password="ServicePassword123")
    user = user_service.create_user(user_schema)
    assert user is not None
    assert user.username == "serviceuser"
    assert user.email == "service@user.com"
    assert verify_password("ServicePassword123", user.hashed_password)

# --- Security Tests ---

@pytest.mark.security
@pytest.mark.parametrize("endpoint", [
    "/api/v1/users/me",
    "/api/v1/orders/my-orders"
])
def test_access_protected_route_without_token(test_client: TestClient, endpoint):
    """
    Security: Verifies that protected routes return 401 Unauthorized without a token.
    Covers: main.py, auth.py
    """
    response = test_client.get(endpoint)
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

@pytest.mark.security
def test_access_protected_route_with_invalid_token(test_client: TestClient):
    """
    Security: Verifies that protected routes return 401 with a malformed token.
    Covers: main.py, auth.py
    """
    headers = {"Authorization": "Bearer an-invalid-token"}
    response = test_client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"

@pytest.mark.security
def test_access_protected_route_with_expired_token(test_user):
    """
    Security: Verifies that protected routes return 401 with an expired token.
    Covers: main.py, auth.py
    """
    # Create a token that expired 1 minute ago
    expired_token = create_access_token(
        data={"sub": test_user.username},
        expires_delta=timedelta(minutes=-1)
    )
    # This test needs a live client to make a request, so it's a hybrid
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = client.get("/api/v1/users/me", headers=headers)
        assert response.status_code == 401
        assert response.json()["detail"] == "Could not validate credentials" # Or "Token has expired" depending on implementation

@pytest.mark.security
def test_admin_route_access_by_regular_user(test_client: TestClient, auth_headers):
    """
    Security: Ensures a regular user cannot access admin-only routes.
    Covers: main.py, auth.py
    """
    response = test_client.post(
        "/api/v1/items/",
        headers=auth_headers,
        json={"name": "Attempted Item", "description": "Should fail", "price": 10.0, "stock": 1}
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "The user doesn't have enough privileges"

@pytest.mark.security
def test_inactive_user_cannot_login(test_client: TestClient, inactive_user):
    """
    Security: Ensures an inactive user cannot log in and get a token.
    Covers: main.py, auth.py
    """
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "inactive", "password": "InactPass123"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Inactive user"

@pytest.mark.security
def test_sql_injection_attempt_in_login(test_client: TestClient):
    """
    Security: Attempts a basic SQL injection in the login form. ORM should prevent it.
    Covers: main.py, auth.py
    """
    # A simple SQL injection payload
    malicious_username = "' OR 1=1 --"
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": malicious_username, "password": "anypassword"}
    )
    # Expecting failure, not a 200 OK with a token
    assert response.status_code == 404 # Because user ' OR 1=1 --' does not exist
    assert "access_token" not in response.json()

# --- Contract and Edge Case Tests ---

@pytest.mark.contract
def test_login_response_contract(test_client: TestClient, test_user):
    """
    Contract: Validates the schema of a successful login response.
    Covers: main.py, auth.py
    """
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "TestPass123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert list(data.keys()) == ["access_token", "token_type"]
    assert isinstance(data["access_token"], str)
    assert data["token_type"] == "bearer"

@pytest.mark.contract
def test_validation_error_contract(test_client: TestClient):
    """
    Contract: Validates the schema of a 422 Unprocessable Entity error.
    Covers: main.py
    """
    response = test_client.post("/api/v1/auth/register", json={"username": "no_email_or_pass"})
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    assert isinstance(data["detail"], list)
    assert "loc" in data["detail"][0]
    assert "msg" in data["detail"][0]
    assert "type" in data["detail"][0]

@pytest.mark.contract
def test_not_found_error_contract(test_client: TestClient):
    """
    Contract: Validates the schema of a 404 Not Found error.
    Covers: main.py
    """
    response = test_client.get("/api/v1/items/999999") # Assuming this item does not exist
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Item not found"

@pytest.mark.edge_case
def test_create_order_with_zero_stock_item(test_client: TestClient, auth_headers, db_session):
    """
    Edge Case: Tests creating an order for an item that is out of stock.
    Covers: services/order_service.py
    """
    from models import Item
    zero_stock_item = Item(name="Out of Stock", description="None left", price=10.0, stock=0)
    db_session.add(zero_stock_item)
    db_session.commit()

    response = test_client.post(
        "/api/v1/orders/",
        headers=auth_headers,
        json={"items": [{"item_id": zero_stock_item.id, "quantity": 1}]}
    )
    assert response.status_code == 400
    assert "not enough stock" in response.json()["detail"].lower()

@pytest.mark.edge_case
def test_create_order_with_nonexistent_item(test_client: TestClient, auth_headers):
    """
    Edge Case: Tests creating an order with an item_id that does not exist.
    Covers: services/order_service.py
    """
    response = test_client.post(
        "/api/v1/orders/",
        headers=auth_headers,
        json={"items": [{"item_id": 99999, "quantity": 1}]}
    )
    assert response.status_code == 404
    assert "Item with ID 99999 not found" in response.json()["detail"]

@pytest.mark.edge_case
def test_register_duplicate_username(test_client: TestClient, test_user):
    """
    Edge Case: Tests registering a user with an already existing username.
    Covers: services/user_service.py
    """
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "testuser", "email": "newemail@example.com", "password": "somepassword"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Username already registered"

@pytest.mark.edge_case
def test_register_duplicate_email(test_client: TestClient, test_user):
    """
    Edge Case: Tests registering a user with an already existing email.
    Covers: services/user_service.py
    """
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "newuser", "email": "test@example.com", "password": "somepassword"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Email already registered"