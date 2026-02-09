import pytest
from unittest.mock import patch
from config import Settings
from auth import verify_password, get_password_hash, create_access_token, ALGORITHM, SECRET_KEY
from jose import jwt

# Mark all tests in this file
pytestmark = [
    pytest.mark.unit,
    pytest.mark.integration,
    pytest.mark.security,
    pytest.mark.contract
]


@pytest.mark.unit
def test_settings_model_has_environment_default():
    """Unit: Verify that the Settings model has 'environment' with a default value."""
    s = Settings()
    assert hasattr(s, 'environment'), "Settings model should have an 'environment' attribute."
    assert s.environment == "development", "Default environment should be 'development'."


@pytest.mark.unit
def test_settings_model_environment_override(monkeypatch):
    """Unit: Verify the 'environment' in Settings can be overridden by an env var."""
    monkeypatch.setenv("ENVIRONMENT", "staging")
    s = Settings()
    assert s.environment == "staging", "Environment variable should override the default."


@pytest.mark.unit
def test_password_verification():
    """Unit: Test password hashing and verification from auth.py."""
    password = "short_password"
    hashed_password = get_password_hash(password)
    assert verify_password(password, hashed_password), "Password verification should succeed for correct password."
    assert not verify_password("wrong_password", hashed_password), "Password verification should fail for incorrect password."


@pytest.mark.integration
def test_health_check_endpoint_success(test_client):
    """Integration: Test that the /health endpoint returns a 200 OK status."""
    response = test_client.get("/health")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}. Response: {response.text}"


@pytest.mark.contract
def test_health_check_endpoint_contract(test_client):
    """Contract: Validate the schema and data types of the /health endpoint response."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    
    expected_keys = {"status", "version", "app", "environment"}
    assert set(data.keys()) == expected_keys, f"Response keys {set(data.keys())} do not match expected {expected_keys}"
    
    assert isinstance(data["status"], str)
    assert isinstance(data["version"], str)
    assert isinstance(data["app"], str)
    assert isinstance(data["environment"], str)
    assert data["status"] == "healthy"


@pytest.mark.integration
def test_health_check_environment_in_development_mode(test_client):
    """Integration: Verify /health reports 'development' when debug is True."""
    with patch('config.settings.debug', True):
        response = test_client.get("/health")
        assert response.status_code == 200
        assert response.json()["environment"] == "development", "Environment should be 'development' when debug is True."


@pytest.mark.integration
def test_health_check_environment_in_production_mode(test_client):
    """Integration: Verify /health reports 'production' when debug is False."""
    with patch('config.settings.debug', False):
        response = test_client.get("/health")
        assert response.status_code == 200
        assert response.json()["environment"] == "production", "Environment should be 'production' when debug is False."


@pytest.mark.security
def test_health_endpoint_does_not_expose_extra_sensitive_data(test_client):
    """Security: Ensure /health endpoint does not expose sensitive config other than intended."""
    with patch('config.settings') as mock_settings:
        mock_settings.database_url = "super_secret_db_connection_string"
        mock_settings.secret_key = "super_secret_jwt_key"
        mock_settings.app_name = "Test App"
        mock_settings.app_version = "1.0"
        mock_settings.debug = True

        response = test_client.get("/health")
        data = response.json()

        assert "database_url" not in data, "Database URL should not be exposed."
        assert "secret_key" not in data, "Secret key should not be exposed."
        assert len(data) == 4, "Only the four intended fields should be in the response."


# --- Smoke Tests for Import Refactoring Regression ---

@pytest.mark.integration
def test_smoke_user_registration(test_client):
    """Integration (Smoke): Test user registration to check for import refactoring regressions."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "smokeuser", "email": "smoke@test.com", "password": "SmokePass123"}
    )
    assert response.status_code == 201, f"User registration smoke test failed: {response.text}"
    data = response.json()
    assert data["username"] == "smokeuser"
    assert "id" in data


@pytest.mark.integration
def test_smoke_user_login(test_client, test_user):
    """Integration (Smoke): Test user login to check for import refactoring regressions."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "TestPass123"}
    )
    assert response.status_code == 200, f"User login smoke test failed: {response.text}"
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.integration
def test_smoke_create_item(test_client, auth_headers):
    """Integration (Smoke): Test item creation to check for import refactoring regressions."""
    response = test_client.post(
        "/api/v1/items/",
        json={"name": "Smoke Item", "description": "A test item", "price": 10.50, "stock": 100},
        headers=auth_headers
    )
    assert response.status_code == 201, f"Item creation smoke test failed: {response.text}"
    assert response.json()["name"] == "Smoke Item"


@pytest.mark.integration
def test_smoke_create_order(test_client, auth_headers, sample_item):
    """Integration (Smoke): Test order creation to check for import refactoring regressions."""
    response = test_client.post(
        "/api/v1/orders/",
        json={"items": [{"item_id": sample_item.id, "quantity": 1}]},
        headers=auth_headers
    )
    assert response.status_code == 201, f"Order creation smoke test failed: {response.text}"
    data = response.json()
    assert data["status"] == "pending"
    assert len(data["items"]) == 1


# --- Comprehensive Security and Edge Case Tests ---

@pytest.mark.security
def test_access_admin_route_as_regular_user(test_client, auth_headers):
    """Security: A regular user cannot access an admin-only route."""
    response = test_client.get("/api/v1/users/", headers=auth_headers)
    assert response.status_code == 403, "Regular user should get 403 Forbidden on admin routes."


@pytest.mark.security
def test_access_admin_route_as_admin(test_client, admin_headers):
    """Security: An admin user can access an admin-only route."""
    response = test_client.get("/api/v1/users/", headers=admin_headers)
    assert response.status_code == 200, "Admin user should be able to access admin routes."


@pytest.mark.security
def test_access_protected_route_with_invalid_token(test_client):
    """Security: API should reject requests with an invalid JWT token."""
    headers = {"Authorization": "Bearer invalidtoken"}
    response = test_client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401, "Access with invalid token should be unauthorized."


@pytest.mark.security
def test_access_protected_route_with_expired_token(test_client, test_user):
    """Security: API should reject requests with an expired JWT token."""
    # Create a token that is already expired
    expired_token = create_access_token(data={"sub": test_user.username}, expires_delta_seconds=-1)
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = test_client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401, "Access with expired token should be unauthorized."
    assert "token has expired" in response.json()["detail"].lower()


@pytest.mark.security
def test_password_hash_not_exposed_in_user_endpoints(test_client, admin_headers, test_user):
    """Security: Ensure hashed_password is not present in any user-related API responses."""
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


@pytest.mark.security
@pytest.mark.parametrize("payload", ["' OR 1=1 --", "admin'--", "'; SELECT * FROM users; --"])
def test_sql_injection_in_login(test_client, payload):
    """Security: Test for SQL injection vulnerabilities in the login form."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": payload, "password": "fakepassword"}
    )
    # Expect 401 Unauthorized, not 200 (successful injection) or 500 (query error)
    assert response.status_code == 401, f"Potential SQL injection vulnerability detected with payload: {payload}"


@pytest.mark.integration
def test_login_with_inactive_user(test_client, inactive_user):
    """Integration: An inactive user should not be able to log in."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "inactive", "password": "InactPass123"}
    )
    assert response.status_code == 401, "Inactive user should not be able to log in."
    assert "inactive" in response.json()["detail"].lower()


@pytest.mark.integration
@pytest.mark.parametrize("username, email, password, status_code, detail_substring", [
    ("test", "a@b.com", "GoodPass123", 422, "username"),  # Short username
    ("longenough", "a@b.com", "short", 422, "password"),  # Short password
    ("longenough", "not-an-email", "GoodPass123", 422, "email"), # Invalid email
    (None, "a@b.com", "GoodPass123", 422, "username"), # Missing username
])
def test_registration_validation_edge_cases(test_client, username, email, password, status_code, detail_substring):
    """Integration: Test various validation failures during user registration."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": username, "email": email, "password": password}
    )
    assert response.status_code == status_code
    # Pydantic v2 includes field name in error loc
    assert any(detail_substring in str(err['loc']) for err in response.json()['detail'])


@pytest.mark.contract
def test_404_not_found_contract(test_client, auth_headers):
    """Contract: Verify the response schema for a 404 Not Found error."""
    response = test_client.get("/api/v1/items/99999", headers=auth_headers)
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert isinstance(data["detail"], str)
    assert "not found" in data["detail"].lower()


@pytest.mark.contract
def test_401_unauthorized_contract(test_client):
    """Contract: Verify the response schema for a 401 Unauthorized error."""
    response = test_client.get("/api/v1/users/me")
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Not authenticated"
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.contract
def test_403_forbidden_contract(test_client, auth_headers):
    """Contract: Verify the response schema for a 403 Forbidden error."""
    response = test_client.delete("/api/v1/items/12345", headers=auth_headers) # Non-admin trying admin action
    assert response.status_code == 403
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Admin privileges required"


@pytest.mark.contract
def test_422_validation_error_contract(test_client):
    """Contract: Verify the response schema for a 422 Unprocessable Entity error."""
    response = test_client.post("/api/v1/auth/register", json={"username": "user"}) # Missing fields
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    assert isinstance(data["detail"], list)
    assert all("loc" in err and "msg" in err and "type" in err for err in data["detail"])


@pytest.mark.unit
def test_jwt_token_creation_and_decoding():
    """Unit: Test that JWT token creation and decoding works as expected."""
    username = "tokenuser"
    token = create_access_token(data={"sub": username})
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == username
    assert "exp" in payload


@pytest.mark.integration
def test_get_nonexistent_user(test_client, admin_headers):
    """Integration: Test requesting a user that does not exist."""
    response = test_client.get("/api/v1/users/99999", headers=admin_headers)
    assert response.status_code == 404
    assert "User not found" in response.json()["detail"]


@pytest.mark.integration
def test_create_item_with_negative_price(test_client, auth_headers):
    """Integration: Test creating an item with invalid data (negative price)."""
    response = test_client.post(
        "/api/v1/items/",
        json={"name": "Negative Price Item", "description": "Invalid", "price": -10.0, "stock": 5},
        headers=auth_headers
    )
    assert response.status_code == 422, "Negative price should be rejected with a 422 error."


@pytest.mark.integration
def test_update_order_status_as_admin(test_client, admin_headers, db_session, test_user, sample_item):
    """Integration: Test that an admin can update an order's status."""
    # Create an order first
    order = Order(user_id=test_user.id, items=[sample_item])
    db_session.add(order)
    db_session.commit()

    response = test_client.patch(
        f"/api/v1/orders/{order.id}/status?new_status=shipped",
        headers=admin_headers
    )
    assert response.status_code == 200, f"Admin should be able to update order status: {response.text}"
    assert response.json()["status"] == "shipped"


@pytest.mark.integration
def test_cancel_own_order(test_client, auth_headers, db_session, test_user, sample_item):
    """Integration: Test that a user can cancel their own order."""
    order = Order(user_id=test_user.id, items=[sample_item])
    db_session.add(order)
    db_session.commit()

    response = test_client.patch(f"/api/v1/orders/{order.id}/cancel", headers=auth_headers)
    assert response.status_code == 200, f"User should be able to cancel their own order: {response.text}"
    assert response.json()["status"] == "cancelled"


@pytest.mark.security
def test_user_cannot_cancel_another_users_order(test_client, auth_headers, db_session, admin_user, sample_item):
    """Security: Test that a user cannot cancel an order belonging to another user."""
    # Order belongs to admin_user
    order = Order(user_id=admin_user.id, items=[sample_item])
    db_session.add(order)
    db_session.commit()

    # test_user (with auth_headers) tries to cancel it
    response = test_client.patch(f"/api/v1/orders/{order.id}/cancel", headers=auth_headers)
    assert response.status_code == 403, "User should not be able to cancel another user's order."