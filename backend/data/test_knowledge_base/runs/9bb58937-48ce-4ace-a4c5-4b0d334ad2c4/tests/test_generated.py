import pytest
from fastapi.testclient import TestClient
from jose import jwt
from config import settings
from auth import verify_password, get_password_hash, create_access_token

# --- UNIT TESTS ---

@pytest.mark.unit
def test_password_hashing_and_verification():
    """Unit: Test password hashing and verification functions."""
    password = "A_Secure_Password_123"
    hashed_password = get_password_hash(password)
    assert hashed_password != password, "Hashed password should not be the same as the original."
    assert verify_password(password, hashed_password), "Password verification should succeed with correct password."
    assert not verify_password("WrongPassword", hashed_password), "Password verification should fail with incorrect password."

@pytest.mark.unit
def test_create_access_token():
    """Unit: Test JWT access token creation."""
    data = {"sub": "testuser"}
    token = create_access_token(data)
    decoded_token = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    assert decoded_token["sub"] == "testuser"
    assert "exp" in decoded_token, "Token should have an expiration claim."

# --- INTEGRATION TESTS for backend/main.py ---

@pytest.mark.integration
def test_read_root_endpoint(test_client: TestClient):
    """Integration: Test the root endpoint (/) for backend/main.py."""
    response = test_client.get("/")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert response.json() == {"message": "Hello, World!"}

@pytest.mark.integration
def test_health_check_endpoint(test_client: TestClient):
    """Integration: Test the health check endpoint (/health) for backend/main.py."""
    response = test_client.get("/health")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert response.json() == {"status": "healthy"}

# --- CONTRACT TESTS for backend/main.py ---

@pytest.mark.contract
def test_read_root_contract(test_client: TestClient):
    """Contract: Verify the response schema for the root endpoint (/) of backend/main.py."""
    response = test_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert isinstance(data["message"], str)

@pytest.mark.contract
def test_health_check_contract(test_client: TestClient):
    """Contract: Verify the response schema for the health endpoint (/health) of backend/main.py."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert isinstance(data["status"], str)
    assert data["status"] == "healthy"

# --- SECURITY TESTS for backend/main.py ---

@pytest.mark.security
def test_main_endpoints_allowed_methods(test_client: TestClient):
    """Security: Ensure only GET is allowed on root and health endpoints of backend/main.py."""
    for path in ["/", "/health"]:
        assert test_client.post(path).status_code == 405
        assert test_client.put(path).status_code == 405
        assert test_client.delete(path).status_code == 405
        assert test_client.patch(path).status_code == 405

# --- COMPREHENSIVE REGRESSION TESTS ---

@pytest.mark.integration
def test_user_registration_success(test_client: TestClient):
    """Integration: Test successful user registration."""
    response = test_client.post(
        "/api/v1/auth/register",
        json={"username": "newuser", "email": "new@example.com", "password": "NewUserPass123"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "new@example.com"
    assert "id" in data
    assert "hashed_password" not in data  # Security check

@pytest.mark.integration
@pytest.mark.parametrize("payload, expected_status, detail_substring", [
    ({"username": "testuser", "email": "another@example.com", "password": "password"}, 400, "Username already registered"),
    ({"username": "another", "email": "test@example.com", "password": "password"}, 400, "Email already registered"),
    ({"username": "u", "email": "e@e.com", "password": "p"}, 422, "ensure this value has at least 3 characters"),
    ({"username": "userlong", "email": "e@e.com", "password": "short"}, 422, "ensure this value has at least 8 characters"),
    ({"username": "userlong", "email": "not-an-email", "password": "ValidPassword123"}, 422, "value is not a valid email address"),
])
def test_user_registration_failures(test_client: TestClient, test_user, payload, expected_status, detail_substring):
    """Integration: Test various user registration failure scenarios."""
    response = test_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == expected_status
    assert detail_substring in response.text

@pytest.mark.integration
def test_user_login_success(test_client: TestClient, test_user):
    """Integration: Test successful user login."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "TestPass123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

@pytest.mark.integration
def test_user_login_wrong_password(test_client: TestClient, test_user):
    """Integration: Test login with incorrect password."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "WrongPassword"}
    )
    assert response.status_code == 401
    assert "Incorrect username or password" in response.json()["detail"]

@pytest.mark.integration
def test_user_login_inactive_user(test_client: TestClient, inactive_user):
    """Integration: Test login attempt by an inactive user."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "inactive", "password": "InactPass123"}
    )
    assert response.status_code == 400
    assert "Inactive user" in response.json()["detail"]

@pytest.mark.integration
def test_read_current_user(test_client: TestClient, auth_headers, test_user):
    """Integration: Test accessing the /users/me endpoint."""
    response = test_client.get("/api/v1/users/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == test_user.username
    assert data["email"] == test_user.email

@pytest.mark.security
def test_access_protected_route_no_auth(test_client: TestClient):
    """Security: Verify protected routes require authentication."""
    response = test_client.get("/api/v1/users/me")
    assert response.status_code == 401
    assert "Not authenticated" in response.json()["detail"]

@pytest.mark.security
def test_access_protected_route_invalid_token(test_client: TestClient):
    """Security: Verify protected routes fail with an invalid token."""
    headers = {"Authorization": "Bearer aninvalidtoken"}
    response = test_client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401
    assert "Could not validate credentials" in response.json()["detail"]

@pytest.mark.security
def test_access_admin_route_as_user(test_client: TestClient, auth_headers):
    """Security: Verify regular users cannot access admin routes."""
    response = test_client.get("/api/v1/users/", headers=auth_headers)
    assert response.status_code == 403
    assert "Admin privileges required" in response.json()["detail"]

@pytest.mark.security
def test_access_admin_route_as_admin(test_client: TestClient, admin_headers):
    """Security: Verify admin users can access admin routes."""
    response = test_client.get("/api/v1/users/", headers=admin_headers)
    assert response.status_code == 200

@pytest.mark.security
@pytest.mark.parametrize("username_inject", ["' OR 1=1 --", "admin'--"])
def test_sql_injection_login(test_client: TestClient, username_inject):
    """Security: Test for SQL injection vulnerability in login username field."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": username_inject, "password": "anypassword"}
    )
    assert response.status_code == 401, "Login should not succeed with SQL injection attempt."

@pytest.mark.integration
def test_create_item_as_admin(test_client: TestClient, admin_headers):
    """Integration: Test item creation by an admin user."""
    item_data = {"name": "Admin Item", "description": "An item created by admin.", "price": 199.99, "stock": 50}
    response = test_client.post("/api/v1/items/", json=item_data, headers=admin_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == item_data["name"]
    assert "id" in data

@pytest.mark.integration
def test_create_item_as_user_fails(test_client: TestClient, auth_headers):
    """Integration: Test that a regular user cannot create an item."""
    item_data = {"name": "User Item", "description": "An item created by user.", "price": 29.99, "stock": 5}
    response = test_client.post("/api/v1/items/", json=item_data, headers=auth_headers)
    assert response.status_code == 403

@pytest.mark.integration
def test_read_items_publicly(test_client: TestClient, sample_item):
    """Integration: Test that items can be read without authentication."""
    response = test_client.get("/api/v1/items/")
    assert response.status_code == 200
    assert len(response.json()) >= 1
    assert response.json()[0]["name"] == sample_item.name

@pytest.mark.integration
def test_read_item_by_id(test_client: TestClient, sample_item):
    """Integration: Test reading a single item by its ID."""
    response = test_client.get(f"/api/v1/items/{sample_item.id}")
    assert response.status_code == 200
    assert response.json()["name"] == sample_item.name

@pytest.mark.integration
def test_read_nonexistent_item(test_client: TestClient):
    """Integration: Test reading a nonexistent item results in 404."""
    response = test_client.get("/api/v1/items/99999")
    assert response.status_code == 404
    assert "Item not found" in response.json()["detail"]

@pytest.mark.integration
def test_update_item_as_admin(test_client: TestClient, sample_item, admin_headers):
    """Integration: Test updating an item as an admin."""
    update_data = {"price": 129.99, "stock": 5}
    response = test_client.put(f"/api/v1/items/{sample_item.id}", json=update_data, headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["price"] == 129.99
    assert data["stock"] == 5

@pytest.mark.integration
def test_delete_item_as_admin(test_client: TestClient, sample_item, admin_headers):
    """Integration: Test deleting an item as an admin."""
    response = test_client.delete(f"/api/v1/items/{sample_item.id}", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["message"] == "Item deleted successfully"
    # Verify it's gone
    get_response = test_client.get(f"/api/v1/items/{sample_item.id}")
    assert get_response.status_code == 404

@pytest.mark.contract
def test_validation_error_contract(test_client: TestClient):
    """Contract: Test the structure of a 422 Unprocessable Entity error."""
    response = test_client.post("/api/v1/auth/register", json={"username": "a", "password": "b"})
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    assert isinstance(data["detail"], list)
    assert "loc" in data["detail"][0]
    assert "msg" in data["detail"][0]
    assert "type" in data["detail"][0]

@pytest.mark.contract
def test_user_me_contract(test_client: TestClient, auth_headers):
    """Contract: Verify the response schema for the /users/me endpoint."""
    response = test_client.get("/api/v1/users/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "id" in data and isinstance(data["id"], int)
    assert "username" in data and isinstance(data["username"], str)
    assert "email" in data and isinstance(data["email"], str)
    assert "is_active" in data and isinstance(data["is_active"], bool)
    assert "is_admin" in data and isinstance(data["is_admin"], bool)
    assert "hashed_password" not in data

@pytest.mark.contract
def test_item_schema_contract(test_client: TestClient, sample_item):
    """Contract: Verify the response schema for a single item."""
    response = test_client.get(f"/api/v1/items/{sample_item.id}")
    assert response.status_code == 200
    data = response.json()
    assert "id" in data and isinstance(data["id"], int)
    assert "name" in data and isinstance(data["name"], str)
    assert "description" in data and isinstance(data["description"], str)
    assert "price" in data and isinstance(data["price"], float)
    assert "stock" in data and isinstance(data["stock"], int)

@pytest.mark.integration
def test_create_order_as_user(test_client: TestClient, auth_headers, sample_item):
    """Integration: Test creating an order as an authenticated user."""
    order_data = {"items": [{"item_id": sample_item.id, "quantity": 1}]}
    response = test_client.post("/api/v1/orders/", json=order_data, headers=auth_headers)
    assert response.status_code == 201, f"Failed to create order: {response.text}"
    data = response.json()
    assert data["owner_id"] == 1 # test_user has id 1
    assert len(data["items"]) == 1
    assert data["items"][0]["item_id"] == sample_item.id

@pytest.mark.integration
def test_create_order_insufficient_stock(test_client: TestClient, auth_headers, sample_item):
    """Integration: Test creating an order where item stock is insufficient."""
    order_data = {"items": [{"item_id": sample_item.id, "quantity": sample_item.stock + 1}]}
    response = test_client.post("/api/v1/orders/", json=order_data, headers=auth_headers)
    assert response.status_code == 400
    assert "Not enough stock for item" in response.json()["detail"]

@pytest.mark.integration
def test_get_user_orders(test_client: TestClient, auth_headers, sample_item):
    """Integration: Test retrieving orders for the current user."""
    # First, create an order
    order_data = {"items": [{"item_id": sample_item.id, "quantity": 1}]}
    test_client.post("/api/v1/orders/", json=order_data, headers=auth_headers)

    # Then, retrieve orders
    response = test_client.get("/api/v1/orders/my-orders", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["items"][0]["item_id"] == sample_item.id

@pytest.mark.integration
def test_get_all_orders_as_admin(test_client: TestClient, admin_headers, auth_headers, sample_item):
    """Integration: Test retrieving all orders as an admin."""
    # User creates an order
    order_data = {"items": [{"item_id": sample_item.id, "quantity": 1}]}
    test_client.post("/api/v1/orders/", json=order_data, headers=auth_headers)

    # Admin retrieves all orders
    response = test_client.get("/api/v1/orders/", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1

@pytest.mark.security
def test_get_all_orders_as_user_fails(test_client: TestClient, auth_headers):
    """Security: Test that a regular user cannot retrieve all orders."""
    response = test_client.get("/api/v1/orders/", headers=auth_headers)
    assert response.status_code == 403
    assert "Admin privileges required" in response.json()["detail"]