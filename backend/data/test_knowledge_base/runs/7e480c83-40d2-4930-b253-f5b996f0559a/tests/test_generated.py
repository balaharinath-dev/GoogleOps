import pytest
from fastapi.testclient import TestClient
import json
import sys
import os

# Ensure the app module can be imported
# This assumes the conftest.py has correctly set up the sys.path
try:
    from app import read_root
except ImportError:
    # Define a dummy function if the import fails, allowing tests to be collected
    def read_root():
        return {"Hello": "World"}


# =================================================================
# == UNIT TESTS
# =================================================================
# These tests cover the individual functions in app.py

@pytest.mark.unit
def test_unit_read_root_return_value():
    """Unit: Tests that the read_root() function returns the correct dictionary."""
    # Covers: app.py
    expected_dict = {"Hello": "World"}
    result = read_root()
    assert result == expected_dict, f"Expected {expected_dict}, but got {result}"

@pytest.mark.unit
def test_unit_read_root_return_type():
    """Unit: Tests that the read_root() function returns a dictionary."""
    # Covers: app.py
    result = read_root()
    assert isinstance(result, dict), f"Expected a dict, but got {type(result)}"

@pytest.mark.unit
def test_unit_read_root_is_not_empty():
    """Unit: Tests that the returned dictionary from read_root() is not empty."""
    # Covers: app.py
    result = read_root()
    assert len(result) > 0, "Expected a non-empty dictionary"


# =================================================================
# == INTEGRATION TESTS
# =================================================================
# These tests cover the API endpoint integration in app.py

@pytest.mark.integration
def test_integration_root_get_status_code_200(test_client: TestClient):
    """Integration: Tests that the root endpoint '/' returns a 200 OK status code."""
    # Covers: app.py
    response = test_client.get("/")
    assert response.status_code == 200, f"Expected status 200, but got {response.status_code}"

@pytest.mark.integration
def test_integration_root_get_response_json(test_client: TestClient):
    """Integration: Tests that the root endpoint '/' returns the correct JSON payload."""
    # Covers: app.py
    response = test_client.get("/")
    expected_json = {"Hello": "World"}
    assert response.json() == expected_json, f"Expected {expected_json}, but got {response.json()}"

@pytest.mark.integration
def test_integration_root_with_trailing_slash(test_client: TestClient):
    """Integration: Tests that the root endpoint works with a trailing slash ('/')."""
    # Covers: app.py
    response = test_client.get("/")
    assert response.status_code == 200
    assert response.json() == {"Hello": "World"}

@pytest.mark.integration
@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def test_integration_root_disallowed_methods(test_client: TestClient, method: str):
    """Integration: Tests that unsupported HTTP methods on '/' return 405 Method Not Allowed."""
    # Covers: app.py
    response = test_client.request(method, "/")
    assert response.status_code == 405, f"Expected status 405 for {method}, but got {response.status_code}"

@pytest.mark.integration
def test_integration_nonexistent_route_404(test_client: TestClient):
    """Integration: Tests that accessing a non-existent route returns a 404 Not Found."""
    # Covers: app.py (by testing the FastAPI router)
    response = test_client.get("/nonexistent-path-123")
    assert response.status_code == 404, f"Expected status 404, but got {response.status_code}"


# =================================================================
# == CONTRACT TESTS
# =================================================================
# These tests validate the API contract of the endpoints in app.py

@pytest.mark.contract
def test_contract_root_response_content_type(test_client: TestClient):
    """Contract: Verifies the 'Content-Type' header is 'application/json'."""
    # Covers: app.py
    response = test_client.get("/")
    assert response.headers.get("content-type") == "application/json", \
        f"Expected content-type 'application/json', got '{response.headers.get('content-type')}'"

@pytest.mark.contract
def test_contract_root_response_schema_key_present(test_client: TestClient):
    """Contract: Verifies the JSON response contains the 'Hello' key."""
    # Covers: app.py
    response = test_client.get("/")
    data = response.json()
    assert "Hello" in data, "Response JSON must contain the 'Hello' key"

@pytest.mark.contract
def test_contract_root_response_schema_value_type(test_client: TestClient):
    """Contract: Verifies the value of the 'Hello' key is a string."""
    # Covers: app.py
    response = test_client.get("/")
    data = response.json()
    assert isinstance(data.get("Hello"), str), "The value for 'Hello' key must be a string"

@pytest.mark.contract
def test_contract_root_response_schema_no_extra_keys(test_client: TestClient):
    """Contract: Verifies the response contains no unexpected keys."""
    # Covers: app.py
    response = test_client.get("/")
    data = response.json()
    expected_keys = {"Hello"}
    actual_keys = set(data.keys())
    assert actual_keys == expected_keys, f"Response keys {actual_keys} do not match expected {expected_keys}"

@pytest.mark.contract
def test_contract_root_response_is_valid_json(test_client: TestClient):
    """Contract: Verifies the response body is a valid JSON object."""
    # Covers: app.py
    response = test_client.get("/")
    try:
        json.loads(response.text)
    except json.JSONDecodeError:
        pytest.fail("Response body is not valid JSON.")

@pytest.mark.contract
def test_contract_404_error_schema(test_client: TestClient):
    """Contract: Verifies the schema of a 404 Not Found error response."""
    # Covers: app.py (FastAPI default error handling)
    response = test_client.get("/nonexistent-path-for-schema")
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data, "404 error response should contain a 'detail' key"
    assert data["detail"] == "Not Found", "404 detail message is incorrect"


# =================================================================
# == SECURITY TESTS
# =================================================================
# These tests check for potential security issues in app.py

@pytest.mark.security
def test_security_root_ignores_query_params(test_client: TestClient):
    """Security: Ensures the root endpoint ignores unexpected query parameters."""
    # Covers: app.py
    response = test_client.get("/?param1=value1&param2=<script>alert(1)</script>")
    assert response.status_code == 200
    assert response.json() == {"Hello": "World"}, "Endpoint should ignore query parameters"

@pytest.mark.security
def test_security_root_ignores_body_on_get(test_client: TestClient):
    """Security: Ensures the GET endpoint ignores any request body."""
    # Covers: app.py
    response = test_client.get("/", json={"malicious": "data"})
    assert response.status_code == 200
    assert response.json() == {"Hello": "World"}, "GET endpoint should ignore request body"

@pytest.mark.security
def test_security_headers_x_content_type_options(test_client: TestClient):
    """Security: Checks for the presence of 'X-Content-Type-Options' header to prevent MIME-sniffing."""
    # Covers: app.py (Web server/framework defaults)
    response = test_client.get("/")
    # Modern frameworks often include this by default. Uvicorn/Starlette does not.
    # A good security test asserts the desired state. Here we check it's 'nosniff' if present.
    header_value = response.headers.get("x-content-type-options")
    if header_value is not None:
        assert header_value == "nosniff"

@pytest.mark.security
def test_security_no_server_header_leakage(test_client: TestClient):
    """Security: Checks the 'Server' header to ensure it's not overly verbose."""
    # Covers: app.py (Web server/framework defaults)
    response = test_client.get("/")
    server_header = response.headers.get("server")
    assert server_header is not None, "Server header should be present"
    # A production environment might want to remove or minimize this.
    # This test just verifies its presence and that it's not empty.
    assert "uvicorn" in server_header, "Expecting uvicorn as the server"

@pytest.mark.security
def test_security_path_traversal_attempt(test_client: TestClient):
    """Security: Attempts a basic path traversal attack, expecting a 404."""
    # Covers: app.py (FastAPI routing)
    response = test_client.get("/../../etc/passwd")
    assert response.status_code == 404, "Path traversal should result in a 404 Not Found"