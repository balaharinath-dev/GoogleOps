import pytest
from fastapi.testclient import TestClient
import time

# Import the function and app from the source file to allow for unit testing
from app import read_root, app

# ===================================================================================
# TEST COVERAGE FOR: app.py
# This test suite provides comprehensive coverage for the newly added app.py file.
# ===================================================================================


# =================================
# ===== UNIT TESTS for app.py =====
# =================================

@pytest.mark.unit
def test_unit_read_root_return_type():
    """Unit: Tests that the read_root() function returns a dictionary."""
    # This test covers the function `read_root` in `app.py`.
    result = read_root()
    assert isinstance(result, dict), f"Expected a dict, but got {type(result)}"

@pytest.mark.unit
def test_unit_read_root_return_value():
    """Unit: Tests that read_root() returns the correct static dictionary."""
    # This test covers the function `read_root` in `app.py`.
    expected_value = {"Hello": "World"}
    result = read_root()
    assert result == expected_value, f"Expected {expected_value}, but got {result}"

@pytest.mark.unit
def test_unit_read_root_is_idempotent():
    """Unit: Ensures that multiple calls to read_root() return the same value."""
    # This test covers the function `read_root` in `app.py`.
    first_call = read_root()
    second_call = read_root()
    assert first_call == second_call, "Function is not idempotent, returned different values on subsequent calls."


# ========================================
# ===== INTEGRATION TESTS for app.py =====
# ========================================

@pytest.mark.integration
def test_integration_get_root_endpoint_status_code(test_client: TestClient):
    """Integration: Tests that the root endpoint '/' returns a 200 OK status code."""
    # This test covers the GET endpoint at `/` in `app.py`.
    response = test_client.get("/")
    assert response.status_code == 200, f"Expected status 200, but got {response.status_code}"

@pytest.mark.integration
def test_integration_get_root_endpoint_response_json(test_client: TestClient):
    """Integration: Tests that the root endpoint '/' returns the correct JSON payload."""
    # This test covers the GET endpoint at `/` in `app.py`.
    response = test_client.get("/")
    expected_json = {"Hello": "World"}
    assert response.json() == expected_json, f"Expected JSON {expected_json}, but got {response.json()}"

@pytest.mark.integration
def test_integration_non_existent_endpoint_returns_404(test_client: TestClient):
    """Integration: Tests that accessing a non-existent path returns a 404 Not Found."""
    # This test covers the general routing behavior of the FastAPI app in `app.py`.
    response = test_client.get("/this-path-does-not-exist")
    assert response.status_code == 404, f"Expected status 404 for a non-existent path, but got {response.status_code}"

@pytest.mark.integration
@pytest.mark.parametrize("path", ["/", "//", "/?foo=bar", "/?a=1&b=2"])
def test_integration_root_path_variations(test_client: TestClient, path: str):
    """Integration: Tests that the root endpoint handles variations like trailing slashes and query params."""
    # This test covers the GET endpoint at `/` in `app.py`.
    response = test_client.get(path)
    assert response.status_code == 200
    assert response.json() == {"Hello": "World"}

@pytest.mark.integration
def test_integration_health_check_performance(test_client: TestClient):
    """Integration: Checks if the health check endpoint responds within an acceptable time."""
    # This test covers the GET endpoint at `/` in `app.py`.
    start_time = time.time()
    response = test_client.get("/")
    duration = time.time() - start_time
    assert response.status_code == 200
    assert duration < 0.1, f"Response time {duration:.4f}s is too slow (limit is 0.1s)."


# =====================================
# ===== CONTRACT TESTS for app.py =====
# =====================================

@pytest.mark.contract
def test_contract_root_response_content_type_header(test_client: TestClient):
    """Contract: Verifies the 'Content-Type' header is 'application/json'."""
    # This test covers the API contract of the GET endpoint at `/` in `app.py`.
    response = test_client.get("/")
    assert response.headers["content-type"] == "application/json", f"Wrong Content-Type header: {response.headers.get('content-type')}"

@pytest.mark.contract
def test_contract_root_response_schema_has_hello_key(test_client: TestClient):
    """Contract: Ensures the JSON response contains the 'Hello' key."""
    # This test covers the API contract of the GET endpoint at `/` in `app.py`.
    response = test_client.get("/")
    data = response.json()
    assert "Hello" in data, "Response JSON is missing the 'Hello' key."

@pytest.mark.contract
def test_contract_root_response_schema_value_is_string(test_client: TestClient):
    """Contract: Ensures the value for the 'Hello' key is a string."""
    # This test covers the API contract of the GET endpoint at `/` in `app.py`.
    response = test_client.get("/")
    data = response.json()
    assert isinstance(data.get("Hello"), str), "The value for 'Hello' key is not a string."

@pytest.mark.contract
def test_contract_root_response_schema_is_exact(test_client: TestClient):
    """Contract: Ensures no extra keys are present in the response."""
    # This test covers the API contract of the GET endpoint at `/` in `app.py`.
    response = test_client.get("/")
    data = response.json()
    assert len(data.keys()) == 1, f"Expected 1 key in response, but found {len(data.keys())}."
    assert "Hello" in data

@pytest.mark.contract
@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_contract_disallowed_methods_on_root(test_client: TestClient, method: str):
    """Contract: Tests that non-GET methods are not allowed on the root endpoint."""
    # This test covers the API contract of the GET endpoint at `/` in `app.py`.
    response = test_client.request(method, "/")
    assert response.status_code == 405, f"Expected 405 Method Not Allowed for {method}, but got {response.status_code}"
    assert "detail" in response.json()
    assert response.json()["detail"] == "Method Not Allowed"

@pytest.mark.contract
def test_contract_options_method_on_root(test_client: TestClient):
    """Contract: Verifies the OPTIONS method returns correct 'Allow' header."""
    # This test covers the API contract of the GET endpoint at `/` in `app.py`.
    response = test_client.options("/")
    assert response.status_code == 200
    assert "allow" in response.headers
    # For a simple GET, it should at least contain GET. HEAD and OPTIONS are often included by the framework.
    assert "GET" in response.headers["allow"]

@pytest.mark.contract
def test_contract_404_error_schema(test_client: TestClient):
    """Contract: Verifies the response schema for a 404 Not Found error."""
    # This test covers the general error contract of the FastAPI app in `app.py`.
    response = test_client.get("/not-a-real-endpoint")
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Not Found"


# =====================================
# ===== SECURITY TESTS for app.py =====
# =====================================

@pytest.mark.security
def test_security_no_sensitive_server_header(test_client: TestClient):
    """Security: Checks that the 'Server' header does not leak specific version info."""
    # This test covers a basic security hardening check for the app in `app.py`.
    response = test_client.get("/")
    server_header = response.headers.get("server")
    assert server_header is not None, "Server header is missing."
    # Production servers should not advertise specific versions.
    assert "uvicorn" not in server_header.lower(), f"Server header discloses framework details: {server_header}"

@pytest.mark.security
def test_security_x_content_type_options_header(test_client: TestClient):
    """Security: Ensures 'X-Content-Type-Options: nosniff' header is present."""
    # This test covers a basic security hardening check for the app in `app.py`.
    response = test_client.get("/")
    header_value = response.headers.get("x-content-type-options")
    assert header_value == "nosniff", f"Missing or incorrect X-Content-Type-Options header. Got: {header_value}"

@pytest.mark.security
@pytest.mark.parametrize("payload", ["<script>alert(1)</script>", "' OR 1=1;--", "../../../etc/passwd"])
def test_security_malicious_query_params_ignored(test_client: TestClient, payload: str):
    """Security: Tests that malicious payloads in query params are ignored by the static endpoint."""
    # This test covers the robustness of the endpoint in `app.py` against unsolicited input.
    response = test_client.get(f"/?input={payload}")
    assert response.status_code == 200
    assert response.json() == {"Hello": "World"}, "Endpoint behavior changed with malicious query parameter."

@pytest.mark.security
def test_security_path_traversal_attempt_404(test_client: TestClient):
    """Security: Tests a path traversal attempt, which should result in a 404."""
    # This test covers the robustness of the routing in `app.py` against path traversal.
    response = test_client.get("/../../etc/passwd")
    assert response.status_code == 404, "Path traversal was not handled correctly, expected 404."

@pytest.mark.security
def test_security_no_xss_in_static_response(test_client: TestClient):
    """Security: Verifies that the static response does not contain potential XSS vectors."""
    # This test covers the output encoding of the endpoint in `app.py`.
    response = test_client.get("/")
    response_text = response.text
    assert "<" not in response_text and ">" not in response_text, "Response contains HTML-like characters, potential XSS risk."

@pytest.mark.security
def test_security_root_accessible_with_any_auth_header(test_client: TestClient, auth_headers):
    """Security: Ensures a public endpoint remains accessible even if an auth header is provided."""
    # This test covers the public nature of the endpoint in `app.py`.
    response = test_client.get("/", headers=auth_headers)
    assert response.status_code == 200, "Endpoint should be accessible with an auth header."
    assert response.json() == {"Hello": "World"}

@pytest.mark.security
def test_security_root_accessible_with_invalid_auth_header(test_client: TestClient):
    """Security: Ensures a public endpoint remains accessible with a malformed auth header."""
    # This test covers the public nature of the endpoint in `app.py`.
    headers = {"Authorization": "Bearer this-is-not-a-valid-token"}
    response = test_client.get("/", headers=headers)
    assert response.status_code == 200, "Endpoint should be accessible with an invalid auth header."
    assert response.json() == {"Hello": "World"}

@pytest.mark.security
def test_security_host_header_injection_ignored(test_client: TestClient):
    """Security: Checks if the app is vulnerable to Host header injection (it should not be for this endpoint)."""
    # This test covers a common web security vulnerability.
    headers = {"Host": "malicious-site.com"}
    response = test_client.get("/", headers=headers)
    # The response should not change, and no redirects should occur.
    assert response.status_code == 200
    # Check that no location header is trying to redirect to the malicious host
    assert "location" not in response.headers