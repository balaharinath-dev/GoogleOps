import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
import inspect
import time

# All tests in this file are for the new 'app.py' file.
# This covers the change from commit 1182a78aeadae8768fa6a45e3c344b7da2dbc27a.

# Attempt to import from the user's codebase
try:
    from app import app, read_root
except ImportError:
    # This allows the test file to be syntactically valid even if the app is not found
    # The tests will fail gracefully during execution if imports are truly broken.
    class MockApp:
        def get(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator
    app = MockApp()
    def read_root():
        return {"Error": "App not found"}


# === UNIT TESTS ===
# These tests validate the 'read_root' function in isolation.
# File covered: app.py

@pytest.mark.unit
def test_read_root_return_type():
    """Unit: Validates that read_root() returns a dictionary."""
    # This test covers app.py
    result = read_root()
    assert isinstance(result, dict), f"Expected a dict, but got {type(result)}"

@pytest.mark.unit
def test_read_root_return_value():
    """Unit: Validates the exact content of the dictionary from read_root()."""
    # This test covers app.py
    expected = {"Hello": "World"}
    result = read_root()
    assert result == expected, f"Expected {expected}, but got {result}"

@pytest.mark.unit
def test_read_root_is_not_coroutine():
    """Unit: Ensures read_root() is a standard function, not async."""
    # This test covers app.py
    assert not inspect.iscoroutinefunction(read_root), "read_root should not be an async function."

@pytest.mark.unit
def test_read_root_signature():
    """Unit: Ensures read_root() takes no arguments."""
    # This test covers app.py
    sig = inspect.signature(read_root)
    assert len(sig.parameters) == 0, "read_root should not accept any parameters."
    with pytest.raises(TypeError):
        read_root("some_argument")

@pytest.mark.unit
def test_app_object_is_fastapi_instance():
    """Unit: Verifies that the imported 'app' is a FastAPI instance."""
    # This test covers app.py
    assert isinstance(app, FastAPI), f"The 'app' object should be a FastAPI instance, but got {type(app)}"


# === INTEGRATION TESTS ===
# These tests validate the running application and its HTTP interface.
# File covered: app.py

@pytest.mark.integration
def test_root_get_status_code_ok(test_client: TestClient):
    """Integration: Checks if a GET request to '/' returns a 200 OK status."""
    # This test covers app.py
    response = test_client.get("/")
    assert response.status_code == 200, f"Expected status 200, but got {response.status_code}"

@pytest.mark.integration
def test_root_get_response_json(test_client: TestClient):
    """Integration: Verifies the JSON payload of a GET request to '/'."""
    # This test covers app.py
    response = test_client.get("/")
    expected_json = {"Hello": "World"}
    assert response.json() == expected_json, f"Expected JSON {expected_json}, but got {response.json()}"

@pytest.mark.integration
@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_root_disallowed_methods(test_client: TestClient, method: str):
    """Integration: Ensures that methods other than GET are not allowed on '/'."""
    # This test covers app.py
    response = test_client.request(method, "/")
    assert response.status_code == 405, f"Expected status 405 for {method}, but got {response.status_code}"

@pytest.mark.integration
def test_root_options_method(test_client: TestClient):
    """Integration: Checks the OPTIONS method response on '/'."""
    # This test covers app.py
    response = test_client.options("/")
    assert response.status_code == 200, "OPTIONS should return 200 OK"
    assert "GET" in response.headers.get("allow", ""), "Allow header should include GET"
    assert "HEAD" in response.headers.get("allow", ""), "Allow header should include HEAD"
    assert "OPTIONS" in response.headers.get("allow", ""), "Allow header should include OPTIONS"

@pytest.mark.integration
def test_root_head_method(test_client: TestClient):
    """Integration: Checks that the HEAD method on '/' works and returns no body."""
    # This test covers app.py
    response = test_client.head("/")
    assert response.status_code == 200, "HEAD request should return 200 OK"
    assert response.text == "", "HEAD response should have no body"
    assert "content-length" in response.headers, "Content-Length header should be present"

@pytest.mark.integration
def test_root_ignores_query_parameters(test_client: TestClient):
    """Integration: Confirms that query parameters on '/' are ignored."""
    # This test covers app.py
    response = test_client.get("/?param1=value1&param2=123")
    assert response.status_code == 200
    assert response.json() == {"Hello": "World"}

@pytest.mark.integration
def test_nonexistent_route_returns_404(test_client: TestClient):
    """Integration: Verifies that accessing a non-defined route gives a 404 error."""
    # This test covers app.py (by testing the framework's routing)
    response = test_client.get("/not-a-real-route")
    assert response.status_code == 404, f"Expected 404 for nonexistent route, got {response.status_code}"


# === CONTRACT TESTS ===
# These tests validate the API's "contract" - its schema, headers, and data types.
# File covered: app.py

@pytest.mark.contract
def test_root_content_type_is_json(test_client: TestClient):
    """Contract: Ensures the Content-Type header is 'application/json'."""
    # This test covers app.py
    response = test_client.get("/")
    assert response.headers.get("content-type") == "application/json", \
        f"Expected content-type application/json, got {response.headers.get('content-type')}"

@pytest.mark.contract
def test_root_response_schema_keys(test_client: TestClient):
    """Contract: Validates the keys present in the JSON response."""
    # This test covers app.py
    response = test_client.get("/")
    data = response.json()
    assert list(data.keys()) == ["Hello"], f"Expected keys ['Hello'], but got {list(data.keys())}"

@pytest.mark.contract
def test_root_response_schema_value_types(test_client: TestClient):
    """Contract: Validates the data types of values in the JSON response."""
    # This test covers app.py
    response = test_client.get("/")
    data = response.json()
    assert isinstance(data.get("Hello"), str), f"Expected value of 'Hello' to be a string, got {type(data.get('Hello'))}"

@pytest.mark.contract
def test_root_response_server_header(test_client: TestClient):
    """Contract: Checks for the presence of the Server header."""
    # This test covers app.py (by testing the server framework)
    response = test_client.get("/")
    assert "server" in response.headers, "Server header should be present in the response"

@pytest.mark.contract
def test_root_response_no_unexpected_cookies(test_client: TestClient):
    """Contract: Ensures no unexpected cookies are set in the response."""
    # This test covers app.py
    response = test_client.get("/")
    assert not response.cookies, f"Expected no cookies, but found {response.cookies}"


# === SECURITY TESTS ===
# These tests check for basic security hygiene.
# File covered: app.py

@pytest.mark.security
def test_root_no_xss_reflection_in_headers(test_client: TestClient):
    """Security: Checks for XSS reflection in response from malicious Accept header."""
    # This test covers app.py (by testing the framework's robustness)
    malicious_header = "<script>alert(1)</script>"
    response = test_client.get("/", headers={"Accept": malicious_header})
    assert malicious_header not in response.text, "Malicious script should not be reflected in the response body"
    assert response.status_code == 200, "Malicious Accept header should not cause a server error"

@pytest.mark.security
def test_root_path_traversal_attempt(test_client: TestClient):
    """Security: Attempts a path traversal attack."""
    # This test covers app.py (by testing the framework's URL normalization)
    response = test_client.get("/../")
    # FastAPI/Starlette normalizes the path, so this becomes '/', which is a valid endpoint.
    # The important part is that it doesn't lead to a directory listing or file access error.
    assert response.status_code == 200, "Path traversal should be normalized and handled gracefully"
    assert response.json() == {"Hello": "World"}

@pytest.mark.security
def test_root_sql_injection_in_params_is_ignored(test_client: TestClient):
    """Security: Sends a fake SQL injection payload in query params to ensure it's ignored."""
    # This test covers app.py
    response = test_client.get("/?id=' OR 1=1; --")
    assert response.status_code == 200, "SQL injection attempt in params should not cause an error"
    assert response.json() == {"Hello": "World"}, "Endpoint should ignore malicious query parameters"

@pytest.mark.security
def test_root_does_not_expose_sensitive_headers(test_client: TestClient):
    """Security: Checks that potentially sensitive headers are not exposed."""
    # This test covers app.py (by testing the framework's default configuration)
    response = test_client.get("/")
    sensitive_headers = ["x-powered-by", "x-aspnet-version"]
    for header in sensitive_headers:
        assert header not in response.headers, f"Sensitive header '{header}' should not be exposed"


# === PERFORMANCE TESTS ===
# A simple performance check for the new endpoint.
# File covered: app.py

@pytest.mark.performance
def test_root_response_time_is_fast(test_client: TestClient):
    """Performance: Ensures the root endpoint responds quickly."""
    # This test covers app.py
    start_time = time.perf_counter()
    response = test_client.get("/")
    end_time = time.perf_counter()
    duration = end_time - start_time
    assert response.status_code == 200
    assert duration < 0.1, f"Response time should be under 100ms, but was {duration:.4f}s"