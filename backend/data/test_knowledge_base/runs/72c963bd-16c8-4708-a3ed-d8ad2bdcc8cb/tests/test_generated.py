import pytest
from fastapi.testclient import TestClient

# Assuming the FastAPI app instance is in 'backend/main.py'
# Adjust the import path if your project structure is different.
from backend.main import app, health


@pytest.fixture(scope="module")
def test_client():
    """
    Provides a TestClient instance for the FastAPI application.
    This fixture has a 'module' scope, so it's created once per test module.
    """
    client = TestClient(app)
    yield client


class TestHealthEndpoint:
    """
    Test suite for the /health endpoint and its underlying function.
    """

    @pytest.mark.unit
    def test_health_function_returns_status_and_version(self):
        """
        Unit Test: Verifies that the health() function directly returns
        the expected dictionary containing both 'status' and 'version'.
        """
        # Arrange
        expected_response = {"status": "ok", "version": "1.0.0"}

        # Act
        response = health()

        # Assert
        assert isinstance(response, dict)
        assert response == expected_response
        assert "status" in response
        assert "version" in response

    @pytest.mark.integration
    def test_health_endpoint_get_request_returns_correct_body(self, test_client: TestClient):
        """
        Integration Test: Verifies that a GET request to the /health endpoint
        returns a 200 OK status and the correct JSON payload.
        """
        # Arrange
        expected_json = {"status": "ok", "version": "1.0.0"}

        # Act
        response = test_client.get("/health")

        # Assert
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        assert response.json() == expected_json

    @pytest.mark.regression
    def test_health_endpoint_response_includes_version_key(self, test_client: TestClient):
        """
        Regression Test: Ensures the 'version' key is always present in the
        /health endpoint's response, preventing a regression where it might be
        accidentally removed.
        """
        # Act
        response = test_client.get("/health")
        response_data = response.json()

        # Assert
        assert response.status_code == 200
        assert "version" in response_data, "The 'version' key is missing from the /health response"
        assert response_data["version"] == "1.0.0"

    @pytest.mark.edge_case
    @pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
    def test_health_endpoint_disallows_other_methods(self, test_client: TestClient, method: str):
        """
        Edge Case Test: Verifies that the /health endpoint correctly
        handles and rejects HTTP methods other than GET, returning a
        405 Method Not Allowed status code.
        """
        # Act
        response = test_client.request(method, "/health")

        # Assert
        assert response.status_code == 405, f"Method {method} should not be allowed on /health"