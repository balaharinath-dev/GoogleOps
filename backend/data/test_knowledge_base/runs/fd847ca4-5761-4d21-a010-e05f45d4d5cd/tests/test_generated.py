import pytest
from fastapi.testclient import TestClient

# Assuming the FastAPI app instance in backend/main.py is named 'app'
# If the file structure is different, this import might need adjustment.
# For this test, we will assume 'backend' is a package in the python path.
from backend.main import app

@pytest.fixture(scope="module")
def client():
    """
    Pytest fixture to create a FastAPI TestClient.
    This client is used to make requests to the application in tests.
    The scope is 'module' to create the client only once per test module.
    """
    with TestClient(app) as c:
        yield c

class TestHealthEndpoint:
    """
    Test suite for the /health endpoint.
    Focuses on the changes introduced in commit 15f5a5c.
    """

    @pytest.mark.unit
    def test_health_endpoint_status_code(self, client: TestClient):
        """
        Tests if the /health endpoint returns a 200 OK status code.
        """
        response = client.get("/health")
        assert response.status_code == 200, "The /health endpoint should return a 200 status code."

    @pytest.mark.unit
    def test_health_endpoint_response_body(self, client: TestClient):
        """
        Tests if the /health endpoint response body is a JSON object
        containing both the 'status' and the new 'version' fields.
        """
        response = client.get("/health")
        assert response.status_code == 200
        
        expected_json = {
            "status": "ok",
            "version": "1.0.0"
        }
        
        assert response.json() == expected_json, "The response body does not match the expected structure and values."

    @pytest.mark.unit
    def test_health_endpoint_content_type(self, client: TestClient):
        """
        Tests if the /health endpoint returns the correct 'application/json' content type.
        """
        response = client.get("/health")
        assert "application/json" in response.headers["content-type"]

class TestRegression:
    """
    Regression test suite to ensure existing functionality remains unaffected.
    Since there were no previous failures, these are general sanity checks
    on other endpoints to ensure no unintended side effects occurred.
    """

    @pytest.mark.regression
    def test_get_items_endpoint_unaffected(self, client: TestClient):
        """
        Performs a sanity check on the GET /items/ endpoint to ensure it still
        functions correctly and returns a 200 status code.
        """
        response = client.get("/items/")
        assert response.status_code == 200, "The GET /items/ endpoint seems to be affected."
        # Check if the response is a list, which is the expected type for this endpoint
        assert isinstance(response.json(), list)

    @pytest.mark.regression
    def test_get_nonexistent_item_unaffected(self, client: TestClient):
        """
        Performs a sanity check on the GET /items/{item_id} endpoint for a
        non-existent item to ensure 404 error handling is still working.
        """
        response = client.get("/items/99999") # Use an ID that is unlikely to exist
        assert response.status_code == 404, "The 404 error handling for non-existent items seems to be affected."
        
    @pytest.mark.regression
    def test_root_endpoint_unaffected(self, client: TestClient):
        """
        Performs a sanity check on the root endpoint ('/') to ensure it was not
        inadvertently changed. The default FastAPI root endpoint returns a 404 Not Found
        unless explicitly defined. We will assume it's not defined and should be 404.
        """
        response = client.get("/")
        # This assertion depends on whether a root path is defined in main.py.
        # Based on the analysis, it is not, so a 404 is expected.
        assert response.status_code == 404, "The root endpoint behavior has changed."