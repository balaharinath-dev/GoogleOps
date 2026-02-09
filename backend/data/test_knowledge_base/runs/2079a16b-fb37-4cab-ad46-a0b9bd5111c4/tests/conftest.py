import pytest
import sys
import os
from fastapi.testclient import TestClient
import warnings

# Fix for Python 3.14 compatibility, as per best practices.
if sys.version_info >= (3, 14):
    warnings.filterwarnings('ignore', message='.*bcrypt.*')
    warnings.filterwarnings('ignore', category=UserWarning)

# CRITICAL: Add codebase directory to path for imports.
# This logic is adapted from the prompt's template to find the correct root directory.
codebase_path = os.environ.get('CODEBASE_PATH')
if not codebase_path:
    _current_dir = os.path.dirname(os.path.abspath(__file__))
    for i in range(10):  # Search up to 10 levels
        candidate = os.path.join(_current_dir, *(['..'] * i), 'codebase')
        if os.path.exists(candidate) and os.path.isfile(os.path.join(candidate, 'app.py')):
            codebase_path = os.path.abspath(candidate)
            break
if codebase_path and codebase_path not in sys.path:
    sys.path.insert(0, codebase_path)

# Import the main application object
# This is the correct import based on the provided file analysis.
from app import app

@pytest.fixture(scope="function")
def client():
    """
    Provides a TestClient instance for the FastAPI app.
    
    CRITICAL: This fixture also resets the application's in-memory data stores
    before each test. This is essential for maintaining test isolation, a cornerstone
    of production-grade testing. It replaces the template's database-specific
    reset logic with logic that is correct for the current application's architecture.
    """
    # Reset in-memory state before each test run to ensure isolation
    app.users_db.clear()
    app.items_db.clear()
    
    # Reset counters, which are module-level globals in app.py
    app.user_id_counter = 0
    app.item_id_counter = 0
    
    with TestClient(app) as c:
        yield c