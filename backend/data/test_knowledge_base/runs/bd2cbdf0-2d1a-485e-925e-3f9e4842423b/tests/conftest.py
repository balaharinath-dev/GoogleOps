import pytest
import sys
import os
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Add backend directory to path for imports
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..', 'codebase', 'backend'))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Import application components (using absolute imports without 'backend.' prefix)
from main import app
from database import Base, get_db
from models import User
from auth import get_password_hash
from config import settings

# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={{"check_same_thread": False}},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    """Override the get_db dependency to use the test database."""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="session", autouse=True)
def setup_teardown_db():
    """Create and drop the test database for the session."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session(setup_teardown_db):
    """Provide a clean database session for each test."""
    connection = engine.connect()
    transaction = connection.begin()
    db = TestingSessionLocal(bind=connection)
    try:
        yield db
    finally:
        db.close()
        transaction.rollback()
        connection.close()

@pytest.fixture(scope="function")
def test_client(db_session):
    """Provide a TestClient instance that uses the test database session."""
    def override_get_db_for_client():
        try:
            yield db_session
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db_for_client
    with TestClient(app) as client:
        yield client
    app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="function")
def test_user(db_session):
    """Create and return a standard test user."""
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
        is_admin=False
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture(scope="function")
def admin_user(db_session):
    """Create and return an admin test user."""
    user = User(
        username="admin",
        email="admin@example.com",
        hashed_password=get_password_hash("adminpass123"),
        is_active=True,
        is_admin=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture(scope="function")
def auth_headers(test_client, test_user):
    """Get authentication headers for a standard test user."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={{"username": "testuser", "password": "testpass123"}}
    )
    token = response.json()["access_token"]
    return {{"Authorization": f"Bearer {{token}}"}}

@pytest.fixture(scope="function")
def admin_headers(test_client, admin_user):
    """Get authentication headers for an admin user."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={{"username": "admin", "password": "adminpass123"}}
    )
    token = response.json()["access_token"]
    return {{"Authorization": f"Bearer {{token}}"}}