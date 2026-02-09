import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Import application components
from backend.main import app
from backend.database import Base, get_db
from backend.models import User, Item, Order
from backend.auth import get_password_hash
from backend.config import settings

# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={{"check_same_thread": False}},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Dependency override for database sessions in tests."""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="function", autouse=True)
def db_session():
    """
    Provide a clean database session for each test.
    Drops and recreates all tables before each test.
    """
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture(scope="function")
def test_client(db_session):
    """Provide a TestClient instance with a clean database."""
    with TestClient(app) as client:
        yield client

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
    """Create and return an admin user."""
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