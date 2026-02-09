# tests/conftest.py
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend.models import User, Item, Order, OrderItem
from backend.auth import get_password_hash

# Use an in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables at the beginning of the test session
Base.metadata.create_all(bind=engine)


def override_get_db():
    """Dependency override for getting a test database session."""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


# Apply the override to the FastAPI app
app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="function")
def db_session():
    """Fixture to provide a clean database session for each test function."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="function")
def test_client(db_session):
    """Fixture to provide a TestClient instance."""
    # The db_session fixture ensures the database is clean for each test
    with TestClient(app) as client:
        yield client

@pytest.fixture(scope="function")
def test_data(db_session):
    """Fixture to pre-populate the database with test data."""
    hashed_password = get_password_hash("testpass123")
    admin_user = User(username="admin", email="admin@example.com", hashed_password=hashed_password, is_admin=True, is_active=True)
    normal_user = User(username="testuser", email="test@example.com", hashed_password=hashed_password, is_admin=False, is_active=True)
    
    db_session.add(admin_user)
    db_session.add(normal_user)
    
    item1 = Item(name="Laptop", description="A powerful laptop", price=1200.00, stock=10, category="Electronics")
    item2 = Item(name="Book", description="A great book", price=25.50, stock=50, category="Books")
    item3 = Item(name="T-Shirt", description="A cotton T-shirt", price=15.00, stock=0, category="Apparel") # Out of stock
    
    db_session.add_all([item1, item2, item3])
    db_session.commit()
    
    db_session.refresh(admin_user)
    db_session.refresh(normal_user)
    db_session.refresh(item1)
    db_session.refresh(item2)
    db_session.refresh(item3)
    
    return {
        "admin": admin_user,
        "user": normal_user,
        "item1": item1,
        "item2": item2,
        "item3": item3
    }

@pytest.fixture(scope="function")
def admin_auth_headers(test_client):
    """Fixture to get authentication headers for an admin user."""
    response = test_client.post(
        "/login",
        data={"username": "admin", "password": "testpass123"}
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="function")
def user_auth_headers(test_client):
    """Fixture to get authentication headers for a normal user."""
    response = test_client.post(
        "/login",
        data={"username": "testuser", "password": "testpass123"}
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}