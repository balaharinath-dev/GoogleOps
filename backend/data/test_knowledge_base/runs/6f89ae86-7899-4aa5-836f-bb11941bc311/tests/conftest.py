import sys
import os
from pathlib import Path
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient
import warnings

# Fix for Python 3.14 bcrypt compatibility
if sys.version_info >= (3, 14):
    warnings.filterwarnings('ignore', message='.*bcrypt.*')
    warnings.filterwarnings('ignore', category=UserWarning)

# Add the backend directory to the Python path for absolute imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from database import Base, get_db
from main import app
from models import User, Item, Order, OrderItem
from auth import get_password_hash
from schemas import UserCreate

# Use an in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)

# Enable foreign key support for SQLite in-memory
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db_session():
    """
    Fixture for providing a transactional scope around a test function.
    Creates all tables before the test and drops them afterwards.
    """
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def test_client(db_session):
    """
    Fixture for creating a TestClient for the FastAPI application.
    Overrides the `get_db` dependency to use the test database session.
    """
    def override_get_db():
        try:
            yield db_session
        finally:
            db_session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()

@pytest.fixture(scope="function")
def test_user(db_session):
    """Fixture to create a standard test user in the database."""
    user_data = UserCreate(
        username="testuser",
        email="testuser@example.com",
        password="TestPass123"
    )
    hashed_password = get_password_hash(user_data.password)
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture(scope="function")
def admin_user(db_session):
    """Fixture to create an admin test user in the database."""
    user_data = UserCreate(
        username="adminuser",
        email="admin@example.com",
        password="AdminPass123"
    )
    hashed_password = get_password_hash(user_data.password)
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        is_admin=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture(scope="function")
def inactive_user(db_session):
    """Fixture to create an inactive test user in the database."""
    user_data = UserCreate(
        username="inactiveuser",
        email="inactive@example.com",
        password="InactivePass123"
    )
    hashed_password = get_password_hash(user_data.password)
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        is_active=False
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture(scope="function")
def auth_headers(test_client, test_user):
    """Fixture to get authentication headers for the standard test user."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": test_user.username, "password": "TestPass123"}
    )
    assert response.status_code == 200, "Failed to log in test_user"
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="function")
def admin_headers(test_client, admin_user):
    """Fixture to get authentication headers for the admin user."""
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": admin_user.username, "password": "AdminPass123"}
    )
    assert response.status_code == 200, "Failed to log in admin_user"
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="function")
def sample_item(db_session):
    """Fixture to create a sample item in the database."""
    item = Item(
        name="Sample Item",
        description="A sample item for testing.",
        price=19.99,
        stock=100,
        category="testing"
    )
    db_session.add(item)
    db_session.commit()
    db_session.refresh(item)
    return item

@pytest.fixture(scope="function")
def multiple_users(db_session):
    """Fixture to create multiple users for pagination tests."""
    users = []
    for i in range(15):
        user = User(
            username=f"user{i}",
            email=f"user{i}@example.com",
            hashed_password=get_password_hash("TestPass123")
        )
        users.append(user)
    db_session.add_all(users)
    db_session.commit()
    return users