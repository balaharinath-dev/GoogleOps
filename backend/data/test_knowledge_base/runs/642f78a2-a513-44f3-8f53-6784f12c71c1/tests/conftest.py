import pytest
import sys
import os
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import warnings

# Fix for Python 3.14 bcrypt compatibility
if sys.version_info >= (3, 14):
    warnings.filterwarnings('ignore', message='.*bcrypt.*')
    warnings.filterwarnings('ignore', category=UserWarning)

# CRITICAL: Add backend directory to path for imports
# This path calculation is MANDATORY - do not change it
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..', 'codebase', 'backend'))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Import application components (using absolute imports without 'backend.' prefix)
from main import app
from database import Base, get_db
from models import User, Item, Order
from auth import get_password_hash, create_access_token
from config import settings

# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="function", autouse=True)
def reset_db():
    '''Reset database before each test for isolation.'''
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def db_session(reset_db):
    '''Provide a clean database session for each test.'''
    db = TestingSessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

@pytest.fixture(scope="function")
def test_client(reset_db):
    '''Provide a TestClient instance.'''
    with TestClient(app) as client:
        yield client

@pytest.fixture(scope="function")
def test_user(db_session):
    '''Create a standard test user with SHORT password for Python 3.14 compatibility.'''
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password=get_password_hash("TestPass123"),  # SHORT password
        is_active=True,
        is_admin=False
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture(scope="function")
def admin_user(db_session):
    '''Create an admin user with SHORT password for Python 3.14 compatibility.'''
    user = User(
        username="admin",
        email="admin@example.com",
        hashed_password=get_password_hash("AdminPass123"),  # SHORT password
        is_active=True,
        is_admin=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture(scope="function")
def inactive_user(db_session):
    '''Create an inactive user for testing access control.'''
    user = User(
        username="inactive",
        email="inactive@example.com",
        hashed_password=get_password_hash("InactPass123"),  # SHORT password
        is_active=False,
        is_admin=False
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture(scope="function")
def auth_headers(test_client, test_user):
    '''Get authentication headers for test user.'''
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "TestPass123"}
    )
    assert response.status_code == 200, f"Login failed: {response.text}"
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="function")
def admin_headers(test_client, admin_user):
    '''Get authentication headers for admin user.'''
    response = test_client.post(
        "/api/v1/auth/login",
        data={"username": "admin", "password": "AdminPass123"}
    )
    assert response.status_code == 200, f"Admin login failed: {response.text}"
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="function")
def sample_item(db_session):
    '''Create a sample item for testing.'''
    from models import Item
    item = Item(
        name="Test Item",
        description="A test item",
        price=99.99,
        stock=10
    )
    db_session.add(item)
    db_session.commit()
    db_session.refresh(item)
    return item

@pytest.fixture(scope="function")
def multiple_users(db_session):
    '''Create multiple users for batch testing.'''
    users = []
    for i in range(5):
        user = User(
            username=f"user{i}",
            email=f"user{i}@example.com",
            hashed_password=get_password_hash(f"Pass{i}123"),  # SHORT passwords
            is_active=True,
            is_admin=False
        )
        db_session.add(user)
        users.append(user)
    db_session.commit()
    for user in users:
        db_session.refresh(user)
    return users