"""
Pytest configuration for Playwright UI tests.
This file should be placed in the tests directory.
"""
import pytest
from playwright.sync_api import sync_playwright, Browser, Page, BrowserContext


@pytest.fixture(scope="session")
def browser():
    """
    Provides a Playwright browser instance for the entire test session.
    Uses Chromium by default.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture(scope="function")
def context(browser: Browser):
    """
    Provides a new browser context for each test.
    Contexts are isolated from each other.
    """
    context = browser.new_context()
    yield context
    context.close()


@pytest.fixture(scope="function")
def page(context: BrowserContext):
    """
    Provides a new page for each test.
    """
    page = context.new_page()
    yield page
    page.close()


@pytest.fixture(scope="session")
def base_url():
    """
    Base URL for the application under test.
    Override this in your tests if needed.
    """
    return "http://localhost:8000"
