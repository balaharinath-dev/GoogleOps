"""
Test Generator Tools for CI/CD Pipeline
Provides test generation, validation, Docker/Playwright support with runtime installation.
"""
import subprocess
import os
import re
import ast
import sys
from typing import Dict, List, Optional
from langchain.tools import tool


@tool
def install_runtime_dependencies(dependency_type: str) -> str:
    """
    Install dependencies at runtime if needed.
    
    Args:
        dependency_type: Type of dependencies to install (pytest, docker, playwright, all).
    
    Returns:
        Installation status.
    """
    try:
        results = []
        
        if dependency_type in ["pytest", "all"]:
            # Install pytest and related packages
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-q",
                 "pytest", "pytest-asyncio", "pytest-cov", "pytest-xdist"],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                results.append("✓ pytest installed")
            else:
                results.append(f"✗ pytest install failed: {result.stderr[:200]}")
        
        if dependency_type in ["docker", "all"]:
            # Check if Docker is available
            docker_check = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True
            )
            if docker_check.returncode == 0:
                results.append(f"✓ Docker available: {docker_check.stdout.strip()}")
            else:
                results.append("✗ Docker not installed - install from https://docs.docker.com/get-docker/")
        
        if dependency_type in ["playwright", "all"]:
            # Install Playwright
            result1 = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-q",
                 "playwright", "pytest-playwright"],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result1.returncode == 0:
                results.append("✓ playwright package installed")
                
                # Install browsers
                result2 = subprocess.run(
                    ["playwright", "install", "chromium"],
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                if result2.returncode == 0:
                    results.append("✓ Chromium browser installed")
                else:
                    results.append(f"✗ Browser install failed: {result2.stderr[:200]}")
            else:
                results.append(f"✗ playwright install failed: {result1.stderr[:200]}")
        
        return "\n".join(results)
    
    except subprocess.TimeoutExpired:
        return f"Installation TIMEOUT for {dependency_type}"
    except Exception as e:
        return f"Installation ERROR: {str(e)}"


@tool
def detect_project_type(changed_files: str) -> str:
    """
    Detect project type based on changed files to determine test strategy.
    
    Args:
        changed_files: Comma-separated list of changed file paths.
    
    Returns:
        Project type and recommended test strategy.
    """
    files = [f.strip() for f in changed_files.split(',')]
    
    # File extension patterns
    backend_patterns = ['.py', '.java', '.go', '.rb', '.php', '.cs', '.rs']
    frontend_patterns = ['.html', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.css', '.scss']
    
    backend_count = sum(1 for f in files if any(f.endswith(ext) for ext in backend_patterns))
    frontend_count = sum(1 for f in files if any(f.endswith(ext) for ext in frontend_patterns))
    
    # Determine project type
    if backend_count > 0 and frontend_count == 0:
        project_type = "BACKEND_ONLY"
        strategy = "TestClient (in-process)"
        dependencies = "pytest"
    elif frontend_count > 0 and backend_count == 0:
        project_type = "FRONTEND_ONLY"
        strategy = "Playwright (UI testing)"
        dependencies = "playwright"
    elif backend_count > 0 and frontend_count > 0:
        project_type = "FULLSTACK"
        strategy = "TestClient + Docker + Playwright (comprehensive)"
        dependencies = "pytest, docker, playwright"
    else:
        project_type = "UNKNOWN"
        strategy = "TestClient (default)"
        dependencies = "pytest"
    
    return f"""Project Type Detection:
Type: {project_type}
Backend files: {backend_count}
Frontend files: {frontend_count}

Recommended Test Strategy: {strategy}
Required Dependencies: {dependencies}

Test Approach:
{_get_test_approach(project_type)}
"""


def _get_test_approach(project_type: str) -> str:
    """Get detailed test approach based on project type."""
    approaches = {
        "BACKEND_ONLY": """
• Use FastAPI TestClient for API tests
• Run unit + integration + security tests
• Fast execution (10-30 seconds)
• No Docker or Playwright needed
""",
        "FRONTEND_ONLY": """
• Use Playwright for UI testing
• Test user workflows and interactions
• Verify visual elements
• Requires app server running
""",
        "FULLSTACK": """
• TestClient for backend API tests (fast)
• Docker for E2E integration tests (realistic)
• Playwright for frontend UI tests (comprehensive)
• Full stack validation
""",
        "UNKNOWN": """
• Default to TestClient
• Run basic tests
• Minimal dependencies
"""
    }
    return approaches.get(project_type, approaches["UNKNOWN"])


@tool
def validate_test_file(test_file_path: str) -> str:
    """
    Validate that a test file is syntactically correct and contains actual tests.
    
    Args:
        test_file_path: Path to the test file to validate.
    
    Returns:
        Validation report with syntax check, test count, and issues.
    """
    if not os.path.exists(test_file_path):
        return f"ERROR: Test file not found at {test_file_path}"
    
    try:
        with open(test_file_path, 'r') as f:
            content = f.read()
        
        # Check 1: Syntax validation
        try:
            ast.parse(content)
            syntax_valid = True
            syntax_error = None
        except SyntaxError as e:
            syntax_valid = False
            syntax_error = f"Line {e.lineno}: {e.msg}"
        
        # Check 2: Count test functions
        test_functions = re.findall(r'def (test_\w+)\(', content)
        test_count = len(test_functions)
        
        # Check 3: Check for pytest markers
        markers = {
            'unit': len(re.findall(r'@pytest\.mark\.unit', content)),
            'integration': len(re.findall(r'@pytest\.mark\.integration', content)),
            'security': len(re.findall(r'@pytest\.mark\.security', content)),
            'contract': len(re.findall(r'@pytest\.mark\.contract', content)),
            'ui': len(re.findall(r'@pytest\.mark\.ui', content))
        }
        
        # Check 4: Check for required imports
        has_pytest = 'import pytest' in content
        has_testclient = 'TestClient' in content
        
        # Check 5: Check for fixtures usage
        fixture_usage = re.findall(r'def test_\w+\([^)]+\)', content)
        uses_fixtures = any('test_client' in f or 'db_session' in f or 'auth_headers' in f 
                           for f in fixture_usage)
        
        # Generate report
        report = f"""Test File Validation Report
{'='*50}

File: {test_file_path}

✓ Syntax Check: {'PASS' if syntax_valid else 'FAIL'}
{f'  Error: {syntax_error}' if syntax_error else ''}

✓ Test Count: {test_count} test functions found
  Functions: {', '.join(test_functions[:5])}{'...' if len(test_functions) > 5 else ''}

✓ Test Markers:
  - Unit: {markers['unit']}
  - Integration: {markers['integration']}
  - Security: {markers['security']}
  - Contract: {markers['contract']}
  - UI: {markers['ui']}

✓ Required Imports:
  - pytest: {'✓' if has_pytest else '✗ MISSING'}
  - TestClient: {'✓' if has_testclient else '✗ (optional)'}

✓ Fixtures Usage: {'✓' if uses_fixtures else '✗ (tests may not use fixtures)'}

Overall Status: {'VALID' if syntax_valid and test_count > 0 else 'INVALID'}
"""
        
        return report
    
    except Exception as e:
        return f"ERROR: Failed to validate test file: {str(e)}"


@tool
def check_test_coverage(test_file_path: str, changed_files: str) -> str:
    """
    Check if generated tests cover the changed files.
    
    Args:
        test_file_path: Path to the generated test file.
        changed_files: Comma-separated list of changed file paths.
    
    Returns:
        Coverage analysis report.
    """
    if not os.path.exists(test_file_path):
        return f"ERROR: Test file not found at {test_file_path}"
    
    try:
        with open(test_file_path, 'r') as f:
            test_content = f.read()
        
        # Validation for changed_files
        if not changed_files or "Error" in changed_files:
            return "Test Coverage Analysis: SKIPPED (No valid changed files detected)"
            
        changed_file_list = [f.strip() for f in changed_files.split(',')]
        
        coverage_report = "Test Coverage Analysis\n" + "="*50 + "\n\n"
        
        for changed_file in changed_file_list:
            # Normalize file path: strip 'backend/' prefix to match absolute imports
            # e.g., 'backend/auth.py' -> 'auth'
            clean_path = changed_file
            if clean_path.startswith('backend/'):
                clean_path = clean_path[8:]
            
            module_name = clean_path.replace('/', '.').replace('.py', '')
            
            # Check if module is imported or referenced in tests
            # Look for: "from auth", "import auth", "auth.", "backend.auth"
            is_imported = (
                f"from {module_name}" in test_content or 
                f"import {module_name}" in test_content or 
                f" {module_name}." in test_content or
                changed_file in test_content
            )
            
            # Count test functions that might test this module
            # Look for test names that contain parts of the module name
            # e.g., for 'auth', look for 'test_auth', 'test_login', 'test_password'
            module_parts = module_name.split('.')
            relevant_tests = []
            
            # 1. Exact module match in test name
            pattern_exact = rf'def (test_.*{module_parts[-1]}.*)\('
            matches_exact = re.findall(pattern_exact, test_content, re.IGNORECASE)
            relevant_tests.extend(matches_exact)
            
            # 2. Heuristic for common patterns (e.g. auth -> login, register)
            if module_name == 'auth':
                heuristics = ['login', 'register', 'token', 'password', 'security']
                for h in heuristics:
                    p = rf'def (test_.*{h}.*)\('
                    relevant_tests.extend(re.findall(p, test_content, re.IGNORECASE))
            elif 'service' in module_name:
                # e.g. item_service -> test_create_item
                entity = module_name.replace('_service', '')
                p = rf'def (test_.*{entity}.*)\('
                relevant_tests.extend(re.findall(p, test_content, re.IGNORECASE))
            
            # Deduplicate
            relevant_tests = list(set(relevant_tests))
            
            coverage_report += f"File: {changed_file}\n"
            coverage_report += f"  Referenced: {'✓' if is_imported else '✗'}\n"
            coverage_report += f"  Related Tests: {len(relevant_tests)}\n"
            if relevant_tests:
                coverage_report += f"    {', '.join(relevant_tests[:3])}{'...' if len(relevant_tests) > 3 else ''}\n"
            coverage_report += "\n"
        
        return coverage_report
    
    except Exception as e:
        return f"ERROR: Failed to analyze coverage: {str(e)}"


@tool
def build_docker_test_environment(repo_path: str, run_id: str) -> str:
    """
    Build a Docker image for testing the application.
    
    Args:
        repo_path: Path to the repository root.
        run_id: Pipeline run ID for tagging the image.
    
    Returns:
        Build status and image name.
    """
    try:
        # Check if Dockerfile exists
        dockerfile_path = os.path.join(repo_path, "Dockerfile")
        if not os.path.exists(dockerfile_path):
            # Create a basic Dockerfile for FastAPI
            dockerfile_content = """FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/

ENV PYTHONPATH=/app

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
"""
            with open(dockerfile_path, 'w') as f:
                f.write(dockerfile_content)
        
        # Build Docker image
        image_name = f"cicd-test-app:{run_id[:8]}"
        cmd = ["docker", "build", "-t", image_name, "-f", dockerfile_path, repo_path]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            return f"""Docker Build: SUCCESS
Image: {image_name}
Ready for testing against live container.

Build Output (last 500 chars):
{result.stdout[-500:]}"""
        else:
            return f"""Docker Build: FAILED
Error:
{result.stderr}"""
    
    except subprocess.TimeoutExpired:
        return "Docker Build: TIMEOUT (exceeded 5 minutes)"
    except Exception as e:
        return f"Docker Build: ERROR - {str(e)}"


@tool
def start_docker_test_container(image_name: str, port: int = 8000) -> str:
    """
    Start a Docker container for testing.
    
    Args:
        image_name: Docker image name to run.
        port: Port to expose the application on.
    
    Returns:
        Container ID and status.
    """
    try:
        # Stop any existing container on this port
        subprocess.run(
            ["docker", "ps", "-q", "--filter", f"publish={port}"],
            capture_output=True
        )
        
        # Start new container
        cmd = [
            "docker", "run", "-d",
            "-p", f"{port}:8000",
            "--name", f"cicd-test-{port}",
            image_name
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            container_id = result.stdout.strip()
            
            # Wait for container to be ready
            import time
            time.sleep(3)
            
            # Check if container is running
            check_cmd = ["docker", "ps", "-q", "--filter", f"id={container_id}"]
            check_result = subprocess.run(check_cmd, capture_output=True, text=True)
            
            if check_result.stdout.strip():
                return f"""Container Started: SUCCESS
Container ID: {container_id}
Port: {port}
Status: Running
Application URL: http://localhost:{port}"""
            else:
                # Get logs if container failed
                logs_cmd = ["docker", "logs", container_id]
                logs = subprocess.run(logs_cmd, capture_output=True, text=True)
                return f"""Container Started: FAILED
Container exited immediately.
Logs:
{logs.stdout}
{logs.stderr}"""
        else:
            return f"""Container Start: FAILED
Error:
{result.stderr}"""
    
    except Exception as e:
        return f"Container Start: ERROR - {str(e)}"


@tool
def stop_docker_test_container(container_id: str) -> str:
    """
    Stop and remove a Docker test container.
    
    Args:
        container_id: Container ID or name to stop.
    
    Returns:
        Stop status.
    """
    try:
        # Stop container
        stop_result = subprocess.run(
            ["docker", "stop", container_id],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Remove container
        rm_result = subprocess.run(
            ["docker", "rm", container_id],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if stop_result.returncode == 0 and rm_result.returncode == 0:
            return f"Container {container_id} stopped and removed successfully."
        else:
            return f"Container cleanup completed with warnings:\nStop: {stop_result.stderr}\nRemove: {rm_result.stderr}"
    
    except Exception as e:
        return f"Container Stop: ERROR - {str(e)}"
