"""
Test Runner Tools for CI/CD Pipeline
Provides test execution and result parsing utilities.
"""
import subprocess
import os
import sys
import json
import re
from typing import Optional, List
from langchain.tools import tool


@tool
def run_pytest(
    test_path: str,
    run_id: str,
    repo_path: Optional[str] = None,
    markers: Optional[str] = None,
    verbose: bool = True,
    test_type: str = "generated"
) -> str:
    """
    Execute pytest on specified path and store results in database.
    Can run existing tests, generated tests, or specific test types.
    
    IMPORTANT: Automatically detects and uses the codebase's virtual environment if available.
    
    Args:
        test_path: Path to test file or directory.
        run_id: Pipeline run ID for storing results.
        repo_path: Repository root path for working directory.
        markers: Pytest markers to filter tests (e.g., "unit", "integration", "security").
        verbose: Enable verbose output.
        test_type: Type of tests being run (existing, generated, security, ui, contract).
    
    Returns:
        Pytest output and summary with database storage confirmation.
    """
    from tools.t5_database_tools import store_test_result, store_module_stats
    
    # Detect codebase virtual environment
    python_executable = sys.executable  # Default to current Python
    
    if repo_path:
        repo_path = os.path.abspath(repo_path)
        
        # Check for venv in common locations (order matters - more specific first)
        possible_venvs = [
            # When repo_path is /codebase, check /codebase/backend/.venv
            os.path.join(repo_path, "backend", ".venv", "bin", "python"),
            # When repo_path is /codebase/backend directly
            os.path.join(repo_path, ".venv", "bin", "python"),
            # Alternative venv naming
            os.path.join(repo_path, "backend", "venv", "bin", "python"),
            os.path.join(repo_path, "venv", "bin", "python"),
        ]
        
        for venv_python in possible_venvs:
            if os.path.exists(venv_python):
                python_executable = venv_python
                print(f"✓ Using codebase virtual environment: {venv_python}")
                break
        else:
            print(f"⚠ No venv found in {repo_path}, using system Python: {python_executable}")
    
    cmd = [python_executable, "-m", "pytest", test_path, "--tb=short", "-v"]
    
    if markers:
        cmd.extend(["-m", markers])
    
    # Prepare environment with PYTHONPATH and CODEBASE_BACKEND_PATH
    env = os.environ.copy()
    if repo_path:
        # Determine the codebase backend path
        backend_path = os.path.join(repo_path, "backend")
        # Check for common entry point files
        entry_files = ["main.py", "app.py", "__init__.py"]
        has_backend_dir = False
        
        for entry_file in entry_files:
            if os.path.exists(backend_path) and os.path.isfile(os.path.join(backend_path, entry_file)):
                # repo_path is /codebase, backend is /codebase/backend
                env["PYTHONPATH"] = f"{backend_path}:{repo_path}:{env.get('PYTHONPATH', '')}"
                env["CODEBASE_BACKEND_PATH"] = backend_path
                has_backend_dir = True
                break
        
        if not has_backend_dir:
            # Check if repo_path itself is the backend/app directory
            for entry_file in entry_files:
                if os.path.isfile(os.path.join(repo_path, entry_file)):
                    # repo_path is directly the backend/app directory
                    env["PYTHONPATH"] = f"{repo_path}:{env.get('PYTHONPATH', '')}"
                    env["CODEBASE_BACKEND_PATH"] = repo_path
                    break
            else:
                # Fallback: just add repo_path
                env["PYTHONPATH"] = f"{repo_path}:{env.get('PYTHONPATH', '')}"
                env["CODEBASE_BACKEND_PATH"] = repo_path
        
        print(f"✓ PYTHONPATH set to: {env.get('PYTHONPATH', '')[:100]}...")
        if "CODEBASE_BACKEND_PATH" in env:
            print(f"✓ CODEBASE_BACKEND_PATH set to: {env['CODEBASE_BACKEND_PATH']}")
    
    try:
        result = subprocess.run(
            cmd,
            cwd=repo_path or os.getcwd(),
            capture_output=True,
            text=True,
            timeout=300,
            env=env
        )
        
        output = result.stdout + "\n" + result.stderr
        
        # Parse results and store in database
        passed = 0
        failed = 0
        test_results = []
        
        # Parse pytest output
        for line in output.split('\n'):
            # Match test results: test_file.py::test_name PASSED/FAILED
            match = re.match(r'(.+?\.py)::(\w+)\s+(PASSED|FAILED|ERROR)', line)
            if match:
                test_file, test_name, status = match.groups()
                test_results.append({
                    'file': test_file,
                    'name': test_name,
                    'status': status
                })
                if status == 'PASSED':
                    passed += 1
                else:
                    failed += 1
        
        # Extract summary counts if available
        summary_match = re.search(r'(\d+)\s+passed', output)
        if summary_match:
            passed = int(summary_match.group(1))
        
        failed_match = re.search(r'(\d+)\s+failed', output)
        if failed_match:
            failed = int(failed_match.group(1))
        
        # Store individual test results
        stored_count = 0
        for test in test_results:
            # Extract error message if failed
            error_msg = None
            if test['status'] != 'PASSED':
                # Try to find error in output
                error_pattern = rf"{test['name']}.*?(?:AssertionError|Error):(.*?)(?=\n\n|\Z)"
                error_match = re.search(error_pattern, output, re.DOTALL)
                if error_match:
                    error_msg = error_match.group(1).strip()[:500]
            
            store_test_result.invoke({
                "run_id": run_id,
                "test_name": test['name'],
                "status": test['status'],
                "test_module": test['file'].replace('.py', '').replace('/', '.'),
                "test_file_path": test['file'],
                "error_message": error_msg
            })
            stored_count += 1
        
        # Store module stats with test type
        if test_results:
            module_name = f"{test_type}_tests"
            store_module_stats.invoke({
                "run_id": run_id,
                "module_name": module_name,
                "total_tests": passed + failed,
                "passed_tests": passed,
                "failed_tests": failed
            })
        
        status = "PASSED" if result.returncode == 0 else "FAILED"
        
        return f"""Test Type: {test_type}
Status: {status}
Passed: {passed}
Failed: {failed}
Stored: {stored_count} test results in database

Python: {python_executable}

Output:
{output[:1000]}{"..." if len(output) > 1000 else ""}"""
    
    except subprocess.TimeoutExpired:
        return "Status: TIMEOUT\n\nTest execution exceeded 5 minute limit."
    except Exception as e:
        return f"Status: ERROR\n\nError running tests: {str(e)}"


@tool
def run_single_test(
    test_file: str,
    test_name: str,
    run_id: str,
    repo_path: Optional[str] = None
) -> str:
    """
    Run a single test by name and store result in database.
    
    Args:
        test_file: Path to the test file.
        test_name: Name of the test function.
        run_id: Pipeline run ID for storing results.
        repo_path: Repository root path.
    
    Returns:
        Test result output with database storage confirmation.
    """
    from tools.t5_database_tools import store_test_result
    
    test_spec = f"{test_file}::{test_name}"
    cmd = [sys.executable, "-m", "pytest", test_spec, "-v", "--tb=long"]
    
    # Prepare environment with PYTHONPATH
    env = os.environ.copy()
    if repo_path:
        env["PYTHONPATH"] = f"{repo_path}:{env.get('PYTHONPATH', '')}"
    
    try:
        result = subprocess.run(
            cmd,
            cwd=repo_path or os.getcwd(),
            capture_output=True,
            text=True,
            timeout=120,
            env=env
        )
        
        output = result.stdout + "\n" + result.stderr
        status = "PASSED" if result.returncode == 0 else "FAILED"
        
        # Extract error message if failed
        error_msg = None
        if status != "PASSED":
            error_pattern = r'(?:AssertionError|Error):(.*?)(?=\n\n|\Z)'
            error_match = re.search(error_pattern, output, re.DOTALL)
            if error_match:
                error_msg = error_match.group(1).strip()[:500]
        
        # Store result in database
        store_test_result.invoke({
            "run_id": run_id,
            "test_name": test_name,
            "status": status,
            "test_module": test_file.replace('.py', '').replace('/', '.'),
            "test_file_path": test_file,
            "error_message": error_msg
        })
        
        return f"""Test: {test_name}
Status: {status}
Stored in database: ✓

Output:
{output[:800]}{"..." if len(output) > 800 else ""}"""
    
    except Exception as e:
        return f"Error running test: {str(e)}"


@tool
def discover_tests(test_path: str, test_type: Optional[str] = None, repo_path: Optional[str] = None) -> str:
    """
    Discover all tests in a path without running them.
    Can discover existing tests, or filter by type.
    
    Args:
        test_path: Path to test file or directory.
        test_type: Optional filter (unit, integration, security, ui, contract).
        repo_path: Repository root path for working directory.
    
    Returns:
        List of discovered test names with their types.
    """
    # Detect codebase virtual environment
    python_executable = sys.executable
    
    if repo_path:
        repo_path = os.path.abspath(repo_path)
        
        # Check for venv in common locations
        possible_venvs = [
            os.path.join(repo_path, "backend", ".venv", "bin", "python"),
            os.path.join(repo_path, ".venv", "bin", "python"),
            os.path.join(repo_path, "backend", "venv", "bin", "python"),
            os.path.join(repo_path, "venv", "bin", "python"),
        ]
        
        for venv_python in possible_venvs:
            if os.path.exists(venv_python):
                python_executable = venv_python
                break
    
    cmd = [python_executable, "-m", "pytest", test_path, "--collect-only", "-q"]
    
    if test_type:
        cmd.extend(["-m", test_type])
        
    # Prepare environment with PYTHONPATH
    env = os.environ.copy()
    if repo_path:
        # Determine the codebase backend path
        backend_path = os.path.join(repo_path, "backend")
        if os.path.exists(backend_path) and os.path.isfile(os.path.join(backend_path, "main.py")):
            env["PYTHONPATH"] = f"{backend_path}:{repo_path}:{env.get('PYTHONPATH', '')}"
        elif os.path.isfile(os.path.join(repo_path, "main.py")):
            env["PYTHONPATH"] = f"{repo_path}:{env.get('PYTHONPATH', '')}"
        else:
            env["PYTHONPATH"] = f"{repo_path}:{env.get('PYTHONPATH', '')}"
    
    try:
        result = subprocess.run(
            cmd,
            cwd=repo_path or os.getcwd(),
            capture_output=True,
            text=True,
            timeout=60,
            env=env
        )
        
        if result.returncode == 0 or result.returncode == 5:  # 5 = no tests collected
            output = result.stdout
            
            # Count tests by type
            unit_count = output.count('@pytest.mark.unit')
            integration_count = output.count('@pytest.mark.integration')
            security_count = output.count('@pytest.mark.security')
            ui_count = output.count('@pytest.mark.ui')
            contract_count = output.count('@pytest.mark.contract')
            
            summary = f"Discovered Tests:\n{output}\n\n"
            summary += "Test Breakdown:\n"
            if unit_count > 0:
                summary += f"  • Unit Tests: {unit_count}\n"
            if integration_count > 0:
                summary += f"  • Integration Tests: {integration_count}\n"
            if security_count > 0:
                summary += f"  • Security Tests: {security_count}\n"
            if ui_count > 0:
                summary += f"  • UI Tests: {ui_count}\n"
            if contract_count > 0:
                summary += f"  • Contract Tests: {contract_count}\n"
            
            return summary
        else:
            return f"Error discovering tests:\n{result.stderr}\n\nCommand: {' '.join(cmd)}\nPYTHONPATH: {env.get('PYTHONPATH')}"
    
    except Exception as e:
        return f"Error: {str(e)}"


@tool  
def parse_test_output(test_output: str) -> str:
    """
    Parse pytest output and extract structured results.
    
    Args:
        test_output: Raw pytest output string.
    
    Returns:
        Structured summary of test results.
    """
    lines = test_output.split('\n')
    
    passed = 0
    failed = 0
    errors = 0
    skipped = 0
    failed_tests = []
    
    for line in lines:
        if 'passed' in line.lower():
            # Try to extract count from summary line
            import re
            match = re.search(r'(\d+)\s+passed', line.lower())
            if match:
                passed = int(match.group(1))
        if 'failed' in line.lower():
            match = re.search(r'(\d+)\s+failed', line.lower())
            if match:
                failed = int(match.group(1))
        if 'error' in line.lower():
            match = re.search(r'(\d+)\s+error', line.lower())
            if match:
                errors = int(match.group(1))
        if line.startswith('FAILED'):
            failed_tests.append(line)
    
    result = f"""Test Results Summary:
  Passed: {passed}
  Failed: {failed}
  Errors: {errors}
  Skipped: {skipped}
  
Overall: {"PASS" if failed == 0 and errors == 0 else "FAIL"}"""
    
    if failed_tests:
        result += "\n\nFailed Tests:\n" + "\n".join(f"  - {t}" for t in failed_tests)
    
    return result
