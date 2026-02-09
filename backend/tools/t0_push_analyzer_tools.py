"""
Push Analyzer Tools (t0)
Git, dependency analysis, and previous test failure tools for the Push Analyzer Agent.
"""
import subprocess
import os
import ast
from typing import Optional
from langchain.tools import tool


# =============================================================================
# Git Tools
# =============================================================================

def _run_git_command(cmd: list[str], cwd: Optional[str] = None) -> tuple[str, bool]:
    """Run a git command and return (output, success)."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd or os.getcwd(),
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout.strip(), result.returncode == 0
    except subprocess.TimeoutExpired:
        return "Command timed out", False
    except Exception as e:
        return str(e), False


@tool
def get_git_diff(repo_path: Optional[str] = None, base_ref: str = "HEAD~1") -> str:
    """
    Get the git diff from a reference point.
    
    Args:
        repo_path: Path to the repository. Defaults to current directory.
        base_ref: Base reference for diff (default HEAD~1 for last commit).
    
    Returns:
        Git diff output showing all changes.
    """
    # First check if base_ref exists
    check_cmd = ["git", "rev-parse", "--verify", base_ref]
    _, ref_exists = _run_git_command(check_cmd, repo_path)
    
    if not ref_exists:
        # If base_ref doesn't exist, show the entire HEAD commit
        cmd = ["git", "show", "HEAD"]
        output, success = _run_git_command(cmd, repo_path)
        if not success:
            return f"Error getting diff: {output}"
        return output if output else "No changes detected"
    
    cmd = ["git", "diff", base_ref]
    output, success = _run_git_command(cmd, repo_path)
    if not success:
        return f"Error getting diff: {output}"
    return output if output else "No changes detected"


@tool
def get_changed_files(repo_path: Optional[str] = None, base_ref: str = "HEAD~1") -> str:
    """
    Get list of files changed since a reference point.
    
    Args:
        repo_path: Path to the repository. Defaults to current directory.
        base_ref: Base reference for comparison (default HEAD~1).
    
    Returns:
        Newline-separated list of changed files with status (M/A/D).
    """
    # First check if base_ref exists
    check_cmd = ["git", "rev-parse", "--verify", base_ref]
    _, ref_exists = _run_git_command(check_cmd, repo_path)
    
    if not ref_exists:
        # If base_ref doesn't exist, show files in HEAD commit
        cmd = ["git", "diff-tree", "--no-commit-id", "--name-status", "-r", "HEAD"]
        output, success = _run_git_command(cmd, repo_path)
        if not success:
            return f"Error getting changed files: {output}"
        return output if output else "No files changed"
    
    cmd = ["git", "diff", "--name-status", base_ref]
    output, success = _run_git_command(cmd, repo_path)
    if not success:
        return f"Error getting changed files: {output}"
    return output if output else "No files changed"


@tool
def get_commit_info(repo_path: Optional[str] = None, commit_ref: str = "HEAD") -> str:
    """
    Get commit information including message, author, and date.
    
    Args:
        repo_path: Path to the repository. Defaults to current directory.
        commit_ref: Commit reference (default HEAD).
    
    Returns:
        Formatted commit information.
    """
    format_str = "Commit: %H%nAuthor: %an <%ae>%nDate: %ad%nMessage: %s%n%nBody:%n%b"
    cmd = ["git", "log", "-1", f"--format={format_str}", commit_ref]
    output, success = _run_git_command(cmd, repo_path)
    if not success:
        return f"Error getting commit info: {output}"
    return output


# =============================================================================
# Dependency Analysis Tools
# =============================================================================

def _extract_imports_from_file(file_path: str) -> list[str]:
    """Extract import statements from a Python file."""
    try:
        with open(file_path, 'r') as f:
            tree = ast.parse(f.read())
    except (SyntaxError, FileNotFoundError):
        return []
    
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports.append(f"{module}.{alias.name}" if module else alias.name)
    return imports


@tool
def build_dependency_graph(project_path: str) -> str:
    """
    Build a dependency graph for all Python files in a project.
    
    Args:
        project_path: Root path of the project.
    
    Returns:
        Formatted string showing file -> dependencies mapping.
    """
    if not os.path.isdir(project_path):
        return f"Directory not found: {project_path}"
    
    graph = {}
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__' and 'venv' not in d.lower()]
        
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, project_path)
                imports = _extract_imports_from_file(file_path)
                local_imports = [i for i in imports if not i.startswith(('os', 'sys', 'typing', 'json', 'ast', 'subprocess', 're'))]
                if local_imports:
                    graph[rel_path] = local_imports
    
    if not graph:
        return "No dependencies found"
    
    result = []
    for file, deps in sorted(graph.items()):
        result.append(f"{file}:")
        for dep in deps:
            result.append(f"  - {dep}")
    return "\n".join(result)


@tool
def get_affected_modules(changed_files: str, project_path: str) -> str:
    """
    Find all modules affected by changes (including transitive dependencies).
    
    Args:
        changed_files: Newline-separated list of changed files.
        project_path: Root path of the project.
    
    Returns:
        List of all affected modules that may need testing.
    """
    changed = set(changed_files.strip().split('\n'))
    changed = {f.split('\t')[-1] if '\t' in f else f for f in changed if f.endswith('.py')}
    
    if not changed:
        return "No Python files changed"
    
    reverse_deps = {}
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__' and 'venv' not in d.lower()]
        
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, project_path)
                imports = _extract_imports_from_file(file_path)
                
                for imp in imports:
                    imp_path = imp.replace('.', '/') + '.py'
                    if imp_path not in reverse_deps:
                        reverse_deps[imp_path] = set()
                    reverse_deps[imp_path].add(rel_path)
    
    affected = set(changed)
    to_process = list(changed)
    
    while to_process:
        current = to_process.pop()
        for dep_path, dependents in reverse_deps.items():
            if current.endswith(dep_path) or dep_path in current:
                for dependent in dependents:
                    if dependent not in affected:
                        affected.add(dependent)
                        to_process.append(dependent)
    
    return "\n".join(sorted(affected))
