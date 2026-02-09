"""
Code Analysis Tools for CI/CD Pipeline
Provides AST parsing and code structure analysis utilities.
"""
import ast
import os
from typing import Optional
from langchain.tools import tool


class CodeVisitor(ast.NodeVisitor):
    """AST visitor to extract code structure."""
    
    def __init__(self):
        self.functions = []
        self.classes = []
        self.current_class = None
    
    def visit_FunctionDef(self, node):
        func_info = {
            "name": node.name,
            "args": [arg.arg for arg in node.args.args],
            "decorators": [self._get_decorator_name(d) for d in node.decorator_list],
            "lineno": node.lineno,
            "docstring": ast.get_docstring(node) or ""
        }
        if self.current_class:
            func_info["class"] = self.current_class
        self.functions.append(func_info)
        self.generic_visit(node)
    
    def visit_AsyncFunctionDef(self, node):
        func_info = {
            "name": f"async {node.name}",
            "args": [arg.arg for arg in node.args.args],
            "decorators": [self._get_decorator_name(d) for d in node.decorator_list],
            "lineno": node.lineno,
            "docstring": ast.get_docstring(node) or "",
            "async": True
        }
        if self.current_class:
            func_info["class"] = self.current_class
        self.functions.append(func_info)
        self.generic_visit(node)
    
    def visit_ClassDef(self, node):
        self.current_class = node.name
        bases = [self._get_base_name(b) for b in node.bases]
        self.classes.append({
            "name": node.name,
            "bases": bases,
            "lineno": node.lineno,
            "docstring": ast.get_docstring(node) or ""
        })
        self.generic_visit(node)
        self.current_class = None
    
    def _get_decorator_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_decorator_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return self._get_decorator_name(node.func)
        return "unknown"
    
    def _get_base_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_base_name(node.value)}.{node.attr}"
        return "unknown"


@tool
def parse_python_file(file_path: str) -> str:
    """
    Parse a Python file and return its structure.
    
    Args:
        file_path: Path to the Python file (can be relative or absolute).
    
    Returns:
        Structured overview of classes and functions.
    """
    # Convert to absolute path
    abs_path = os.path.abspath(file_path)
    if not os.path.exists(abs_path):
        return f"File not found: {abs_path}"
    file_path = abs_path
    
    try:
        with open(file_path, 'r') as f:
            source = f.read()
        tree = ast.parse(source)
    except SyntaxError as e:
        return f"Syntax error in file: {e}"
    
    visitor = CodeVisitor()
    visitor.visit(tree)
    
    result = [f"File: {file_path}\n"]
    
    if visitor.classes:
        result.append("Classes:")
        for cls in visitor.classes:
            bases = f"({', '.join(cls['bases'])})" if cls['bases'] else ""
            result.append(f"  - {cls['name']}{bases} [line {cls['lineno']}]")
            if cls['docstring']:
                result.append(f"    Doc: {cls['docstring'][:100]}...")
    
    if visitor.functions:
        result.append("\nFunctions:")
        for func in visitor.functions:
            class_prefix = f"{func.get('class', '')}." if func.get('class') else ""
            args = ", ".join(func['args'])
            decorators = f"@{', @'.join(func['decorators'])} " if func['decorators'] else ""
            result.append(f"  - {decorators}{class_prefix}{func['name']}({args}) [line {func['lineno']}]")
    
    return "\n".join(result) if len(result) > 1 else "No classes or functions found"


@tool
def get_function_source(file_path: str, function_name: str) -> str:
    """
    Get the source code of a specific function.
    
    Args:
        file_path: Path to the Python file (can be relative or absolute).
        function_name: Name of the function to extract.
    
    Returns:
        Source code of the function.
    """
    # Convert to absolute path
    abs_path = os.path.abspath(file_path)
    if not os.path.exists(abs_path):
        return f"File not found: {abs_path}"
    file_path = abs_path
    
    try:
        with open(file_path, 'r') as f:
            source_lines = f.readlines()
            source = ''.join(source_lines)
        tree = ast.parse(source)
    except SyntaxError as e:
        return f"Syntax error in file: {e}"
    
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == function_name:
                start = node.lineno - 1
                end = node.end_lineno
                return ''.join(source_lines[start:end])
    
    return f"Function '{function_name}' not found"


@tool
def analyze_complexity(file_path: str) -> str:
    """
    Analyze basic complexity metrics for a Python file.
    
    Args:
        file_path: Path to the Python file (can be relative or absolute).
    
    Returns:
        Complexity metrics for the file.
    """
    # Convert to absolute path
    abs_path = os.path.abspath(file_path)
    if not os.path.exists(abs_path):
        return f"File not found: {abs_path}"
    file_path = abs_path
    
    try:
        with open(file_path, 'r') as f:
            source = f.read()
        tree = ast.parse(source)
    except SyntaxError as e:
        return f"Syntax error in file: {e}"
    
    # Count various constructs
    metrics = {
        "functions": 0,
        "classes": 0,
        "lines": source.count('\n') + 1,
        "if_statements": 0,
        "loops": 0,
        "try_blocks": 0,
        "imports": 0
    }
    
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            metrics["functions"] += 1
        elif isinstance(node, ast.ClassDef):
            metrics["classes"] += 1
        elif isinstance(node, ast.If):
            metrics["if_statements"] += 1
        elif isinstance(node, (ast.For, ast.While)):
            metrics["loops"] += 1
        elif isinstance(node, ast.Try):
            metrics["try_blocks"] += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            metrics["imports"] += 1
    
    result = [f"Complexity Analysis: {file_path}"]
    for key, value in metrics.items():
        result.append(f"  {key.replace('_', ' ').title()}: {value}")
    
    return "\n".join(result)