"""
Test Generator Agent (a2)
Generates and VALIDATES complete test scripts based on code analysis.
"""
from langchain_google_vertexai import ChatVertexAI
from langchain_core.prompts import ChatPromptTemplate
from langchain.agents import create_agent
from prompts.p2_test_generator_prompt import TEST_GENERATOR_PROMPT
from tools.t2_test_generator_tools import (
    validate_test_file, check_test_coverage,
    build_docker_test_environment, start_docker_test_container,
    stop_docker_test_container, install_runtime_dependencies, detect_project_type
)
from utils.logger import setup_logger
import os
import re

logger = setup_logger("TestGeneratorAgent")


def get_test_generator_agent():
    """Create and return the Test Generator agent with validation tools."""
    logger.info("Creating TestGeneratorAgent with Vertex AI and validation tools")
    
    llm = ChatVertexAI(model="gemini-2.5-pro", temperature=0.2)
    
    # Create agent with validation tools
    tools = [
        validate_test_file,
        check_test_coverage,
        build_docker_test_environment,
        start_docker_test_container,
        stop_docker_test_container,
        install_runtime_dependencies,
        detect_project_type
    ]
    
    return create_agent(
        model=llm,
        tools=tools,
        system_prompt=TEST_GENERATOR_PROMPT
    )


def extract_and_save_tests(agent_output: str, test_dir: str) -> dict:
    """
    Extract test code from agent output and save to files.
    
    Args:
        agent_output: Raw output from the test generator agent
        test_dir: Directory to save test files
        
    Returns:
        Dictionary with file paths and status
    """
    logger.info(f"Extracting tests from agent output to {test_dir}")
    
    # Ensure test directory exists
    os.makedirs(test_dir, exist_ok=True)
    
    result = {
        "conftest_path": None,
        "test_file_path": None,
        "conftest_created": False,
        "test_file_created": False,
        "error": None
    }
    
    try:
        # Extract conftest.py content - look for explicit conftest.py marker
        conftest_patterns = [
            r'```python\s*#\s*conftest\.py\s*\n(.*?)```',
            r'```python\s*#\s*File 1:\s*conftest\.py\s*\n(.*?)```',
            r'### Block 1:.*?```python\s*\n(.*?)```'
        ]
        
        conftest_content = None
        for pattern in conftest_patterns:
            match = re.search(pattern, agent_output, re.DOTALL | re.IGNORECASE)
            if match:
                conftest_content = match.group(1).strip()
                # Remove any leading comments that aren't code
                if conftest_content.startswith('# conftest.py'):
                    conftest_content = '\n'.join(conftest_content.split('\n')[1:])
                break
        
        if conftest_content:
            conftest_path = os.path.join(test_dir, "conftest.py")
            with open(conftest_path, 'w') as f:
                f.write(conftest_content)
            
            result["conftest_path"] = conftest_path
            result["conftest_created"] = True
            logger.info(f"✓ Created conftest.py at {conftest_path}")
        else:
            logger.warning("⚠ No conftest.py found in agent output")
        
        # Extract test_generated.py content - look for explicit test file marker
        test_patterns = [
            r'```python\s*#\s*test_generated\.py\s*\n(.*?)```',
            r'```python\s*#\s*File 2:\s*test_generated\.py\s*\n(.*?)```',
            r'### Block 2:.*?```python\s*\n(.*?)```'
        ]
        
        test_content = None
        for pattern in test_patterns:
            match = re.search(pattern, agent_output, re.DOTALL | re.IGNORECASE)
            if match:
                test_content = match.group(1).strip()
                # Remove any leading comments that aren't code
                if test_content.startswith('# test_generated.py'):
                    test_content = '\n'.join(test_content.split('\n')[1:])
                break
        
        if test_content:
            test_path = os.path.join(test_dir, "test_generated.py")
            with open(test_path, 'w') as f:
                f.write(test_content)
            
            result["test_file_path"] = test_path
            result["test_file_created"] = True
            
            # Count test functions
            test_count = len(re.findall(r'def test_\w+\(', test_content))
            logger.info(f"✓ Created test_generated.py with {test_count} test functions at {test_path}")
        else:
            logger.error("✗ No test_generated.py found in agent output")
            result["error"] = "No test file found in agent output"
        
        # If no explicit markers found, try to extract from generic code blocks
        if not result["test_file_created"]:
            logger.info("Attempting fallback extraction from generic code blocks...")
            
            # Find all Python code blocks
            all_blocks = re.findall(r'```python\s*(.*?)```', agent_output, re.DOTALL)
            
            if len(all_blocks) >= 2:
                # First block is likely conftest, second is likely tests
                if not result["conftest_created"] and 'pytest.fixture' in all_blocks[0]:
                    conftest_path = os.path.join(test_dir, "conftest.py")
                    with open(conftest_path, 'w') as f:
                        f.write(all_blocks[0].strip())
                    result["conftest_path"] = conftest_path
                    result["conftest_created"] = True
                    logger.info(f"✓ Extracted conftest.py from first code block")
                
                # Find block with most test functions
                test_block = max(all_blocks, key=lambda x: x.count('def test_'))
                if 'def test_' in test_block:
                    test_path = os.path.join(test_dir, "test_generated.py")
                    with open(test_path, 'w') as f:
                        f.write(test_block.strip())
                    result["test_file_path"] = test_path
                    result["test_file_created"] = True
                    test_count = len(re.findall(r'def test_\w+\(', test_block))
                    logger.info(f"✓ Extracted {test_count} tests from code block")
    
    except Exception as e:
        logger.error(f"✗ Error extracting tests: {str(e)}")
        result["error"] = str(e)
    
    return result
