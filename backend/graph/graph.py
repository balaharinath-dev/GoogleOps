"""
CI/CD Pipeline Graph with Orchestrator
LangGraph workflow with master orchestrator controlling all CI/CD agents.
"""
from langgraph.graph import StateGraph, END, START
from langchain_core.messages import HumanMessage, AIMessage
from models.state import CICDState
from agents.a0_push_analyzer_agent import get_push_analyzer_agent
from agents.a1_code_analyzer_agent import get_code_analyzer_agent
from agents.a2_test_generator_agent import get_test_generator_agent
from agents.a3_test_runner_agent import get_test_runner_agent
from agents.a4_deployment_gate_agent import get_deployment_gate_agent
from agents.a5_orchestrator_agent import get_orchestrator_agent
from tools.t6_orchestrator_tools import (
    update_pipeline_state, reset_pipeline_state, should_retry, get_retry_count
)
from utils.logger import setup_logger
from utils.callback_handler import RichAgentCallback
from tools.t5_database_tools import (
    create_pipeline_run, update_pipeline_run, log_agent_state,
    log_changed_files
)
from rich.console import Console
import os
import re

logger = setup_logger("CICDGraph")
console = Console()


def _extract_text_from_content(content) -> str:
    """Extract text from agent message content (handles both string and list formats)."""
    if isinstance(content, str):
        return content
    elif isinstance(content, list):
        text_parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                text_parts.append(part.get("text", ""))
            elif isinstance(part, str):
                text_parts.append(part)
        return "".join(text_parts)
    else:
        return str(content)


def push_analyzer_node(state: CICDState) -> dict:
    """Analyze the git push and identify changes."""
    run_id = state.get('run_id', 'unknown')
    repo_path = os.path.abspath(state.get('repo_path', '.'))  # Convert to absolute path
    
    logger.info("Running Push Analyzer...")
    console.print("\n")
    console.rule("[bold blue]🔍 Step 1: Analyzing Code Changes[/bold blue]", style="blue")
    console.print("Examining what files were modified and understanding the impact...\n", style="dim")
    
    agent = get_push_analyzer_agent()
    callback = RichAgentCallback("Push Analyzer", run_id)
    
    prompt = f"""
                Analyze the git push for repository at: {repo_path}
                Base reference: {state.get('base_ref', 'HEAD~1')}

                CRITICAL: Use ABSOLUTE PATHS for all tool calls.
                Repository absolute path: {repo_path}

                Please:
                1. Get the changed files using absolute path
                2. Get the git diff using absolute path
                3. Get commit info
                4. Build the dependency graph using absolute path
                5. Find affected modules using absolute path
                6. Check for previous failures in affected modules

                Provide a comprehensive analysis following the format in your system prompt."""

    # create_agent returns a graph, expects "messages"
    result = agent.invoke(
        {"messages": [HumanMessage(content=prompt)]},
        config={"callbacks": [callback]}
    )
    last_msg_content = result["messages"][-1].content if result.get("messages") else ""
    last_msg = _extract_text_from_content(last_msg_content)
    
    # Log agent state to database
    log_agent_state.invoke({
        "run_id": run_id,
        "agent_name": "Push Analyzer",
        "agent_order": 0,
        "input_prompt": prompt[:500],
        "output_result": last_msg[:1000],
        "status": "COMPLETED"
    })
    
    # Get and log changed files directly for database
    from tools.t0_push_analyzer_tools import get_changed_files
    changed_files_output = get_changed_files.invoke({
        "repo_path": repo_path,
        "base_ref": state.get('base_ref', 'HEAD~1')
    })
    
    if changed_files_output and "Error" not in changed_files_output:
        files = []
        for line in changed_files_output.split('\n'):
            if line.strip():
                parts = line.split('\t')
                if len(parts) >= 2:
                    files.append({
                        'file_path': parts[1],
                        'change_type': parts[0],
                        'lines_added': 0,
                        'lines_removed': 0
                    })
        if files:
            log_changed_files.invoke({"run_id": run_id, "files": files})
    
    # Prepare changed files list for state
    final_changed_files = []
    if changed_files_output and "Error" not in changed_files_output:
        final_changed_files = changed_files_output.split('\n')
    
    logger.info("Push analysis complete")
    return {
        "push_analysis": last_msg,
        "changed_files": final_changed_files,
        "affected_modules": state.get("affected_modules", ""),
        "last_agent_executed": "Push Analyzer"
    }


def code_analyzer_node(state: CICDState) -> dict:
    """Analyze the code structure of changed files."""
    run_id = state.get('run_id', 'unknown')
    repo_path = os.path.abspath(state.get('repo_path', '.'))  # Convert to absolute path
    
    logger.info("Running Code Analyzer...")
    console.print("\n")
    console.rule("[bold blue]📊 Step 2: Understanding Code Quality[/bold blue]", style="blue")
    console.print("Analyzing code complexity and identifying what needs testing...\n", style="dim")
    
    agent = get_code_analyzer_agent()
    callback = RichAgentCallback("Code Analyzer", run_id)
    
    # Convert changed files to absolute paths
    changed_files_list = state.get('changed_files', [])
    absolute_changed_files = []
    for file in changed_files_list:
        # Remove status prefix if present (M, A, D)
        file_path = file.split('\t')[-1] if '\t' in file else file
        file_path = file_path.strip()
        if file_path:
            abs_file_path = os.path.join(repo_path, file_path)
            absolute_changed_files.append(abs_file_path)
    
    prompt = f"""
                Analyze the code changes.

                Push Analysis Context:
                {state.get('push_analysis', 'No push analysis available')}

                Changed Files (ABSOLUTE PATHS):
                {chr(10).join(absolute_changed_files)}

                Repository Absolute Path: {repo_path}

                CRITICAL: Use ABSOLUTE PATHS for all tool calls.
                Example: parse_python_file(file_path="{absolute_changed_files[0] if absolute_changed_files else repo_path}")

                Please:
                1. Parse each changed Python file using ABSOLUTE PATH
                2. Analyze complexity using ABSOLUTE PATH
                3. Get function source code using ABSOLUTE PATH for modified functions
                4. Identify new/modified functions and classes
                5. Recommend what tests are needed

                Focus on providing actionable insights for test generation following your system prompt format."""

    result = agent.invoke(
        {"messages": [HumanMessage(content=prompt)]},
        config={"callbacks": [callback]}
    )
    last_msg_content = result["messages"][-1].content if result.get("messages") else ""
    last_msg = _extract_text_from_content(last_msg_content)
    
    # Log agent state to database
    log_agent_state.invoke({
        "run_id": run_id,
        "agent_name": "Code Analyzer",
        "agent_order": 1,
        "input_prompt": prompt[:500],
        "output_result": last_msg[:1000],
        "status": "COMPLETED"
    })
    
    logger.info("Code analysis complete")
    return {"code_analysis": last_msg, "last_agent_executed": "Code Analyzer"}


def test_generator_node(state: CICDState) -> dict:
    """Generate COMPLETE, VALIDATED test scripts based on analysis."""
    run_id = state.get('run_id', 'unknown')
    logger.info("Running Test Generator...")
    console.print("\n")
    console.rule("[bold blue]🧬 Step 3: Creating Test Scripts[/bold blue]", style="blue")
    console.print("Generating comprehensive tests to validate your changes...\n", style="dim")
    
    # Import the extraction function and validation tools
    from agents.a2_test_generator_agent import extract_and_save_tests
    from tools.t2_test_generator_tools import validate_test_file, check_test_coverage
    
    # Get the agent (now returns an agent, not a chain)
    agent = get_test_generator_agent()
    callback = RichAgentCallback("Test Generator", run_id)
    
    # Get changed files for coverage check
    changed_files_list = state.get('changed_files', [])
    if changed_files_list and isinstance(changed_files_list[0], dict):
        changed_files = ','.join([f.get('file_path', '') for f in changed_files_list])
    else:
        # changed_files is already a list of strings - clean them
        # Remove git status prefixes like "M\t", "A\t", "D\t"
        clean_files = []
        for file in changed_files_list:
            # Split by tab and take the last part (the actual filename)
            file_path = file.split('\t')[-1] if '\t' in file else file
            file_path = file_path.strip()
            if file_path:
                clean_files.append(file_path)
        changed_files = ','.join(clean_files) if clean_files else ''
    
    prompt = f"""
                Generate COMPLETE, EXECUTABLE, VALIDATED test scripts for the changed code.

                Push Analysis:
                {state.get('push_analysis', 'No push analysis')}

                Code Analysis:
                {state.get('code_analysis', 'No code analysis')}

                Changed Files:
                {changed_files}

                Previous Failures (consider these for regression tests):
                {state.get('previous_failures', 'No previous failures recorded')}

                CRITICAL REQUIREMENTS:
                1. Generate BOTH conftest.py AND test_generated.py files
                2. Include ALL necessary imports and fixtures in conftest.py
                3. Include AT LEAST 15 actual test functions in test_generated.py
                4. Cover unit, integration, security, and contract tests
                5. Make tests specific to the code changes analyzed above
                6. Ensure tests are immediately executable with pytest
                7. Follow the EXACT format specified in your system prompt
                
                Generate comprehensive pytest test scripts covering:
                - Unit tests for new/modified functions
                - Integration tests for API endpoints
                - Security tests for vulnerabilities
                - Contract tests for API schemas
                - Edge case tests
                - Regression tests if there were previous failures

                Output COMPLETE test code with proper structure using the two-block format."""

    # Agent returns messages
    result = agent.invoke(
        {"messages": [HumanMessage(content=prompt)]},
        config={"callbacks": [callback]}
    )
    
    # Extract last message
    last_msg_content = result["messages"][-1].content if result.get("messages") else ""
    last_msg = _extract_text_from_content(last_msg_content)
    
    # Save generated tests per run_id using extraction function
    test_file_path = None
    tests_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data", "test_knowledge_base", "runs", run_id, "tests"
    )
    
    extraction_result = extract_and_save_tests(last_msg, tests_dir)
    
    validation_report = ""
    coverage_report = ""
    
    if extraction_result["test_file_created"]:
        test_file_path = extraction_result["test_file_path"]
        logger.info(f"✓ Generated test file: {test_file_path}")
        
        if extraction_result["conftest_created"]:
            logger.info(f"✓ Generated conftest: {extraction_result['conftest_path']}")
        else:
            logger.warning("⚠ conftest.py was not generated - tests may fail")
        
        # Validate the generated tests
        logger.info("Validating generated tests...")
        validation_report = validate_test_file.invoke({"test_file_path": test_file_path})
        logger.info(f"Validation Report:\n{validation_report}")
        
        # Check test coverage
        if changed_files:
            logger.info("Checking test coverage...")
            coverage_report = check_test_coverage.invoke({
                "test_file_path": test_file_path,
                "changed_files": changed_files
            })
            logger.info(f"Coverage Report:\n{coverage_report}")
        
        # Check if validation passed
        if "Overall Status: VALID" in validation_report:
            logger.info("✓ Test validation PASSED")
        else:
            logger.error("✗ Test validation FAILED - tests may not execute properly")
    else:
        logger.error(f"✗ Failed to generate tests: {extraction_result.get('error', 'Unknown error')}")
        # Create a minimal test file to prevent complete failure
        test_file_path = os.path.join(tests_dir, "test_generated.py")
        os.makedirs(tests_dir, exist_ok=True)
        with open(test_file_path, 'w') as f:
            f.write("""# Test generation failed - placeholder file
import pytest

@pytest.mark.unit
def test_placeholder():
    '''Placeholder test - actual tests failed to generate'''
    assert True
""")
        validation_report = "Test generation FAILED - using placeholder"
    
    # Log agent state to database
    log_agent_state.invoke({
        "run_id": run_id,
        "agent_name": "Test Generator",
        "agent_order": 2,
        "input_prompt": prompt[:500],
        "output_result": f"{last_msg[:500]}\n\nValidation:\n{validation_report[:500]}",
        "status": "COMPLETED"
    })
    
    logger.info("Test generation complete")
    return {
        "generated_tests": last_msg,
        "test_file_path": test_file_path,
        "test_validation": validation_report,
        "test_coverage": coverage_report,
        "last_agent_executed": "Test Generator"
    }



def test_runner_node(state: CICDState) -> dict:
    """Execute the generated tests."""
    run_id = state.get('run_id', 'unknown')
    logger.info("Running Test Runner...")
    console.print("\n")
    console.rule("[bold blue]🧪 Step 4: Running Tests[/bold blue]", style="blue")
    console.print("Executing tests to ensure everything works correctly...\n", style="dim")
    
    agent = get_test_runner_agent()
    callback = RichAgentCallback("Test Runner", run_id)
    
    test_path = state.get('test_file_path') or os.path.join(state.get('repo_path', '.'), "tests")
    repo_path = state.get('repo_path', '.')
    
    prompt = f"""
                Execute comprehensive tests for the repository.

                Test File Path: {test_path}
                Repository Path: {repo_path}
                Run ID: {run_id}

                Changed Files:
                {state.get('changed_files', 'No files specified')}

                Generated Tests Summary:
                {state.get('generated_tests', 'No generated tests')[:500]}...

                ## Multi-Phase Testing Strategy:

                1. DISCOVER EXISTING TESTS:
                   - Use discover_tests to find existing tests in {repo_path}/tests or similar
                   - Identify tests related to changed files

                2. RUN EXISTING TESTS (if found):
                   - Run with test_type="existing"
                   - This validates no regressions

                3. RUN GENERATED TESTS:
                   - Run unit tests: markers="unit", test_type="generated"
                   - Run integration tests: markers="integration", test_type="generated"
                   - Run security tests: markers="security", test_type="security"
                   - Run contract tests: markers="contract", test_type="contract"
                   - Run UI tests: markers="ui", test_type="ui"

                4. ANALYZE & REPORT:
                   - Compare with previous runs using get_module_history
                   - Provide comprehensive summary

                IMPORTANT: Always pass run_id={run_id} to all test execution tools!

                Provide a detailed test report with pass/fail counts for each test type."""

    result = agent.invoke(
        {"messages": [HumanMessage(content=prompt)]},
        config={"callbacks": [callback]}
    )
    last_msg_content = result["messages"][-1].content if result.get("messages") else ""
    last_msg = _extract_text_from_content(last_msg_content)
    
    # Log agent state to database
    log_agent_state.invoke({
        "run_id": run_id,
        "agent_name": "Test Runner",
        "agent_order": 3,
        "input_prompt": prompt[:500],
        "output_result": last_msg[:1000],
        "status": "COMPLETED"
    })
    
    logger.info("Test execution complete")
    return {
        "test_results": last_msg,
        "test_summary": last_msg[:500] if last_msg else "",
        "last_agent_executed": "Test Runner"
    }


def deployment_gate_node(state: CICDState) -> dict:
    """Make the final deployment decision."""
    run_id = state.get('run_id', 'unknown')
    logger.info("Running Deployment Gate...")
    console.print("\n")
    console.rule("[bold blue]🚦 Step 5: Making Deployment Decision[/bold blue]", style="blue")
    console.print("Evaluating test results and determining if code is ready to deploy...\n", style="dim")
    
    agent = get_deployment_gate_agent()
    callback = RichAgentCallback("Deployment Gate", run_id)
    
    prompt = f"""
            Make a deployment decision based on all testing results.

            Test Results:
            {state.get('test_results', 'No test results')}

            Test Validation Report:
            {state.get('test_validation', 'No validation report')}

            Test Coverage Report:
            {state.get('test_coverage', 'No coverage report')}

            Push Analysis Summary:
            {state.get('push_analysis', 'No push analysis')[:500]}

            Code Analysis Summary:
            {state.get('code_analysis', 'No code analysis')[:500]}

            Please:
            1. **FIRST: Validate test quality** - Check if tests are valid, comprehensive, and executed properly
            2. Review the test history
            3. Check module statistics
            4. Evaluate the risk level of changes
            5. Make a GO/NO-GO decision

            CRITICAL: If test validation shows issues (syntax errors, collection errors, placeholder tests, 
            or insufficient coverage), you MUST BLOCK deployment regardless of other factors.

            Provide clear DEPLOY or BLOCK decision with rationale including test quality assessment."""

    # create_agent returns a graph, expects "messages"
    result = agent.invoke(
        {"messages": [HumanMessage(content=prompt)]},
        config={"callbacks": [callback]}
    )
    
    last_message = result["messages"][-1]
    last_msg_content = last_message.content if result.get("messages") else ""
    
    # Robust Content Extraction
    final_text = ""
    if isinstance(last_msg_content, str):
        final_text = last_msg_content
    elif isinstance(last_msg_content, list):
        # Handle list of blocks (e.g. [{'type': 'text', 'text': '...'}])
        text_parts = []
        for part in last_msg_content:
            if isinstance(part, dict) and part.get("type") == "text":
                text_parts.append(part.get("text", ""))
            elif isinstance(part, str):
                text_parts.append(part)
        final_text = "".join(text_parts)
    else:
        final_text = str(last_msg_content)

    # Extract decision
    decision = "BLOCK"  # Default to safe
    if "DEPLOY" in final_text.upper() and "BLOCK" not in final_text.upper():
        decision = "DEPLOY"
    
    logger.info(f"Deployment decision: {decision}")
    
    # Construct Detailed Summary
    summary = f"""
# 🚀 CI/CD Pipeline Report

### 📋 1. Git Push Analysis
{state.get('push_analysis', 'No analysis available')}

### 🔍 2. Code Analysis
{state.get('code_analysis', 'No analysis available')}

### 🧪 3. Test Execution
{state.get('test_results', 'No results available')}

### 🏁 4. Deployment Decision: {decision}

**Rationale:**
{final_text}
"""

    # Log agent state to database
    log_agent_state.invoke({
        "run_id": run_id,
        "agent_name": "Deployment Gate",
        "agent_order": 4,
        "input_prompt": prompt[:500],
        "output_result": final_text[:1000],
        "status": "COMPLETED"
    })
    
    # Report to orchestrator
    update_pipeline_state("Deployment Gate", final_text)
    
    # Update pipeline run with final decision
    update_pipeline_run.invoke({
        "run_id": run_id,
        "status": "COMPLETED",
        "decision": decision,
        "decision_rationale": final_text,
        "pipeline_summary": summary
    })

    return {
        "deployment_decision": decision,
        "decision_rationale": final_text,
        "pipeline_summary": summary,
        "last_agent_executed": "Deployment Gate"
    }


def orchestrator_node(state: CICDState) -> dict:
    """
    Orchestrator node - simple router that evaluates and directs traffic.
    Does NOT generate anything, just decides which agent to run next.
    """
    run_id = state.get('run_id', 'unknown')
    last_agent = state.get('last_agent_executed', 'START')
    
    logger.info(f"🎯 Orchestrator evaluating after: {last_agent}")
    console.print(f"\n[bold cyan]🎯 Orchestrator: Evaluating {last_agent} results...[/bold cyan]")
    
    chain = get_orchestrator_agent()
    callback = RichAgentCallback("Orchestrator", run_id)
    
    # Get last agent's output for evaluation
    last_output = ""
    if last_agent == "Push Analyzer":
        last_output = state.get('push_analysis', '')[:500]
    elif last_agent == "Code Analyzer":
        last_output = state.get('code_analysis', '')[:500]
    elif last_agent == "Test Generator":
        last_output = f"Validation: {state.get('test_validation', '')[:300]}"
    elif last_agent == "Test Runner":
        last_output = state.get('test_results', '')[:500]
    elif last_agent == "Deployment Gate":
        last_output = state.get('deployment_decision', '')
    
    # Build evaluation context
    context = f"""Last Agent Executed: {last_agent}

Agent Output Summary:
{last_output}

Current Retry Counts:
- Push Analyzer: {get_retry_count('Push Analyzer')}/2
- Code Analyzer: {get_retry_count('Code Analyzer')}/2
- Test Generator: {get_retry_count('Test Generator')}/3
- Test Runner: {get_retry_count('Test Runner')}/2

Evaluate the output and decide which agent to run next.
Output format:
NEXT_AGENT: [agent_name]
REASON: [brief reason]
RETRY_COUNT: [X/max]
"""
    
    # Get orchestrator decision
    result = chain.invoke(
        {"messages": [HumanMessage(content=context)]},
        config={"callbacks": [callback]}
    )
    
    decision_text = result.content if hasattr(result, 'content') else str(result)
    
    # Parse decision
    next_agent = _parse_next_agent(decision_text)
    
    logger.info(f"✓ Orchestrator decision: {next_agent}")
    console.print(f"[bold green]✓ Next: {next_agent}[/bold green]\n")
    
    return {
        "orchestrator_decision": decision_text,
        "next_agent": next_agent,
        "last_agent_executed": last_agent
    }


def _parse_next_agent(decision_text: str) -> str:
    """Parse orchestrator decision to extract next agent name."""
    # Look for "NEXT_AGENT: agent_name" pattern
    match = re.search(r'NEXT_AGENT:\s*(\w+)', decision_text, re.IGNORECASE)
    if match:
        agent_name = match.group(1).lower()
        
        # Map to valid agent names
        agent_map = {
            'push_analyzer': 'push_analyzer',
            'code_analyzer': 'code_analyzer',
            'test_generator': 'test_generator',
            'test_runner': 'test_runner',
            'deployment_gate': 'deployment_gate',
            'end': 'END'
        }
        
        return agent_map.get(agent_name, 'END')
    
    # Default: try to infer from text
    if 'push' in decision_text.lower():
        return 'push_analyzer'
    elif 'code' in decision_text.lower():
        return 'code_analyzer'
    elif 'test' in decision_text.lower() and 'generat' in decision_text.lower():
        return 'test_generator'
    elif 'test' in decision_text.lower() and 'run' in decision_text.lower():
        return 'test_runner'
    elif 'deploy' in decision_text.lower() or 'gate' in decision_text.lower():
        return 'deployment_gate'
    
    return 'END'


def route_from_orchestrator(state: CICDState) -> str:
    """Route to next agent based on orchestrator decision."""
    next_agent = state.get('next_agent', 'END')
    logger.info(f"Routing to: {next_agent}")
    return next_agent


def create_cicd_graph():
    """Create and compile the CI/CD pipeline graph with orchestrator routing."""
    logger.info("Creating CI/CD pipeline graph with Orchestrator")
    
    # Reset pipeline state for new run
    reset_pipeline_state()
    
    workflow = StateGraph(CICDState)
    
    # Add all nodes
    workflow.add_node("orchestrator", orchestrator_node)
    workflow.add_node("push_analyzer", push_analyzer_node)
    workflow.add_node("code_analyzer", code_analyzer_node)
    workflow.add_node("test_generator", test_generator_node)
    workflow.add_node("test_runner", test_runner_node)
    workflow.add_node("deployment_gate", deployment_gate_node)
    
    # Start with push analyzer
    workflow.add_edge(START, "push_analyzer")
    
    # After each agent, go to orchestrator
    workflow.add_edge("push_analyzer", "orchestrator")
    workflow.add_edge("code_analyzer", "orchestrator")
    workflow.add_edge("test_generator", "orchestrator")
    workflow.add_edge("test_runner", "orchestrator")
    workflow.add_edge("deployment_gate", "orchestrator")
    
    # Orchestrator routes to next agent
    workflow.add_conditional_edges(
        "orchestrator",
        route_from_orchestrator,
        {
            "push_analyzer": "push_analyzer",
            "code_analyzer": "code_analyzer",
            "test_generator": "test_generator",
            "test_runner": "test_runner",
            "deployment_gate": "deployment_gate",
            "END": END
        }
    )
    
    logger.info("CI/CD graph compiled with Orchestrator routing")
    return workflow.compile()
