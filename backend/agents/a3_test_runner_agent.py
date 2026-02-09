"""
Test Runner Agent (a3)
Executes tests and records results in the knowledge base.
"""
from langchain.agents import create_agent
from langchain_google_vertexai import ChatVertexAI
from prompts.p3_test_runner_prompt import TEST_RUNNER_PROMPT
from tools.t3_test_runner_tools import run_pytest, run_single_test, discover_tests, parse_test_output
from tools.t5_database_tools import store_test_result, store_module_stats, get_module_history, get_recent_runs
from utils.logger import setup_logger

logger = setup_logger("TestRunnerAgent")


def get_test_runner_agent():
    """Create and return the Test Runner agent."""
    logger.info("Creating TestRunnerAgent with Vertex AI")
    
    llm = ChatVertexAI(model="gemini-2.5-pro", temperature=0)
    
    tools = [
        run_pytest,
        run_single_test,
        discover_tests,
        parse_test_output,
        store_test_result,
        store_module_stats,
        get_module_history,
        get_recent_runs
    ]
    
    return create_agent(
        model=llm,
        tools=tools,
        system_prompt=TEST_RUNNER_PROMPT
    )
