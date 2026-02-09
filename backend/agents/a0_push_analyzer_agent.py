"""
Push Analyzer Agent (a0)
Analyzes git pushes, identifies changes, and checks test history.
"""
from langchain.agents import create_agent
from langchain_google_vertexai import ChatVertexAI
from prompts.p0_push_analyzer_prompt import PUSH_ANALYZER_PROMPT
from tools.t0_push_analyzer_tools import (
    get_git_diff, get_changed_files, get_commit_info,
    build_dependency_graph, get_affected_modules
)
from tools.t5_database_tools import get_module_history, get_recent_runs, get_commit_runs
from utils.logger import setup_logger

logger = setup_logger("PushAnalyzerAgent")


def get_push_analyzer_agent():
    """Create and return the Push Analyzer agent."""
    logger.info("Creating PushAnalyzerAgent with Vertex AI")
    
    # Initialize Vertex AI Chat Model
    llm = ChatVertexAI(model="gemini-2.5-pro", temperature=0)
    
    tools = [
        get_git_diff,
        get_changed_files,
        get_commit_info,
        build_dependency_graph,
        get_affected_modules,
        get_module_history,
        get_recent_runs,
        get_commit_runs
    ]
    
    # create_agent returns a CompiledStateGraph
    return create_agent(
        model=llm,
        tools=tools,
        system_prompt=PUSH_ANALYZER_PROMPT
    )
