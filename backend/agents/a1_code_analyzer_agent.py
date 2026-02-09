"""
Code Analyzer Agent (a1)
Performs deep code analysis using AST parsing and structure extraction.
"""
from langchain.agents import create_agent
from langchain_google_vertexai import ChatVertexAI
from prompts.p1_code_analyzer_prompt import CODE_ANALYZER_PROMPT
from tools.t1_code_analyzer_tools import parse_python_file, get_function_source, analyze_complexity
from utils.logger import setup_logger

logger = setup_logger("CodeAnalyzerAgent")


def get_code_analyzer_agent():
    """Create and return the Code Analyzer agent."""
    logger.info("Creating CodeAnalyzerAgent with Vertex AI")
    
    llm = ChatVertexAI(model="gemini-2.5-pro", temperature=0)
    
    tools = [
        parse_python_file,
        get_function_source,
        analyze_complexity
    ]
    
    return create_agent(
        model=llm,
        tools=tools,
        system_prompt=CODE_ANALYZER_PROMPT
    )
