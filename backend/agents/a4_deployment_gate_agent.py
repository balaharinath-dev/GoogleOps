"""
Deployment Gate Agent (a4)
Makes final deployment decisions based on test results and risk assessment.
Can create Jira tickets for test failures when quality is good but tests fail.
"""
from langchain.agents import create_agent
from langchain_google_vertexai import ChatVertexAI
from prompts.p4_deployment_gate_prompt import DEPLOYMENT_GATE_PROMPT
from tools.t5_database_tools import get_module_history, get_recent_runs, get_run_details
from tools.t4_jira_tools import create_jira_story_with_tasks, store_jira_ticket_link
from utils.logger import setup_logger

logger = setup_logger("DeploymentGateAgent")


def get_deployment_gate_agent():
    """Create and return the Deployment Gate agent with Jira integration."""
    logger.info("Creating DeploymentGateAgent with Vertex AI and Jira tools")
    
    llm = ChatVertexAI(model="gemini-2.5-pro", temperature=0)
    
    tools = [
        get_module_history,
        get_recent_runs,
        get_run_details,
        create_jira_story_with_tasks,
        store_jira_ticket_link
    ]
    
    return create_agent(
        model=llm,
        tools=tools,
        system_prompt=DEPLOYMENT_GATE_PROMPT
    )
