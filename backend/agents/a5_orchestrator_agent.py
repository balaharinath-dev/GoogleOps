"""
Orchestrator Agent (a5)
Simple router that directs traffic between agents.
Does NOT generate anything - just evaluates and routes.
"""
from langchain_google_vertexai import ChatVertexAI
from langchain_core.prompts import ChatPromptTemplate
from prompts.p5_orchestrator_prompt import ORCHESTRATOR_PROMPT
from utils.logger import setup_logger

logger = setup_logger("OrchestratorAgent")


def get_orchestrator_agent():
    """Create and return the Orchestrator agent as a simple chain."""
    logger.info("Creating OrchestratorAgent (Router) with Vertex AI")
    
    llm = ChatVertexAI(model="gemini-2.5-pro", temperature=0)
    
    # Simple chain - no tools needed, just routing logic
    prompt = ChatPromptTemplate.from_messages([
        ("system", ORCHESTRATOR_PROMPT),
        ("placeholder", "{messages}")
    ])
    
    chain = prompt | llm
    return chain
