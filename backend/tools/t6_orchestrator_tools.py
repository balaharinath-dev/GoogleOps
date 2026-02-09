"""
Orchestrator Tools for CI/CD Pipeline
Provides control flow tools for the orchestrator agent.
"""
from typing import Dict, Optional
from langchain.tools import tool


# Global state to track agent executions and retries
_pipeline_state = {
    "current_agent": None,
    "agent_outputs": {},
    "retry_counts": {},
    "max_retries": 2,
    "force_regenerate_count": 0,
    "max_regenerate": 3
}


@tool
def rerun_agent(agent_name: str, reason: str) -> str:
    """
    Request to rerun a specific agent.
    
    Args:
        agent_name: Name of the agent to rerun (Push Analyzer, Code Analyzer, etc.)
        reason: Explanation for why the agent needs to rerun.
    
    Returns:
        Status message indicating if rerun is allowed.
    """
    global _pipeline_state
    
    # Check retry count
    current_retries = _pipeline_state["retry_counts"].get(agent_name, 0)
    max_retries = _pipeline_state["max_retries"]
    
    if current_retries >= max_retries:
        return f"""RERUN DENIED: {agent_name}
Reason: Maximum retries ({max_retries}) reached.
Current retries: {current_retries}
Recommendation: Proceed with warning or abort pipeline."""
    
    # Increment retry count
    _pipeline_state["retry_counts"][agent_name] = current_retries + 1
    
    return f"""RERUN APPROVED: {agent_name}
Reason: {reason}
Retry: {current_retries + 1}/{max_retries}
Action: Agent will be executed again with same inputs."""


@tool
def check_agent_status(agent_name: str) -> str:
    """
    Check the status and output of a specific agent.
    
    Args:
        agent_name: Name of the agent to check.
    
    Returns:
        Status summary including success/failure and output preview.
    """
    global _pipeline_state
    
    if agent_name not in _pipeline_state["agent_outputs"]:
        return f"Agent '{agent_name}' has not been executed yet."
    
    output = _pipeline_state["agent_outputs"][agent_name]
    retry_count = _pipeline_state["retry_counts"].get(agent_name, 0)
    
    # Determine status based on output content
    status = "SUCCESS"
    if "error" in output.lower() or "failed" in output.lower():
        status = "FAILED"
    elif "invalid" in output.lower() or "placeholder" in output.lower():
        status = "INVALID"
    
    return f"""Agent Status: {agent_name}
Status: {status}
Retries: {retry_count}/{_pipeline_state['max_retries']}
Output Preview: {output[:300]}...
"""


@tool
def get_pipeline_state() -> str:
    """
    Get the current state of the entire pipeline.
    
    Returns:
        Complete pipeline state including all agent outputs and retry counts.
    """
    global _pipeline_state
    
    report = "PIPELINE STATE REPORT\n" + "="*50 + "\n\n"
    report += f"Current Agent: {_pipeline_state.get('current_agent', 'None')}\n\n"
    
    report += "Agent Execution Status:\n"
    for agent, output in _pipeline_state["agent_outputs"].items():
        retries = _pipeline_state["retry_counts"].get(agent, 0)
        status = "✓" if "success" in output.lower() else "✗"
        report += f"  {status} {agent} (Retries: {retries})\n"
    
    report += f"\nTest Regeneration Count: {_pipeline_state['force_regenerate_count']}/{_pipeline_state['max_regenerate']}\n"
    
    return report


@tool
def force_regenerate_tests(reason: str) -> str:
    """
    Force the Test Generator to regenerate tests.
    
    Args:
        reason: Explanation for why tests need regeneration.
    
    Returns:
        Status message indicating if regeneration is allowed.
    """
    global _pipeline_state
    
    current_count = _pipeline_state["force_regenerate_count"]
    max_count = _pipeline_state["max_regenerate"]
    
    if current_count >= max_count:
        return f"""REGENERATE DENIED
Reason: Maximum regeneration attempts ({max_count}) reached.
Current attempts: {current_count}
Recommendation: Abort pipeline or proceed with existing tests."""
    
    _pipeline_state["force_regenerate_count"] = current_count + 1
    
    return f"""REGENERATE APPROVED
Reason: {reason}
Attempt: {current_count + 1}/{max_count}
Action: Test Generator will create new tests with stricter requirements."""


@tool
def skip_to_agent(agent_name: str, reason: str) -> str:
    """
    Skip to a specific agent in the pipeline.
    
    Args:
        agent_name: Name of the agent to skip to.
        reason: Explanation for why we're skipping.
    
    Returns:
        Status message confirming the skip.
    """
    global _pipeline_state
    
    valid_agents = [
        "Push Analyzer",
        "Code Analyzer",
        "Test Generator",
        "Test Runner",
        "Deployment Gate"
    ]
    
    if agent_name not in valid_agents:
        return f"SKIP DENIED: Invalid agent name '{agent_name}'. Valid agents: {', '.join(valid_agents)}"
    
    _pipeline_state["current_agent"] = agent_name
    
    return f"""SKIP APPROVED
Target: {agent_name}
Reason: {reason}
Action: Pipeline will jump to {agent_name} and continue from there."""


def update_pipeline_state(agent_name: str, output: str):
    """
    Update the pipeline state with agent output.
    Called internally by the graph after each agent execution.
    
    Args:
        agent_name: Name of the agent that just executed.
        output: Output from the agent.
    """
    global _pipeline_state
    _pipeline_state["current_agent"] = agent_name
    _pipeline_state["agent_outputs"][agent_name] = output


def reset_pipeline_state():
    """Reset the pipeline state for a new run."""
    global _pipeline_state
    _pipeline_state = {
        "current_agent": None,
        "agent_outputs": {},
        "retry_counts": {},
        "max_retries": 2,
        "force_regenerate_count": 0,
        "max_regenerate": 3
    }


def get_retry_count(agent_name: str) -> int:
    """Get the current retry count for an agent."""
    return _pipeline_state["retry_counts"].get(agent_name, 0)


def should_retry(agent_name: str) -> bool:
    """Check if an agent can be retried."""
    return get_retry_count(agent_name) < _pipeline_state["max_retries"]
