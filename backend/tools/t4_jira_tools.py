"""
Jira Integration Tools for CI/CD Pipeline
Automatically creates Jira tickets when tests fail.
"""
import os
import json
import requests
from requests.auth import HTTPBasicAuth
from langchain.tools import tool
from typing import Optional


def _get_jira_account_id_from_email(email: str, jira_url: str, auth: HTTPBasicAuth) -> Optional[str]:
    """
    Get Jira account ID from email address.
    
    Args:
        email: Email address to search for
        jira_url: Jira instance URL
        auth: HTTPBasicAuth object
    
    Returns:
        Account ID if found, None otherwise
    """
    try:
        headers = {"Accept": "application/json"}
        
        # Search for user by email
        response = requests.get(
            f"{jira_url}/rest/api/3/user/search",
            params={"query": email},
            headers=headers,
            auth=auth,
            timeout=10
        )
        
        if response.status_code == 200:
            users = response.json()
            if users and len(users) > 0:
                # Return the first matching user's account ID
                return users[0].get('accountId')
        
        return None
    except Exception:
        return None


@tool
def create_jira_story_with_tasks(
    project_key: str,
    summary: str,
    description_text: str,
    assignee_account_id: Optional[str] = None,
    assignee_email: Optional[str] = None,
    tasks: Optional[list] = None,
) -> str:
    """
    Create a Jira Story with optional child tasks for test failures.
    
    Args:
        project_key: Jira project key (e.g., "CICD")
        summary: Story title
        description_text: Story description (plain text)
        assignee_account_id: accountId of user to assign (optional)
        assignee_email: Email address to find and assign user (optional, used if account_id not provided)
        tasks: list of task summaries to create under the story (optional)
    
    Returns:
        JSON string with story_key and created task keys
    """
    JIRA_URL = os.getenv("JIRA_URL")
    EMAIL = os.getenv("JIRA_EMAIL")
    TOKEN = os.getenv("JIRA_TOKEN")
    
    if not all([JIRA_URL, EMAIL, TOKEN]):
        return json.dumps({
            "error": "Jira credentials not configured. Set JIRA_URL, JIRA_EMAIL, and JIRA_TOKEN in .env"
        })
    
    auth = HTTPBasicAuth(EMAIL, TOKEN)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    
    # If assignee_email provided but not account_id, look up the account_id
    if assignee_email and not assignee_account_id:
        assignee_account_id = _get_jira_account_id_from_email(assignee_email, JIRA_URL, auth)
    
    # Jira description format (ADF - Atlassian Document Format)
    description = {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": description_text}
                ],
            }
        ],
    }
    
    # Create Story
    story_payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Story"},
        }
    }
    
    if assignee_account_id:
        story_payload["fields"]["assignee"] = {"accountId": assignee_account_id}
    
    try:
        response = requests.post(
            f"{JIRA_URL}/rest/api/3/issue",
            headers=headers,
            auth=auth,
            data=json.dumps(story_payload),
            timeout=30
        )
        response.raise_for_status()
        story_data = response.json()
        story_key = story_data["key"]
        story_url = f"{JIRA_URL}/browse/{story_key}"
        
    except requests.exceptions.RequestException as e:
        return json.dumps({
            "error": f"Failed to create Jira story: {str(e)}",
            "status_code": getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
        })
    
    # Create Tasks
    created_tasks = []
    if tasks:
        for task_summary in tasks:
            task_payload = {
                "fields": {
                    "project": {"key": project_key},
                    "summary": task_summary,
                    "issuetype": {"name": "Task"},
                    "parent": {"key": story_key},
                }
            }
            
            try:
                r = requests.post(
                    f"{JIRA_URL}/rest/api/3/issue",
                    headers=headers,
                    auth=auth,
                    data=json.dumps(task_payload),
                    timeout=30
                )
                r.raise_for_status()
                task_data = r.json()
                task_key = task_data["key"]
                created_tasks.append({
                    "key": task_key,
                    "url": f"{JIRA_URL}/browse/{task_key}"
                })
            except requests.exceptions.RequestException as e:
                created_tasks.append({
                    "error": f"Failed to create task '{task_summary}': {str(e)}"
                })
    
    return json.dumps({
        "story_key": story_key,
        "story_url": story_url,
        "tasks": created_tasks,
        "success": True
    }, indent=2)


@tool
def store_jira_ticket_link(
    run_id: str,
    jira_story_key: str,
    jira_story_url: str,
    jira_task_keys: Optional[str] = None
) -> str:
    """
    Store Jira ticket information in the database for a pipeline run.
    
    Args:
        run_id: Pipeline run ID
        jira_story_key: Jira story key (e.g., "CICD-123")
        jira_story_url: Full URL to the Jira story
        jira_task_keys: Comma-separated list of task keys (optional)
    
    Returns:
        Confirmation message
    """
    from tools.t5_database_tools import update_pipeline_run_jira
    
    result = update_pipeline_run_jira.invoke({
        "run_id": run_id,
        "jira_story_key": jira_story_key,
        "jira_story_url": jira_story_url,
        "jira_task_keys": jira_task_keys
    })
    
    return result
