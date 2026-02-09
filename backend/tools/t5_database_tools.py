"""
Database Tools for CI/CD Pipeline
SQLite-based storage for pipeline runs, test results, and history.
"""
import sqlite3
import json
import os
from datetime import datetime
from typing import Optional, Dict, List, Any
from contextlib import contextmanager
from langchain.tools import tool

# Database path
DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "test_knowledge_base")
DB_PATH = os.path.join(DB_DIR, "cicd_pipeline.db")


def _ensure_db_dir():
    """Ensure database directory exists."""
    os.makedirs(DB_DIR, exist_ok=True)


@contextmanager
def get_db_connection():
    """Context manager for database connections."""
    _ensure_db_dir()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_database():
    """Initialize database schema."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Pipeline Runs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_runs (
                run_id TEXT PRIMARY KEY,
                commit_hash TEXT,
                commit_message TEXT,
                commit_author TEXT,
                commit_date TEXT,
                base_ref TEXT,
                repo_path TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT,
                decision TEXT,
                decision_rationale TEXT,
                pipeline_summary TEXT,
                jira_story_key TEXT,
                jira_story_url TEXT,
                jira_task_keys TEXT
            )
        """)
        
        # Agent States table (stores each agent's output)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_states (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                agent_order INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                input_prompt TEXT,
                output_result TEXT,
                status TEXT,
                FOREIGN KEY (run_id) REFERENCES pipeline_runs(run_id)
            )
        """)
        
        # Changed Files table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS changed_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                change_type TEXT,
                lines_added INTEGER,
                lines_removed INTEGER,
                FOREIGN KEY (run_id) REFERENCES pipeline_runs(run_id)
            )
        """)
        
        # Test Results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS test_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                test_file_path TEXT,
                test_name TEXT NOT NULL,
                test_module TEXT,
                status TEXT NOT NULL,
                duration_ms INTEGER,
                error_message TEXT,
                error_traceback TEXT,
                executed_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES pipeline_runs(run_id)
            )
        """)
        
        # Module Statistics table (aggregated stats per module)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS module_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module_name TEXT NOT NULL,
                run_id TEXT NOT NULL,
                total_tests INTEGER,
                passed_tests INTEGER,
                failed_tests INTEGER,
                pass_rate REAL,
                executed_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES pipeline_runs(run_id)
            )
        """)
        
        # Tool Calls table (tracks all tool invocations)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tool_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                tool_input TEXT,
                tool_output TEXT,
                status TEXT,
                executed_at TEXT NOT NULL,
                duration_ms INTEGER,
                FOREIGN KEY (run_id) REFERENCES pipeline_runs(run_id)
            )
        """)
        
        # Create indexes for better query performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_runs_commit ON pipeline_runs(commit_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_runs_status ON pipeline_runs(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_runs_started ON pipeline_runs(started_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_agent_states_run ON agent_states(run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_test_results_run ON test_results(run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_test_results_module ON test_results(test_module)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_module_stats_module ON module_stats(module_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_calls_run ON tool_calls(run_id)")


# =============================================================================
# Pipeline Run Management
# =============================================================================

@tool
def create_pipeline_run(
    run_id: str,
    commit_hash: Optional[str] = None,
    commit_message: Optional[str] = None,
    commit_author: Optional[str] = None,
    commit_date: Optional[str] = None,
    base_ref: str = "HEAD~1",
    repo_path: str = "."
) -> str:
    """
    Create a new pipeline run record.
    
    Args:
        run_id: Unique run identifier
        commit_hash: Git commit hash
        commit_message: Commit message
        commit_author: Commit author
        commit_date: Commit date
        base_ref: Base git reference
        repo_path: Repository path
    
    Returns:
        Confirmation message
    """
    init_database()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO pipeline_runs (
                run_id, commit_hash, commit_message, commit_author, commit_date,
                base_ref, repo_path, started_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id, commit_hash, commit_message, commit_author, commit_date,
            base_ref, repo_path, datetime.now().isoformat(), "RUNNING"
        ))
    
    return f"Pipeline run {run_id[:8]} created"


@tool
def update_pipeline_run(
    run_id: str,
    status: Optional[str] = None,
    decision: Optional[str] = None,
    decision_rationale: Optional[str] = None,
    pipeline_summary: Optional[str] = None
) -> str:
    """
    Update pipeline run with final results.
    
    Args:
        run_id: Run identifier
        status: Pipeline status (COMPLETED/FAILED)
        decision: Deployment decision (DEPLOY/BLOCK)
        decision_rationale: Explanation of decision
        pipeline_summary: Full pipeline summary
    
    Returns:
        Confirmation message
    """
    init_database()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        updates = []
        params = []
        
        if status:
            updates.append("status = ?")
            params.append(status)
        if decision:
            updates.append("decision = ?")
            params.append(decision)
        if decision_rationale:
            updates.append("decision_rationale = ?")
            params.append(decision_rationale)
        if pipeline_summary:
            updates.append("pipeline_summary = ?")
            params.append(pipeline_summary)
        
        updates.append("completed_at = ?")
        params.append(datetime.now().isoformat())
        
        params.append(run_id)
        
        cursor.execute(f"""
            UPDATE pipeline_runs 
            SET {', '.join(updates)}
            WHERE run_id = ?
        """, params)
    
    return f"Pipeline run {run_id[:8]} updated"


# =============================================================================
# Agent State Management
# =============================================================================

@tool
def log_agent_state(
    run_id: str,
    agent_name: str,
    agent_order: int,
    input_prompt: str,
    output_result: str,
    status: str = "COMPLETED"
) -> str:
    """
    Log an agent's execution state.
    
    Args:
        run_id: Run identifier
        agent_name: Name of the agent
        agent_order: Order in pipeline (0-4)
        input_prompt: Input prompt given to agent
        output_result: Agent's output
        status: Execution status
    
    Returns:
        Confirmation message
    """
    init_database()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO agent_states (
                run_id, agent_name, agent_order, started_at, completed_at,
                input_prompt, output_result, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id, agent_name, agent_order, datetime.now().isoformat(),
            datetime.now().isoformat(), input_prompt, output_result, status
        ))
    
    return f"Agent {agent_name} state logged"


# =============================================================================
# Changed Files Management
# =============================================================================

@tool
def log_changed_files(
    run_id: str,
    files: List[Dict[str, Any]]
) -> str:
    """
    Log changed files for a run.
    
    Args:
        run_id: Run identifier
        files: List of dicts with file_path, change_type, lines_added, lines_removed
    
    Returns:
        Confirmation message
    """
    init_database()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        for file_info in files:
            cursor.execute("""
                INSERT INTO changed_files (
                    run_id, file_path, change_type, lines_added, lines_removed
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                run_id,
                file_info.get('file_path'),
                file_info.get('change_type'),
                file_info.get('lines_added', 0),
                file_info.get('lines_removed', 0)
            ))
    
    return f"Logged {len(files)} changed files"


# =============================================================================
# Test Results Management
# =============================================================================

@tool
def store_test_result(
    run_id: str,
    test_name: str,
    status: str,
    test_module: Optional[str] = None,
    test_file_path: Optional[str] = None,
    duration_ms: Optional[int] = None,
    error_message: Optional[str] = None,
    error_traceback: Optional[str] = None
) -> str:
    """
    Store a test result in the database.
    
    Args:
        run_id: Run identifier
        test_name: Name of the test
        status: PASSED, FAILED, or ERROR
        test_module: Module being tested
        test_file_path: Path to test file
        duration_ms: Test duration in milliseconds
        error_message: Error message if failed
        error_traceback: Full error traceback
    
    Returns:
        Confirmation message
    """
    init_database()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO test_results (
                run_id, test_file_path, test_name, test_module, status,
                duration_ms, error_message, error_traceback, executed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id, test_file_path, test_name, test_module, status,
            duration_ms, error_message, error_traceback, datetime.now().isoformat()
        ))
    
    return f"Test result stored: {test_name} = {status}"


@tool
def store_module_stats(
    run_id: str,
    module_name: str,
    total_tests: int,
    passed_tests: int,
    failed_tests: int
) -> str:
    """
    Store aggregated module statistics.
    
    Args:
        run_id: Run identifier
        module_name: Module name
        total_tests: Total number of tests
        passed_tests: Number of passed tests
        failed_tests: Number of failed tests
    
    Returns:
        Confirmation message
    """
    init_database()
    
    pass_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO module_stats (
                module_name, run_id, total_tests, passed_tests, failed_tests,
                pass_rate, executed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            module_name, run_id, total_tests, passed_tests, failed_tests,
            pass_rate, datetime.now().isoformat()
        ))
    
    return f"Module stats stored: {module_name}"


# =============================================================================
# Tool Call Tracking
# =============================================================================

@tool
def log_tool_call(
    run_id: str,
    agent_name: str,
    tool_name: str,
    tool_input: str,
    tool_output: str,
    status: str = "SUCCESS",
    duration_ms: Optional[int] = None
) -> str:
    """
    Log a tool invocation.
    
    Args:
        run_id: Run identifier
        agent_name: Name of the agent calling the tool
        tool_name: Name of the tool
        tool_input: Tool input parameters
        tool_output: Tool output
        status: SUCCESS or ERROR
        duration_ms: Execution duration
    
    Returns:
        Confirmation message
    """
    init_database()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO tool_calls (
                run_id, agent_name, tool_name, tool_input, tool_output,
                status, executed_at, duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id, agent_name, tool_name, tool_input, tool_output,
            status, datetime.now().isoformat(), duration_ms
        ))
    
    return f"Tool call logged: {tool_name}"


# =============================================================================
# Query Tools
# =============================================================================

@tool
def get_run_details(run_id: str) -> str:
    """
    Get complete details for a pipeline run.
    
    Args:
        run_id: Run identifier
    
    Returns:
        Formatted run details
    """
    init_database()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Get run info
        cursor.execute("SELECT * FROM pipeline_runs WHERE run_id = ?", (run_id,))
        run = cursor.fetchone()
        
        if not run:
            return f"Run {run_id} not found"
        
        # Get agent states
        cursor.execute("""
            SELECT agent_name, status, completed_at 
            FROM agent_states 
            WHERE run_id = ? 
            ORDER BY agent_order
        """, (run_id,))
        agents = cursor.fetchall()
        
        # Get test results
        cursor.execute("""
            SELECT status, COUNT(*) as count 
            FROM test_results 
            WHERE run_id = ? 
            GROUP BY status
        """, (run_id,))
        test_stats = {row['status']: row['count'] for row in cursor.fetchall()}
        
        result = [
            f"Pipeline Run: {run_id[:8]}",
            f"Commit: {run['commit_hash'][:8] if run['commit_hash'] else 'N/A'}",
            f"Status: {run['status']}",
            f"Decision: {run['decision'] or 'PENDING'}",
            f"Started: {run['started_at'][:19]}",
            f"Completed: {run['completed_at'][:19] if run['completed_at'] else 'RUNNING'}",
            "",
            "Agents:",
        ]
        
        for agent in agents:
            result.append(f"  ✓ {agent['agent_name']} - {agent['status']}")
        
        result.append("")
        result.append("Test Results:")
        for status, count in test_stats.items():
            icon = "✓" if status == "PASSED" else "✗"
            result.append(f"  {icon} {status}: {count}")
        
        return "\n".join(result)


@tool
def update_pipeline_run_jira(
    run_id: str,
    jira_story_key: str,
    jira_story_url: str,
    jira_task_keys: Optional[str] = None
) -> str:
    """
    Update pipeline run with Jira ticket information.
    
    Args:
        run_id: Pipeline run ID
        jira_story_key: Jira story key (e.g., "CICD-123")
        jira_story_url: Full URL to the Jira story
        jira_task_keys: Comma-separated list of task keys (optional)
    
    Returns:
        Confirmation message
    """
    init_database()
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE pipeline_runs
                SET jira_story_key = ?,
                    jira_story_url = ?,
                    jira_task_keys = ?
                WHERE run_id = ?
            """, (jira_story_key, jira_story_url, jira_task_keys, run_id))
            
            if cursor.rowcount == 0:
                return f"Warning: No pipeline run found with ID {run_id}"
            
            return f"✓ Jira ticket {jira_story_key} linked to pipeline run {run_id}"
    
    except sqlite3.Error as e:
        return f"Error updating Jira information: {str(e)}"


@tool
def get_module_history(module_name: str, limit: int = 10) -> str:
    """
    Get test history for a specific module.
    
    Args:
        module_name: Module name
        limit: Number of recent runs to return
    
    Returns:
        Module test history with pass rate trends
    """
    init_database()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                ms.run_id,
                ms.pass_rate,
                ms.total_tests,
                ms.passed_tests,
                ms.failed_tests,
                ms.executed_at,
                pr.commit_hash,
                pr.decision
            FROM module_stats ms
            JOIN pipeline_runs pr ON ms.run_id = pr.run_id
            WHERE ms.module_name = ?
            ORDER BY ms.executed_at DESC
            LIMIT ?
        """, (module_name, limit))
        
        rows = cursor.fetchall()
        
        if not rows:
            return f"No history for module: {module_name}"
        
        result = [f"Module History: {module_name} (last {len(rows)} runs)"]
        result.append("")
        
        for row in rows:
            decision_icon = "🚀" if row['decision'] == "DEPLOY" else "🚫" if row['decision'] == "BLOCK" else "⏳"
            result.append(
                f"  {decision_icon} Run {row['run_id'][:8]} - "
                f"{row['pass_rate']:.0f}% pass rate "
                f"({row['passed_tests']}/{row['total_tests']} passed) "
                f"[{row['executed_at'][:19]}]"
            )
        
        return "\n".join(result)


@tool
def get_recent_runs(limit: int = 10) -> str:
    """
    Get recent pipeline runs.
    
    Args:
        limit: Number of runs to return
    
    Returns:
        List of recent runs with status
    """
    init_database()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                run_id,
                commit_hash,
                commit_message,
                status,
                decision,
                started_at,
                completed_at
            FROM pipeline_runs
            ORDER BY started_at DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        
        if not rows:
            return "No pipeline runs found"
        
        result = [f"Recent Pipeline Runs (last {len(rows)}):"]
        result.append("")
        
        for row in rows:
            decision_icon = "🚀" if row['decision'] == "DEPLOY" else "🚫" if row['decision'] == "BLOCK" else "⏳"
            commit_short = row['commit_hash'][:8] if row['commit_hash'] else "N/A"
            msg_short = (row['commit_message'][:40] + "...") if row['commit_message'] and len(row['commit_message']) > 40 else (row['commit_message'] or "")
            
            result.append(
                f"  {decision_icon} {row['run_id'][:8]} - "
                f"Commit {commit_short} - "
                f"{row['status']} - "
                f"{msg_short} "
                f"[{row['started_at'][:19]}]"
            )
        
        return "\n".join(result)


@tool
def get_commit_runs(commit_hash: str) -> str:
    """
    Get all pipeline runs for a specific commit.
    
    Args:
        commit_hash: Git commit hash (full or short)
    
    Returns:
        List of runs for the commit
    """
    init_database()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                run_id,
                status,
                decision,
                started_at,
                completed_at
            FROM pipeline_runs
            WHERE commit_hash LIKE ?
            ORDER BY started_at DESC
        """, (f"{commit_hash}%",))
        
        rows = cursor.fetchall()
        
        if not rows:
            return f"No runs found for commit: {commit_hash}"
        
        result = [f"Pipeline Runs for Commit {commit_hash[:8]}:"]
        result.append("")
        
        for row in rows:
            decision_icon = "🚀" if row['decision'] == "DEPLOY" else "🚫" if row['decision'] == "BLOCK" else "⏳"
            duration = "RUNNING"
            if row['completed_at']:
                start = datetime.fromisoformat(row['started_at'])
                end = datetime.fromisoformat(row['completed_at'])
                duration = f"{(end - start).total_seconds():.1f}s"
            
            result.append(
                f"  {decision_icon} {row['run_id'][:8]} - "
                f"{row['status']} - "
                f"Duration: {duration} "
                f"[{row['started_at'][:19]}]"
            )
        
        return "\n".join(result)


# Initialize database on module import
init_database()
