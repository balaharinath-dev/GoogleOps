#!/usr/bin/env python3
"""
FastAPI Server for CI/CD Pipeline with Streaming
"""
import os
import sys
import json
import asyncio
from typing import AsyncGenerator
from datetime import datetime

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import subprocess
import uuid

import warnings
try:
    from langchain_core._api.deprecation import LangChainDeprecationWarning
    warnings.simplefilter("ignore", LangChainDeprecationWarning)
except ImportError:
    pass
warnings.simplefilter("ignore", UserWarning)

from dotenv import load_dotenv
from graph.graph import create_cicd_graph
from tools.t5_database_tools import create_pipeline_run, get_recent_runs, get_run_details, update_pipeline_run
from utils.logger import setup_logger

load_dotenv()
logger = setup_logger("API")

app = FastAPI(title="CI/CD Pipeline API", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RunRequest(BaseModel):
    repo_path: str = "../codebase"
    base_ref: str = "HEAD~1"


class StreamEvent(BaseModel):
    type: str  # agent_start, agent_end, tool_start, tool_end, thought, final_report
    data: dict


@app.get("/")
async def root():
    return {"message": "CI/CD Pipeline API", "version": "1.0.0"}


@app.get("/codebase/status")
async def get_codebase_status():
    """Get current codebase git status and commit info."""
    repo_path = os.path.abspath("../codebase")
    
    try:
        # Get current commit
        commit_result = subprocess.run(
            ["git", "log", "-1", "--format=%H%n%s%n%an <%ae>%n%aI"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        commit_info = {}
        if commit_result.returncode == 0:
            lines = commit_result.stdout.strip().split('\n')
            if len(lines) >= 4:
                commit_info = {
                    "hash": lines[0],
                    "hash_short": lines[0][:8],
                    "message": lines[1],
                    "author": lines[2],
                    "date": lines[3]
                }
        
        # Get git status
        status_result = subprocess.run(
            ["git", "status", "--short"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        status = status_result.stdout.strip() if status_result.returncode == 0 else ""
        
        # Get branch
        branch_result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        branch = branch_result.stdout.strip() if branch_result.returncode == 0 else "unknown"
        
        return {
            "repo_path": repo_path,
            "branch": branch,
            "commit": commit_info,
            "status": status,
            "has_changes": bool(status)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/history")
async def get_history(limit: int = 10):
    """Get recent pipeline runs."""
    try:
        # Query database directly for structured data
        import sqlite3
        from tools.t5_database_tools import DB_PATH
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
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
            WHERE decision IS NOT NULL AND decision != ''
            ORDER BY started_at DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        runs = []
        for row in rows:
            runs.append({
                "run_id": row['run_id'],
                "commit_hash": row['commit_hash'],
                "commit_message": row['commit_message'] or "No message",
                "status": row['status'],
                "decision": row['decision'],
                "started_at": row['started_at'],
                "completed_at": row['completed_at']
            })
        
        return {"runs": runs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/run/{run_id}")
async def get_run(run_id: str):
    """Get comprehensive details of a specific run."""
    try:
        import sqlite3
        from tools.t5_database_tools import DB_PATH, DB_DIR
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get run info
        cursor.execute("SELECT * FROM pipeline_runs WHERE run_id = ?", (run_id,))
        run = cursor.fetchone()
        
        if not run:
            conn.close()
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        
        # Get agent states
        cursor.execute("""
            SELECT agent_name, status, input_prompt, output_result, started_at, completed_at
            FROM agent_states 
            WHERE run_id = ? 
            ORDER BY agent_order
        """, (run_id,))
        agents = [dict(row) for row in cursor.fetchall()]
        
        # Get the final graph state from pipeline_summary or construct it
        final_graph_state = {
            "run_id": run['run_id'],
            "repo_path": run['repo_path'],
            "base_ref": run['base_ref'],
            "status": run['status'],
            "decision": run['decision'],
            "pipeline_summary": run['pipeline_summary'],
            "deployment_decision": run['decision'],
            "commit_info": f"Commit: {run['commit_hash'][:8] if run['commit_hash'] else 'N/A'}\nMessage: {run['commit_message'] or 'N/A'}\nAuthor: {run['commit_author'] or 'N/A'}",
        }
        
        # Get test results
        cursor.execute("""
            SELECT test_name, test_module, status, duration_ms, error_message
            FROM test_results 
            WHERE run_id = ?
            ORDER BY test_module, test_name
        """, (run_id,))
        tests = [dict(row) for row in cursor.fetchall()]
        
        # Get test statistics
        cursor.execute("""
            SELECT status, COUNT(*) as count 
            FROM test_results 
            WHERE run_id = ? 
            GROUP BY status
        """, (run_id,))
        test_stats = {row['status']: row['count'] for row in cursor.fetchall()}
        
        # Get changed files
        cursor.execute("""
            SELECT file_path, change_type, lines_added, lines_removed
            FROM changed_files 
            WHERE run_id = ?
        """, (run_id,))
        changed_files = [dict(row) for row in cursor.fetchall()]
        
        # Get module stats
        cursor.execute("""
            SELECT module_name, total_tests, passed_tests, failed_tests, pass_rate
            FROM module_stats 
            WHERE run_id = ?
        """, (run_id,))
        module_stats = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        # Read test scripts from run directory
        test_scripts = {}
        run_test_dir = os.path.join(DB_DIR, "runs", run_id, "tests")
        if os.path.exists(run_test_dir):
            for filename in os.listdir(run_test_dir):
                if filename.endswith('.py'):
                    file_path = os.path.join(run_test_dir, filename)
                    try:
                        with open(file_path, 'r') as f:
                            test_scripts[filename] = f.read()
                    except Exception as e:
                        logger.warning(f"Could not read test script {filename}: {e}")
        
        # Build comprehensive response
        return {
            "run": {
                "run_id": run['run_id'],
                "commit_hash": run['commit_hash'],
                "commit_message": run['commit_message'],
                "commit_author": run['commit_author'],
                "commit_date": run['commit_date'],
                "status": run['status'],
                "decision": run['decision'],
                "decision_rationale": run['decision_rationale'],
                "pipeline_summary": run['pipeline_summary'],
                "started_at": run['started_at'],
                "completed_at": run['completed_at'],
                "jira_story_key": run['jira_story_key'],
                "jira_story_url": run['jira_story_url']
            },
            "agents": agents,
            "tests": tests,
            "test_stats": test_stats,
            "changed_files": changed_files,
            "module_stats": module_stats,
            "test_scripts": test_scripts,
            "final_graph_state": final_graph_state
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/run/{run_id}")
async def delete_run(run_id: str):
    """Delete a pipeline run and all related data."""
    try:
        import sqlite3
        from tools.t5_database_tools import DB_PATH
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if run exists
        cursor.execute("SELECT run_id FROM pipeline_runs WHERE run_id = ?", (run_id,))
        if not cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        
        # Delete from all related tables
        cursor.execute("DELETE FROM tool_calls WHERE run_id = ?", (run_id,))
        cursor.execute("DELETE FROM test_results WHERE run_id = ?", (run_id,))
        cursor.execute("DELETE FROM module_stats WHERE run_id = ?", (run_id,))
        cursor.execute("DELETE FROM changed_files WHERE run_id = ?", (run_id,))
        cursor.execute("DELETE FROM agent_states WHERE run_id = ?", (run_id,))
        cursor.execute("DELETE FROM pipeline_runs WHERE run_id = ?", (run_id,))
        
        conn.commit()
        conn.close()
        
        return {"message": f"Run {run_id[:8]} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def stream_pipeline(repo_path: str, base_ref: str) -> AsyncGenerator[str, None]:
    """Stream pipeline execution events."""
    
    repo_path = os.path.abspath(repo_path)
    run_id = str(uuid.uuid4())
    
    # Send initial event
    yield f"data: {json.dumps({'type': 'start', 'data': {'run_id': run_id, 'repo_path': repo_path}})}\n\n"
    
    try:
        # Extract commit info
        commit_hash = None
        commit_message = None
        commit_author = None
        commit_date = None
        
        try:
            result = subprocess.run(
                ["git", "log", "-1", "--format=%H%n%s%n%an <%ae>%n%aI"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) >= 4:
                    commit_hash = lines[0]
                    commit_message = lines[1]
                    commit_author = lines[2]
                    commit_date = lines[3]
        except Exception as e:
            logger.warning(f"Could not extract commit info: {e}")
        
        # Create pipeline run in database
        create_pipeline_run.invoke({
            "run_id": run_id,
            "commit_hash": commit_hash,
            "commit_message": commit_message,
            "commit_author": commit_author,
            "commit_date": commit_date,
            "base_ref": base_ref,
            "repo_path": repo_path
        })
        
        # Create pipeline
        pipeline = create_cicd_graph()
        
        initial_state = {
            "run_id": run_id,
            "repo_path": repo_path,
            "base_ref": base_ref,
            "changed_files": [],
            "git_diff": "",
            "affected_modules": [],
            "push_analysis": "",
            "code_analysis": "",
            "previous_failures": [],
            "generated_tests": "",
            "test_results": {},
            "deployment_decision": "",
            "pipeline_summary": "",
            "commit_info": f"Commit: {commit_hash[:8] if commit_hash else 'N/A'}\nMessage: {commit_message or 'N/A'}\nAuthor: {commit_author or 'N/A'}\nDate: {commit_date or 'N/A'}"
        }
        
        # Stream pipeline execution
        final_state = None
        last_state = initial_state
        
        async for event in pipeline.astream(initial_state, stream_mode="updates"):
            # Handle different event types
            for node_name, node_data in event.items():
                # Skip __end__ node
                if node_name == "__end__":
                    continue
                
                # Store the latest state
                last_state = {**last_state, **node_data}
                
                # Determine event type
                if node_name == "orchestrator":
                    next_agent = node_data.get('next_agent', 'unknown')
                    yield f"data: {json.dumps({'type': 'orchestrator', 'data': {'decision': next_agent}})}\n\n"
                    
                    # If orchestrator says END, prepare to finish
                    if next_agent == "END":
                        logger.info("Orchestrator decided to END pipeline")
                
                elif node_name in ["push_analyzer", "code_analyzer", "test_generator", "test_runner", "deployment_gate"]:
                    # Agent completed
                    agent_name = node_name.replace("_", " ").title()
                    
                    yield f"data: {json.dumps({'type': 'agent_complete', 'data': {'agent': agent_name, 'node': node_name, 'output': node_data}})}\n\n"
            
            await asyncio.sleep(0.05)  # Small delay for UI
        
        # Use the last accumulated state for final report
        logger.info(f"Pipeline completed. Final state keys: {last_state.keys()}")
        
        # Send final report
        yield f"data: {json.dumps({'type': 'final_report', 'data': {'summary': last_state.get('pipeline_summary', ''), 'decision': last_state.get('deployment_decision', 'UNKNOWN'), 'test_file_path': last_state.get('test_file_path', '')}})}\n\n"
        
        # Update database with final state
        update_pipeline_run.invoke({
            "run_id": run_id,
            "status": "COMPLETED",
            "decision": last_state.get('deployment_decision', 'UNKNOWN'),
            "pipeline_summary": last_state.get('pipeline_summary', '')
        })
        
        yield f"data: {json.dumps({'type': 'complete', 'data': {'run_id': run_id}})}\n\n"
        
    except Exception as e:
        logger.error(f"Pipeline error: {e}", exc_info=True)
        yield f"data: {json.dumps({'type': 'error', 'data': {'message': str(e)}})}\n\n"


@app.post("/run")
async def run_pipeline(request: RunRequest):
    """Run the CI/CD pipeline with streaming."""
    return StreamingResponse(
        stream_pipeline(request.repo_path, request.base_ref),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
