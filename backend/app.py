#!/usr/bin/env python3
"""
CI/CD Testing Pipeline Entry Point
Run this script to execute the full CI/CD testing workflow.
"""
import argparse
import sys
import os

import warnings
try:
    from langchain_core._api.deprecation import LangChainDeprecationWarning
    warnings.simplefilter("ignore", LangChainDeprecationWarning)
except ImportError:
    pass

warnings.simplefilter("ignore", UserWarning)

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
from graph.graph import create_cicd_graph
from utils.logger import setup_logger
from tools.t5_database_tools import create_pipeline_run
import re

load_dotenv()

logger = setup_logger("CICD")

def main():
    parser = argparse.ArgumentParser(description="Run CI/CD Testing Pipeline")
    parser.add_argument(
        "--repo-path",
        default="../codebase",
        help="Path to the repository to test (default: ../codebase)"
    )
    parser.add_argument(
        "--base-ref",
        default="HEAD~1",
        help="Git reference for comparison (default: HEAD~1)"
    )
    args = parser.parse_args()
    
    repo_path = os.path.abspath(args.repo_path)
    
    from rich.console import Console
    from rich.panel import Panel
    console_main = Console()
    
    console_main.print("\n")
    console_main.print(Panel.fit(
        "[bold cyan]🚀 CI/CD Testing Pipeline[/bold cyan]\n\n"
        f"📁 Repository: {repo_path}\n"
        f"🔄 Comparing against: {args.base_ref}",
        border_style="cyan"
    ))
    console_main.print("\n")
    
    try:
        # Create the pipeline
        pipeline = create_cicd_graph()
        
        # Initialize state
        import uuid
        import subprocess
        run_id = str(uuid.uuid4())
        logger.info(f"Starting Pipeline Run: {run_id}")
        
        # Extract commit info for database
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
                    commit_author = lines[2]  # Now includes email: "Name <email@example.com>"
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
            "base_ref": args.base_ref,
            "repo_path": repo_path
        })
        
        initial_state = {
            "run_id": run_id,
            "repo_path": repo_path,
            "base_ref": args.base_ref,
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
        
        # Run the pipeline
        console_main.print("⏳ Starting pipeline execution...\n", style="dim")
        final_state = pipeline.invoke(initial_state)
    
        console_main.print("\n")
        console_main.print("✅ Pipeline execution completed!\n", style="bold green")
        # The callback handlers in graph.py will handle streaming output.
        # Here we just print the final summary.
        
        if "pipeline_summary" in final_state:
            from rich.console import Console
            from rich.markdown import Markdown
            console = Console()
            console.print(Markdown(final_state["pipeline_summary"]))
        else:
            logger.info("Pipeline finished (no summary generated)")
        
        # Return exit code based on decision
        if final_state.get("deployment_decision") == "DEPLOY":
            console_main.print(Panel.fit(
                "[bold green]✅ APPROVED FOR DEPLOYMENT[/bold green]\n\n"
                "All tests passed! Your code is ready to deploy.",
                border_style="green"
            ))
            return 0
        else:
            console_main.print(Panel.fit(
                "[bold red]🚫 DEPLOYMENT BLOCKED[/bold red]\n\n"
                "Tests failed or issues detected. Please review and fix.",
                border_style="red"
            ))
            return 1
            
    except Exception as e:
        logger.error(f"Pipeline error: {e}", exc_info=True)
        console_main.print(Panel.fit(
            f"[bold red]❌ PIPELINE ERROR[/bold red]\n\n"
            f"Something went wrong: {str(e)[:200]}",
            border_style="red"
        ))
        return 2


if __name__ == "__main__":
    sys.exit(main())