"""
CI/CD Pipeline State Definitions
Defines the state schema for the CI/CD testing workflow with Orchestrator.
"""
from typing import TypedDict, Optional


class CICDState(TypedDict):
    """
    Represents the state of the CI/CD pipeline.
    """
    run_id: str                 # Unique ID for this pipeline run
    repo_path: str              # Path to the repository
    base_ref: str               # Base git reference (e.g., main, HEAD~1)
    
    # Orchestrator Control
    last_agent_executed: str    # Last agent that ran
    orchestrator_decision: str  # Orchestrator's routing decision
    next_agent: str             # Next agent to run
    
    # Push Analysis Output
    changed_files: list[str]    # List of changed files
    git_diff: str               # Content of git diff content
    commit_info: str                # Commit message and metadata
    affected_modules: str           # Modules affected by changes
    push_analysis: str              # Complete push analysis summary
    
    # Code Analysis Output
    code_analysis: str              # Code structure analysis results
    test_recommendations: str       # Recommended test types
    
    # Test Generation Output
    generated_tests: str            # Generated test script content
    test_file_path: Optional[str]   # Path to written test file
    test_validation: str            # Test validation report
    test_coverage: str              # Test coverage analysis
    
    # Test Execution Output
    test_results: str               # Test execution results
    test_summary: str               # Parsed test summary
    
    # Previous Test Context
    previous_failures: str          # Historical failures for context
    test_history: str               # Recent test history
    
    # Final Decision
    deployment_decision: str        # DEPLOY or BLOCK
    decision_rationale: str         # Explanation of decision
    
    # Pipeline Summary
    pipeline_summary: str           # Full pipeline execution summary
