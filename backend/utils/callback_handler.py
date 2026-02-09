"""
Rich Text Callback Handler
Visualizes LangChain agent and tool execution using the 'rich' library.
"""
from typing import Any, Dict, List, Optional
from uuid import UUID
from datetime import datetime
import time

from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_core.messages import BaseMessage
from langchain_core.outputs import LLMResult

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.style import Style

console = Console()

class RichAgentCallback(BaseCallbackHandler):
    """Callback Handler that prints clean, brief tool execution logs."""

    def __init__(self, agent_name: str = "Agent", run_id: Optional[str] = None):
        self.agent_name = agent_name
        self.run_id = run_id
        self.console = console
        self.tool_start_time = None
        self.current_tool = None
        
        # Color mapping for different event types
        self.styles = {
            "agent": Style(color="blue", bold=True),
            "tool": Style(color="cyan", bold=True),
            "tool_input": Style(color="yellow", dim=True),
            "tool_output": Style(color="green"),
            "success": Style(color="green", bold=True),
            "error": Style(color="red", bold=True)
        }

    def on_chain_start(
        self, serialized: Dict[str, Any], inputs: Dict[str, Any], **kwargs: Any
    ) -> None:
        """Print out that we are entering a chain."""
        pass

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        """Print out that we finished a chain."""
        pass

    def on_agent_action(self, action: Any, **kwargs: Any) -> Any:
        """Run on agent action - log tool call start."""
        self.current_tool = action.tool
        self.tool_start_time = time.time()
        tool_input = action.tool_input
        
        # Human-readable tool descriptions
        tool_descriptions = {
            "get_changed_files": "📂 Checking which files were modified",
            "get_git_diff": "🔍 Analyzing code changes",
            "get_commit_info": "📝 Reading commit details",
            "build_dependency_graph": "🔗 Mapping code dependencies",
            "get_affected_modules": "📦 Finding affected components",
            "get_module_history": "📊 Checking test history",
            "get_recent_runs": "⏱️  Reviewing recent pipeline runs",
            "parse_python_file": "🐍 Analyzing Python code structure",
            "analyze_complexity": "📈 Measuring code complexity",
            "run_pytest": "🧪 Running tests",
            "discover_tests": "🔎 Finding available tests",
            "store_test_result": "💾 Saving test results",
        }
        
        description = tool_descriptions.get(self.current_tool, f"🛠️  {self.current_tool}")
        self.console.print(f"\n{description}...", style="cyan")
        
        # Show key parameters only (simplified)
        if isinstance(tool_input, dict):
            important_keys = ['repo_path', 'test_path', 'module_name', 'file_path', 'base_ref']
            for key in important_keys:
                if key in tool_input and tool_input[key]:
                    value = str(tool_input[key])
                    if len(value) > 50:
                        value = value[:50] + "..."
                    self.console.print(f"  → {key.replace('_', ' ').title()}: {value}", style="dim")

    def on_tool_end(self, output: Any, **kwargs: Any) -> Any:
        """Run when tool ends running - log brief result."""
        duration = None
        if self.tool_start_time:
            duration = time.time() - self.tool_start_time
        
        # Format output in human-readable way
        out_str = str(output)
        
        # Determine if output indicates success or error
        is_error = "error" in out_str.lower() or "failed" in out_str.lower()
        
        # Simplify output for readability
        if len(out_str) > 200:
            lines = out_str.split('\n')
            if len(lines) > 4:
                out_str = '\n  '.join(lines[:4]) + f"\n  ... ({len(lines) - 4} more lines)"
            elif len(out_str) > 200:
                out_str = out_str[:200] + "..."
        
        # Show result with icon
        icon = "✅" if not is_error else "❌"
        duration_str = f"({duration:.1f}s)" if duration else ""
        
        self.console.print(f"{icon} Done {duration_str}", style="green" if not is_error else "red")
        
        # Show simplified output
        if out_str and len(out_str.strip()) > 0:
            # Make output more readable
            if "M\t" in out_str or "A\t" in out_str or "D\t" in out_str:
                # File changes - format nicely
                self.console.print("  Files changed:", style="dim")
                for line in out_str.split('\n')[:5]:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) == 2:
                            change_type = {"M": "Modified", "A": "Added", "D": "Deleted"}.get(parts[0], parts[0])
                            self.console.print(f"    • {change_type}: {parts[1]}", style="dim")
            elif "passed" in out_str.lower() or "failed" in out_str.lower():
                # Test results - highlight key info
                for line in out_str.split('\n')[:3]:
                    if line.strip():
                        self.console.print(f"  {line.strip()}", style="dim")
            else:
                # Generic output - show first few lines
                preview = out_str.split('\n')[0]
                if len(preview) > 100:
                    preview = preview[:100] + "..."
                self.console.print(f"  {preview}", style="dim")

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> Any:
        """Run when tool errors."""
        error_text = Text()
        error_text.append("❌ Error: ", style=self.styles["error"])
        error_text.append(str(error)[:150])
        self.console.print(error_text)
        self.console.print()

    def on_llm_start(
        self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any
    ) -> None:
        """Run when LLM starts running."""
        # Don't log LLM calls to reduce noise
        pass

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        """Run when LLM ends running."""
        # Don't log LLM responses to reduce noise
        pass
