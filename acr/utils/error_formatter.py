# Copyright 2026 Adversarial Code Reviewer Contributors
#
# Licensed under the MIT License;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://opensource.org/licenses/MIT
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""User-friendly error message formatting."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ErrorContext:
    """Context information about where an error occurred."""

    component: str
    """Name of the component that raised the error (e.g., "config", "parser", "analyzer")."""

    operation: Optional[str] = None
    """Operation being performed when error occurred (e.g., "loading configuration", "parsing Python file")."""

    file: Optional[str] = None
    """File path if applicable."""

    line: Optional[int] = None
    """Line number if applicable."""

    extra: Optional[Dict[str, Any]] = None
    """Additional context data."""


@dataclass
class ErrorSuggestion:
    """A suggested action to resolve an error."""

    title: str
    """Brief title for the suggestion."""

    description: str
    """Detailed explanation of the suggestion."""

    command: Optional[str] = None
    """Command to run if applicable."""

    code: Optional[str] = None
    """Code snippet to fix the issue."""


class ErrorFormatter:
    """Format errors with helpful context and suggestions."""

    _suggestion_registry: Dict[str, List[ErrorSuggestion]] = {
        "ConfigurationError": [
            ErrorSuggestion(
                title="Check configuration file",
                description="Ensure your .acrrc.yaml file is valid YAML and follows the schema.",
                command="acr config validate",
            ),
            ErrorSuggestion(
                title="Initialize configuration",
                description="Run init to create a default configuration file.",
                command="acr init",
            ),
        ],
        "ParseError": [
            ErrorSuggestion(
                title="Check file for syntax errors",
                description="The file contains invalid Python syntax. Fix the syntax errors and try again.",
            ),
            ErrorSuggestion(
                title="Check Python version",
                description="Ensure you're using Python 3.8+. Run: python --version",
                command="python --version",
            ),
            ErrorSuggestion(
                title="Use legacy analysis mode",
                description="For older Python code, enable legacy analysis mode in .acrrc.yaml.",
                code="analysis:\n  enable_legacy_mode: true",
            ),
        ],
        "AnalysisError": [
            ErrorSuggestion(
                title="Check file permissions",
                description="Ensure ACR has read access to all files in the target directory.",
            ),
            ErrorSuggestion(
                title="Exclude problematic files",
                description="Use --exclude flag to skip files that cannot be analyzed.",
                command="acr scan . --exclude '*/vendor/*'",
            ),
            ErrorSuggestion(
                title="Increase recursion depth",
                description="For deep call stacks, increase max_recursion_depth in .acrrc.yaml.",
                code="analysis:\n  max_recursion_depth: 20",
            ),
        ],
        "LLMError": [
            ErrorSuggestion(
                title="Check API key",
                description="Ensure your API key is set correctly. Use keyring for secure storage.",
                command="acr config",
            ),
            ErrorSuggestion(
                title="Test API connectivity",
                description="Run doctor to check LLM API connectivity.",
                command="acr doctor",
            ),
            ErrorSuggestion(
                title="Disable LLM features",
                description="Run scan without LLM integration using: acr scan . --no-llm",
                command="acr scan . --no-llm",
            ),
            ErrorSuggestion(
                title="Check API quota",
                description="Ensure you have sufficient API quota/balance for your LLM provider.",
            ),
        ],
        "PatternError": [
            ErrorSuggestion(
                title="Validate pattern files",
                description="Ensure custom pattern files are valid YAML and follow the schema.",
                command="acr patterns validate",
            ),
            ErrorSuggestion(
                title="Check pattern dependencies",
                description="Some patterns require specific language features or frameworks.",
            ),
            ErrorSuggestion(
                title="Use default patterns",
                description="Run without custom patterns to use the built-in library.",
                command="acr patterns",
            ),
        ],
    }

    @classmethod
    def register_suggestion(
        cls,
        error_type: str,
        suggestion: ErrorSuggestion,
    ) -> None:
        """Register a custom suggestion for an error type.

        Args:
            error_type: Name of the exception class
            suggestion: Suggestion to register
        """
        if error_type not in cls._suggestion_registry:
            cls._suggestion_registry[error_type] = []
        cls._suggestion_registry[error_type].append(suggestion)

    @classmethod
    def get_suggestions(cls, error_type: str) -> List[ErrorSuggestion]:
        """Get suggestions for an error type.

        Args:
            error_type: Name of the exception class

        Returns:
            List of suggestions for this error type
        """
        return cls._suggestion_registry.get(error_type, [])

    @classmethod
    def format_error(
        cls,
        error: Exception,
        context: Optional[ErrorContext] = None,
        verbose: bool = False,
    ) -> str:
        """Format an error with helpful context and suggestions.

        Args:
            error: The exception to format
            context: Additional context about where the error occurred
            verbose: Include additional debug information

        Returns:
            Formatted error message string
        """
        lines = []

        error_type = type(error).__name__

        lines.append(f"❌ {error_type}")

        if context:
            lines.append("")
            lines.append("Context:")
            lines.append(f"  Component: {context.component}")
            if context.operation:
                lines.append(f"  Operation: {context.operation}")
            if context.file:
                loc = context.file
                if context.line:
                    loc += f":{context.line}"
                lines.append(f"  Location: {loc}")
            if context.extra:
                lines.append("  Additional:")
                for key, value in context.extra.items():
                    lines.append(f"    {key}: {value}")

        lines.append("")
        lines.append("Details:")
        lines.append(f"  {str(error)}")

        if verbose and error.__cause__:
            lines.append("")
            lines.append("Caused by:")
            lines.append(f"  {type(error.__cause__).__name__}: {error.__cause__}")

        suggestions = cls.get_suggestions(error_type)
        if suggestions:
            lines.append("")
            lines.append("Suggestions:")
            for i, suggestion in enumerate(suggestions, 1):
                lines.append(f"  {i}. {suggestion.title}")
                if suggestion.description:
                    lines.append(f"     {suggestion.description}")
                if suggestion.command:
                    lines.append(f"     Command: {suggestion.command}")
                if suggestion.code:
                    for line in suggestion.code.split("\n"):
                        lines.append(f"     {line}")

        return "\n".join(lines)

    @classmethod
    def format_error_markdown(
        cls,
        error: Exception,
        context: Optional[ErrorContext] = None,
        verbose: bool = False,
    ) -> str:
        """Format an error as Markdown.

        Args:
            error: The exception to format
            context: Additional context about where the error occurred
            verbose: Include additional debug information

        Returns:
            Formatted error message as Markdown string
        """
        lines = []

        error_type = type(error).__name__

        lines.append(f"## ❌ {error_type}")

        if context:
            lines.append("")
            lines.append("**Context:**")
            lines.append(f"- Component: `{context.component}`")
            if context.operation:
                lines.append(f"- Operation: `{context.operation}`")
            if context.file:
                loc = f"`{context.file}`"
                if context.line:
                    loc = f"`{context.file}:{context.line}`"
                lines.append(f"- Location: {loc}")
            if context.extra:
                lines.append("- Additional:")
                for key, value in context.extra.items():
                    lines.append(f"  - {key}: `{value}`")

        lines.append("")
        lines.append("**Details:**")
        lines.append(f"```\n{str(error)}\n```")

        if verbose and error.__cause__:
            lines.append("")
            lines.append("**Caused by:**")
            lines.append(f"{type(error.__cause__).__name__}: {error.__cause__}")

        suggestions = cls.get_suggestions(error_type)
        if suggestions:
            lines.append("")
            lines.append("**Suggestions:**")
            for i, suggestion in enumerate(suggestions, 1):
                lines.append(f"{i}. **{suggestion.title}**")
                if suggestion.description:
                    lines.append(f"   {suggestion.description}")
                if suggestion.command:
                    lines.append(f"   ```bash\n{suggestion.command}\n```")
                if suggestion.code:
                    lines.append(f"   ```yaml\n{suggestion.code}\n```")

        return "\n".join(lines)
