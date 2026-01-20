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

"""Tests for error_formatter."""


from acr.utils.error_formatter import (
    ErrorContext,
    ErrorFormatter,
    ErrorSuggestion,
)
from acr.utils.errors import (
    AnalysisError,
    ConfigurationError,
    LLMError,
    ParseError,
)


class TestErrorContext:
    """Test ErrorContext dataclass."""

    def test_minimal_context(self) -> None:
        """Test creating minimal context."""
        ctx = ErrorContext(component="test")
        assert ctx.component == "test"
        assert ctx.operation is None
        assert ctx.file is None
        assert ctx.line is None
        assert ctx.extra is None

    def test_full_context(self) -> None:
        """Test creating full context."""
        ctx = ErrorContext(
            component="parser",
            operation="parsing file",
            file="test.py",
            line=42,
            extra={"test": "value"},
        )
        assert ctx.component == "parser"
        assert ctx.operation == "parsing file"
        assert ctx.file == "test.py"
        assert ctx.line == 42
        assert ctx.extra == {"test": "value"}


class TestErrorSuggestion:
    """Test ErrorSuggestion dataclass."""

    def test_minimal_suggestion(self) -> None:
        """Test creating minimal suggestion."""
        sug = ErrorSuggestion(title="Test", description="Test desc")
        assert sug.title == "Test"
        assert sug.description == "Test desc"
        assert sug.command is None
        assert sug.code is None

    def test_full_suggestion(self) -> None:
        """Test creating full suggestion."""
        sug = ErrorSuggestion(
            title="Test",
            description="Test desc",
            command="test command",
            code="test code",
        )
        assert sug.title == "Test"
        assert sug.description == "Test desc"
        assert sug.command == "test command"
        assert sug.code == "test code"


class TestErrorFormatter:
    """Test ErrorFormatter."""

    def test_get_suggestions_configuration_error(self) -> None:
        """Test getting suggestions for ConfigurationError."""
        suggestions = ErrorFormatter.get_suggestions("ConfigurationError")
        assert len(suggestions) == 2
        assert any("Check configuration file" in s.title for s in suggestions)
        assert any("Initialize configuration" in s.title for s in suggestions)

    def test_get_suggestions_parse_error(self) -> None:
        """Test getting suggestions for ParseError."""
        suggestions = ErrorFormatter.get_suggestions("ParseError")
        assert len(suggestions) == 3
        assert any("Check file for syntax errors" in s.title for s in suggestions)
        assert any("Check Python version" in s.title for s in suggestions)

    def test_get_suggestions_analysis_error(self) -> None:
        """Test getting suggestions for AnalysisError."""
        suggestions = ErrorFormatter.get_suggestions("AnalysisError")
        assert len(suggestions) == 3
        assert any("Check file permissions" in s.title for s in suggestions)

    def test_get_suggestions_llm_error(self) -> None:
        """Test getting suggestions for LLMError."""
        suggestions = ErrorFormatter.get_suggestions("LLMError")
        assert len(suggestions) == 4
        assert any("Check API key" in s.title for s in suggestions)

    def test_get_suggestions_pattern_error(self) -> None:
        """Test getting suggestions for PatternError."""
        suggestions = ErrorFormatter.get_suggestions("PatternError")
        assert len(suggestions) == 3
        assert any("Validate pattern files" in s.title for s in suggestions)

    def test_get_suggestions_unknown_error(self) -> None:
        """Test getting suggestions for unknown error type."""
        suggestions = ErrorFormatter.get_suggestions("UnknownError")
        assert suggestions == []

    def test_register_suggestion(self) -> None:
        """Test registering custom suggestion."""
        custom_sug = ErrorSuggestion(
            title="Custom Fix",
            description="Do something custom",
        )
        ErrorFormatter.register_suggestion("CustomError", custom_sug)

        suggestions = ErrorFormatter.get_suggestions("CustomError")
        assert len(suggestions) == 1
        assert suggestions[0].title == "Custom Fix"

    def test_register_multiple_suggestions(self) -> None:
        """Test registering multiple suggestions for same error type."""
        sug1 = ErrorSuggestion(title="Fix 1", description="First fix")
        sug2 = ErrorSuggestion(title="Fix 2", description="Second fix")

        ErrorFormatter.register_suggestion("MultiError", sug1)
        ErrorFormatter.register_suggestion("MultiError", sug2)

        suggestions = ErrorFormatter.get_suggestions("MultiError")
        assert len(suggestions) == 2
        assert suggestions[0].title == "Fix 1"
        assert suggestions[1].title == "Fix 2"

    def test_format_error_simple(self) -> None:
        """Test formatting simple error without context."""
        error = ConfigurationError("Invalid config")
        formatted = ErrorFormatter.format_error(error)

        assert "❌ ConfigurationError" in formatted
        assert "Details:" in formatted
        assert "Invalid config" in formatted

    def test_format_error_with_context(self) -> None:
        """Test formatting error with context."""
        error = ParseError("Syntax error", "test.py", 42)
        context = ErrorContext(
            component="parser",
            operation="parsing file",
            file="test.py",
            line=42,
        )
        formatted = ErrorFormatter.format_error(error, context)

        assert "❌ ParseError" in formatted
        assert "Context:" in formatted
        assert "Component: parser" in formatted
        assert "Operation: parsing file" in formatted
        assert "Location: test.py:42" in formatted
        assert "Details:" in formatted
        assert "Syntax error at test.py:42" in formatted

    def test_format_error_with_extra_context(self) -> None:
        """Test formatting error with extra context data."""
        error = AnalysisError("Analysis failed")
        context = ErrorContext(
            component="analyzer",
            extra={"file_count": 10, "errors": 2},
        )
        formatted = ErrorFormatter.format_error(error, context)

        assert "Additional:" in formatted
        assert "file_count: 10" in formatted
        assert "errors: 2" in formatted

    def test_format_error_verbose_with_cause(self) -> None:
        """Test formatting error in verbose mode with cause."""
        try:
            try:
                raise ValueError("Inner error")
            except ValueError as e:
                raise AnalysisError("Outer error") from e
        except AnalysisError as error:
            formatted = ErrorFormatter.format_error(error, verbose=True)

            assert "❌ AnalysisError" in formatted
            assert "Caused by:" in formatted
            assert "ValueError: Inner error" in formatted

    def test_format_error_includes_suggestions(self) -> None:
        """Test formatting error includes suggestions."""
        error = ConfigurationError("Config not found")
        formatted = ErrorFormatter.format_error(error)

        assert "Suggestions:" in formatted
        assert "Check configuration file" in formatted
        assert "acr config validate" in formatted
        assert "Initialize configuration" in formatted
        assert "acr init" in formatted

    def test_format_error_llm_with_code_suggestion(self) -> None:
        """Test formatting LLM error includes code snippet suggestion."""
        error = LLMError("API quota exceeded")
        formatted = ErrorFormatter.format_error(error)

        assert "Suggestions:" in formatted
        assert any("Check API key" in formatted for s in formatted.split("\n"))

    def test_format_error_no_suggestions(self) -> None:
        """Test formatting error type with no suggestions."""

        class UnknownError(Exception):
            pass

        error = UnknownError("Unknown issue")
        formatted = ErrorFormatter.format_error(error)

        assert "❌ UnknownError" in formatted
        assert "Details:" in formatted
        assert "Suggestions:" not in formatted

    def test_format_error_markdown_simple(self) -> None:
        """Test formatting simple error as Markdown."""
        error = ConfigurationError("Invalid config")
        formatted = ErrorFormatter.format_error_markdown(error)

        assert "## ❌ ConfigurationError" in formatted
        assert "**Details:**" in formatted
        assert "```" in formatted

    def test_format_error_markdown_with_context(self) -> None:
        """Test formatting error with context as Markdown."""
        error = ParseError("Syntax error", "test.py", 42)
        context = ErrorContext(
            component="parser",
            operation="parsing file",
            file="test.py",
            line=42,
        )
        formatted = ErrorFormatter.format_error_markdown(error, context)

        assert "## ❌ ParseError" in formatted
        assert "**Context:**" in formatted
        assert "- Component: `parser`" in formatted
        assert "- Location: `test.py:42`" in formatted
        assert "**Details:**" in formatted

    def test_format_error_markdown_includes_suggestions(self) -> None:
        """Test formatting error as Markdown includes suggestions."""
        error = LLMError("API connection failed")
        formatted = ErrorFormatter.format_error_markdown(error)

        assert "**Suggestions:**" in formatted
        assert any("**Check API key**" in formatted for s in formatted.split("\n"))
        assert "```bash" in formatted
        assert "acr config" in formatted
        assert "```" in formatted

    def test_format_error_markdown_verbose(self) -> None:
        """Test formatting error as Markdown in verbose mode."""
        try:
            try:
                raise ValueError("Inner error")
            except ValueError as e:
                raise AnalysisError("Outer error") from e
        except AnalysisError as error:
            formatted = ErrorFormatter.format_error_markdown(error, verbose=True)

            assert "**Caused by:**" in formatted
            assert "ValueError: Inner error" in formatted

    def test_suggestion_with_command_and_code(self) -> None:
        """Test suggestion includes both command and code."""
        sug = ErrorSuggestion(
            title="Full Suggestion",
            description="Has both",
            command="test command",
            code="test: code\nwith: multiple\nlines",
        )

        ErrorFormatter.register_suggestion("TestError", sug)

        class TestError(Exception):
            pass

        formatted = ErrorFormatter.format_error(TestError("test"))
        assert "Full Suggestion" in formatted
        assert "Has both" in formatted
        assert "Command: test command" in formatted
        assert "test: code" in formatted
        assert "with: multiple" in formatted
        assert "lines" in formatted
