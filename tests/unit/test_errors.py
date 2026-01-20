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

"""Tests for error handling framework."""

import pytest

from acr.utils.errors import (
    ACRError,
    ConfigurationError,
    ParseError,
    AnalysisError,
    LLMError,
    PatternError,
)


class TestACRError:
    """Test base ACRError exception."""

    def test_base_exception_inheritance(self):
        """Test that ACRError inherits from Exception."""
        error = ACRError("test error")
        assert isinstance(error, Exception)
        assert isinstance(error, ACRError)

    def test_base_exception_message(self):
        """Test that ACRError stores error message."""
        message = "base error message"
        error = ACRError(message)
        assert str(error) == message

    def test_base_exception_without_message(self):
        """Test that ACRError can be created without message."""
        error = ACRError()
        assert str(error) == ""

    def test_base_exception_can_be_raised(self):
        """Test that ACRError can be raised and caught."""
        with pytest.raises(ACRError):
            raise ACRError("test")

    def test_base_exception_in_catch_block(self):
        """Test catching ACRError."""
        try:
            raise ACRError("test error")
        except ACRError as e:
            assert str(e) == "test error"


class TestConfigurationError:
    """Test ConfigurationError exception."""

    def test_inherits_from_base(self):
        """Test that ConfigurationError inherits from ACRError."""
        error = ConfigurationError("config error")
        assert isinstance(error, ACRError)
        assert isinstance(error, ConfigurationError)
        assert isinstance(error, Exception)

    def test_error_message(self):
        """Test ConfigurationError message."""
        message = "invalid configuration"
        error = ConfigurationError(message)
        assert str(error) == message

    def test_can_be_raised(self):
        """Test that ConfigurationError can be raised."""
        with pytest.raises(ConfigurationError):
            raise ConfigurationError("config error")

    def test_can_be_caught_as_base(self):
        """Test that ConfigurationError can be caught as ACRError."""
        try:
            raise ConfigurationError("config error")
        except ACRError as e:
            assert isinstance(e, ConfigurationError)
            assert str(e) == "config error"


class TestParseError:
    """Test ParseError exception."""

    def test_inherits_from_base(self):
        """Test that ParseError inherits from ACRError."""
        error = ParseError("parse error", "test.py", 10)
        assert isinstance(error, ACRError)
        assert isinstance(error, ParseError)
        assert isinstance(error, Exception)

    def test_has_file_attribute(self):
        """Test that ParseError has file attribute."""
        error = ParseError("parse error", "test.py", 10)
        assert error.file == "test.py"

    def test_has_line_attribute(self):
        """Test that ParseError has line attribute."""
        error = ParseError("parse error", "test.py", 10)
        assert error.line == 10

    def test_message_formatting(self):
        """Test ParseError message includes file and line."""
        error = ParseError("syntax error", "main.py", 42)
        message = str(error)
        assert "syntax error" in message
        assert "main.py" in message
        assert "42" in message

    def test_message_format_with_colon(self):
        """Test ParseError message format uses colon separator."""
        error = ParseError("syntax error", "main.py", 42)
        assert str(error) == "syntax error at main.py:42"

    def test_with_zero_line(self):
        """Test ParseError with line 0."""
        error = ParseError("error", "test.py", 0)
        assert error.line == 0
        assert "test.py:0" in str(error)

    def test_with_negative_line(self):
        """Test ParseError with negative line number."""
        error = ParseError("error", "test.py", -1)
        assert error.line == -1

    def test_with_large_line_number(self):
        """Test ParseError with large line number."""
        error = ParseError("error", "test.py", 10000)
        assert error.line == 10000

    def test_with_empty_file(self):
        """Test ParseError with empty file name."""
        error = ParseError("error", "", 10)
        assert error.file == ""

    def test_with_file_path(self):
        """Test ParseError with full file path."""
        error = ParseError("error", "/path/to/file.py", 10)
        assert error.file == "/path/to/file.py"

    def test_can_be_raised(self):
        """Test that ParseError can be raised."""
        with pytest.raises(ParseError):
            raise ParseError("parse error", "test.py", 10)

    def test_can_be_caught_as_base(self):
        """Test that ParseError can be caught as ACRError."""
        try:
            raise ParseError("parse error", "test.py", 10)
        except ACRError as e:
            assert isinstance(e, ParseError)
            assert e.file == "test.py"
            assert e.line == 10


class TestAnalysisError:
    """Test AnalysisError exception."""

    def test_inherits_from_base(self):
        """Test that AnalysisError inherits from ACRError."""
        error = AnalysisError("analysis error")
        assert isinstance(error, ACRError)
        assert isinstance(error, AnalysisError)
        assert isinstance(error, Exception)

    def test_error_message(self):
        """Test AnalysisError message."""
        message = "analysis failed"
        error = AnalysisError(message)
        assert str(error) == message

    def test_can_be_raised(self):
        """Test that AnalysisError can be raised."""
        with pytest.raises(AnalysisError):
            raise AnalysisError("analysis error")

    def test_can_be_caught_as_base(self):
        """Test that AnalysisError can be caught as ACRError."""
        try:
            raise AnalysisError("analysis error")
        except ACRError as e:
            assert isinstance(e, AnalysisError)
            assert str(e) == "analysis error"


class TestLLMError:
    """Test LLMError exception."""

    def test_inherits_from_base(self):
        """Test that LLMError inherits from ACRError."""
        error = LLMError("LLM error")
        assert isinstance(error, ACRError)
        assert isinstance(error, LLMError)
        assert isinstance(error, Exception)

    def test_error_message(self):
        """Test LLMError message."""
        message = "LLM API call failed"
        error = LLMError(message)
        assert str(error) == message

    def test_can_be_raised(self):
        """Test that LLMError can be raised."""
        with pytest.raises(LLMError):
            raise LLMError("LLM error")

    def test_can_be_caught_as_base(self):
        """Test that LLMError can be caught as ACRError."""
        try:
            raise LLMError("LLM error")
        except ACRError as e:
            assert isinstance(e, LLMError)
            assert str(e) == "LLM error"


class TestPatternError:
    """Test PatternError exception."""

    def test_inherits_from_base(self):
        """Test that PatternError inherits from ACRError."""
        error = PatternError("pattern error")
        assert isinstance(error, ACRError)
        assert isinstance(error, PatternError)
        assert isinstance(error, Exception)

    def test_error_message(self):
        """Test PatternError message."""
        message = "invalid pattern"
        error = PatternError(message)
        assert str(error) == message

    def test_can_be_raised(self):
        """Test that PatternError can be raised."""
        with pytest.raises(PatternError):
            raise PatternError("pattern error")

    def test_can_be_caught_as_base(self):
        """Test that PatternError can be caught as ACRError."""
        try:
            raise PatternError("pattern error")
        except ACRError as e:
            assert isinstance(e, PatternError)
            assert str(e) == "pattern error"


class TestExceptionHierarchy:
    """Test exception hierarchy relationships."""

    def test_all_errors_are_exceptions(self):
        """Test that all custom errors inherit from Exception."""
        assert issubclass(ACRError, Exception)
        assert issubclass(ConfigurationError, Exception)
        assert issubclass(ParseError, Exception)
        assert issubclass(AnalysisError, Exception)
        assert issubclass(LLMError, Exception)
        assert issubclass(PatternError, Exception)

    def test_all_errors_inherit_from_base(self):
        """Test that all custom errors inherit from ACRError."""
        assert issubclass(ACRError, ACRError)
        assert issubclass(ConfigurationError, ACRError)
        assert issubclass(ParseError, ACRError)
        assert issubclass(AnalysisError, ACRError)
        assert issubclass(LLMError, ACRError)
        assert issubclass(PatternError, ACRError)

    def test_catch_all_as_base(self):
        """Test catching all errors as ACRError."""
        errors = [
            ACRError("base"),
            ConfigurationError("config"),
            ParseError("parse", "test.py", 10),
            AnalysisError("analysis"),
            LLMError("LLM"),
            PatternError("pattern"),
        ]

        for error_class in errors:
            try:
                raise error_class
            except ACRError:
                pass

    def test_specific_error_catch(self):
        """Test catching specific error types."""
        with pytest.raises(ConfigurationError):
            raise ConfigurationError("config")

        with pytest.raises(ParseError):
            raise ParseError("parse", "test.py", 10)

        with pytest.raises(AnalysisError):
            raise AnalysisError("analysis")

        with pytest.raises(LLMError):
            raise LLMError("LLM")

        with pytest.raises(PatternError):
            raise PatternError("pattern")


class TestExceptionChaining:
    """Test exception chaining behavior."""

    def test_chaining_with_from(self):
        """Test exception chaining with 'from' keyword."""
        try:
            try:
                raise ValueError("original error")
            except ValueError as e:
                raise ConfigurationError("config failed") from e
        except ConfigurationError as ce:
            assert ce.__cause__ is not None
            assert isinstance(ce.__cause__, ValueError)

    def test_chaining_none(self):
        """Test exception chaining with None."""
        try:
            try:
                raise ValueError("original")
            except ValueError:
                raise ConfigurationError("config failed") from None
        except ConfigurationError as ce:
            assert ce.__cause__ is None

    def test_implicit_chaining(self):
        """Test implicit exception chaining."""
        try:
            try:
                raise ValueError("original")
            except ValueError:
                raise ConfigurationError("config failed")
        except ConfigurationError as ce:
            assert ce.__context__ is not None
            assert isinstance(ce.__context__, ValueError)


class TestEdgeCases:
    """Test edge cases for error handling."""

    def test_multiline_message(self):
        """Test errors with multiline messages."""
        message = "line1\nline2\nline3"
        error = ACRError(message)
        assert str(error) == message

    def test_unicode_message(self):
        """Test errors with unicode characters."""
        message = "Error: café, 日本語, 🚨"
        error = ACRError(message)
        assert str(error) == message

    def test_empty_message(self):
        """Test errors with empty message."""
        error = ACRError("")
        assert str(error) == ""

    def test_very_long_message(self):
        """Test errors with very long message."""
        message = "x" * 10000
        error = ACRError(message)
        assert len(str(error)) == 10000

    def test_special_characters_in_file(self):
        """Test ParseError with special characters in file."""
        error = ParseError("error", "test-文件.py", 10)
        assert "test-文件.py" in error.file

    def test_line_number_as_type_hint(self):
        """Test ParseError requires line as int."""
        error = ParseError("error", "test.py", 10)
        assert error.line == 10

    def test_exception_reraising(self):
        """Test reraising exceptions."""
        try:
            try:
                raise ACRError("original")
            except ACRError:
                raise
        except ACRError as e:
            assert str(e) == "original"
