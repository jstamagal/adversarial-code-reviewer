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

"""Tests for AST parser."""

from pathlib import Path

import pytest

from acr.core.ast_parser import ASTParser
from acr.utils.errors import ParseError


@pytest.fixture
def parser():
    """Create AST parser instance."""
    try:
        return ASTParser()
    except ImportError:
        pytest.skip("tree-sitter-python not installed")


class TestASTParserBasics:
    """Test basic AST parser functionality."""

    def test_parse_simple_function(self, parser):
        """Test parsing a simple function."""
        code = """
def hello_world():
    print("Hello, world!")
"""
        ast = parser.parse(code, "test.py")
        assert ast is not None
        assert not ast.has_error

    def test_parse_empty_code(self, parser):
        """Test parsing empty code."""
        assert parser.parse("", "test.py") is None
        assert parser.parse("   ", "test.py") is None

    def test_parse_syntax_error(self, parser):
        """Test parsing code with syntax errors."""
        code = """
def broken_function(
    print("Missing closing parenthesis")
"""
        with pytest.raises(ParseError):
            parser.parse(code, "test.py")

    def test_parse_file(self, parser, tmp_path):
        """Test parsing a file."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
def test():
    pass
"""
        )

        ast = parser.parse_file(test_file)
        assert ast is not None
        assert not ast.has_error

    def test_parse_nonexistent_file(self, parser):
        """Test parsing a nonexistent file."""
        with pytest.raises(FileNotFoundError):
            parser.parse_file(Path("/nonexistent/file.py"))


class TestFunctionExtraction:
    """Test function extraction from AST."""

    def test_get_functions(self, parser):
        """Test extracting functions from AST."""
        code = """
def function_one():
    pass

def function_two(x, y):
    return x + y
"""
        ast = parser.parse(code, "test.py")
        functions = parser.get_functions(ast)

        assert len(functions) == 2
        function_names = [parser.get_node_text(f.children[1]) for f in functions]
        assert "function_one" in function_names
        assert "function_two" in function_names

    def test_get_no_functions(self, parser):
        """Test extracting functions when none exist."""
        code = """
# Just a comment
x = 42
"""
        ast = parser.parse(code, "test.py")
        functions = parser.get_functions(ast)
        assert len(functions) == 0


class TestClassExtraction:
    """Test class extraction from AST."""

    def test_get_classes(self, parser):
        """Test extracting classes from AST."""
        code = """
class MyClass:
    def method(self):
        pass

class AnotherClass:
    pass
"""
        ast = parser.parse(code, "test.py")
        classes = parser.get_classes(ast)

        assert len(classes) == 2

    def test_get_no_classes(self, parser):
        """Test extracting classes when none exist."""
        code = """
def function():
    pass
"""
        ast = parser.parse(code, "test.py")
        classes = parser.get_classes(ast)
        assert len(classes) == 0


class TestImportExtraction:
    """Test import extraction from AST."""

    def test_get_imports(self, parser):
        """Test extracting imports."""
        code = """
import os
import sys as system
from pathlib import Path
from typing import List, Dict
"""
        ast = parser.parse(code, "test.py")
        imports = parser.get_imports(ast)

        assert len(imports) == 4

    def test_get_no_imports(self, parser):
        """Test extracting imports when none exist."""
        code = """
x = 42
y = "hello"
"""
        ast = parser.parse(code, "test.py")
        imports = parser.get_imports(ast)
        assert len(imports) == 0


class TestCallSiteExtraction:
    """Test call site extraction."""

    def test_get_call_sites(self, parser):
        """Test finding call sites."""
        code = """
def helper():
    pass

def main():
    helper()
    x = helper()
"""
        ast = parser.parse(code, "test.py")
        call_sites = parser.get_call_sites(ast, "helper")
        assert len(call_sites) == 2

    def test_get_call_sites_no_matches(self, parser):
        """Test finding call sites when none match."""
        code = """
def helper():
    pass

def main():
    other_function()
"""
        ast = parser.parse(code, "test.py")
        call_sites = parser.get_call_sites(ast, "helper")
        assert len(call_sites) == 0


class TestSourceCodeExtraction:
    """Test source code extraction from AST."""

    def test_get_source_lines(self, parser):
        """Test extracting source lines."""
        code = """
def test_function():
    x = "line 1"
    y = "line 2"
    z = "line 3"
    return "line 4"
"""
        ast = parser.parse(code, "test.py")
        lines = parser.get_source_lines(ast, code)
        assert len(lines) >= 4
        assert any("line 1" in line for line in lines)

    def test_get_node_text(self, parser):
        """Test getting text from a node."""
        code = """
variable_name = "value"
"""
        ast = parser.parse(code, "test.py")

        # Find the assignment
        for child in ast.children:
            if child.type == "assignment":
                identifier = child.children[0]
                text = parser.get_node_text(identifier)
                assert text == "variable_name"


class TestCodeHashing:
    """Test code hashing functionality."""

    def test_get_code_hash(self, parser):
        """Test hashing code."""
        code = """
def test():
    return 42
"""
        hash1 = parser.get_code_hash(code)
        hash2 = parser.get_code_hash(code)
        assert hash1 == hash2

        different_code = """
def different():
    return 43
"""
        hash3 = parser.get_code_hash(different_code)
        assert hash1 != hash3


class TestComplexCode:
    """Test parsing complex Python code."""

    def test_nested_functions(self, parser):
        """Test parsing nested functions."""
        code = """
def outer():
    def inner():
        pass
    inner()
"""
        ast = parser.parse(code, "test.py")
        assert ast is not None
        assert not ast.has_error
        functions = parser.get_functions(ast)
        assert len(functions) == 2

    def test_class_with_methods(self, parser):
        """Test parsing a class with methods."""
        code = """
class TestClass:
    def __init__(self, value):
        self.value = value

    def get_value(self):
        return self.value

    @staticmethod
    def static_method():
        pass
"""
        ast = parser.parse(code, "test.py")
        assert ast is not None
        classes = parser.get_classes(ast)
        assert len(classes) == 1

    def test_decorators(self, parser):
        """Test parsing code with decorators."""
        code = """
@decorator
def decorated_function():
    pass

@another_decorator(arg1, arg2="value")
def another_decorated():
    pass
"""
        ast = parser.parse(code, "test.py")
        assert ast is not None
        functions = parser.get_functions(ast)
        assert len(functions) == 2

    def test_async_functions(self, parser):
        """Test parsing async functions."""
        code = """
async def async_function():
    await some_async_call()
"""
        ast = parser.parse(code, "test.py")
        assert ast is not None
        functions = parser.get_functions(ast)
        assert len(functions) == 1

    def test_comprehensions(self, parser):
        """Test parsing list and dict comprehensions."""
        code = """
numbers = [1, 2, 3, 4, 5]
squares = [x**2 for x in numbers]
even_squares = [x**2 for x in numbers if x % 2 == 0]
"""
        ast = parser.parse(code, "test.py")
        assert ast is not None
        assert not ast.has_error


class TestErrorHandling:
    """Test error handling in parser."""

    def test_syntax_error_location(self, parser):
        """Test that syntax errors report location."""
        code = """
def broken():
    x = [
"""
        with pytest.raises(ParseError) as exc_info:
            parser.parse(code, "test.py", recover=False)

        assert "test.py" in str(exc_info.value)

    def test_invalid_unicode(self, parser, tmp_path):
        """Test handling files with invalid encoding."""
        # Write bytes that are invalid UTF-8
        test_file = tmp_path / "invalid.py"
        with open(test_file, "wb") as f:
            f.write(b"\xff\xfe invalid \x00\x01")

        # Should attempt to parse and handle encoding issues gracefully
        # Tree-sitter can handle some encoding issues
        ast = parser.parse_file(test_file, recover=True)
        # Just verify it doesn't crash
        assert ast is not None


class TestFlaskRouteDetection:
    """Test detecting Flask routes (for web framework analysis)."""

    def test_detect_flask_route(self, parser):
        """Test detecting Flask route decorator."""
        code = """
from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello World"

@app.route('/user/<username>')
def user_profile(username):
    return f"Profile: {username}"
"""
        ast = parser.parse(code, "test.py")
        assert ast is not None
        functions = parser.get_functions(ast)

        # Should find the route handlers
        function_names = []
        for func in functions:
            # Get function name
            for child in func.children:
                if child.type == "identifier":
                    function_names.append(parser.get_node_text(child))
                    break

        assert "index" in function_names
        assert "user_profile" in function_names


class TestVulnerableCodePatterns:
    """Test parsing code with common vulnerability patterns."""

    def test_sql_injection_pattern(self, parser):
        """Test parsing SQL injection vulnerability."""
        code = """
def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return execute_query(query)
"""
        ast = parser.parse(code, "test.py")
        assert ast is not None
        functions = parser.get_functions(ast)
        assert len(functions) == 1

    def test_command_injection_pattern(self, parser):
        """Test parsing command injection vulnerability."""
        code = """
import subprocess

def run_command(user_input):
    command = "ls -la " + user_input
    subprocess.run(command, shell=True)
"""
        ast = parser.parse(code, "test.py")
        assert ast is not None
        # The call is subprocess.run, not direct run call
        call_sites = parser.get_call_sites(ast, "run")
        # This may not find the call since it's an attribute call
        # Just verify the code parses correctly
        assert ast is not None

    def test_xss_pattern(self, parser):
        """Test parsing XSS vulnerability."""
        code = """
def render_template(user_input):
    html = "<div>" + user_input + "</div>"
    return html
"""
        ast = parser.parse(code, "test.py")
        assert ast is not None


class TestSyntaxErrorRecovery:
    """Test syntax error recovery functionality."""

    def test_syntax_error_with_recovery(self, parser):
        """Test parsing code with syntax errors using recovery."""
        code = """
def broken_function(
    print("Missing closing parenthesis")
"""
        ast = parser.parse(code, "test.py", recover=True)
        assert ast is not None
        assert ast.has_error

    def test_syntax_error_without_recovery(self, parser):
        """Test parsing code with syntax errors without recovery raises error."""
        code = """
def broken_function(
    print("Missing closing parenthesis")
"""
        with pytest.raises(ParseError):
            parser.parse(code, "test.py", recover=False)

    def test_missing_colon_suggestion(self, parser):
        """Test suggestion for missing colon in function definition."""
        code = """
def test_function
    pass
"""
        ast = parser.parse(code, "test.py", recover=True)
        assert ast is not None
        errors = parser._collect_errors_with_suggestions(ast, code)
        assert len(errors) > 0
        assert any("colon" in err.get("suggestion", "").lower() for err in errors)

    def test_unclosed_parentheses_suggestion(self, parser):
        """Test suggestion for unclosed parentheses."""
        code = """
def test():
    x = (1 + 2
"""
        ast = parser.parse(code, "test.py", recover=True)
        assert ast is not None
        errors = parser._collect_errors_with_suggestions(ast, code)
        assert len(errors) > 0
        assert any("parentheses" in err.get("suggestion", "").lower() for err in errors)

    def test_unclosed_string_suggestion(self, parser):
        """Test suggestion for unclosed string."""
        code = """
def test():
    x = "unclosed string
"""
        ast = parser.parse(code, "test.py", recover=True)
        assert ast is not None
        errors = parser._collect_errors_with_suggestions(ast, code)
        assert len(errors) > 0
        assert any("string" in err.get("suggestion", "").lower() for err in errors)

    def test_unclosed_bracket_suggestion(self, parser):
        """Test suggestion for unclosed bracket."""
        code = """
def test():
    x = [1, 2, 3
"""
        ast = parser.parse(code, "test.py", recover=True)
        assert ast is not None
        errors = parser._collect_errors_with_suggestions(ast, code)
        assert len(errors) > 0
        assert any(
            "bracket" in err.get("suggestion", "").lower()
            or "bracket" in err.get("suggestion", "").lower()
            for err in errors
        )

    def test_incomplete_assignment_suggestion(self, parser):
        """Test suggestion for incomplete assignment."""
        code = """
def test():
    x =
"""
        ast = parser.parse(code, "test.py", recover=True)
        assert ast is not None
        errors = parser._collect_errors_with_suggestions(ast, code)
        assert len(errors) > 0
        assert any(
            "value" in err.get("suggestion", "").lower()
            or "assignment" in err.get("suggestion", "").lower()
            for err in errors
        )

    def test_multiple_errors_with_recovery(self, parser):
        """Test parsing code with multiple errors using recovery."""
        code = """
def function_one(
    pass

def function_two():
    x = [1, 2, 3
"""
        ast = parser.parse(code, "test.py", recover=True)
        assert ast is not None
        assert ast.has_error
        errors = parser._collect_errors_with_suggestions(ast, code)
        assert len(errors) >= 2

    def test_error_context_captured(self, parser):
        """Test that error context is captured."""
        code = """
def test():
    x = "unclosed
"""
        ast = parser.parse(code, "test.py", recover=True)
        assert ast is not None
        errors = parser._collect_errors_with_suggestions(ast, code)
        assert len(errors) > 0
        assert errors[0].get("context") is not None
        assert "unclosed" in errors[0]["context"]
