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

"""AST parser implementation."""

import hashlib
from pathlib import Path
from typing import Any, List, Optional, cast

try:
    import tree_sitter_python as tspython
    from tree_sitter import Language, Node, Parser
except ImportError:
    raise ImportError(
        "tree-sitter-python is required. Install with: pip install tree-sitter-python"
    )

from acr.utils.errors import ParseError


class ASTParser:
    """Python AST parser using tree-sitter."""

    def __init__(self):
        """Initialize AST parser."""
        if tspython is None:
            raise ImportError(
                "tree-sitter-python is required. Install with: pip install tree-sitter-python"
            )

        assert Language is not None
        assert Parser is not None
        self.language = Language(tspython.language())
        self.parser = Parser(self.language)

    def parse(self, code: str, file: str = "<string>", recover: bool = False) -> Optional[Node]:
        """Parse code string into AST.

        Args:
            code: Source code string
            file: File path for error reporting
            recover: If True, attempt to recover from syntax errors and continue parsing

        Returns:
            AST root node or None if parsing fails

        Raises:
            ParseError: If code contains syntax errors and recover=False
        """
        if not code or not code.strip():
            return None

        try:
            tree = self.parser.parse(bytes(code, "utf8"))
            root = cast(Node, tree.root_node)

            if root.has_error:
                if recover:
                    errors = self._collect_errors_with_suggestions(root, code)
                    if errors:
                        for error_info in errors:
                            self._log_syntax_error(error_info, file)
                    return root
                else:
                    errors = self._collect_errors_with_suggestions(root, code)
                    error_messages = [e["message"] for e in errors]
                    raise ParseError(f"Syntax errors found: {', '.join(error_messages)}", file, 0)

            return root

        except Exception as e:
            if not isinstance(e, ParseError):
                raise ParseError(f"Failed to parse code: {e}", file, 0) from e
            raise

    def parse_file(self, file_path: Path, recover: bool = False) -> Optional[Node]:
        """Parse a Python file.

        Args:
            file_path: Path to Python file
            recover: If True, attempt to recover from syntax errors

        Returns:
            AST root node or None if file is empty

        Raises:
            ParseError: If file cannot be read or contains syntax errors
            FileNotFoundError: If file does not exist
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if not file_path.is_file():
            raise ValueError(f"Not a file: {file_path}")

        try:
            with open(file_path, encoding="utf-8") as f:
                code = f.read()
        except UnicodeDecodeError:
            try:
                with open(file_path, encoding="latin-1") as f:
                    code = f.read()
            except Exception as e:
                raise ParseError(f"Failed to read file {file_path}: {e}", str(file_path), 0) from e

        return self.parse(code, str(file_path), recover=recover)

    def get_functions(self, root: Node) -> List[Node]:
        """Extract all function definitions from AST.

        Args:
            root: AST root node

        Returns:
            List of function definition nodes
        """
        functions = []

        def visit(node: Node):
            if node.type == "function_definition":
                functions.append(node)
            for child in node.children:
                visit(child)

        visit(root)
        return functions

    def get_classes(self, root: Node) -> List[Node]:
        """Extract all class definitions from AST.

        Args:
            root: AST root node

        Returns:
            List of class definition nodes
        """
        classes = []

        def visit(node: Node):
            if node.type == "class_definition":
                classes.append(node)
            for child in node.children:
                visit(child)

        visit(root)
        return classes

    def get_imports(self, root: Node) -> List[dict]:
        """Extract all import statements from AST.

        Args:
            root: AST root node

        Returns:
            List of import dictionaries with 'module' and 'name' keys
        """
        imports = []

        def visit(node: Node):
            if node.type == "import_statement":
                for child in node.children:
                    if child.type == "dotted_name":
                        imports.append({"module": child.text.decode("utf-8"), "name": None})
                    elif child.type == "aliased_import":
                        imports.append(self._parse_aliased_import(child))
            elif node.type == "import_from_statement":
                imports.append(self._parse_import_from(node))

            for child in node.children:
                visit(child)

        visit(root)
        return imports

    def get_call_sites(self, root: Node, function_name: str) -> List[Node]:
        """Find all call sites for a specific function.

        Args:
            root: AST root node
            function_name: Name of function to find calls for

        Returns:
            List of call nodes
        """
        call_sites = []

        def visit(node: Node):
            if node.type == "call":
                func_name = self._get_called_function_name(node)
                if func_name == function_name:
                    call_sites.append(node)
            for child in node.children:
                visit(child)

        visit(root)
        return call_sites

    def get_source_lines(self, root: Node, code: str) -> List[str]:
        """Get source code lines from AST node.

        Args:
            root: AST node
            code: Original source code

        Returns:
            List of source lines
        """
        lines = code.split("\n")
        start_line = root.start_point.row
        end_line = root.end_point.row
        return lines[start_line : end_line + 1]

    def get_node_text(self, node: Node) -> str:
        """Get text representation of an AST node.

        Args:
            node: AST node

        Returns:
            Text of the node
        """
        return node.text.decode("utf-8")

    def get_code_hash(self, code: str) -> str:
        """Get hash of code for caching.

        Args:
            code: Source code string

        Returns:
            SHA256 hash of the code
        """
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    def _collect_errors_with_suggestions(self, root: Node, code: str) -> List[dict]:
        """Collect all syntax errors from AST with helpful suggestions.

        Args:
            root: AST root node
            code: Original source code

        Returns:
            List of error dictionaries with line, message, and suggestion
        """
        errors = []
        lines = code.split("\n")

        def visit(node: Node):
            line_num = node.start_point.row + 1
            if line_num - 1 < len(lines):
                line_content = lines[line_num - 1].strip()

                if node.is_missing:
                    suggestion = self._suggest_fix_for_missing(node, line_content)
                    errors.append(
                        {
                            "line": line_num,
                            "message": f"Missing syntax at line {line_num}",
                            "suggestion": suggestion,
                            "context": line_content,
                        }
                    )
                if node.is_error:
                    suggestion = self._suggest_fix_for_error(node, line_content)
                    errors.append(
                        {
                            "line": line_num,
                            "message": f"Syntax error at line {line_num}",
                            "suggestion": suggestion,
                            "context": line_content,
                        }
                    )
            for child in node.children:
                visit(child)

        visit(root)
        return errors

    def _suggest_fix_for_missing(self, node: Node, line_content: str) -> str:
        """Suggest fix for missing syntax node.

        Args:
            node: Missing syntax node
            line_content: Content of the line with error

        Returns:
            Suggestion message
        """
        suggestions = []

        if line_content.endswith(":") and any(
            keyword in line_content
            for keyword in [
                "def ",
                "class ",
                "if ",
                "elif ",
                "else:",
                "for ",
                "while ",
                "try:",
                "except ",
                "with ",
                "async def ",
            ]
        ):
            suggestions.append("Add indented code block after this line")

        if line_content.startswith("import ") and "," in line_content:
            suggestions.append("Ensure imports are properly separated")

        if "lambda" in line_content and ":" not in line_content:
            suggestions.append("Add colon after lambda expression")

        if line_content.startswith(("return ", "yield ", "raise ")) and not line_content.endswith(
            ("(", "[", "{", "'", '"')
        ):
            suggestions.append("Add value after return/yield/raise")

        return "; ".join(suggestions) if suggestions else "Check syntax in this line"

    def _suggest_fix_for_error(self, node: Node, line_content: str) -> str:
        """Suggest fix for syntax error node.

        Args:
            node: Error node
            line_content: Content of the line with error

        Returns:
            Suggestion message
        """
        suggestions = []

        if "=" in line_content and "==" not in line_content and line_content.endswith("="):
            suggestions.append("Missing value after assignment operator")

        if "def " in line_content and ":" not in line_content:
            suggestions.append("Add colon after function definition")

        if (
            "if " in line_content
            and "elif " not in line_content
            and "else:" not in line_content
            and ":" not in line_content
        ):
            suggestions.append("Add colon after if condition")

        if ":" in line_content and not any(
            line_content.lstrip().startswith(k)
            for k in [
                "def ",
                "class ",
                "if ",
                "elif ",
                "else:",
                "for ",
                "while ",
                "try:",
                "except ",
                "with ",
                "async def ",
            ]
        ):
            suggestions.append("Check if colon is used correctly")

        if line_content.count("(") != line_content.count(")"):
            suggestions.append(
                f"{'Missing' if line_content.count('(') > line_content.count(')') else 'Extra'} parentheses"
            )

        if line_content.count("[") != line_content.count("]"):
            suggestions.append(
                f"{'Missing' if line_content.count('[') > line_content.count(']') else 'Extra'} brackets"
            )

        if line_content.count("{") != line_content.count("}"):
            suggestions.append(
                f"{'Missing' if line_content.count('{') > line_content.count('}') else 'Extra'} braces"
            )

        if '"""' in line_content or "'''" in line_content:
            if line_content.count('"""') % 2 != 0 or line_content.count("'''") % 2 != 0:
                suggestions.append("Unclosed multiline string")

        if '"' in line_content and line_content.count('"') % 2 != 0:
            suggestions.append("Unclosed double-quoted string")

        if "'" in line_content and line_content.count("'") % 2 != 0:
            suggestions.append("Unclosed single-quoted string")

        return (
            "; ".join(suggestions) if suggestions else "Check indentation, punctuation, and syntax"
        )

    def _log_syntax_error(self, error_info: dict, file: str):
        """Log a syntax error with helpful information.

        Args:
            error_info: Error information dictionary
            file: File path
        """
        from acr.utils.logger import get_logger

        logger = get_logger(__name__)
        logger.warning(f"Syntax error in {file}:{error_info['line']}: {error_info['message']}")
        if error_info.get("suggestion"):
            logger.warning(f"  Suggestion: {error_info['suggestion']}")
        if error_info.get("context"):
            logger.warning(f"  Context: {error_info['context']}")

    def _collect_errors(self, root: Node) -> List[str]:
        """Collect all syntax errors from AST.

        Args:
            root: AST root node

        Returns:
            List of error messages
        """
        errors = []

        def visit(node: Node):
            if node.is_missing:
                errors.append(f"Missing syntax at line {node.start_point.row + 1}")
            if node.is_error:
                errors.append(f"Syntax error at line {node.start_point.row + 1}")
            for child in node.children:
                visit(child)

        visit(root)
        return errors

    def _parse_aliased_import(self, node: Node) -> dict:
        """Parse an aliased import (e.g., 'import x as y').

        Args:
            node: Aliased import node

        Returns:
            Import dictionary
        """
        result = {"module": None, "name": None}
        for child in node.children:
            if child.type == "dotted_name":
                result["module"] = child.text.decode("utf-8")
            elif child.type == "identifier":
                result["name"] = child.text.decode("utf-8")
        return result

    def _parse_import_from(self, node: Node) -> dict:
        """Parse a 'from x import y' statement.

        Args:
            node: Import from node

        Returns:
            Import dictionary
        """
        result = {"module": None, "name": None}
        for child in node.children:
            if child.type == "dotted_name":
                result["module"] = child.text.decode("utf-8")
            elif child.type == "identifier":
                result["name"] = child.text.decode("utf-8")
        return result

    def _get_called_function_name(self, call_node: Node) -> Optional[str]:
        """Get the name of the function being called.

        Args:
            call_node: Call AST node

        Returns:
            Function name or None
        """
        for child in call_node.children:
            if child.type == "identifier":
                return child.text.decode("utf-8")
            elif child.type == "attribute":
                return self._get_attribute_name(child)
        return None

    def _get_attribute_name(self, attr_node: Node) -> Optional[str]:
        """Get the full attribute name (e.g., 'module.function').

        Args:
            attr_node: Attribute node

        Returns:
            Attribute name or None
        """
        parts = []
        for child in attr_node.children:
            if child.type == "identifier":
                parts.append(child.text.decode("utf-8"))
            elif child.type == "attribute":
                nested = self._get_attribute_name(child)
                if nested:
                    parts.append(nested)
        return ".".join(reversed(parts))

    def extract_analysis_data(self, root: Node) -> dict:
        """Extract useful analysis data from AST.

        Args:
            root: AST root node

        Returns:
            Dictionary with functions and call sites data
        """
        functions = self.get_functions(root)
        call_sites = []

        for func in functions:
            func_name = self._get_function_name(func)
            calls = self._find_calls_in_function(func)
            for call_node in calls:
                call_name = self._get_called_function_name(call_node)
                if call_name:
                    call_sites.append(
                        {
                            "name": call_name,
                            "line": call_node.start_point.row + 1,
                            "function": func_name,
                        }
                    )

        return {"functions": functions, "call_sites": call_sites}

    def _get_function_name(self, func_node: Node) -> Optional[str]:
        """Get function name from function definition node."""
        for child in func_node.children:
            if child.type == "identifier":
                return child.text.decode("utf-8")
        return None

    def _find_calls_in_function(self, func_node: Node) -> List[Node]:
        """Find all function calls within a function."""
        calls = []

        def visit(node: Node):
            if node.type == "call":
                calls.append(node)
            for child in node.children:
                visit(child)

        visit(func_node)
        return calls
