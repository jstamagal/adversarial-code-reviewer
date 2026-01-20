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

"""Sink identification for security analysis."""

from dataclasses import dataclass
from typing import Any, List, Optional

from acr.core.ast_parser import ASTParser


@dataclass
class Sink:
    """Represents an identified sink."""

    type: str
    name: str
    file: str
    line: int
    function_name: str
    sink_call: str
    args: List[str] | None = None
    details: dict[str, Any] | None = None


class SinkIdentifier:
    """Identify security-sensitive sinks in Python code."""

    def __init__(self):
        """Initialize sink identifier."""
        self.parser = ASTParser()
        self.sink_patterns = {
            "sql_execution": {
                "patterns": [
                    r"\.execute\s*\(",
                    r"\.executemany\s*\(",
                    r"\.executescript\s*\(",
                ],
                "module_patterns": ["sqlite3", "psycopg2", "mysql", "pymongo", "sqlalchemy"],
            },
            "shell_command": {
                "patterns": [
                    r"os\.system\s*\(",
                    r"os\.popen\s*\(",
                    r"subprocess\.(call|run|Popen|check_output|check_call)\s*\(",
                    r"commands\.(getoutput|getstatusoutput)\s*\(",
                ],
                "module_patterns": ["os", "subprocess", "commands"],
            },
            "network_operation": {
                "patterns": [
                    r"requests\.(get|post|put|delete|patch|request)\s*\(",
                    r"urlopen\s*\(",
                    r"urllib\.request\.(urlopen|Request)\s*\(",
                    r"httpx\.(get|post|put|delete|patch|request)\s*\(",
                    r"socket\.connect\s*\(",
                    r"\.connect\s*\(",
                ],
                "module_patterns": ["requests", "urllib", "httpx", "socket"],
            },
            "file_operation": {
                "patterns": [
                    r"(?<!\w)open\s*\(",
                    r"(?<!\w)file\s*\(",
                    r"\.write\s*\(",
                    r"\.read\s*\(",
                ],
                "module_patterns": ["os", "pathlib"],
            },
            "serialization": {
                "patterns": [
                    r"pickle\.(load|loads)\s*\(",
                    r"cPickle\.(load|loads)\s*\(",
                    r"yaml\.load\s*\(",
                    r"yaml\.unsafe_load\s*\(",
                    r"marshal\.load\s*\(",
                    r"shelve\.open\s*\(",
                    r"eval\s*\(",
                    r"exec\s*\(",
                    r"__import__\s*\(",
                ],
                "module_patterns": ["pickle", "cPickle", "yaml", "marshal", "shelve", "builtins"],
            },
        }

    def identify(self, code: str, file: str = "<string>") -> List[Sink]:
        """Identify all sinks in code.

        Args:
            code: Source code string
            file: File path for error reporting

        Returns:
            List of identified sinks
        """
        try:
            ast_node = self.parser.parse(code, file)
            if not ast_node:
                return []

            sinks: List[Sink] = []

            sinks.extend(self._find_sql_sinks(ast_node, code, file))
            sinks.extend(self._find_shell_sinks(ast_node, code, file))
            sinks.extend(self._find_network_sinks(ast_node, code, file))
            sinks.extend(self._find_file_sinks(ast_node, code, file))
            sinks.extend(self._find_serialization_sinks(ast_node, code, file))

            return sinks

        except Exception:
            return []

    def _find_sql_sinks(self, root, code: str, file: str) -> List[Sink]:
        """Find SQL execution sinks.

        Args:
            root: AST root node
            code: Source code
            file: File path

        Returns:
            List of SQL sink entries
        """
        sinks: List[Sink] = []
        patterns = [
            r"\.execute\s*\(",
            r"\.executemany\s*\(",
            r"\.executescript\s*\(",
        ]

        for pattern in patterns:
            matches = self._find_call_pattern(root, pattern, code)
            for match in matches:
                func_name = self._find_enclosing_function(match)
                sink_text = self.parser.get_node_text(match)

                sinks.append(
                    Sink(
                        type="sql_execution",
                        name=f"SQL execution: {sink_text[:50]}",
                        file=file,
                        line=match.start_point.row + 1,
                        function_name=func_name or "<unknown>",
                        sink_call=sink_text,
                        args=self._extract_call_args(match, code),
                    )
                )

        return sinks

    def _find_shell_sinks(self, root, code: str, file: str) -> List[Sink]:
        """Find shell command execution sinks.

        Args:
            root: AST root node
            code: Source code
            file: File path

        Returns:
            List of shell sink entries
        """
        sinks: List[Sink] = []
        patterns = [
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"subprocess\.(call|run|Popen|check_output|check_call)\s*\(",
            r"commands\.(getoutput|getstatusoutput)\s*\(",
        ]

        for pattern in patterns:
            matches = self._find_call_pattern(root, pattern, code)
            for match in matches:
                func_name = self._find_enclosing_function(match)
                sink_text = self.parser.get_node_text(match)

                sinks.append(
                    Sink(
                        type="shell_command",
                        name=f"Shell command: {sink_text[:50]}",
                        file=file,
                        line=match.start_point.row + 1,
                        function_name=func_name or "<unknown>",
                        sink_call=sink_text,
                        args=self._extract_call_args(match, code),
                    )
                )

        return sinks

    def _find_file_sinks(self, root, code: str, file: str) -> List[Sink]:
        """Find file operation sinks.

        Args:
            root: AST root node
            code: Source code
            file: File path

        Returns:
            List of file sink entries
        """
        sinks: List[Sink] = []
        patterns = [
            r"(?<!\w)open\s*\(",
            r"(?<!\w)file\s*\(",
            r"\.write\s*\(",
            r"\.read\s*\(",
        ]

        for pattern in patterns:
            matches = self._find_call_pattern(root, pattern, code)
            for match in matches:
                func_name = self._find_enclosing_function(match)
                sink_text = self.parser.get_node_text(match)

                sinks.append(
                    Sink(
                        type="file_operation",
                        name=f"File operation: {sink_text[:50]}",
                        file=file,
                        line=match.start_point.row + 1,
                        function_name=func_name or "<unknown>",
                        sink_call=sink_text,
                        args=self._extract_call_args(match, code),
                    )
                )

        return sinks

    def _find_network_sinks(self, root, code: str, file: str) -> List[Sink]:
        """Find network operation sinks.

        Args:
            root: AST root node
            code: Source code
            file: File path

        Returns:
            List of network sink entries
        """
        sinks: List[Sink] = []
        patterns = [
            r"requests\.(get|post|put|delete|patch|request)\s*\(",
            r"urlopen\s*\(",
            r"urllib\.request\.(urlopen|Request)\s*\(",
            r"httpx\.(get|post|put|delete|patch|request)\s*\(",
            r"socket\.connect\s*\(",
            r"\.connect\s*\(",
        ]

        for pattern in patterns:
            matches = self._find_call_pattern(root, pattern, code)
            for match in matches:
                func_name = self._find_enclosing_function(match)
                sink_text = self.parser.get_node_text(match)

                sinks.append(
                    Sink(
                        type="network_operation",
                        name=f"Network operation: {sink_text[:50]}",
                        file=file,
                        line=match.start_point.row + 1,
                        function_name=func_name or "<unknown>",
                        sink_call=sink_text,
                        args=self._extract_call_args(match, code),
                    )
                )

        return sinks

    def _find_serialization_sinks(self, root, code: str, file: str) -> List[Sink]:
        """Find serialization/deserialization sinks.

        Args:
            root: AST root node
            code: Source code
            file: File path

        Returns:
            List of serialization sink entries
        """
        sinks: List[Sink] = []
        patterns = [
            r"pickle\.(load|loads)\s*\(",
            r"cPickle\.(load|loads)\s*\(",
            r"yaml\.load\s*\(",
            r"yaml\.unsafe_load\s*\(",
            r"marshal\.load\s*\(",
            r"shelve\.open\s*\(",
            r"eval\s*\(",
            r"exec\s*\(",
            r"__import__\s*\(",
        ]

        for pattern in patterns:
            matches = self._find_call_pattern(root, pattern, code)
            for match in matches:
                func_name = self._find_enclosing_function(match)
                sink_text = self.parser.get_node_text(match)

                sinks.append(
                    Sink(
                        type="serialization",
                        name=f"Serialization: {sink_text[:50]}",
                        file=file,
                        line=match.start_point.row + 1,
                        function_name=func_name or "<unknown>",
                        sink_call=sink_text,
                        args=self._extract_call_args(match, code),
                    )
                )

        return sinks

    def _find_call_pattern(self, root, pattern: str, code: str) -> List:
        """Find function call nodes matching a pattern.

        Args:
            root: AST root node
            pattern: Regex pattern to match
            code: Source code

        Returns:
            List of matching call nodes
        """
        import re

        matches = []

        def visit(node):
            if node.type == "call":
                text = self.parser.get_node_text(node)
                if re.search(pattern, text):
                    matches.append(node)
            for child in node.children:
                visit(child)

        visit(root)
        return matches

    def _find_enclosing_function(self, node) -> Optional[str]:
        """Find the name of the function containing a node.

        Args:
            node: AST node

        Returns:
            Function name or None
        """
        parent = node.parent
        while parent:
            if parent.type == "function_definition":
                for child in parent.children:
                    if child.type == "identifier":
                        return self.parser.get_node_text(child)
            parent = parent.parent
        return None

    def _extract_call_args(self, call_node, code: str) -> List[str]:
        """Extract arguments from a function call.

        Args:
            call_node: Call node
            code: Source code

        Returns:
            List of argument strings
        """
        args = []

        for child in call_node.children:
            if child.type == "argument_list" or child.type == "parenthesized_expression":
                arg_text = self.parser.get_node_text(child)
                if arg_text.startswith("(") and arg_text.endswith(")"):
                    arg_text = arg_text[1:-1]
                if arg_text:
                    args.append(arg_text)

        return args
