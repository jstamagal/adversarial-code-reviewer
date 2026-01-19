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

"""Entry point identification for security analysis."""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from acr.core.ast_parser import ASTParser


@dataclass
class EntryPoint:
    """Represents an identified entry point."""

    type: str
    name: str
    file: str
    line: int
    function_name: str
    path: str | None = None
    method: str | None = None
    details: dict[str, Any] | None = None


class EntryPointIdentifier:
    """Identify entry points in Python code."""

    def __init__(self):
        """Initialize entry point identifier."""
        self.parser = ASTParser()
        self.framework_patterns = {
            "flask": ["@app.route", "@bp.route", "flask.Flask"],
            "fastapi": ["@app.get", "@app.post", "@app.put", "@app.delete", "@app.patch"],
            "django": ["View", "APIView", "TemplateView", "ListView"],
            "click": ["@click.command", "@click.group"],
        }

    def identify(self, code: str, file: str = "<string>") -> List[EntryPoint]:
        """Identify all entry points in code.

        Args:
            code: Source code string
            file: File path for error reporting

        Returns:
            List of identified entry points
        """
        try:
            ast_node = self.parser.parse(code, file)
            if not ast_node:
                return []

            entry_points: List[EntryPoint] = []

            entry_points.extend(self._find_flask_routes(ast_node, code, file))
            entry_points.extend(self._find_fastapi_endpoints(ast_node, code, file))
            entry_points.extend(self._find_django_views(ast_node, code, file))
            entry_points.extend(self._find_cli_commands(ast_node, code, file))
            entry_points.extend(self._find_public_functions(ast_node, code, file))

            return entry_points

        except Exception:
            return []

    def _find_flask_routes(self, root, code: str, file: str) -> List[EntryPoint]:
        """Find Flask route decorators.

        Args:
            root: AST root node
            code: Source code
            file: File path

        Returns:
            List of Flask route entry points
        """
        entry_points: List[EntryPoint] = []
        decorators = self._find_decorators_by_names(root, ["route"])

        for decorator in decorators:
            func_node = self._find_decorated_function(decorator)
            if func_node:
                func_name = self.parser._get_function_name(func_node)
                if not func_name:
                    continue
                path = self._extract_route_path(decorator)

                entry_points.append(
                    EntryPoint(
                        type="flask_route",
                        name=f"Flask route: {func_name}",
                        file=file,
                        line=decorator.start_point.row + 1,
                        function_name=func_name,
                        path=path,
                        method="GET",
                    )
                )

        return entry_points

    def _find_fastapi_endpoints(self, root, code: str, file: str) -> List[EntryPoint]:
        """Find FastAPI endpoint decorators.

        Args:
            root: AST root node
            code: Source code
            file: File path

        Returns:
            List of FastAPI entry points
        """
        entry_points: List[EntryPoint] = []
        http_methods = ["get", "post", "put", "delete", "patch", "options", "head"]

        for method in http_methods:
            decorators = self._find_decorators_by_names(root, [method])

            for decorator in decorators:
                func_node = self._find_decorated_function(decorator)
                if func_node:
                    func_name = self.parser._get_function_name(func_node)
                    if not func_name:
                        continue
                    path = self._extract_route_path(decorator)

                    entry_points.append(
                        EntryPoint(
                            type="fastapi_endpoint",
                            name=f"FastAPI {method.upper()}: {func_name}",
                            file=file,
                            line=decorator.start_point.row + 1,
                            function_name=func_name,
                            path=path,
                            method=method.upper(),
                        )
                    )

        return entry_points

    def _find_django_views(self, root, code: str, file: str) -> List[EntryPoint]:
        """Find Django view classes.

        Args:
            root: AST root node
            code: Source code
            file: File path

        Returns:
            List of Django view entry points
        """
        entry_points: List[EntryPoint] = []
        classes = self.parser.get_classes(root)

        for class_node in classes:
            class_name = self._get_class_name(class_node)
            if self._is_django_view(class_node):
                methods = self._find_http_methods(class_node)

                for method_name in methods:
                    entry_points.append(
                        EntryPoint(
                            type="django_view",
                            name=f"Django view: {class_name}.{method_name}",
                            file=file,
                            line=class_node.start_point.row + 1,
                            function_name=f"{class_name}.{method_name}",
                            method=method_name.upper(),
                        )
                    )

        return entry_points

    def _find_cli_commands(self, root, code: str, file: str) -> List[EntryPoint]:
        """Find Click CLI commands.

        Args:
            root: AST root node
            code: Source code
            file: File path

        Returns:
            List of CLI command entry points
        """
        entry_points: List[EntryPoint] = []
        decorators = self._find_decorators_by_names(root, ["command", "group"])

        for decorator in decorators:
            func_node = self._find_decorated_function(decorator)
            if func_node:
                func_name = self.parser._get_function_name(func_node)
                if not func_name:
                    continue
                entry_points.append(
                    EntryPoint(
                        type="cli_command",
                        name=f"CLI command: {func_name}",
                        file=file,
                        line=decorator.start_point.row + 1,
                        function_name=func_name,
                    )
                )

        return entry_points

    def _find_public_functions(self, root, code: str, file: str) -> List[EntryPoint]:
        """Find public functions (non-private, top-level).

        Args:
            root: AST root node
            code: Source code
            file: File path

        Returns:
            List of public function entry points
        """
        entry_points: List[EntryPoint] = []
        functions = self.parser.get_functions(root)

        for func_node in functions:
            func_name = self.parser._get_function_name(func_node=func_node)

            if func_name and not func_name.startswith("_"):
                if self._is_top_level_function(func_node) and not self._has_decorators(func_node):
                    entry_points.append(
                        EntryPoint(
                            type="public_function",
                            name=f"Public function: {func_name}",
                            file=file,
                            line=func_node.start_point.row + 1,
                            function_name=func_name,
                        )
                    )

        return entry_points

    def _find_decorators_by_names(self, root, names: List[str]) -> List:
        """Find decorator nodes with specific names.

        Args:
            root: AST root node
            names: List of decorator names to find

        Returns:
            List of decorator nodes
        """
        decorators = []

        def visit(node):
            if node.type == "decorator":
                text = self.parser.get_node_text(node)
                for name in names:
                    if name in text:
                        decorators.append(node)
                        break
            for child in node.children:
                visit(child)

        visit(root)
        return decorators

    def _find_decorated_function(self, decorator) -> Any | None:
        """Find the function decorated by a decorator node.

        Args:
            decorator: Decorator node

        Returns:
            Function definition node or None
        """
        parent = decorator.parent

        if parent is None or parent.type != "decorated_definition":
            return None

        for child in parent.children:
            if child.type == "function_definition":
                return child

        return None

    def _extract_route_path(self, decorator) -> Optional[str]:
        """Extract route path from decorator.

        Args:
            decorator: Decorator node

        Returns:
            Route path string or None
        """
        text = self.parser.get_node_text(decorator)

        if "(" not in text:
            return None

        try:
            start = text.index("(") + 1
            end = text.index(")")
            inner = text[start:end].strip()

            if inner.startswith(('"', "'")):
                quote_char = inner[0]
                end_quote = inner.index(quote_char, 1)
                return inner[1:end_quote]

            return inner

        except (ValueError, IndexError):
            return None

    def _get_class_name(self, class_node) -> Optional[str]:
        """Get class name from class definition node."""
        for child in class_node.children:
            if child.type == "identifier":
                return self.parser.get_node_text(child)
        return None

    def _is_django_view(self, class_node) -> bool:
        """Check if a class is a Django view."""
        class_name = self._get_class_name(class_node)
        if not class_name:
            return False

        view_bases = [
            "View",
            "APIView",
            "TemplateView",
            "ListView",
            "DetailView",
            "CreateView",
            "UpdateView",
            "DeleteView",
        ]

        for base in view_bases:
            if base in class_name:
                return True

        return False

    def _find_http_methods(self, class_node) -> List[str]:
        """Find HTTP method implementations in a class.

        Args:
            class_node: Class definition node

        Returns:
            List of method names (get, post, put, delete, etc.)
        """
        methods = []
        http_method_names = ["get", "post", "put", "delete", "patch", "head", "options"]

        def visit(node):
            if node.type == "function_definition":
                func_name = self.parser._get_function_name(func_node=node)
                if func_name in http_method_names:
                    methods.append(func_name)
            for child in node.children:
                visit(child)

        visit(class_node)
        return methods

    def _is_top_level_function(self, func_node) -> bool:
        """Check if a function is defined at top level."""
        parent = func_node.parent
        while parent:
            if parent.type == "module":
                return True
            if parent.type == "class_definition":
                return False
            parent = parent.parent
        return True

    def _has_decorators(self, func_node) -> bool:
        """Check if a function has decorators.

        Args:
            func_node: Function definition node

        Returns:
            True if function has decorators
        """
        parent = func_node.parent
        if parent and parent.type == "decorated_definition":
            return True
        return False
