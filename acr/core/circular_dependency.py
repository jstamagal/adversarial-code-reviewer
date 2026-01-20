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

"""Circular dependency detection for Python imports."""

from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
from pathlib import Path

from acr.core.ast_parser import ASTParser


@dataclass
class CircularDependency:
    """Represents a detected circular dependency."""

    cycle: List[str]
    severity: str
    description: str


class CircularDependencyDetector:
    """Detect circular import dependencies in Python code."""

    def __init__(self, max_depth: int = 20):
        """Initialize detector.

        Args:
            max_depth: Maximum recursion depth for cycle detection
        """
        self.parser = ASTParser()
        self.max_depth = max_depth
        self.import_graph: Dict[str, Set[str]] = {}

    def detect_all(self, root_path: Path) -> List[CircularDependency]:
        """Detect all circular dependencies in a codebase.

        Args:
            root_path: Root directory path to scan

        Returns:
            List of circular dependencies found
        """
        self._build_import_graph(root_path)
        return self._find_cycles()

    def detect_cycles(self, start_file: str, root_path: Path) -> List[CircularDependency]:
        """Detect cycles starting from a specific file.

        Args:
            start_file: File path to start from
            root_path: Root directory path for resolving relative imports

        Returns:
            List of circular dependencies starting from this file
        """
        self._build_import_graph(root_path)

        if start_file not in self.import_graph:
            return []

        cycles = []
        for target in self.import_graph[start_file]:
            cycle = self._find_path(start_file, target, set())
            if cycle and len(cycle) > 1:
                cycles.append(
                    CircularDependency(
                        cycle=cycle,
                        severity=self._calculate_severity(cycle),
                        description=self._generate_description(cycle),
                    )
                )

        return cycles

    def _build_import_graph(self, root_path: Path) -> None:
        """Build import graph from all Python files.

        Args:
            root_path: Root directory to scan
        """
        self.import_graph.clear()

        for py_file in root_path.rglob("*.py"):
            if not py_file.is_file():
                continue

            try:
                source_code = py_file.read_text(encoding="utf-8")
                ast_node = self.parser.parse(source_code, str(py_file))
                if not ast_node:
                    continue

                imports = self.parser.get_imports(ast_node)
                normalized_file = str(py_file)

                self.import_graph[normalized_file] = set()

                for imp in imports:
                    module_name = imp.get("module", "")
                    if module_name:
                        resolved_path = self._resolve_module_to_path(module_name, root_path)
                        if resolved_path:
                            self.import_graph[normalized_file].add(resolved_path)

            except Exception:
                continue

    def _resolve_module_to_path(self, module_name: str, root_path: Path) -> str:
        """Resolve module name to file path.

        Args:
            module_name: Module name from import statement
            root_path: Root directory of project

        Returns:
            Resolved file path or empty string if not found
        """
        module_parts = module_name.split(".")
        possible_paths = [
            root_path / f"{module_name}.py",
            root_path / "/".join(module_parts) / "__init__.py",
        ]

        for path in possible_paths:
            if path.exists() and path.is_file():
                return str(path)

        return ""

    def _find_cycles(self) -> List[CircularDependency]:
        """Find all cycles in import graph.

        Returns:
            List of circular dependencies
        """
        cycles = []
        visited = set()
        visiting = set()

        def dfs(node: str, path: List[str]) -> None:
            """Depth-first search to detect cycles.

            Args:
                node: Current node being visited
                path: Current path being explored
            """
            if node in visiting:
                cycle_start = path.index(node)
                cycle = path[cycle_start:] + [node]
                if len(cycle) > 1:
                    cycles.append(
                        CircularDependency(
                            cycle=cycle,
                            severity=self._calculate_severity(cycle),
                            description=self._generate_description(cycle),
                        )
                    )
                return

            if node in visited or node not in self.import_graph:
                return

            visiting.add(node)
            path.append(node)

            for neighbor in self.import_graph.get(node, set()):
                if len(path) < self.max_depth:
                    dfs(neighbor, path.copy())

            visiting.remove(node)
            visited.add(node)

        for node in self.import_graph:
            if node not in visited:
                dfs(node, [])

        return cycles

    def _find_path(self, start: str, end: str, visited: Set[str]) -> List[str]:
        """Find path between two nodes.

        Args:
            start: Starting node
            end: Target node
            visited: Set of already visited nodes

        Returns:
            List of nodes forming path, or empty list if no path
        """
        if start == end:
            return [start]

        if start in visited:
            return []

        visited.add(start)

        for neighbor in self.import_graph.get(start, set()):
            path = self._find_path(neighbor, end, visited.copy())
            if path:
                return [start] + path

        return []

    def _calculate_severity(self, cycle: List[str]) -> str:
        """Calculate severity based on cycle length.

        Args:
            cycle: List of files in cycle (includes repeated start/end node)

        Returns:
            Severity level (medium, low, info)
        """
        cycle_length = len(cycle)

        if cycle_length == 3:
            return "medium"
        elif cycle_length == 4:
            return "low"
        else:
            return "info"

    def _generate_description(self, cycle: List[str]) -> str:
        """Generate description for circular dependency.

        Args:
            cycle: List of files in the cycle

        Returns:
            Description string
        """
        if not cycle:
            return "Empty cycle"

        cycle_names = [Path(f).name for f in cycle]
        return f"Circular import detected: {' -> '.join(cycle_names)}"
