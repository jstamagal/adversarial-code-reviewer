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

"""Taint tracking implementation."""

from typing import Set, List, Any, Optional, Dict, Tuple
from dataclasses import dataclass
from ..utils.logger import get_logger
from .entry_points import EntryPoint, EntryPointIdentifier
from .sink_identification import Sink, SinkIdentifier
from .dfg_builder import DFGBuilder
from .cfg_builder import CFGBuilder

logger = get_logger(__name__)


@dataclass
class TaintPath:
    """Represents a complete taint flow from source to sink."""

    source_var: str
    source_line: int
    source_function: str
    source_type: str
    sink_var: str
    sink_line: int
    sink_function: str
    sink_type: str
    path: List[str]
    sanitized: bool = False


class TaintedVar:
    """Represents a tainted variable with tracking metadata."""

    def __init__(
        self, name: str, source_line: int, source_function: str = "", source_type: str = "unknown"
    ):
        """Initialize tainted variable.

        Args:
            name: Variable name
            source_line: Line where taint originated
            source_function: Function where taint originated
            source_type: Type of taint source (user_input, env_var, file, etc.)
        """
        self.name = name
        self.source_line = source_line
        self.source_function = source_function
        self.source_type = source_type
        self.sanitized: bool = False
        self.propagation_path: List[str] = []


class TaintTracker:
    """Track taint propagation through code."""

    def __init__(self):
        """Initialize taint tracker."""
        self.tainted_vars: Dict[str, TaintedVar] = {}
        self.sanitized_vars: Set[str] = set()
        self.taint_flows: List[Dict[str, Any]] = []
        self.taint_paths: List[TaintPath] = []

        self.entry_point_identifier = EntryPointIdentifier()
        self.sink_identifier = SinkIdentifier()
        self.dfg_builder = DFGBuilder()
        self.cfg_builder = CFGBuilder()

        from .ast_parser import ASTParser

        self.parser = ASTParser()

        self.untrusted_sources = {
            "flask": [
                "request.form",
                "request.args",
                "request.values",
                "request.json",
                "request.files",
                "request.data",
                "request.cookies",
            ],
            "fastapi": [
                "request.query_params",
                "request.path_params",
                "request.json",
                "request.form",
                "request.cookies",
            ],
            "django": [
                "request.GET",
                "request.POST",
                "request.FILES",
                "request.COOKIES",
                "request.body",
            ],
            "env": ["os.environ", "os.getenv", "os.environ.get"],
            "stdin": ["sys.stdin.read", "input", "sys.stdin.readline"],
            "file": ["open", "file.read", "file.readline"],
        }

    def add_taint_source(
        self, name: str, source_line: int, source_function: str = "", source_type: str = "unknown"
    ) -> bool:
        """Mark a variable as tainted.

        Args:
            name: Variable name
            source_line: Line where taint originated
            source_function: Function where taint originated
            source_type: Type of taint source (user_input, env_var, file, etc.)

        Returns:
            True if variable was marked as tainted, False if already sanitized
        """
        if name in self.sanitized_vars:
            logger.debug(f"Variable {name} is already sanitized, not marking as tainted")
            return False
        self.tainted_vars[name] = TaintedVar(name, source_line, source_function, source_type)
        logger.debug(f"Added taint source: {name} at line {source_line} (type: {source_type})")
        return True

    def discover_taint_sources_from_entry_points(
        self, code: str, file: str = "<string>"
    ) -> List[TaintedVar]:
        """Automatically discover taint sources from entry points.

        Args:
            code: Source code string
            file: File path for error reporting

        Returns:
            List of discovered tainted variables
        """
        discovered: List[TaintedVar] = []

        try:
            entry_points = self.entry_point_identifier.identify(code, file)

            for ep in entry_points:
                if ep.type in ["flask", "fastapi", "django"]:
                    var_name = f"{ep.function_name}_request"
                    tvar = TaintedVar(var_name, ep.line, ep.function_name, "user_input")
                    self.tainted_vars[var_name] = tvar
                    discovered.append(tvar)
                    logger.debug(f"Discovered taint source from {ep.type} route: {var_name}")

        except Exception as e:
            logger.warning(f"Error discovering taint sources: {e}")

        return discovered

    def discover_taint_sources_from_code(
        self, code: str, file: str = "<string>"
    ) -> List[TaintedVar]:
        """Discover taint sources by analyzing code patterns.

        Args:
            code: Source code string
            file: File path for error reporting

        Returns:
            List of discovered tainted variables
        """
        discovered: List[TaintedVar] = []

        try:
            lines = code.split("\n")

            for line_num, line in enumerate(lines, start=1):
                line_lower = line.lower()

                for source_type, patterns in self.untrusted_sources.items():
                    for pattern in patterns:
                        if pattern in line_lower:
                            var_name = f"taint_{source_type}_{line_num}"

                            if (
                                var_name not in self.tainted_vars
                                and var_name not in self.sanitized_vars
                            ):
                                tvar = TaintedVar(var_name, line_num, "", source_type)
                                self.tainted_vars[var_name] = tvar
                                discovered.append(tvar)
                                logger.debug(
                                    f"Discovered taint from pattern '{pattern}': {var_name}"
                                )

        except Exception as e:
            logger.warning(f"Error discovering taint from code: {e}")

        return discovered

    def add_sanitizer(self, var: str) -> None:
        """Mark a variable as sanitized.

        Args:
            var: Variable that sanitizes taint
        """
        self.sanitized_vars.add(var)
        if var in self.tainted_vars:
            self.tainted_vars[var].sanitized = True
        logger.debug(f"Added sanitizer: {var}")

    def is_tainted(self, var: str) -> bool:
        """Check if variable is tainted.

        Args:
            var: Variable name

        Returns:
            True if tainted, False otherwise
        """
        if var in self.sanitized_vars:
            return False
        if var in self.tainted_vars:
            return not self.tainted_vars[var].sanitized
        return False

    def propagate(self, dfg: Any, cfg: Any = None) -> List[Dict[str, Any]]:
        """Propagate taint through data flow and control flow.

        Args:
            dfg: Data Flow Graph (expected to have edges and nodes)
            cfg: Control Flow Graph (optional, for better propagation)

        Returns:
            List of tainted sink information
        """
        tainted_sinks = []

        if dfg is None:
            return tainted_sinks

        try:
            if hasattr(dfg, "edges"):
                for edge in dfg.edges:
                    source, target, data = edge

                    if self._is_source_tainted(source):
                        if not self._is_target_sanitized(target):
                            sink_info = {
                                "source": source,
                                "target": target,
                                "edge_data": data,
                                "tainted_vars": [
                                    v for v in self.tainted_vars.values() if not v.sanitized
                                ],
                            }
                            tainted_sinks.append(sink_info)
                            self.taint_flows.append(sink_info)

                            if isinstance(source, str) and source in self.tainted_vars:
                                tvar = self.tainted_vars[source]
                                tvar.propagation_path.append(target)

        except Exception as e:
            logger.warning(f"Error during taint propagation: {e}")

        return tainted_sinks

    def find_taint_paths_to_sinks(self, code: str, file: str = "<string>") -> List[TaintPath]:
        """Find complete taint paths from sources to sinks.

        Args:
            code: Source code string
            file: File path for error reporting

        Returns:
            List of TaintPath objects representing complete flows
        """
        paths: List[TaintPath] = []

        try:
            ast_node = self.parser.parse(code, file)
            if ast_node is None:
                return paths

            dfg = self.dfg_builder.build(ast_node)
            sinks = self.sink_identifier.identify(code, file)

            for sink in sinks:
                for var_name, tvar in self.tainted_vars.items():
                    if tvar.sanitized:
                        continue

                    path = self._find_path_to_sink(dfg, var_name, sink)

                    if path:
                        sanitized_in_path = self._is_path_sanitized(path)

                        taint_path = TaintPath(
                            source_var=var_name,
                            source_line=tvar.source_line,
                            source_function=tvar.source_function,
                            source_type=tvar.source_type,
                            sink_var=sink.sink_call,
                            sink_line=sink.line,
                            sink_function=sink.function_name,
                            sink_type=sink.type,
                            path=path,
                            sanitized=sanitized_in_path,
                        )
                        paths.append(taint_path)
                        self.taint_paths.append(taint_path)

        except Exception as e:
            logger.warning(f"Error finding taint paths: {e}")

        return paths

    def _find_path_to_sink(self, dfg: Any, source_var: str, sink: Sink) -> List[str]:
        """Find a path from source variable to sink using DFS.

        Args:
            dfg: Data Flow Graph
            source_var: Source variable name
            sink: Sink object

        Returns:
            List of variable names representing path
        """
        path: List[str] = []
        visited: Set[str] = set()
        target = sink.sink_call

        def dfs(current: str, target_str: str, current_path: List[str]) -> bool:
            """Depth-first search for path to target."""
            if current in visited:
                return False
            if current == target_str or target_str in str(current):
                path.extend(current_path + [current])
                return True

            visited.add(current)

            if hasattr(dfg, "edges"):
                for edge in dfg.edges:
                    if len(edge) >= 3:
                        src, tgt, _ = edge
                        if str(src) == current:
                            if dfs(str(tgt), target_str, current_path + [current]):
                                return True

            return False

        dfs(source_var, target, [])
        return path

        return path

    def _is_path_sanitized(self, path: List[str]) -> bool:
        """Check if any variable in path is sanitized.

        Args:
            path: List of variable names

        Returns:
            True if path contains sanitized variable
        """
        for var in path:
            if var in self.sanitized_vars:
                return True
        return False

    def _is_source_tainted(self, source: Any) -> bool:
        """Check if a source node is tainted.

        Args:
            source: Source node from DFG

        Returns:
            True if source is tainted
        """
        if isinstance(source, str):
            return self.is_tainted(source)
        return False

    def _is_target_sanitized(self, target: Any) -> bool:
        """Check if a target node is sanitized.

        Args:
            target: Target node from DFG

        Returns:
            True if target is sanitized
        """
        if isinstance(target, str):
            return target in self.sanitized_vars
        return False

    def get_tainted_variables(self) -> List[str]:
        """Get list of all tainted variable names.

        Returns:
            List of tainted variable names
        """
        return [var.name for var in self.tainted_vars.values() if not var.sanitized]

    def get_taint_source_info(self, var_name: str) -> Optional[Dict[str, Any]]:
        """Get source information for a tainted variable.

        Args:
            var_name: Variable name

        Returns:
            Dictionary with source info or None
        """
        if var_name in self.tainted_vars:
            tvar = self.tainted_vars[var_name]
            return {
                "name": tvar.name,
                "source_line": tvar.source_line,
                "source_function": tvar.source_function,
                "sanitized": tvar.sanitized,
            }
        return None

    def reset(self) -> None:
        """Reset taint tracking state."""
        self.tainted_vars.clear()
        self.sanitized_vars.clear()
        self.taint_flows.clear()
        self.taint_paths.clear()

    def analyze(self, code: str, file: str = "<string>") -> Dict[str, Any]:
        """Perform complete taint analysis on code.

        Args:
            code: Source code string
            file: File path for error reporting

        Returns:
            Dictionary with analysis results including sources, sinks, paths
        """
        self.reset()

        results: Dict[str, Any] = {
            "file": file,
            "sources": [],
            "sinks": [],
            "sanitizers": [],
            "taint_paths": [],
            "tainted_vars": [],
        }

        try:
            results["sources"] = self.discover_taint_sources_from_code(code, file)
            results["sinks"] = self.sink_identifier.identify(code, file)
            results["sanitizers"] = self.detect_sanitization_in_code(code, file)

            for sanitization in results["sanitizers"]:
                self.add_sanitizer(f"sanitized_{sanitization['line']}")

            results["taint_paths"] = self.find_taint_paths_to_sinks(code, file)
            results["tainted_vars"] = list(self.tainted_vars.values())

            logger.info(
                f"Taint analysis complete for {file}: found {len(results['taint_paths'])} taint paths"
            )

        except Exception as e:
            logger.error(f"Error during taint analysis: {e}")

        return results

    def identify_sanitization(self, code_node: Any) -> Optional[str]:
        """Identify if a code node represents sanitization.

        Args:
            code_node: AST node or code structure

        Returns:
            Variable name being sanitized or None
        """
        if code_node is None:
            return None

        try:
            node_str = str(code_node).lower()

            sanitization_patterns = {
                "html.escape": "html_escape",
                "markupsafe.escape": "html_escape",
                "urllib.parse.quote": "url_escape",
                "urllib.parse.quote_plus": "url_escape",
                "re.escape": "regex_escape",
                "validate": "validate",
                "sanitize": "sanitize",
                "clean": "clean",
                "strip": "strip",
                "escape": "escape",
                "encode": "encode",
                "filter": "filter",
                "int(": "type_coercion",
                "float(": "type_coercion",
                "str(": "type_coercion",
                "re.sub": "regex_sanitization",
                "re.match": "regex_validation",
                "re.fullmatch": "regex_validation",
                "validator": "validation",
            }

            for pattern, sanitization_type in sanitization_patterns.items():
                if pattern in node_str:
                    logger.debug(f"Identified sanitization: {sanitization_type}")
                    return sanitization_type

        except Exception as e:
            logger.warning(f"Error identifying sanitization: {e}")

        return None

    def detect_sanitization_in_code(
        self, code: str, file: str = "<string>"
    ) -> List[Dict[str, Any]]:
        """Detect sanitization operations in code.

        Args:
            code: Source code string
            file: File path for error reporting

        Returns:
            List of sanitization operations found
        """
        sanitizations: List[Dict[str, Any]] = []

        try:
            lines = code.split("\n")

            for line_num, line in enumerate(lines, start=1):
                sanitized = self.identify_sanitization(line)

                if sanitized:
                    sanitizations.append(
                        {
                            "line": line_num,
                            "code": line.strip(),
                            "type": sanitized,
                            "file": file,
                        }
                    )

        except Exception as e:
            logger.warning(f"Error detecting sanitization: {e}")

        return sanitizations
