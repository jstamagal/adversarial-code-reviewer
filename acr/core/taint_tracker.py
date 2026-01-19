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

from typing import Set, List, Any, Optional, Dict
from ..utils.logger import get_logger

logger = get_logger(__name__)


class TaintedVar:
    """Represents a tainted variable with tracking metadata."""

    def __init__(self, name: str, source_line: int, source_function: str = ""):
        """Initialize tainted variable.

        Args:
            name: Variable name
            source_line: Line where taint originated
            source_function: Function where taint originated
        """
        self.name = name
        self.source_line = source_line
        self.source_function = source_function
        self.sanitized: bool = False


class TaintTracker:
    """Track taint propagation through code."""

    def __init__(self):
        """Initialize taint tracker."""
        self.tainted_vars: Dict[str, TaintedVar] = {}
        self.sanitized_vars: Set[str] = set()
        self.taint_flows: List[Dict[str, Any]] = []

    def add_taint_source(self, name: str, source_line: int, source_function: str = "") -> bool:
        """Mark a variable as tainted.

        Args:
            name: Variable name
            source_line: Line where taint originated
            source_function: Function where taint originated

        Returns:
            True if variable was marked as tainted, False if already sanitized
        """
        if name in self.sanitized_vars:
            logger.debug(f"Variable {name} is already sanitized, not marking as tainted")
            return False
        self.tainted_vars[name] = TaintedVar(name, source_line, source_function)
        logger.debug(f"Added taint source: {name} at line {source_line}")
        return True

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

    def propagate(self, dfg: Any) -> List[Dict[str, Any]]:
        """Propagate taint through data flow.

        Args:
            dfg: Data Flow Graph (expected to have edges and nodes)

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

        except Exception as e:
            logger.warning(f"Error during taint propagation: {e}")

        return tainted_sinks

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
                "urllib.parse.quote": "url_escape",
                "re.escape": "regex_escape",
                "validate": "validate",
                "sanitize": "sanitize",
                "clean": "clean",
                "strip": "strip",
                "escape": "escape",
            }

            for pattern, sanitization_type in sanitization_patterns.items():
                if pattern in node_str:
                    logger.debug(f"Identified sanitization: {sanitization_type}")
                    return sanitization_type

        except Exception as e:
            logger.warning(f"Error identifying sanitization: {e}")

        return None
