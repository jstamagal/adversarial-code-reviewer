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

"""Data Flow Graph builder implementation."""

from typing import Any, Dict, List, Set, Optional, Tuple
import networkx as nx
from ..utils.logger import get_logger

logger = get_logger(__name__)


class DFGBuilder:
    """Builder for Data Flow Graphs."""

    def __init__(self):
        """Initialize DFG builder."""
        self.graph: nx.DiGraph = nx.DiGraph()
        self._var_assignments: Dict[str, List[Any]] = {}
        self._var_uses: Dict[str, List[Any]] = {}
        self._function_params: Dict[str, List[str]] = {}
        self._current_function: Optional[str] = None

    def build(self, ast_node: Any, cfg: Optional[nx.DiGraph] = None) -> nx.DiGraph:
        """Build DFG from AST and CFG.

        Args:
            ast_node: AST root node
            cfg: Control Flow Graph (optional, for context)

        Returns:
            Data Flow Graph
        """
        if ast_node is None:
            logger.warning("AST node is None, returning empty DFG")
            return self.graph

        try:
            self._reset()
            self._build_from_node(ast_node)
            logger.debug(
                f"Built DFG with {self.graph.number_of_nodes()} nodes, "
                f"{self.graph.number_of_edges()} edges"
            )
            return self.graph

        except Exception as e:
            logger.error(f"Error building DFG: {e}")
            return self.graph

    def _reset(self):
        """Reset DFG builder state."""
        self.graph = nx.DiGraph()
        self._var_assignments = {}
        self._var_uses = {}
        self._function_params = {}
        self._current_function = None

    def _build_from_node(self, node: Any):
        """Build DFG from AST node.

        Args:
            node: AST node
        """
        if node is None:
            return

        node_type = self._get_node_type(node)

        if node_type == "function_definition":
            self._process_function(node)
        elif node_type == "assignment":
            self._process_assignment(node)
        elif node_type == "augmented_assignment":
            self._process_augmented_assignment(node)
        elif node_type == "call":
            self._process_call(node)
        elif node_type == "return_statement":
            self._process_return(node)
        elif node_type == "block":
            for child in self._get_children(node):
                self._build_from_node(child)
        elif node_type in [
            "if_statement",
            "elif_clause",
            "else_clause",
            "while_statement",
            "try_statement",
        ]:
            for child in self._get_children(node):
                self._build_from_node(child)
        elif node_type == "for_statement":
            self._process_for_statement(node)
        else:
            for child in self._get_children(node):
                self._build_from_node(child)

    def _process_function(self, node: Any):
        """Process function definition.

        Args:
            node: Function definition node
        """
        old_function = self._current_function
        function_name = self._get_function_name(node)
        self._current_function = function_name

        params = self._get_function_parameters(node)
        self._function_params[function_name] = params

        for param in params:
            param_id = self._generate_node_id(node, param)
            self.graph.add_node(param_id, type="param", name=param, function=function_name)
            self._var_assignments.setdefault(param, []).append(param_id)

        body = self._get_child_by_type(node, "block")
        if body:
            self._build_from_node(body)

        self._current_function = old_function

    def _process_assignment(self, node: Any):
        """Process assignment statement.

        Args:
            node: Assignment node
        """
        children = self._get_children(node)
        if not children or len(children) < 3:
            return

        target_name = self._get_variable_name(children[0])
        if not target_name:
            return

        target_id = self._generate_node_id(node, "def")
        self.graph.add_node(
            target_id,
            type="assignment",
            name=target_name,
            line=self._get_node_line(node),
            function=self._current_function,
        )
        self._var_assignments.setdefault(target_name, []).append(target_id)

        if len(children) >= 3:
            value = children[2]
            value_deps = self._collect_variable_dependencies(value)
            for dep in value_deps:
                dep_ids = self._var_assignments.get(dep, [])
                for dep_id in dep_ids:
                    self.graph.add_edge(dep_id, target_id, type="dataflow")
                    self._var_uses.setdefault(dep, []).append(dep_id)

    def _process_augmented_assignment(self, node: Any):
        """Process augmented assignment statement (+=, -=, etc.).

        Args:
            node: Augmented assignment node
        """
        children = self._get_children(node)
        if not children or len(children) < 3:
            return

        target_name = self._get_variable_name(children[0])
        if not target_name:
            return

        target_id = self._generate_node_id(node, "aug_def")
        self.graph.add_node(
            target_id,
            type="assignment",
            name=target_name,
            line=self._get_node_line(node),
            function=self._current_function,
        )
        self._var_assignments.setdefault(target_name, []).append(target_id)

        if len(children) >= 3:
            value = children[2]
            value_deps = self._collect_variable_dependencies(value)
            value_deps.add(target_name)
            for dep in value_deps:
                dep_ids = self._var_assignments.get(dep, [])
                for dep_id in dep_ids:
                    self.graph.add_edge(dep_id, target_id, type="dataflow")
                    self._var_uses.setdefault(dep, []).append(dep_id)

    def _process_for_statement(self, node: Any):
        """Process for statement.

        Args:
            node: For statement node
        """
        children = self._get_children(node)
        if len(children) < 3:
            return

        loop_var = self._get_variable_name(children[1])
        if loop_var:
            loop_var_id = self._generate_node_id(children[1], "loop_var")
            self.graph.add_node(
                loop_var_id,
                type="param",
                name=loop_var,
                line=self._get_node_line(node),
                function=self._current_function,
            )
            self._var_assignments.setdefault(loop_var, []).append(loop_var_id)

        for child in self._get_children(node):
            self._build_from_node(child)

    def _process_call(self, node: Any):
        """Process function call.

        Args:
            node: Call node
        """
        children = self._get_children(node)
        if not children:
            return

        call_id = self._generate_node_id(node, "call")
        if not self.graph.has_node(call_id):
            self.graph.add_node(
                call_id,
                type="call",
                line=self._get_node_line(node),
                function=self._current_function,
            )

        func_name = None
        for child in children:
            child_type = self._get_node_type(child)
            if child_type == "identifier":
                func_name = self._get_variable_name(child)
                if func_name and func_name in self._var_assignments:
                    func_ids = self._var_assignments.get(func_name, [])
                    for func_id in func_ids:
                        self.graph.add_edge(func_id, call_id, type="dataflow")
                        self._var_uses.setdefault(func_name, []).append(func_id)
            elif child_type == "argument_list":
                for arg in self._get_children(child):
                    arg_type = self._get_node_type(arg)
                    if arg_type == "identifier":
                        var_name = self._get_variable_name(arg)
                        if var_name:
                            dep_ids = self._var_assignments.get(var_name, [])
                            for dep_id in dep_ids:
                                self.graph.add_edge(dep_id, call_id, type="dataflow")
                                self._var_uses.setdefault(var_name, []).append(dep_id)

        args = self._get_children_by_type(node, "argument")
        for arg in args:
            arg_deps = self._collect_variable_dependencies(arg)
            for dep in arg_deps:
                dep_ids = self._var_assignments.get(dep, [])
                for dep_id in dep_ids:
                    call_id = self._generate_node_id(node, "call")
                    if not self.graph.has_node(call_id):
                        self.graph.add_node(
                            call_id,
                            type="call",
                            line=self._get_node_line(node),
                            function=self._current_function,
                        )
                    self.graph.add_edge(dep_id, call_id, type="dataflow")
                    self._var_uses.setdefault(dep, []).append(dep_id)

    def _process_return(self, node: Any):
        """Process return statement.

        Args:
            node: Return node
        """
        children = self._get_children(node)
        if not children or len(children) < 2:
            return

        value = children[1]
        if not value:
            return

        return_deps = self._collect_variable_dependencies(value)
        return_id = self._generate_node_id(node, "return")
        self.graph.add_node(
            return_id,
            type="return",
            line=self._get_node_line(node),
            function=self._current_function,
        )

        for dep in return_deps:
            dep_ids = self._var_assignments.get(dep, [])
            for dep_id in dep_ids:
                self.graph.add_edge(dep_id, return_id, type="dataflow")
                self._var_uses.setdefault(dep, []).append(dep_id)

    def _collect_variable_dependencies(self, node: Any) -> Set[str]:
        """Collect variable names that a node depends on.

        Args:
            node: AST node

        Returns:
            Set of variable names
        """
        dependencies = set()
        node_type = self._get_node_type(node)

        if node_type == "identifier":
            var_name = self._get_variable_name(node)
            if var_name:
                dependencies.add(var_name)
        elif node_type == "attribute":
            obj = self._get_child_by_type(node, "object")
            if obj:
                dependencies.update(self._collect_variable_dependencies(obj))
        elif node_type == "subscript":
            children = self._get_children(node)
            if children:
                obj = children[0]
                if self._get_node_type(obj) == "identifier":
                    dependencies.add(self._get_variable_name(obj))
                else:
                    dependencies.update(self._collect_variable_dependencies(obj))
                if len(children) >= 3:
                    index = children[2]
                    dependencies.update(self._collect_variable_dependencies(index))
        elif node_type in ["binary_operator", "boolean_operator", "comparison_operator"]:
            left = None
            right = None
            children = self._get_children(node)
            if children:
                left = children[0]
                if len(children) > 1:
                    right = children[1]
            if left:
                dependencies.update(self._collect_variable_dependencies(left))
            if right:
                dependencies.update(self._collect_variable_dependencies(right))
        elif node_type == "call":
            children = self._get_children(node)
            for child in children:
                child_type = self._get_node_type(child)
                if child_type == "identifier":
                    var_name = self._get_variable_name(child)
                    if var_name:
                        dependencies.add(var_name)
                elif child_type == "argument_list":
                    for arg in self._get_children(child):
                        dependencies.update(self._collect_variable_dependencies(arg))
        else:
            for child in self._get_children(node):
                dependencies.update(self._collect_variable_dependencies(child))

        return dependencies

    def trace_variable(self, var_name: str) -> List[Any]:
        """Trace variable usage across the code.

        Args:
            var_name: Variable name to trace

        Returns:
            List of usage nodes
        """
        usages = []
        assignment_ids = self._var_assignments.get(var_name, [])

        for assign_id in assignment_ids:
            if self.graph.has_node(assign_id):
                node_data = self.graph.nodes[assign_id]
                usages.append(
                    {
                        "id": assign_id,
                        "type": node_data.get("type", "unknown"),
                        "line": node_data.get("line", 0),
                        "function": node_data.get("function", None),
                        "name": node_data.get("name", var_name),
                    }
                )

        for use_id in self._var_uses.get(var_name, []):
            if use_id not in assignment_ids and self.graph.has_node(use_id):
                node_data = self.graph.nodes[use_id]
                usages.append(
                    {
                        "id": use_id,
                        "type": node_data.get("type", "unknown"),
                        "line": node_data.get("line", 0),
                        "function": node_data.get("function", None),
                        "name": var_name,
                    }
                )

        return sorted(usages, key=lambda x: x.get("line", 0))

    def get_dataflow_path(self, source: str, sink: str) -> List[Any]:
        """Get data flow path from source to sink.

        Args:
            source: Source variable name
            sink: Sink variable name

        Returns:
            List of nodes in the data flow path
        """
        source_ids = self._var_assignments.get(source, [])
        sink_ids = self._var_assignments.get(sink, [])

        paths = []
        for source_id in source_ids:
            for sink_id in sink_ids:
                try:
                    path = nx.shortest_path(self.graph, source_id, sink_id)
                    paths.append(path)
                except nx.NetworkXNoPath:
                    continue

        return paths

    def get_reaching_definitions(self, var_name: str) -> List[str]:
        """Get reaching definitions for a variable.

        Args:
            var_name: Variable name

        Returns:
            List of node IDs that define the variable
        """
        return self._var_assignments.get(var_name, [])

    def _get_node_type(self, node: Any) -> str:
        """Get node type.

        Args:
            node: AST node

        Returns:
            Node type string
        """
        return node.type if hasattr(node, "type") else str(type(node))

    def _get_node_line(self, node: Any) -> int:
        """Get node line number.

        Args:
            node: AST node

        Returns:
            Line number
        """
        if hasattr(node, "start_point"):
            return node.start_point[0] + 1
        return 0

    def _get_children(self, node: Any) -> List[Any]:
        """Get child nodes.

        Args:
            node: AST node

        Returns:
            List of child nodes
        """
        if hasattr(node, "children"):
            return node.children
        return []

    def _get_child_by_type(self, node: Any, node_type: str) -> Optional[Any]:
        """Get child node by type.

        Args:
            node: AST node
            node_type: Node type to find

        Returns:
            Child node or None
        """
        for child in self._get_children(node):
            if self._get_node_type(child) == node_type:
                return child
        return None

    def _get_children_by_type(self, node: Any, node_type: str) -> List[Any]:
        """Get all child nodes of a type.

        Args:
            node: AST node
            node_type: Node type to find

        Returns:
            List of child nodes
        """
        return [
            child for child in self._get_children(node) if self._get_node_type(child) == node_type
        ]

    def _get_variable_name(self, node: Any) -> Optional[str]:
        """Get variable name from identifier node.

        Args:
            node: Identifier node

        Returns:
            Variable name or None
        """
        if self._get_node_type(node) == "identifier":
            text = node.text.decode("utf-8") if hasattr(node, "text") else str(node)
            return text
        return None

    def _get_function_name(self, node: Any) -> str:
        """Get function name from function definition node.

        Args:
            node: Function definition node

        Returns:
            Function name
        """
        name_node = self._get_child_by_type(node, "identifier")
        if name_node:
            return self._get_variable_name(name_node) or "unknown"
        return "unknown"

    def _get_function_parameters(self, node: Any) -> List[str]:
        """Get function parameter names.

        Args:
            node: Function definition node

        Returns:
            List of parameter names
        """
        params = []
        params_node = self._get_child_by_type(node, "parameters")
        if params_node:
            for child in self._get_children(params_node):
                child_type = self._get_node_type(child)
                if child_type == "identifier":
                    param_name = self._get_variable_name(child)
                    if param_name:
                        params.append(param_name)
                elif child_type == "typed_parameter":
                    for subchild in self._get_children(child):
                        if self._get_node_type(subchild) == "identifier":
                            param_name = self._get_variable_name(subchild)
                            if param_name:
                                params.append(param_name)
        return params

    def _generate_node_id(self, node: Any, suffix: str) -> str:
        """Generate unique node ID.

        Args:
            node: AST node
            suffix: Suffix for ID

        Returns:
            Unique node ID
        """
        line = self._get_node_line(node)
        return f"node_{line}_{suffix}"
