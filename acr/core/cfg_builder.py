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

"""Control Flow Graph builder implementation."""

from typing import Any, Dict, List, Set, Optional
import networkx as nx
from ..utils.logger import get_logger

logger = get_logger(__name__)


class BasicBlock:
    """Represents a basic block in the CFG."""

    def __init__(
        self,
        block_id: str,
        statements: List[Any],
        start_line: int,
        end_line: int,
    ):
        """Initialize basic block.

        Args:
            block_id: Unique identifier for the block
            statements: List of AST nodes in the block
            start_line: Starting line number
            end_line: Ending line number
        """
        self.id = block_id
        self.statements = statements
        self.start_line = start_line
        self.end_line = end_line

    def __repr__(self) -> str:
        return f"BasicBlock({self.id}, lines {self.start_line}-{self.end_line})"


class CFGBuilder:
    """Builder for Control Flow Graphs."""

    def __init__(self):
        """Initialize CFG builder."""
        self.graph: nx.DiGraph = nx.DiGraph()
        self.basic_blocks: Dict[str, BasicBlock] = {}
        self._block_counter = 0
        self._current_function: Optional[str] = None

    def build(self, ast_node: Any) -> nx.DiGraph:
        """Build CFG from AST node.

        Args:
            ast_node: AST root node

        Returns:
            Control Flow Graph
        """
        if ast_node is None:
            logger.warning("AST node is None, returning empty CFG")
            return self.graph

        try:
            self._reset()
            self._build_from_node(ast_node, entry_id="entry")
            logger.debug(f"Built CFG with {self.graph.number_of_nodes()} nodes")
            return self.graph

        except Exception as e:
            logger.error(f"Error building CFG: {e}")
            return self.graph

    def get_basic_blocks(self) -> List[BasicBlock]:
        """Get basic blocks from CFG.

        Returns:
            List of basic blocks
        """
        return list(self.basic_blocks.values())

    def get_basic_block(self, block_id: str) -> Optional[BasicBlock]:
        """Get a specific basic block by ID.

        Args:
            block_id: Block identifier

        Returns:
            BasicBlock or None if not found
        """
        return self.basic_blocks.get(block_id)

    def _reset(self) -> None:
        """Reset builder state."""
        self.graph.clear()
        self.basic_blocks.clear()
        self._block_counter = 0
        self._current_function = None

    def _generate_block_id(self) -> str:
        """Generate a unique block ID.

        Returns:
            Unique block identifier
        """
        self._block_counter += 1
        return f"block_{self._block_counter}"

    def _build_from_node(
        self,
        node: Any,
        entry_id: str,
        exit_id: Optional[str] = None,
    ) -> tuple[str, Optional[str]]:
        """Recursively build CFG from AST node.

        Args:
            node: AST node
            entry_id: Entry block ID for this node
            exit_id: Optional exit block ID

        Returns:
            Tuple of (actual_entry_id, actual_exit_id)
        """
        if node is None:
            return (entry_id, exit_id)

        node_type = self._get_node_type(node)

        if node_type in {"if_statement", "conditional_expression"}:
            return self._build_conditional(node, entry_id, exit_id)
        elif node_type in {"for_statement", "while_statement"}:
            return self._build_loop(node, entry_id, exit_id)
        elif node_type in {"try_statement"}:
            return self._build_try_except(node, entry_id, exit_id)
        elif node_type in {"function_definition", "lambda_expression"}:
            return self._build_function(node)
        elif node_type in {"block"}:
            return self._build_block(node, entry_id, exit_id)
        else:
            return self._build_statement(node, entry_id)

    def _build_statement(
        self,
        node: Any,
        entry_id: str,
    ) -> tuple[str, Optional[str]]:
        """Build CFG for a simple statement.

        Args:
            node: AST statement node
            entry_id: Entry block ID

        Returns:
            Tuple of (entry_id, exit_id)
        """
        block = self._create_basic_block([node])
        self.graph.add_edge(entry_id, block.id)
        return (block.id, block.id)

    def _build_block(
        self,
        node: Any,
        entry_id: str,
        exit_id: Optional[str] = None,
    ) -> tuple[str, Optional[str]]:
        """Build CFG for a block of statements.

        Args:
            node: AST block node
            entry_id: Entry block ID
            exit_id: Optional exit block ID

        Returns:
            Tuple of (entry_id, exit_id)
        """
        statements = self._get_children(node)
        if not statements:
            return (entry_id, exit_id)

        current_entry = entry_id
        for stmt in statements:
            stmt_type = self._get_node_type(stmt)
            if stmt_type in {
                "if_statement",
                "for_statement",
                "while_statement",
                "try_statement",
            }:
                current_entry, _ = self._build_from_node(stmt, current_entry, exit_id)
            else:
                current_entry, _ = self._build_statement(stmt, current_entry)

        if exit_id:
            self.graph.add_edge(current_entry, exit_id)
            return (entry_id, exit_id)

        return (entry_id, current_entry)

    def _build_conditional(
        self,
        node: Any,
        entry_id: str,
        exit_id: Optional[str] = None,
    ) -> tuple[str, Optional[str]]:
        """Build CFG for conditional (if/elif/else).

        Args:
            node: AST conditional node
            entry_id: Entry block ID
            exit_id: Optional exit block ID

        Returns:
            Tuple of (entry_id, exit_id)
        """
        condition = self._get_child_by_type(node, "condition")
        consequence = self._get_child_by_type(node, "consequence")
        alternative = self._get_child_by_type(node, "alternative")

        cond_block = self._create_basic_block([condition])
        self.graph.add_edge(entry_id, cond_block.id)

        if exit_id is None:
            exit_id = self._generate_block_id()
            self.basic_blocks[exit_id] = BasicBlock(exit_id, [], 0, 0)

        if consequence:
            cons_entry, _ = self._build_from_node(consequence, cond_block.id, exit_id)
            self.graph.add_edge(cond_block.id, cons_entry)

        if alternative:
            alt_entry, _ = self._build_from_node(alternative, cond_block.id, exit_id)
            self.graph.add_edge(cond_block.id, alt_entry)

        self.graph.add_edge(cond_block.id, exit_id)

        return (entry_id, exit_id)

    def _build_loop(
        self,
        node: Any,
        entry_id: str,
        exit_id: Optional[str] = None,
    ) -> tuple[str, Optional[str]]:
        """Build CFG for loop (for/while).

        Args:
            node: AST loop node
            entry_id: Entry block ID
            exit_id: Optional exit block ID

        Returns:
            Tuple of (entry_id, exit_id)
        """
        condition = self._get_child_by_type(node, "condition")
        body = self._get_child_by_type(node, "body")

        if exit_id is None:
            exit_id = self._generate_block_id()
            self.basic_blocks[exit_id] = BasicBlock(exit_id, [], 0, 0)

        body_entry = entry_id
        body_exit = entry_id

        if body:
            body_entry, body_exit = self._build_from_node(body, entry_id, exit_id)

        if condition:
            cond_block = self._create_basic_block([condition])
            self.graph.add_edge(body_exit, cond_block.id)
            self.graph.add_edge(cond_block.id, body_entry)
            self.graph.add_edge(cond_block.id, exit_id)
        else:
            self.graph.add_edge(body_exit, body_entry)
            self.graph.add_edge(body_entry, exit_id)

        return (entry_id, exit_id)

    def _build_try_except(
        self,
        node: Any,
        entry_id: str,
        exit_id: Optional[str] = None,
    ) -> tuple[str, Optional[str]]:
        """Build CFG for try/except/finally.

        Args:
            node: AST try statement node
            entry_id: Entry block ID
            exit_id: Optional exit block ID

        Returns:
            Tuple of (entry_id, exit_id)
        """
        try_block = self._get_child_by_type(node, "block")
        except_blocks = self._get_children_by_type(node, "except_clause")
        finally_block = self._get_child_by_type(node, "finally_clause")

        if exit_id is None:
            exit_id = self._generate_block_id()
            self.basic_blocks[exit_id] = BasicBlock(exit_id, [], 0, 0)

        try_entry, try_exit = self._build_from_node(try_block, entry_id, exit_id)

        for except_block in except_blocks:
            except_entry, _ = self._build_from_node(except_block, entry_id, exit_id)
            self.graph.add_edge(try_entry, except_entry)

        if finally_block:
            fin_entry, fin_exit = self._build_from_node(finally_block, entry_id, exit_id)
            self.graph.add_edge(try_exit, fin_entry)
            return (entry_id, fin_exit)

        return (entry_id, exit_id)

    def _build_function(self, node: Any) -> tuple[str, Optional[str]]:
        """Build CFG for function definition.

        Args:
            node: AST function definition node

        Returns:
            Tuple of (entry_id, exit_id)
        """
        function_name = self._get_function_name(node)
        old_function = self._current_function
        self._current_function = function_name

        entry_id = f"{function_name}_entry"
        exit_id = f"{function_name}_exit"
        self.basic_blocks[entry_id] = BasicBlock(entry_id, [], 0, 0)
        self.basic_blocks[exit_id] = BasicBlock(exit_id, [], 0, 0)

        body = self._get_child_by_type(node, "body")
        if body:
            _, body_exit = self._build_from_node(body, entry_id, exit_id)
            self.graph.add_edge(body_exit, exit_id)

        self._current_function = old_function
        return (entry_id, exit_id)

    def _create_basic_block(self, statements: List[Any]) -> BasicBlock:
        """Create a new basic block.

        Args:
            statements: List of AST nodes

        Returns:
            New BasicBlock
        """
        block_id = self._generate_block_id()
        start_line = 0
        end_line = 0

        if statements:
            start_line = min(self._get_node_line(stmt) for stmt in statements if stmt is not None)
            end_line = max(self._get_node_line(stmt) for stmt in statements if stmt is not None)

        block = BasicBlock(block_id, statements, start_line, end_line)
        self.basic_blocks[block_id] = block
        self.graph.add_node(block_id, block=block)
        return block

    def _get_node_type(self, node: Any) -> str:
        """Get node type.

        Args:
            node: AST node

        Returns:
            Node type string
        """
        return getattr(node, "type", str(type(node).__name__))

    def _get_node_line(self, node: Any) -> int:
        """Get line number for node.

        Args:
            node: AST node

        Returns:
            Line number (0 if not found)
        """
        return getattr(node, "start_point", (0, 0))[0]

    def _get_children(self, node: Any) -> List[Any]:
        """Get children of node.

        Args:
            node: AST node

        Returns:
            List of child nodes
        """
        if hasattr(node, "children"):
            return node.children
        return []

    def _get_child_by_type(self, node: Any, child_type: str) -> Optional[Any]:
        """Get first child of specific type.

        Args:
            node: AST node
            child_type: Type to find

        Returns:
            Child node or None
        """
        for child in self._get_children(node):
            if self._get_node_type(child) == child_type:
                return child
        return None

    def _get_children_by_type(self, node: Any, child_type: str) -> List[Any]:
        """Get all children of specific type.

        Args:
            node: AST node
            child_type: Type to find

        Returns:
            List of child nodes
        """
        return [
            child for child in self._get_children(node) if self._get_node_type(child) == child_type
        ]

    def _get_function_name(self, node: Any) -> str:
        """Get function name from function definition node.

        Args:
            node: AST function definition node

        Returns:
            Function name string
        """
        name_node = self._get_child_by_type(node, "identifier")
        if name_node:
            return name_node.text.decode("utf-8") if hasattr(name_node, "text") else "anonymous"
        return "anonymous"
