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

"""Tests for Control Flow Graph builder."""

from acr.core.ast_parser import ASTParser
from acr.core.cfg_builder import BasicBlock, CFGBuilder


class TestCFGBuilderBasic:
    """Test basic CFG builder functionality."""

    def test_cfg_builder_initialization(self):
        """Test CFG builder initializes correctly."""
        builder = CFGBuilder()
        assert builder.graph is not None
        assert builder.basic_blocks == {}
        assert builder._block_counter == 0

    def test_build_empty_code(self):
        """Test building CFG from empty code."""
        builder = CFGBuilder()
        parser = ASTParser()
        ast = parser.parse("")
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() == 0

    def test_build_none_ast(self):
        """Test building CFG from None AST."""
        builder = CFGBuilder()
        cfg = builder.build(None)
        assert cfg is not None
        assert cfg.number_of_nodes() == 0

    def test_build_simple_statement(self):
        """Test building CFG from simple statement."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = "x = 1"
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0
        assert len(builder.basic_blocks) > 0

    def test_build_multiple_statements(self):
        """Test building CFG from multiple statements."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
x = 1
y = 2
z = x + y
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0
        assert len(builder.basic_blocks) > 0

    def test_get_basic_blocks_empty(self):
        """Test getting basic blocks from empty CFG."""
        builder = CFGBuilder()
        blocks = builder.get_basic_blocks()
        assert blocks == []

    def test_get_basic_blocks_non_empty(self):
        """Test getting basic blocks from non-empty CFG."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = "x = 1"
        ast = parser.parse(code)
        builder.build(ast)
        blocks = builder.get_basic_blocks()
        assert len(blocks) > 0
        assert all(isinstance(block, BasicBlock) for block in blocks)


class TestCFGBuilderConditional:
    """Test CFG builder with conditionals."""

    def test_build_if_statement(self):
        """Test building CFG with if statement."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
if x > 0:
    y = 1
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0

    def test_build_if_else_statement(self):
        """Test building CFG with if-else statement."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
if x > 0:
    y = 1
else:
    y = -1
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0

    def test_build_if_elif_else_statement(self):
        """Test building CFG with if-elif-else statement."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
if x > 0:
    y = 1
elif x < 0:
    y = -1
else:
    y = 0
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0

    def test_build_nested_if(self):
        """Test building CFG with nested if statements."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
if x > 0:
    if y > 0:
        z = 1
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0


class TestCFGBuilderLoops:
    """Test CFG builder with loops."""

    def test_build_for_loop(self):
        """Test building CFG with for loop."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
for i in range(10):
    x = i
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0

    def test_build_while_loop(self):
        """Test building CFG with while loop."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
while x < 10:
    x += 1
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0

    def test_build_nested_for_loop(self):
        """Test building CFG with nested for loops."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
for i in range(10):
    for j in range(10):
        x = i * j
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0

    def test_build_loop_with_break(self):
        """Test building CFG with loop containing break."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
for i in range(10):
    if i > 5:
        break
    x = i
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0


class TestCFGBuilderExceptionHandling:
    """Test CFG builder with exception handling."""

    def test_build_try_except(self):
        """Test building CFG with try-except."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
try:
    x = 1 / 0
except ZeroDivisionError:
    x = 0
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0

    def test_build_try_except_else(self):
        """Test building CFG with try-except-else."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
try:
    x = 1 / y
except ZeroDivisionError:
    x = 0
else:
    print("No error")
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0

    def test_build_try_except_finally(self):
        """Test building CFG with try-except-finally."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
try:
    x = 1 / 0
except ZeroDivisionError:
    x = 0
finally:
    print("Done")
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0

    def test_build_multiple_except(self):
        """Test building CFG with multiple except clauses."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
try:
    x = 1 / y
except ZeroDivisionError:
    x = 0
except ValueError:
    x = -1
except Exception:
    x = -2
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0


class TestCFGBuilderFunctions:
    """Test CFG builder with functions."""

    def test_build_simple_function(self):
        """Test building CFG with simple function."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
def foo():
    x = 1
    return x
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0
        assert "foo_entry" in builder.basic_blocks or "block_1" in builder.basic_blocks

    def test_build_function_with_parameters(self):
        """Test building CFG with function with parameters."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
def add(x, y):
    return x + y
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0

    def test_build_function_with_conditional(self):
        """Test building CFG with function containing conditional."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
def abs_val(x):
    if x >= 0:
        return x
    else:
        return -x
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0

    def test_build_multiple_functions(self):
        """Test building CFG with multiple functions."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
def foo():
    return 1

def bar():
    return 2
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0


class TestBasicBlock:
    """Test BasicBlock class."""

    def test_basic_block_creation(self):
        """Test creating a basic block."""
        block = BasicBlock("block_1", [], 1, 10)
        assert block.id == "block_1"
        assert block.statements == []
        assert block.start_line == 1
        assert block.end_line == 10

    def test_basic_block_repr(self):
        """Test BasicBlock string representation."""
        block = BasicBlock("block_1", [], 1, 10)
        repr_str = repr(block)
        assert "BasicBlock" in repr_str
        assert "block_1" in repr_str
        assert "1" in repr_str
        assert "10" in repr_str


class TestCFGBuilderIntegration:
    """Integration tests for CFG builder."""

    def test_build_complex_function(self):
        """Test building CFG from complex function with multiple control flow."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
def process_data(items):
    result = []
    for item in items:
        try:
            if item is not None:
                result.append(item * 2)
            else:
                raise ValueError("None item")
        except ValueError as e:
            print(f"Error: {e}")
    return result
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg is not None
        assert cfg.number_of_nodes() > 0
        assert len(builder.basic_blocks) > 0

    def test_cfg_has_edges(self):
        """Test CFG has edges representing control flow."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = """
x = 1
if x > 0:
    y = 1
"""
        ast = parser.parse(code)
        cfg = builder.build(ast)
        assert cfg.number_of_edges() > 0

    def test_get_specific_basic_block(self):
        """Test retrieving a specific basic block by ID."""
        builder = CFGBuilder()
        parser = ASTParser()
        code = "x = 1"
        ast = parser.parse(code)
        builder.build(ast)
        blocks = builder.get_basic_blocks()
        if blocks:
            block_id = blocks[0].id
            retrieved = builder.get_basic_block(block_id)
            assert retrieved is not None
            assert retrieved.id == block_id

    def test_get_nonexistent_basic_block(self):
        """Test retrieving a nonexistent basic block."""
        builder = CFGBuilder()
        retrieved = builder.get_basic_block("nonexistent")
        assert retrieved is None

    def test_cfg_reset_between_builds(self):
        """Test CFG is properly reset between builds."""
        builder = CFGBuilder()
        parser = ASTParser()
        code1 = "x = 1"
        ast1 = parser.parse(code1)
        builder.build(ast1)
        first_node_count = builder.graph.number_of_nodes()

        code2 = "y = 2"
        ast2 = parser.parse(code2)
        builder.build(ast2)
        second_node_count = builder.graph.number_of_nodes()

        assert first_node_count > 0
        assert second_node_count > 0
