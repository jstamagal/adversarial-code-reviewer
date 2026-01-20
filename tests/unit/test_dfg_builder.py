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

"""Tests for Data Flow Graph builder."""

import pytest

from acr.core.dfg_builder import DFGBuilder
from acr.core.ast_parser import ASTParser


class TestDFGBuilderBasics:
    """Test basic DFG builder functionality."""

    def test_initialization(self):
        """Test DFG builder initialization."""
        builder = DFGBuilder()
        assert builder.graph is not None
        assert builder.graph.number_of_nodes() == 0

    def test_build_empty_code(self):
        """Test building DFG from empty code."""
        builder = DFGBuilder()
        parser = ASTParser()
        ast = parser.parse("")
        dfg = builder.build(ast)
        assert dfg is not None
        assert dfg.number_of_nodes() == 0

    def test_build_none_ast(self):
        """Test building DFG from None AST."""
        builder = DFGBuilder()
        dfg = builder.build(None)
        assert dfg is not None
        assert dfg.number_of_nodes() == 0


class TestDFGBuilderAssignments:
    """Test DFG builder with variable assignments."""

    def test_simple_assignment(self):
        """Test building DFG with simple assignment."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = "x = 1"
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert dfg.number_of_nodes() == 1
        assert dfg.number_of_edges() == 0
        assert any(dfg.nodes[n].get("name") == "x" for n in dfg.nodes())

    def test_multiple_assignments(self):
        """Test building DFG with multiple assignments."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = 1
y = 2
z = 3
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert dfg.number_of_nodes() == 3
        assert dfg.number_of_edges() == 0

    def test_chained_assignment(self):
        """Test building DFG with chained assignment."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = 1
y = x
z = y
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert dfg.number_of_nodes() >= 3
        assert dfg.number_of_edges() >= 2

    def test_assignment_with_expression(self):
        """Test building DFG with assignment containing expression."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = 1
y = x + 2
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert dfg.number_of_nodes() >= 2
        assert dfg.number_of_edges() >= 1


class TestDFGBuilderFunctions:
    """Test DFG builder with function definitions."""

    def test_function_definition(self):
        """Test building DFG with function definition."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
def foo(x):
    return x
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert dfg.number_of_nodes() >= 2

    def test_function_with_multiple_params(self):
        """Test building DFG with function with multiple parameters."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
def foo(x, y, z):
    return x + y + z
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert dfg.number_of_nodes() >= 4

    def test_function_with_assignment(self):
        """Test building DFG with function containing assignment."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
def foo(x):
    y = x + 1
    return y
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert dfg.number_of_nodes() >= 3
        assert dfg.number_of_edges() >= 2

    def test_function_with_call(self):
        """Test building DFG with function containing call."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
def foo(x):
    return len(x)
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert dfg.number_of_nodes() >= 2
        assert dfg.number_of_edges() >= 1


class TestDFGBuilderControlFlow:
    """Test DFG builder with control flow."""

    def test_if_statement(self):
        """Test building DFG with if statement."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = 1
if x > 0:
    y = 1
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert dfg.number_of_nodes() >= 2

    def test_for_loop(self):
        """Test building DFG with for loop."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
for i in range(10):
    x = i
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert dfg.number_of_nodes() >= 2
        assert dfg.number_of_edges() >= 1
        assert dfg.number_of_edges() >= 1

    def test_while_loop(self):
        """Test building DFG with while loop."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = 0
while x < 10:
    x += 1
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert dfg.number_of_nodes() >= 2
        assert dfg.number_of_edges() >= 1


class TestDFGBuilderTracing:
    """Test variable tracing functionality."""

    def test_trace_simple_variable(self):
        """Test tracing a simple variable."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = 1
y = x
z = y
"""
        ast = parser.parse(code)
        builder.build(ast)

        traces = builder.trace_variable("x")
        assert len(traces) > 0
        assert any(trace["name"] == "x" for trace in traces)

    def test_trace_variable_not_found(self):
        """Test tracing a variable that doesn't exist."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = "x = 1"
        ast = parser.parse(code)
        builder.build(ast)

        traces = builder.trace_variable("y")
        assert len(traces) == 0

    def test_trace_variable_uses(self):
        """Test tracing variable uses."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = 1
y = x
z = x
"""
        ast = parser.parse(code)
        builder.build(ast)

        traces = builder.trace_variable("x")
        assert len(traces) > 0

    def test_trace_in_function(self):
        """Test tracing variable in function."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
def foo(x):
    y = x
    return y
"""
        ast = parser.parse(code)
        builder.build(ast)

        traces = builder.trace_variable("x")
        assert len(traces) > 0


class TestDFGBuilderDataflowPaths:
    """Test data flow path extraction."""

    def test_simple_dataflow_path(self):
        """Test extracting simple data flow path."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = 1
y = x
z = y
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        paths = builder.get_dataflow_path("x", "y")
        assert len(paths) > 0

    def test_no_dataflow_path(self):
        """Test when no data flow path exists."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = 1
y = 2
z = 3
"""
        ast = parser.parse(code)
        builder.build(ast)

        paths = builder.get_dataflow_path("x", "y")
        assert len(paths) == 0

    def test_complex_dataflow_path(self):
        """Test extracting complex data flow path."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = 1
y = x + 2
z = y * 3
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        paths = builder.get_dataflow_path("x", "z")
        assert len(paths) > 0


class TestDFGBuilderReachingDefinitions:
    """Test reaching definitions."""

    def test_single_definition(self):
        """Test reaching definitions for single definition."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = "x = 1"
        ast = parser.parse(code)
        builder.build(ast)

        defs = builder.get_reaching_definitions("x")
        assert len(defs) == 1

    def test_multiple_definitions(self):
        """Test reaching definitions for multiple definitions."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = 1
x = 2
x = 3
"""
        ast = parser.parse(code)
        builder.build(ast)

        defs = builder.get_reaching_definitions("x")
        assert len(defs) == 3

    def test_function_parameters(self):
        """Test reaching definitions for function parameters."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
def foo(x, y):
    return x + y
"""
        ast = parser.parse(code)
        builder.build(ast)

        defs_x = builder.get_reaching_definitions("x")
        defs_y = builder.get_reaching_definitions("y")
        assert len(defs_x) == 1
        assert len(defs_y) == 1

    def test_undefined_variable(self):
        """Test reaching definitions for undefined variable."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = "x = 1"
        ast = parser.parse(code)
        builder.build(ast)

        defs = builder.get_reaching_definitions("y")
        assert len(defs) == 0


class TestDFGBuilderComplexScenarios:
    """Test complex scenarios."""

    def test_dataflow_with_conditionals(self):
        """Test data flow with conditionals."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = 1
if x > 0:
    y = x
else:
    y = 0
z = y
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg.number_of_nodes() >= 3
        assert dfg.number_of_edges() >= 1

    def test_dataflow_with_loops(self):
        """Test data flow with loops."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = 0
for i in range(10):
    x = x + i
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg.number_of_nodes() >= 2
        assert dfg.number_of_edges() >= 1

    def test_dataflow_with_nested_functions(self):
        """Test data flow with nested function calls."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
def foo(x):
    return x * 2

def bar(y):
    return foo(y) + 1

z = bar(5)
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg.number_of_nodes() >= 4

    def test_dataflow_with_attributes(self):
        """Test data flow with attribute access."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = "hello"
y = x.upper()
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg.number_of_nodes() >= 2

    def test_dataflow_with_subscripts(self):
        """Test data flow with subscript access."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
x = [1, 2, 3]
y = x[0]
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg.number_of_nodes() >= 2
        assert dfg.number_of_edges() >= 1


class TestDFGBuilderIntegration:
    """Integration tests for DFG builder."""

    def test_simple_function(self):
        """Test DFG for a simple function."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
def add(a, b):
    result = a + b
    return result
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert dfg.number_of_nodes() >= 4

    def test_function_with_return(self):
        """Test DFG for function with return statement."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
def foo(x):
    y = x + 1
    return y
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert any(dfg.nodes[n].get("type") == "return" for n in dfg.nodes())

    def test_complex_function(self):
        """Test DFG for a complex function."""
        builder = DFGBuilder()
        parser = ASTParser()
        code = """
def process_data(data):
    result = []
    for item in data:
        if item > 0:
            result.append(item * 2)
    return result
"""
        ast = parser.parse(code)
        dfg = builder.build(ast)

        assert dfg is not None
        assert dfg.number_of_nodes() >= 4
