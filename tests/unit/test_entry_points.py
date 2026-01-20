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

"""Tests for entry point identification."""

import pytest

from acr.core.entry_points import EntryPoint, EntryPointIdentifier


@pytest.fixture
def identifier():
    """Create entry point identifier instance."""
    try:
        return EntryPointIdentifier()
    except ImportError:
        pytest.skip("tree-sitter-python not installed")


class TestFlaskRoutes:
    """Test Flask route identification."""

    def test_simple_flask_route(self, identifier):
        """Test identifying a simple Flask route."""
        code = """
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return 'Hello World'
"""
        entry_points = identifier.identify(code, "test.py")
        assert len(entry_points) == 1
        assert entry_points[0].type == "flask_route"
        assert entry_points[0].function_name == "index"
        assert entry_points[0].path == "/"

    def test_multiple_flask_routes(self, identifier):
        """Test identifying multiple Flask routes."""
        code = """
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return 'Home'

@app.route('/users')
def users():
    return 'Users'

@app.route('/posts/<int:id>')
def post_detail(id):
    return f'Post {id}'
"""
        entry_points = identifier.identify(code, "test.py")
        flask_routes = [ep for ep in entry_points if ep.type == "flask_route"]
        assert len(flask_routes) == 3
        route_names = [ep.function_name for ep in flask_routes]
        assert "index" in route_names
        assert "users" in route_names
        assert "post_detail" in route_names

    def test_no_flask_routes(self, identifier):
        """Test code without Flask routes."""
        code = """
def regular_function():
    pass

class RegularClass:
    pass
"""
        entry_points = identifier.identify(code, "test.py")
        flask_routes = [ep for ep in entry_points if ep.type == "flask_route"]
        assert len(flask_routes) == 0


class TestFastAPIEndpoints:
    """Test FastAPI endpoint identification."""

    def test_simple_fastapi_get(self, identifier):
        """Test identifying a simple FastAPI GET endpoint."""
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.get('/')
def read_root():
    return {'Hello': 'World'}
"""
        entry_points = identifier.identify(code, "test.py")
        assert len(entry_points) == 1
        assert entry_points[0].type == "fastapi_endpoint"
        assert entry_points[0].function_name == "read_root"
        assert entry_points[0].method == "GET"

    def test_fastapi_post_endpoint(self, identifier):
        """Test identifying a FastAPI POST endpoint."""
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.post('/users')
def create_user():
    return {'id': 1}
"""
        entry_points = identifier.identify(code, "test.py")
        assert len(entry_points) == 1
        assert entry_points[0].method == "POST"
        assert entry_points[0].function_name == "create_user"

    def test_multiple_fastapi_methods(self, identifier):
        """Test identifying multiple FastAPI endpoints with different methods."""
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.get('/')
def get_items():
    return []

@app.post('/items')
def create_item():
    return {}

@app.put('/items/{id}')
def update_item(id):
    return {}

@app.delete('/items/{id}')
def delete_item(id):
    return {}
"""
        entry_points = identifier.identify(code, "test.py")
        fastapi_endpoints = [ep for ep in entry_points if ep.type == "fastapi_endpoint"]
        assert len(fastapi_endpoints) == 4
        methods = [ep.method for ep in fastapi_endpoints]
        assert "GET" in methods
        assert "POST" in methods
        assert "PUT" in methods
        assert "DELETE" in methods


class TestDjangoViews:
    """Test Django view identification."""

    def test_simple_django_view(self, identifier):
        """Test identifying a simple Django view."""
        code = """
from django.views import View

class MyView(View):
    def get(self, request):
        return HttpResponse('Hello')
"""
        entry_points = identifier.identify(code, "test.py")
        django_views = [ep for ep in entry_points if ep.type == "django_view"]
        assert len(django_views) == 1
        assert django_views[0].function_name == "MyView.get"
        assert django_views[0].method == "GET"

    def test_django_api_view(self, identifier):
        """Test identifying a Django APIView."""
        code = """
from rest_framework.views import APIView

class UserAPIView(APIView):
    def get(self, request):
        return Response({})

    def post(self, request):
        return Response({})
"""
        entry_points = identifier.identify(code, "test.py")
        django_views = [ep for ep in entry_points if ep.type == "django_view"]
        assert len(django_views) == 2
        methods = [ep.method for ep in django_views]
        assert "GET" in methods
        assert "POST" in methods

    def test_no_django_views(self, identifier):
        """Test code without Django views."""
        code = """
class RegularClass:
    pass

def regular_function():
    pass
"""
        entry_points = identifier.identify(code, "test.py")
        django_views = [ep for ep in entry_points if ep.type == "django_view"]
        assert len(django_views) == 0


class TestCLICommands:
    """Test CLI command identification."""

    def test_click_command(self, identifier):
        """Test identifying a Click command."""
        code = """
import click

@click.command()
def hello():
    click.echo('Hello World!')
"""
        entry_points = identifier.identify(code, "test.py")
        assert len(entry_points) == 1
        assert entry_points[0].type == "cli_command"
        assert entry_points[0].function_name == "hello"

    def test_click_group_command(self, identifier):
        """Test identifying a Click group command."""
        code = """
import click

@click.group()
def cli():
    pass

@cli.command()
def init():
    click.echo('Initialized')
"""
        entry_points = identifier.identify(code, "test.py")
        cli_commands = [ep for ep in entry_points if ep.type == "cli_command"]
        assert len(cli_commands) == 2
        command_names = [ep.function_name for ep in cli_commands]
        assert "cli" in command_names
        assert "init" in command_names

    def test_no_cli_commands(self, identifier):
        """Test code without CLI commands."""
        code = """
def regular_function():
    pass

class RegularClass:
    pass
"""
        entry_points = identifier.identify(code, "test.py")
        cli_commands = [ep for ep in entry_points if ep.type == "cli_command"]
        assert len(cli_commands) == 0


class TestPublicFunctions:
    """Test public function identification."""

    def test_public_function(self, identifier):
        """Test identifying a public function."""
        code = """
def public_function():
    return 'public'

def _private_function():
    return 'private'
"""
        entry_points = identifier.identify(code, "test.py")
        public_funcs = [ep for ep in entry_points if ep.type == "public_function"]
        assert len(public_funcs) == 1
        assert public_funcs[0].function_name == "public_function"

    def test_multiple_public_functions(self, identifier):
        """Test identifying multiple public functions."""
        code = """
def func_one():
    pass

def func_two():
    pass

def func_three():
    pass

def _private_func():
    pass
"""
        entry_points = identifier.identify(code, "test.py")
        public_funcs = [ep for ep in entry_points if ep.type == "public_function"]
        assert len(public_funcs) == 3
        func_names = [ep.function_name for ep in public_funcs]
        assert "func_one" in func_names
        assert "func_two" in func_names
        assert "func_three" in func_names
        assert "_private_func" not in func_names

    def test_class_methods_not_public_functions(self, identifier):
        """Test that class methods are not identified as public functions."""
        code = """
class MyClass:
    def public_method(self):
        pass

def public_function():
    pass
"""
        entry_points = identifier.identify(code, "test.py")
        public_funcs = [ep for ep in entry_points if ep.type == "public_function"]
        assert len(public_funcs) == 1
        assert public_funcs[0].function_name == "public_function"


class TestMixedEntryPoints:
    """Test code with multiple types of entry points."""

    def test_flask_and_public_functions(self, identifier):
        """Test Flask routes alongside public functions."""
        code = """
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return 'Home'

def helper_function():
    return 'helper'
"""
        entry_points = identifier.identify(code, "test.py")
        assert len(entry_points) == 2
        types = [ep.type for ep in entry_points]
        assert "flask_route" in types
        assert "public_function" in types

    def test_empty_code(self, identifier):
        """Test empty code."""
        entry_points = identifier.identify("", "test.py")
        assert len(entry_points) == 0

    def test_syntax_error(self, identifier):
        """Test code with syntax errors returns empty list."""
        code = """
def broken_function(
    print('Missing closing parenthesis')
"""
        entry_points = identifier.identify(code, "test.py")
        assert len(entry_points) == 0


class TestEntryPointData:
    """Test EntryPoint data class."""

    def test_entry_point_creation(self):
        """Test creating an EntryPoint."""
        ep = EntryPoint(
            type="flask_route",
            name="Test route",
            file="test.py",
            line=10,
            function_name="test_func",
            path="/test",
            method="GET",
        )
        assert ep.type == "flask_route"
        assert ep.name == "Test route"
        assert ep.file == "test.py"
        assert ep.line == 10
        assert ep.function_name == "test_func"
        assert ep.path == "/test"
        assert ep.method == "GET"
        assert ep.details is None

    def test_entry_point_optional_fields(self):
        """Test EntryPoint with optional fields."""
        ep = EntryPoint(
            type="public_function",
            name="Public func",
            file="test.py",
            line=5,
            function_name="public",
        )
        assert ep.type == "public_function"
        assert ep.path is None
        assert ep.method is None
        assert ep.details is None
