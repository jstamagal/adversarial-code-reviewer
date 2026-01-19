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

"""Tests for sink identification."""

import pytest

from acr.core.sink_identification import SinkIdentifier, Sink


class TestSQLSinkIdentification:
    """Test SQL sink identification."""

    def test_sqlite_execute(self):
        """Test detection of sqlite3 execute calls."""
        code = """
import sqlite3

conn = sqlite3.connect('test.db')
cursor = conn.cursor()

def vulnerable_query(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        sql_sinks = [s for s in sinks if s.type == "sql_execution"]
        assert len(sql_sinks) >= 1
        assert any("cursor.execute" in s.sink_call for s in sql_sinks)

    def test_psycopg2_execute(self):
        """Test detection of psycopg2 execute calls."""
        code = """
import psycopg2

conn = psycopg2.connect("dbname=test user=postgres")
cursor = conn.cursor()

def execute_query(query):
    cursor.execute(query)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        sql_sinks = [s for s in sinks if s.type == "sql_execution"]
        assert len(sql_sinks) >= 1
        assert any("cursor.execute" in s.sink_call for s in sql_sinks)

    def test_executemany(self):
        """Test detection of executemany calls."""
        code = """
import sqlite3

conn = sqlite3.connect('test.db')
cursor = conn.cursor()

def batch_insert(records):
    cursor.executemany("INSERT INTO users VALUES (?, ?)", records)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        sql_sinks = [s for s in sinks if s.type == "sql_execution"]
        assert len(sql_sinks) >= 1
        assert any("executemany" in s.sink_call for s in sql_sinks)

    def test_executescript(self):
        """Test detection of executescript calls."""
        code = """
import sqlite3

conn = sqlite3.connect('test.db')
cursor = conn.cursor()

def run_script(script):
    cursor.executescript(script)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        sql_sinks = [s for s in sinks if s.type == "sql_execution"]
        assert len(sql_sinks) >= 1
        assert any("executescript" in s.sink_call for s in sql_sinks)


class TestShellSinkIdentification:
    """Test shell command sink identification."""

    def test_os_system(self):
        """Test detection of os.system calls."""
        code = """
import os

def run_command(cmd):
    os.system(cmd)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        shell_sinks = [s for s in sinks if s.type == "shell_command"]
        assert len(shell_sinks) >= 1
        assert any("os.system" in s.sink_call for s in shell_sinks)

    def test_os_popen(self):
        """Test detection of os.popen calls."""
        code = """
import os

def read_command_output(cmd):
    output = os.popen(cmd).read()
    return output
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        shell_sinks = [s for s in sinks if s.type == "shell_command"]
        assert len(shell_sinks) >= 1
        assert any("os.popen" in s.sink_call for s in shell_sinks)

    def test_subprocess_run(self):
        """Test detection of subprocess.run calls."""
        code = """
import subprocess

def execute_process(cmd):
    result = subprocess.run(cmd, shell=True)
    return result
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        shell_sinks = [s for s in sinks if s.type == "shell_command"]
        assert len(shell_sinks) >= 1
        assert any("subprocess.run" in s.sink_call for s in shell_sinks)

    def test_subprocess_popen(self):
        """Test detection of subprocess.Popen calls."""
        code = """
import subprocess

def spawn_process(cmd):
    proc = subprocess.Popen(cmd, shell=True)
    return proc
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        shell_sinks = [s for s in sinks if s.type == "shell_command"]
        assert len(shell_sinks) >= 1
        assert any("subprocess.Popen" in s.sink_call for s in shell_sinks)

    def test_subprocess_check_output(self):
        """Test detection of subprocess.check_output calls."""
        code = """
import subprocess

def get_output(cmd):
    output = subprocess.check_output(cmd)
    return output
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        shell_sinks = [s for s in sinks if s.type == "shell_command"]
        assert len(shell_sinks) >= 1
        assert any("check_output" in s.sink_call for s in shell_sinks)

    def test_subprocess_call(self):
        """Test detection of subprocess.call calls."""
        code = """
import subprocess

def call_command(cmd):
    return subprocess.call(cmd, shell=True)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        shell_sinks = [s for s in sinks if s.type == "shell_command"]
        assert len(shell_sinks) >= 1
        assert any("subprocess.call" in s.sink_call for s in shell_sinks)

    def test_subprocess_check_call(self):
        """Test detection of subprocess.check_call calls."""
        code = """
import subprocess

def check_command(cmd):
    subprocess.check_call(cmd)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        shell_sinks = [s for s in sinks if s.type == "shell_command"]
        assert len(shell_sinks) >= 1
        assert any("check_call" in s.sink_call for s in shell_sinks)


class TestFileSinkIdentification:
    """Test file operation sink identification."""

    def test_open_call(self):
        """Test detection of open() calls."""
        code = """
def read_file(filename):
    with open(filename, 'r') as f:
        return f.read()
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        file_sinks = [s for s in sinks if s.type == "file_operation"]
        assert len(file_sinks) >= 1
        assert any("open" in s.sink_call for s in file_sinks)

    def test_write_operation(self):
        """Test detection of write() calls."""
        code = """
def write_data(filename, data):
    with open(filename, 'w') as f:
        f.write(data)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        file_sinks = [s for s in sinks if s.type == "file_operation"]
        assert len(file_sinks) >= 1
        assert any(".write" in s.sink_call for s in file_sinks)

    def test_read_operation(self):
        """Test detection of read() calls."""
        code = """
def read_file_content(filename):
    with open(filename, 'r') as f:
        return f.read()
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        file_sinks = [s for s in sinks if s.type == "file_operation"]
        assert len(file_sinks) >= 2
        assert any(".read" in s.sink_call for s in file_sinks)


class TestNetworkSinkIdentification:
    """Test network operation sink identification."""

    def test_requests_get(self):
        """Test detection of requests.get calls."""
        code = """
import requests

def fetch_url(url):
    response = requests.get(url)
    return response.json()
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        network_sinks = [s for s in sinks if s.type == "network_operation"]
        assert len(network_sinks) >= 1
        assert any("requests.get" in s.sink_call for s in network_sinks)

    def test_requests_post(self):
        """Test detection of requests.post calls."""
        code = """
import requests

def send_data(url, data):
    response = requests.post(url, json=data)
    return response
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        network_sinks = [s for s in sinks if s.type == "network_operation"]
        assert len(network_sinks) >= 1
        assert any("requests.post" in s.sink_call for s in network_sinks)

    def test_requests_delete(self):
        """Test detection of requests.delete calls."""
        code = """
import requests

def delete_resource(url):
    response = requests.delete(url)
    return response
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        network_sinks = [s for s in sinks if s.type == "network_operation"]
        assert len(network_sinks) >= 1
        assert any("requests.delete" in s.sink_call for s in network_sinks)

    def test_urllib_urlopen(self):
        """Test detection of urllib.request.urlopen calls."""
        code = """
from urllib.request import urlopen

def fetch_page(url):
    response = urlopen(url)
    return response.read()
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        network_sinks = [s for s in sinks if s.type == "network_operation"]
        assert len(network_sinks) >= 1
        assert any("urlopen" in s.sink_call for s in network_sinks)

    def test_httpx_get(self):
        """Test detection of httpx.get calls."""
        code = """
import httpx

def fetch_with_httpx(url):
    response = httpx.get(url)
    return response.json()
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        network_sinks = [s for s in sinks if s.type == "network_operation"]
        assert len(network_sinks) >= 1
        assert any("httpx.get" in s.sink_call for s in network_sinks)

    def test_socket_connect(self):
        """Test detection of socket.connect calls."""
        code = """
    import socket

    def connect_to_server(host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        return sock
    """
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        network_sinks = [s for s in sinks if s.type == "network_operation"]
        assert len(network_sinks) >= 1
        assert any(".connect" in s.sink_call for s in network_sinks)


class TestSerializationSinkIdentification:
    """Test serialization/deserialization sink identification."""

    def test_pickle_load(self):
        """Test detection of pickle.load calls."""
        code = """
import pickle

def load_object(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        serialization_sinks = [s for s in sinks if s.type == "serialization"]
        assert len(serialization_sinks) >= 1
        assert any("pickle.load" in s.sink_call for s in serialization_sinks)

    def test_pickle_loads(self):
        """Test detection of pickle.loads calls."""
        code = """
import pickle

def deserialize_object(data):
    return pickle.loads(data)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        serialization_sinks = [s for s in sinks if s.type == "serialization"]
        assert len(serialization_sinks) >= 1
        assert any("pickle.loads" in s.sink_call for s in serialization_sinks)

    def test_yaml_load(self):
        """Test detection of yaml.load calls."""
        code = """
import yaml

def load_yaml_file(filename):
    with open(filename, 'r') as f:
        return yaml.load(f)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        serialization_sinks = [s for s in sinks if s.type == "serialization"]
        assert len(serialization_sinks) >= 1
        assert any("yaml.load" in s.sink_call for s in serialization_sinks)

    def test_yaml_unsafe_load(self):
        """Test detection of yaml.unsafe_load calls."""
        code = """
import yaml

def unsafe_load_yaml(data):
    return yaml.unsafe_load(data)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        serialization_sinks = [s for s in sinks if s.type == "serialization"]
        assert len(serialization_sinks) >= 1
        assert any("unsafe_load" in s.sink_call for s in serialization_sinks)

    def test_marshal_load(self):
        """Test detection of marshal.load calls."""
        code = """
import marshal

def load_bytecode(filename):
    with open(filename, 'rb') as f:
        return marshal.load(f)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        serialization_sinks = [s for s in sinks if s.type == "serialization"]
        assert len(serialization_sinks) >= 1
        assert any("marshal.load" in s.sink_call for s in serialization_sinks)

    def test_shelve_open(self):
        """Test detection of shelve.open calls."""
        code = """
import shelve

def open_shelf(filename):
    return shelve.open(filename)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        serialization_sinks = [s for s in sinks if s.type == "serialization"]
        assert len(serialization_sinks) >= 1
        assert any("shelve.open" in s.sink_call for s in serialization_sinks)

    def test_eval(self):
        """Test detection of eval calls."""
        code = """
def evaluate_expression(expr):
    return eval(expr)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        serialization_sinks = [s for s in sinks if s.type == "serialization"]
        assert len(serialization_sinks) >= 1
        assert any("eval" in s.sink_call for s in serialization_sinks)

    def test_exec(self):
        """Test detection of exec calls."""
        code = """
def execute_code(code_str):
    exec(code_str)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        serialization_sinks = [s for s in sinks if s.type == "serialization"]
        assert len(serialization_sinks) >= 1
        assert any("exec" in s.sink_call for s in serialization_sinks)

    def test_import_builtin(self):
        """Test detection of __import__ calls."""
        code = """
def dynamic_import(module_name):
    return __import__(module_name)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        serialization_sinks = [s for s in sinks if s.type == "serialization"]
        assert len(serialization_sinks) >= 1
        assert any("__import__" in s.sink_call for s in serialization_sinks)


class TestSinkMetadata:
    """Test sink metadata and structure."""

    def test_sink_type_and_name(self):
        """Test that sinks have correct type and name."""
        code = """
import sqlite3

def query_user(user_id):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        assert len(sinks) >= 1
        sink = sinks[0]
        assert sink.type == "sql_execution"
        assert sink.name.startswith("SQL execution:")

    def test_sink_location(self):
        """Test that sinks have correct file and line information."""
        code = """
import os

def run_command(cmd):
    os.system(cmd)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        assert len(sinks) >= 1
        sink = sinks[0]
        assert sink.file == "test.py"
        assert sink.line == 5

    def test_sink_function_name(self):
        """Test that sinks have correct enclosing function name."""
        code = """
import subprocess

def execute_shell(cmd):
    subprocess.run(cmd, shell=True)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        assert len(sinks) >= 1
        sink = sinks[0]
        assert sink.function_name == "execute_shell"

    def test_sink_args(self):
        """Test that sinks extract arguments."""
        code = """
import requests

def fetch_url(url, params):
    response = requests.get(url, params=params)
    return response
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        assert len(sinks) >= 1
        sink = sinks[0]
        assert sink.args is not None
        assert len(sink.args) > 0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_code(self):
        """Test that empty code returns no sinks."""
        code = ""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        assert len(sinks) == 0

    def test_no_sinks(self):
        """Test that code without sinks returns empty list."""
        code = """
def safe_function(x, y):
    return x + y

class MyClass:
    def method(self):
        return self.value
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        assert len(sinks) == 0

    def test_syntax_error(self):
        """Test that syntax errors are handled gracefully."""
        code = """
def broken_syntax(
    # Missing closing parenthesis
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        assert len(sinks) == 0

    def test_multiple_sink_types(self):
        """Test that multiple sink types are detected in one file."""
        code = """
import sqlite3
import os
import requests
import pickle

def mixed_sinks(user_input):
    # SQL sink
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")

    # Shell sink
    os.system("ls -la " + user_input)

    # Network sink
    requests.get("https://example.com/" + user_input)

    # Serialization sink
    pickle.loads(user_input)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        sink_types = set(s.type for s in sinks)
        assert "sql_execution" in sink_types
        assert "shell_command" in sink_types
        assert "network_operation" in sink_types
        assert "serialization" in sink_types


class TestIntegratedScenarios:
    """Test integrated scenarios with real-world code patterns."""

    def test_sql_injection_vulnerability(self):
        """Test a classic SQL injection vulnerability."""
        code = """
import sqlite3

def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)

    result = cursor.fetchone()
    return result
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        sql_sinks = [s for s in sinks if s.type == "sql_execution"]
        assert len(sql_sinks) >= 1
        assert sql_sinks[0].function_name == "login"

    def test_command_injection_vulnerability(self):
        """Test a command injection vulnerability."""
        code = """
import subprocess

def ping_host(hostname):
    # Vulnerable to command injection
    cmd = f"ping -c 4 {hostname}"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        shell_sinks = [s for s in sinks if s.type == "shell_command"]
        assert len(shell_sinks) >= 1
        assert shell_sinks[0].function_name == "ping_host"

    def test_path_traversal_vulnerability(self):
        """Test a path traversal vulnerability with file operations."""
        code = """
def read_user_file(filename):
    # Vulnerable to path traversal
    with open(f'/var/www/{filename}', 'r') as f:
        return f.read()
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        file_sinks = [s for s in sinks if s.type == "file_operation"]
        assert len(file_sinks) >= 1

    def test_ssrf_vulnerability(self):
        """Test a Server-Side Request Forgery vulnerability."""
        code = """
import requests

def fetch_user_url(url):
    # Vulnerable to SSRF
    response = requests.get(url)
    return response.text
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        network_sinks = [s for s in sinks if s.type == "network_operation"]
        assert len(network_sinks) >= 1
        assert network_sinks[0].function_name == "fetch_user_url"

    def test_pickle_deserialization_rce(self):
        """Test a pickle deserialization RCE vulnerability."""
        code = """
import pickle

def load_session(session_data):
    # Vulnerable to RCE via pickle
    return pickle.loads(session_data)
"""
        identifier = SinkIdentifier()
        sinks = identifier.identify(code, "test.py")

        serialization_sinks = [s for s in sinks if s.type == "serialization"]
        assert len(serialization_sinks) >= 1
        assert "pickle" in serialization_sinks[0].sink_call
