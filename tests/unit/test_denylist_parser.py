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

"""Tests for DenylistParser."""

import pytest
from pathlib import Path
import tempfile
from acr.denylist.parser import DenylistParser, DenylistEntry


class TestDenylistParser:
    """Test DenylistParser functionality."""

    def test_parse_nonexistent_file(self, tmp_path: Path):
        """Test parsing a non-existent file."""
        parser = DenylistParser(tmp_path / "nonexistent.txt")
        parser.parse()
        assert len(parser.entries) == 0
        assert len(parser.file_patterns) == 0
        assert len(parser.function_patterns) == 0

    def test_parse_empty_file(self, tmp_path: Path):
        """Test parsing an empty file."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("")
        parser = DenylistParser(denylist_file)
        parser.parse()
        assert len(parser.entries) == 0

    def test_parse_file_patterns(self, tmp_path: Path):
        """Test parsing file patterns."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("""
# Test denylist
src/auth.py
test_.*\\.py
file:admin/
""")
        parser = DenylistParser(denylist_file)
        parser.parse()

        assert len(parser.entries) == 3
        assert parser.entries[0].pattern == "src/auth.py"
        assert parser.entries[0].entry_type == "file"
        assert parser.entries[0].comment is None

        assert len(parser.file_patterns) == 3

    def test_parse_function_patterns(self, tmp_path: Path):
        """Test parsing function patterns."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("""
auth.py:login
function:user.py:authenticate
user.py->validate_password
logout()
""")
        parser = DenylistParser(denylist_file)
        parser.parse()

        assert len(parser.entries) == 4
        assert parser.entries[0].pattern == "auth.py:login"
        assert parser.entries[0].entry_type == "function"

        assert len(parser.function_patterns) == 4

    def test_parse_comments(self, tmp_path: Path):
        """Test parsing entries with comments."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("""
src/auth.py  # Critical authentication code
function:login  # Entry point
""")
        parser = DenylistParser(denylist_file)
        parser.parse()

        assert len(parser.entries) == 2
        assert parser.entries[0].comment == "Critical authentication code"
        assert parser.entries[1].comment == "Entry point"

    def test_parse_inline_and_hash_comments(self, tmp_path: Path):
        """Test parsing with both inline comments and hash-only lines."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("""
# This is a comment
src/auth.py  # Inline comment
# Another comment
login()
""")
        parser = DenylistParser(denylist_file)
        parser.parse()

        assert len(parser.entries) == 2

    def test_parse_whitespace_handling(self, tmp_path: Path):
        """Test that whitespace is handled correctly."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("""
    
    src/auth.py
    
    login()
    
""")
        parser = DenylistParser(denylist_file)
        parser.parse()

        assert len(parser.entries) == 2

    def test_is_file_denied(self, tmp_path: Path):
        """Test file denial matching."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("""
src/auth.py
test_.*\\.py
file:admin/
""")
        parser = DenylistParser(denylist_file)
        parser.parse()

        assert parser.is_file_denied("src/auth.py") is True
        assert parser.is_file_denied("src/auth.py") is True
        assert parser.is_file_denied("test_login.py") is True
        assert parser.is_file_denied("admin/settings.py") is True
        assert parser.is_file_denied("src/user.py") is False
        assert parser.is_file_denied("production.py") is False

    def test_is_function_denied(self, tmp_path: Path):
        """Test function denial matching."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("""
function:auth.py:login
function:user.py:authenticate
function:user.py->validate_password
logout()
""")
        parser = DenylistParser(denylist_file)
        parser.parse()

        assert parser.is_function_denied("auth.py", "login") is True
        assert parser.is_function_denied("user.py", "authenticate") is True
        assert parser.is_function_denied("user.py", "validate_password") is True
        assert parser.is_function_denied("session.py", "logout") is True
        assert parser.is_function_denied("auth.py", "logout") is True
        assert parser.is_function_denied("user.py", "delete") is False

    def test_invalid_regex_handling(self, tmp_path: Path, caplog):
        """Test that invalid regex patterns are logged but don't crash."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("""
src/auth.py
[invalid(regex
login()
""")
        parser = DenylistParser(denylist_file)
        parser.parse()

        assert len(parser.entries) == 3
        assert len(parser.file_patterns) == 1  # Only valid pattern

    def test_get_entries(self, tmp_path: Path):
        """Test getting all entries."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("""
src/auth.py  # Critical file
login()  # Critical function
""")
        parser = DenylistParser(denylist_file)
        parser.parse()

        entries = parser.get_entries()
        assert len(entries) == 2
        assert all(isinstance(entry, DenylistEntry) for entry in entries)

    def test_file_prefix_handling(self, tmp_path: Path):
        """Test that file: prefix is properly stripped."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("""
file:src/auth.py
src/user.py
""")
        parser = DenylistParser(denylist_file)
        parser.parse()

        assert len(parser.file_patterns) == 2

    def test_function_prefix_handling(self, tmp_path: Path):
        """Test that function: prefix is properly stripped."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("""
function:login
logout()
""")
        parser = DenylistParser(denylist_file)
        parser.parse()

        assert len(parser.function_patterns) == 2

    def test_mixed_patterns(self, tmp_path: Path):
        """Test parsing mixed file and function patterns."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("""
src/auth.py
login()
test_.*\\.py
user.py:authenticate
admin/
""")
        parser = DenylistParser(denylist_file)
        parser.parse()

        assert len(parser.file_patterns) == 3
        assert len(parser.function_patterns) == 2
        assert len(parser.entries) == 5
