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

"""Tests for allowlist parser."""

from pathlib import Path

from acr.allowlist.parser import AllowlistEntry, AllowlistParser


class TestAllowlistEntry:
    """Test AllowlistEntry model."""

    def test_create_entry(self):
        """Test creating an allowlist entry."""
        entry = AllowlistEntry(pattern="test.py:42", entry_type="line", comment="Test exclusion")
        assert entry.pattern == "test.py:42"
        assert entry.entry_type == "line"
        assert entry.comment == "Test exclusion"

    def test_create_entry_without_comment(self):
        """Test creating an entry without comment."""
        entry = AllowlistEntry(pattern="test.py:42", entry_type="line")
        assert entry.comment is None


class TestAllowlistParser:
    """Test AllowlistParser."""

    def test_parser_init(self, tmp_path: Path):
        """Test parser initialization."""
        allowlist_file = tmp_path / ".acr-ignore"
        parser = AllowlistParser(allowlist_file)
        assert parser.file_path == allowlist_file
        assert len(parser.entries) == 0

    def test_parse_nonexistent_file(self, tmp_path: Path):
        """Test parsing nonexistent file."""
        allowlist_file = tmp_path / ".acr-ignore"
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        assert len(parser.entries) == 0

    def test_parse_empty_file(self, tmp_path: Path):
        """Test parsing empty file."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("")
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        assert len(parser.entries) == 0

    def test_parse_line_exclusions(self, tmp_path: Path):
        """Test parsing line exclusions."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text(
            """
test.py:42
another.py:100
"""
        )
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        assert len(parser.entries) == 2
        assert parser.is_line_excluded("test.py", 42)
        assert parser.is_line_excluded("another.py", 100)
        assert not parser.is_line_excluded("test.py", 43)

    def test_parse_with_comments(self, tmp_path: Path):
        """Test parsing file with comments."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text(
            """
# Comment line
test.py:42  # This is a comment

another.py:100  # Another comment
"""
        )
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        assert len(parser.entries) == 2
        assert parser.entries[0].comment == "This is a comment"
        assert parser.entries[1].comment == "Another comment"

    def test_parse_regex_exclusions(self, tmp_path: Path):
        """Test parsing regex exclusions."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text(
            """
regex:^.*_test\\.py$
regex:^vendor/.*$
"""
        )
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        assert len(parser.entries) == 2
        assert parser.is_regex_excluded("my_test.py")
        assert parser.is_regex_excluded("vendor/library.py")
        assert not parser.is_regex_excluded("main.py")
        assert parser.is_regex_excluded("src/my_test.py")

    def test_parse_pattern_exclusions(self, tmp_path: Path):
        """Test parsing pattern exclusions."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text(
            """
pattern:sql_injection
pattern:xss
broken_authentication
"""
        )
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        assert len(parser.entries) == 3
        assert parser.is_pattern_excluded("sql_injection")
        assert parser.is_pattern_excluded("xss")
        assert parser.is_pattern_excluded("broken_authentication")
        assert not parser.is_pattern_excluded("command_injection")

    def test_parse_mixed_entries(self, tmp_path: Path):
        """Test parsing mixed entry types."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text(
            """
test.py:42
regex:.*_test\\.py$
pattern:sql_injection
"""
        )
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        assert len(parser.entries) == 3
        assert parser.is_line_excluded("test.py", 42)
        assert parser.is_regex_excluded("my_test.py")
        assert parser.is_pattern_excluded("sql_injection")

    def test_invalid_regex(self, tmp_path: Path):
        """Test handling of invalid regex."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("regex:[invalid(regex")
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        assert len(parser.entries) == 1
        assert len(parser.regex_exclusions) == 0

    def test_invalid_line_format(self, tmp_path: Path):
        """Test handling of invalid line format."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("invalid:line:format")
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        assert len(parser.entries) == 1
        assert not parser.is_line_excluded("invalid", 42)

    def test_invalid_line_number(self, tmp_path: Path):
        """Test handling of invalid line number."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("test.py:abc")
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        assert len(parser.entries) == 1
        assert not parser.is_line_excluded("test.py", 42)

    def test_detect_entry_type_line(self):
        """Test detecting line entry type."""
        parser = AllowlistParser(Path(".acr-ignore"))
        assert parser._detect_entry_type("test.py:42") == "line"

    def test_detect_entry_type_regex(self):
        """Test detecting regex entry type."""
        parser = AllowlistParser(Path(".acr-ignore"))
        assert parser._detect_entry_type("regex:.*\\.py$") == "regex"

    def test_detect_entry_type_pattern(self):
        """Test detecting pattern entry type."""
        parser = AllowlistParser(Path(".acr-ignore"))
        assert parser._detect_entry_type("pattern:sql_injection") == "pattern"
        assert parser._detect_entry_type("sql_injection") == "pattern"

    def test_is_valid_line_number(self):
        """Test line number validation."""
        parser = AllowlistParser(Path(".acr-ignore"))
        assert parser._is_valid_line_number("42") is True
        assert parser._is_valid_line_number("1") is True
        assert parser._is_valid_line_number("0") is False
        assert parser._is_valid_line_number("-1") is False
        assert parser._is_valid_line_number("abc") is False

    def test_get_entries(self, tmp_path: Path):
        """Test getting all entries."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text(
            """
test.py:42  # Comment 1
regex:.*\\.py$  # Comment 2
"""
        )
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        entries = parser.get_entries()
        assert len(entries) == 2
        assert entries[0].pattern == "test.py:42"
        assert entries[1].pattern == "regex:.*\\.py$"

    def test_multiple_line_exclusions_same_file(self, tmp_path: Path):
        """Test multiple line exclusions for same file."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text(
            """
test.py:10
test.py:20
test.py:30
"""
        )
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        assert parser.is_line_excluded("test.py", 10)
        assert parser.is_line_excluded("test.py", 20)
        assert parser.is_line_excluded("test.py", 30)
        assert not parser.is_line_excluded("test.py", 15)

    def test_whitespace_handling(self, tmp_path: Path):
        """Test handling of whitespace."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("   test.py:42   ")
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        assert len(parser.entries) == 1
        assert parser.is_line_excluded("test.py", 42)

    def test_pattern_prefix_optional(self, tmp_path: Path):
        """Test that pattern: prefix is optional."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text(
            """
sql_injection
pattern:xss
"""
        )
        parser = AllowlistParser(allowlist_file)
        parser.parse()
        assert parser.is_pattern_excluded("sql_injection")
        assert parser.is_pattern_excluded("xss")
