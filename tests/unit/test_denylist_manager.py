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

"""Tests for DenylistManager."""

import pytest
from pathlib import Path
from pydantic import BaseModel
from acr.denylist.manager import DenylistManager


class MockLocation(BaseModel):
    """Mock Finding location."""

    file: str
    line: int
    function: str | None = None


class MockFinding(BaseModel):
    """Mock Finding."""

    location: MockLocation
    category: str = "injection"


class TestDenylistManager:
    """Test DenylistManager functionality."""

    def test_init_without_denylist_file(self, tmp_path: Path):
        """Test initialization without a denylist file."""
        manager = DenylistManager(denylist_path=tmp_path / "nonexistent.txt")
        assert manager.parser is None

    def test_init_with_custom_denylist_path(self, tmp_path: Path):
        """Test initialization with custom denylist path."""
        denylist_file = tmp_path / "custom-denylist.txt"
        denylist_file.write_text("src/auth.py")
        manager = DenylistManager(denylist_path=denylist_file)
        assert manager.parser is not None
        assert len(manager.parser.file_patterns) == 1

    def test_load_default_denylist_files(self, tmp_path: Path):
        """Test loading default denylist file locations."""
        import os

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            (tmp_path / ".acr-denylist").write_text("src/auth.py")
            manager = DenylistManager(denylist_path=None)
            assert manager.parser is not None
            assert len(manager.parser.file_patterns) == 1
        finally:
            os.chdir(old_cwd)

    def test_should_force_include_finding_by_file(self, tmp_path: Path):
        """Test forcing inclusion of findings from specific files."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text(
            """
src/auth.py
test_.*\\.py
"""
        )
        manager = DenylistManager(denylist_path=denylist_file)

        finding1 = MockFinding(
            location=MockLocation(file="src/auth.py", line=42), category="injection"
        )
        assert manager.should_force_include_finding(finding1) is True

        finding2 = MockFinding(location=MockLocation(file="test_login.py", line=10), category="xss")
        assert manager.should_force_include_finding(finding2) is True

        finding3 = MockFinding(
            location=MockLocation(file="src/user.py", line=15), category="injection"
        )
        assert manager.should_force_include_finding(finding3) is False

    def test_should_force_include_finding_by_function(self, tmp_path: Path):
        """Test forcing inclusion of findings from specific functions."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text(
            """
function:auth.py:login
function:user.py:authenticate
"""
        )
        manager = DenylistManager(denylist_path=denylist_file)

        finding1 = MockFinding(
            location=MockLocation(file="auth.py", line=42, function="login"),
            category="injection",
        )
        assert manager.should_force_include_finding(finding1) is True

        finding2 = MockFinding(
            location=MockLocation(file="user.py", line=15, function="authenticate"),
            category="xss",
        )
        assert manager.should_force_include_finding(finding2) is True

        finding3 = MockFinding(
            location=MockLocation(file="auth.py", line=50, function="logout"),
            category="injection",
        )
        assert manager.should_force_include_finding(finding3) is False

    def test_should_force_include_without_denylist(self, tmp_path: Path):
        """Test that no findings are forced when no denylist exists."""
        manager = DenylistManager(denylist_path=tmp_path / "nonexistent.txt")

        finding = MockFinding(
            location=MockLocation(file="src/auth.py", line=42, function="login"),
            category="injection",
        )
        assert manager.should_force_include_finding(finding) is False

    def test_get_deny_reason_for_file(self, tmp_path: Path):
        """Test getting denial reason for file-based denial."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("src/auth.py")
        manager = DenylistManager(denylist_path=denylist_file)

        finding = MockFinding(
            location=MockLocation(file="src/auth.py", line=42), category="injection"
        )
        reason = manager.get_deny_reason(finding)
        assert "src/auth.py" in reason
        assert "denylist" in reason.lower()

    def test_get_deny_reason_for_function(self, tmp_path: Path):
        """Test getting denial reason for function-based denial."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("function:auth.py:login")
        manager = DenylistManager(denylist_path=denylist_file)

        finding = MockFinding(
            location=MockLocation(file="auth.py", line=42, function="login"),
            category="injection",
        )
        reason = manager.get_deny_reason(finding)
        assert "login" in reason
        assert "denylist" in reason.lower()

    def test_get_deny_reason_none(self, tmp_path: Path):
        """Test getting denial reason when not denied."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("src/auth.py")
        manager = DenylistManager(denylist_path=denylist_file)

        finding = MockFinding(
            location=MockLocation(file="src/user.py", line=42), category="injection"
        )
        reason = manager.get_deny_reason(finding)
        assert reason is None

    def test_reload_denylist(self, tmp_path: Path):
        """Test reloading denylist from file."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("src/auth.py")
        manager = DenylistManager(denylist_path=denylist_file)

        assert len(manager.parser.file_patterns) == 1

        denylist_file.write_text(
            """
src/auth.py
login()
"""
        )
        manager.reload()

        assert len(manager.parser.file_patterns) == 1
        assert len(manager.parser.function_patterns) == 1

    def test_function_without_name_in_finding(self, tmp_path: Path):
        """Test handling findings without function names."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("login()")
        manager = DenylistManager(denylist_path=denylist_file)

        finding = MockFinding(location=MockLocation(file="auth.py", line=42), category="injection")
        assert manager.should_force_include_finding(finding) is False

    def test_mixed_file_and_function_patterns(self, tmp_path: Path):
        """Test manager with mixed file and function patterns."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text(
            """
src/auth.py
login()
test_.*\\.py
function:user.py:authenticate
"""
        )
        manager = DenylistManager(denylist_path=denylist_file)

        finding1 = MockFinding(
            location=MockLocation(file="src/auth.py", line=42), category="injection"
        )
        assert manager.should_force_include_finding(finding1) is True

        finding2 = MockFinding(
            location=MockLocation(file="session.py", line=10, function="login"),
            category="xss",
        )
        assert manager.should_force_include_finding(finding2) is True

        finding3 = MockFinding(
            location=MockLocation(file="test_unit.py", line=5), category="injection"
        )
        assert manager.should_force_include_finding(finding3) is True

        finding4 = MockFinding(
            location=MockLocation(file="user.py", line=15, function="authenticate"),
            category="injection",
        )
        assert manager.should_force_include_finding(finding4) is True

        finding5 = MockFinding(
            location=MockLocation(file="admin.py", line=20, function="login"),
            category="xss",
        )
        assert manager.should_force_include_finding(finding5) is True

    def test_default_denylist_search_paths(self, tmp_path: Path):
        """Test that default denylist files are found in order."""
        import os

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            (tmp_path / ".acr").mkdir(exist_ok=True)
            (tmp_path / ".acr/denylist").write_text("priority.py")

            manager = DenylistManager(denylist_path=None)
            assert manager.parser is not None
            assert len(manager.parser.file_patterns) == 1
        finally:
            os.chdir(old_cwd)

    def test_empty_denylist_file(self, tmp_path: Path):
        """Test manager with an empty denylist file."""
        denylist_file = tmp_path / "test-denylist.txt"
        denylist_file.write_text("")
        manager = DenylistManager(denylist_path=denylist_file)

        finding = MockFinding(
            location=MockLocation(file="src/auth.py", line=42), category="injection"
        )
        assert manager.should_force_include_finding(finding) is False
        assert manager.get_deny_reason(finding) is None
