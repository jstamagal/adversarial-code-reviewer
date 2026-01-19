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

"""Tests for allowlist manager."""

import pytest
from pathlib import Path
import tempfile
from acr.allowlist.manager import AllowlistManager
from acr.models.finding import Finding, FindingLocation, FindingImpact, FindingRemediation


class TestAllowlistManager:
    """Test AllowlistManager."""

    def create_finding(
        self, file_path: str = "test.py", line_number: int = 42, category: str = "sql_injection"
    ) -> Finding:
        """Helper to create a test finding.

        Args:
            file_path: File path for the finding
            line_number: Line number for the finding
            category: Category for the finding

        Returns:
            Finding object
        """
        return Finding(
            id="test-001",
            title="Test Finding",
            severity="high",
            confidence="medium",
            category=category,
            location=FindingLocation(file=file_path, line=line_number),
            description="Test description",
            attack_vector="Test attack",
            impact=FindingImpact(confidentiality="medium", integrity="medium", availability="none"),
            remediation=FindingRemediation(description="Fix it"),
        )

    def test_manager_init_no_allowlist(self, tmp_path: Path):
        """Test manager initialization without allowlist file."""
        manager = AllowlistManager(allowlist_path=None)
        assert manager.parser is None

    def test_manager_init_with_path(self, tmp_path: Path):
        """Test manager initialization with allowlist path."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("test.py:42")
        manager = AllowlistManager(allowlist_file)
        assert manager.parser is not None
        assert len(manager.parser.entries) == 1

    def test_manager_load_default_files(self, tmp_path: Path):
        """Test manager loads default allowlist files."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("test.py:42")
        manager = AllowlistManager(allowlist_file)
        assert manager.parser is not None

    def test_should_exclude_finding_no_allowlist(self, tmp_path: Path):
        """Test finding exclusion when no allowlist exists."""
        manager = AllowlistManager()
        finding = self.create_finding()
        assert not manager.should_exclude_finding(finding)

    def test_should_exclude_by_line(self, tmp_path: Path):
        """Test excluding finding by line number."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("test.py:42")
        manager = AllowlistManager(allowlist_file)

        finding = self.create_finding(file_path="test.py", line_number=42)
        assert manager.should_exclude_finding(finding)

        finding = self.create_finding(file_path="test.py", line_number=43)
        assert not manager.should_exclude_finding(finding)

    def test_should_exclude_by_regex(self, tmp_path: Path):
        """Test excluding finding by regex pattern."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("regex:.*_test\\.py$")
        manager = AllowlistManager(allowlist_file)

        finding = self.create_finding(file_path="my_test.py")
        assert manager.should_exclude_finding(finding)

        finding = self.create_finding(file_path="main.py")
        assert not manager.should_exclude_finding(finding)

    def test_should_exclude_by_pattern(self, tmp_path: Path):
        """Test excluding finding by pattern name."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("pattern:sql_injection")
        manager = AllowlistManager(allowlist_file)

        finding = self.create_finding(category="sql_injection")
        assert manager.should_exclude_finding(finding)

        finding = self.create_finding(category="xss")
        assert not manager.should_exclude_finding(finding)

    def test_get_exclusion_reason_none(self, tmp_path: Path):
        """Test getting exclusion reason when not excluded."""
        manager = AllowlistManager()
        finding = self.create_finding()
        reason = manager.get_exclusion_reason(finding)
        assert reason is None

    def test_get_exclusion_reason_line(self, tmp_path: Path):
        """Test getting exclusion reason for line exclusion."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("test.py:42")
        manager = AllowlistManager(allowlist_file)

        finding = self.create_finding(file_path="test.py", line_number=42)
        reason = manager.get_exclusion_reason(finding)
        assert reason is not None
        assert "Line 42" in reason
        assert "test.py" in reason

    def test_get_exclusion_reason_regex(self, tmp_path: Path):
        """Test getting exclusion reason for regex exclusion."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("regex:.*_test\\.py$")
        manager = AllowlistManager(allowlist_file)

        finding = self.create_finding(file_path="my_test.py")
        reason = manager.get_exclusion_reason(finding)
        assert reason is not None
        assert "my_test.py" in reason
        assert "regex" in reason

    def test_get_exclusion_reason_pattern(self, tmp_path: Path):
        """Test getting exclusion reason for pattern exclusion."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("pattern:sql_injection")
        manager = AllowlistManager(allowlist_file)

        finding = self.create_finding(category="sql_injection")
        reason = manager.get_exclusion_reason(finding)
        assert reason is not None
        assert "sql_injection" in reason
        assert "Pattern" in reason

    def test_reload(self, tmp_path: Path):
        """Test reloading allowlist."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("test.py:42")
        manager = AllowlistManager(allowlist_file)

        finding = self.create_finding(file_path="test.py", line_number=42)
        assert manager.should_exclude_finding(finding)

        allowlist_file.write_text("")
        manager.reload()

        assert not manager.should_exclude_finding(finding)

    def test_priority_line_over_pattern(self, tmp_path: Path):
        """Test that line exclusions take priority."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("""
test.py:42
pattern:sql_injection
""")
        manager = AllowlistManager(allowlist_file)

        finding = self.create_finding(file_path="test.py", line_number=42, category="sql_injection")
        assert manager.should_exclude_finding(finding)

        reason = manager.get_exclusion_reason(finding)
        assert reason is not None
        assert "Line 42" in reason

    def test_multiple_files_same_line(self, tmp_path: Path):
        """Test line exclusion works correctly for different files."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("test.py:42")
        manager = AllowlistManager(allowlist_file)

        finding = self.create_finding(file_path="test.py", line_number=42)
        assert manager.should_exclude_finding(finding)

        finding = self.create_finding(file_path="other.py", line_number=42)
        assert not manager.should_exclude_finding(finding)

    def test_regex_matches_subdirectory(self, tmp_path: Path):
        """Test regex matches files in subdirectories."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("regex:^vendor/.*$")
        manager = AllowlistManager(allowlist_file)

        finding = self.create_finding(file_path="vendor/lib.py")
        assert manager.should_exclude_finding(finding)

        finding = self.create_finding(file_path="src/lib.py")
        assert not manager.should_exclude_finding(finding)

    def test_pattern_exclusion_case_sensitive(self, tmp_path: Path):
        """Test pattern exclusions are case sensitive."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("pattern:SQL_INJECTION")
        manager = AllowlistManager(allowlist_file)

        finding = self.create_finding(category="SQL_INJECTION")
        assert manager.should_exclude_finding(finding)

        finding = self.create_finding(category="sql_injection")
        assert not manager.should_exclude_finding(finding)

    def test_empty_allowlist(self, tmp_path: Path):
        """Test behavior with empty allowlist."""
        allowlist_file = tmp_path / ".acr-ignore"
        allowlist_file.write_text("")
        manager = AllowlistManager(allowlist_file)

        finding = self.create_finding()
        assert not manager.should_exclude_finding(finding)
        assert manager.get_exclusion_reason(finding) is None
