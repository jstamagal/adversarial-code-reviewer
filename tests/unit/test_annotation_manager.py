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

"""Tests for AnnotationManager."""

import os

import pytest
import yaml

from acr.annotations.manager import AnnotationManager, FindingAnnotation
from acr.models.finding import Finding, FindingImpact, FindingLocation, FindingRemediation


class TestFindingAnnotation:
    """Tests for FindingAnnotation model."""

    def test_create_annotation(self):
        """Test creating a finding annotation."""
        annotation = FindingAnnotation(
            finding_id="ACR-2025-0001",
            state="false-positive",
            notes="Not actually a vulnerability",
            updated_by="developer1",
        )

        assert annotation.finding_id == "ACR-2025-0001"
        assert annotation.state == "false-positive"
        assert annotation.notes == "Not actually a vulnerability"
        assert annotation.updated_by == "developer1"
        assert annotation.created_at is not None
        assert annotation.updated_at is not None

    def test_create_annotation_minimal(self):
        """Test creating annotation with minimal fields."""
        annotation = FindingAnnotation(
            finding_id="ACR-2025-0002",
            state="won't-fix",
        )

        assert annotation.finding_id == "ACR-2025-0002"
        assert annotation.state == "won't-fix"
        assert annotation.notes is None
        assert annotation.updated_by is None


class TestAnnotationManagerInit:
    """Tests for AnnotationManager initialization."""

    def test_init_no_file(self, tmp_path):
        """Test initialization when no state file exists."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        assert manager.annotations == {}
        assert manager.get_statistics()["total"] == 0

    def test_init_load_from_default_path(self, tmp_path):
        """Test loading annotations from default .acr-state.yaml."""
        state_file = tmp_path / ".acr-state.yaml"
        state_file.write_text(
            yaml.dump(
                {
                    "version": "1.0",
                    "created_at": "2025-01-19T00:00:00",
                    "updated_at": "2025-01-19T00:00:00",
                    "annotations": [
                        {
                            "finding_id": "ACR-2025-0001",
                            "state": "false-positive",
                            "notes": "Test annotation",
                            "created_at": "2025-01-19T00:00:00",
                            "updated_at": "2025-01-19T00:00:00",
                        }
                    ],
                }
            )
        )

        os.chdir(tmp_path)
        manager = AnnotationManager()

        assert len(manager.annotations) == 1
        assert "ACR-2025-0001" in manager.annotations
        assert manager.annotations["ACR-2025-0001"].state == "false-positive"

    def test_init_load_from_custom_path(self, tmp_path):
        """Test loading annotations from custom path."""
        state_file = tmp_path / "custom-state.yaml"
        state_file.write_text(
            yaml.dump(
                {
                    "version": "1.0",
                    "annotations": [
                        {
                            "finding_id": "ACR-2025-0002",
                            "state": "won't-fix",
                        }
                    ],
                }
            )
        )

        manager = AnnotationManager(state_path=state_file)

        assert len(manager.annotations) == 1
        assert "ACR-2025-0002" in manager.annotations

    def test_init_default_path_priority(self, tmp_path):
        """Test that default path priority is correct."""
        state1 = tmp_path / ".acr-state.yaml"
        state1.write_text("version: 1.0\nannotations: []")

        os.chdir(tmp_path)
        manager = AnnotationManager()

        assert manager.state_path == state1


class TestAnnotationManagerSetAnnotation:
    """Tests for setting annotations."""

    def test_set_annotation_new(self, tmp_path):
        """Test setting annotation for new finding."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        annotation = manager.set_annotation(
            finding_id="ACR-2025-0001",
            state="false-positive",
            notes="Not a real issue",
            updated_by="dev1",
        )

        assert annotation.finding_id == "ACR-2025-0001"
        assert annotation.state == "false-positive"
        assert annotation.notes == "Not a real issue"
        assert annotation.updated_by == "dev1"
        assert "ACR-2025-0001" in manager.annotations

    def test_set_annotation_update(self, tmp_path):
        """Test updating existing annotation."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        manager.set_annotation(
            finding_id="ACR-2025-0001",
            state="in-progress",
            notes="Initial notes",
        )

        updated = manager.set_annotation(
            finding_id="ACR-2025-0001",
            state="fixed",
            notes="Fixed it",
            updated_by="dev2",
        )

        assert updated.finding_id == "ACR-2025-0001"
        assert updated.state == "fixed"
        assert updated.notes == "Fixed it"
        assert updated.updated_by == "dev2"
        assert updated.created_at != updated.updated_at

    def test_set_annotation_invalid_state(self, tmp_path):
        """Test that invalid state raises error."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        with pytest.raises(ValueError, match="Invalid state"):
            manager.set_annotation(
                finding_id="ACR-2025-0001",
                state="invalid-state",
            )

    def test_set_annotation_all_states(self, tmp_path):
        """Test setting annotation for all valid states."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        valid_states = ["open", "in-progress", "fixed", "won't-fix", "false-positive"]
        for i, state in enumerate(valid_states):
            manager.set_annotation(finding_id=f"ACR-2025-{i:04d}", state=state)

        assert len(manager.annotations) == 5
        for i, state in enumerate(valid_states):
            assert manager.annotations[f"ACR-2025-{i:04d}"].state == state


class TestAnnotationManagerMarkAs:
    """Tests for mark_as_* methods."""

    def test_mark_as_false_positive(self, tmp_path):
        """Test marking finding as false positive."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        annotation = manager.mark_as_false_positive(
            finding_id="ACR-2025-0001",
            notes="False alarm",
            updated_by="security-team",
        )

        assert annotation.state == "false-positive"
        assert annotation.notes == "False alarm"
        assert annotation.updated_by == "security-team"

    def test_mark_as_accepted_risk(self, tmp_path):
        """Test marking finding as accepted risk (won't-fix)."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        annotation = manager.mark_as_accepted_risk(
            finding_id="ACR-2025-0001",
            notes="Accepting the risk",
        )

        assert annotation.state == "won't-fix"
        assert annotation.notes == "Accepting the risk"

    def test_mark_as_in_progress(self, tmp_path):
        """Test marking finding as in-progress."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        annotation = manager.mark_as_in_progress(
            finding_id="ACR-2025-0001",
            notes="Working on it",
        )

        assert annotation.state == "in-progress"
        assert annotation.notes == "Working on it"

    def test_mark_as_open(self, tmp_path):
        """Test marking finding as open (reset)."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        manager.mark_as_false_positive(finding_id="ACR-2025-0001")
        annotation = manager.mark_as_open(finding_id="ACR-2025-0001")

        assert annotation.state == "open"


class TestAnnotationManagerRemove:
    """Tests for removing annotations."""

    def test_remove_annotation_exists(self, tmp_path):
        """Test removing existing annotation."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        manager.set_annotation(finding_id="ACR-2025-0001", state="false-positive")
        removed = manager.remove_annotation("ACR-2025-0001")

        assert removed is True
        assert "ACR-2025-0001" not in manager.annotations

    def test_remove_annotation_not_exists(self, tmp_path):
        """Test removing non-existent annotation."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        removed = manager.remove_annotation("ACR-2025-0001")

        assert removed is False


class TestAnnotationManagerSaveLoad:
    """Tests for saving and loading annotations."""

    def test_save_and_load(self, tmp_path):
        """Test saving and loading annotations."""
        state_file = tmp_path / ".acr-state.yaml"
        manager = AnnotationManager(state_path=state_file)

        manager.set_annotation(
            finding_id="ACR-2025-0001",
            state="false-positive",
            notes="Test annotation",
            updated_by="user1",
        )
        manager.set_annotation(
            finding_id="ACR-2025-0002",
            state="won't-fix",
            notes="Another annotation",
        )

        manager.save_annotations()

        manager2 = AnnotationManager(state_path=state_file)
        assert len(manager2.annotations) == 2
        assert manager2.get_annotation("ACR-2025-0001").state == "false-positive"
        assert manager2.get_annotation("ACR-2025-0002").state == "won't-fix"

    def test_save_creates_file(self, tmp_path):
        """Test that save creates the state file."""
        state_file = tmp_path / "test-state.yaml"
        manager = AnnotationManager(state_path=state_file)

        manager.set_annotation(finding_id="ACR-2025-0001", state="fixed")
        manager.save_annotations()

        assert state_file.exists()

        with open(state_file) as f:
            data = yaml.safe_load(f)

        assert data["version"] == "1.0"
        assert len(data["annotations"]) == 1


class TestAnnotationManagerApply:
    """Tests for applying annotations to findings."""

    def test_apply_annotations(self, tmp_path):
        """Test applying annotations to findings."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        manager.set_annotation(
            finding_id="ACR-2025-0001",
            state="false-positive",
        )
        manager.set_annotation(
            finding_id="ACR-2025-0002",
            state="won't-fix",
        )

        findings = [
            Finding(
                id="ACR-2025-0001",
                title="SQL Injection",
                severity="critical",
                confidence="high",
                category="injection",
                location=FindingLocation(file="app.py", line=42),
                description="SQL injection vulnerability",
                attack_vector="Malicious SQL input",
                impact=FindingImpact(confidentiality="high", integrity="high", availability="none"),
                remediation=FindingRemediation(description="Use parameterized queries"),
            ),
            Finding(
                id="ACR-2025-0002",
                title="XSS",
                severity="high",
                confidence="medium",
                category="xss",
                location=FindingLocation(file="templates/index.html", line=10),
                description="Cross-site scripting",
                attack_vector="Script injection",
                impact=FindingImpact(
                    confidentiality="medium", integrity="low", availability="none"
                ),
                remediation=FindingRemediation(description="Sanitize output"),
            ),
            Finding(
                id="ACR-2025-0003",
                title="Missing Auth",
                severity="high",
                confidence="high",
                category="auth",
                location=FindingLocation(file="api.py", line=55),
                description="Missing authentication",
                attack_vector="Unauthorized access",
                impact=FindingImpact(
                    confidentiality="high", integrity="high", availability="medium"
                ),
                remediation=FindingRemediation(description="Add authentication"),
            ),
        ]

        updated = manager.apply_annotations(findings)

        assert updated[0].state == "false-positive"
        assert updated[1].state == "won't-fix"
        assert updated[2].state == "open"

    def test_apply_annotations_no_annotations(self, tmp_path):
        """Test applying annotations when no annotations exist."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        findings = [
            Finding(
                id="ACR-2025-0001",
                title="Test",
                severity="medium",
                confidence="high",
                category="test",
                location=FindingLocation(file="test.py", line=1),
                description="Test finding",
                attack_vector="Test",
                impact=FindingImpact(confidentiality="low", integrity="low", availability="none"),
                remediation=FindingRemediation(description="Test"),
            ),
        ]

        updated = manager.apply_annotations(findings)

        assert updated[0].state == "open"


class TestAnnotationManagerQueries:
    """Tests for query methods."""

    def test_get_all_annotations(self, tmp_path):
        """Test getting all annotations."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        manager.set_annotation("ACR-2025-0001", "false-positive")
        manager.set_annotation("ACR-2025-0002", "won't-fix")
        manager.set_annotation("ACR-2025-0003", "in-progress")

        all_annotations = manager.get_all_annotations()

        assert len(all_annotations) == 3

    def test_get_annotations_by_state(self, tmp_path):
        """Test getting annotations filtered by state."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        manager.set_annotation("ACR-2025-0001", "false-positive")
        manager.set_annotation("ACR-2025-0002", "false-positive")
        manager.set_annotation("ACR-2025-0003", "won't-fix")

        false_positives = manager.get_annotations_by_state("false-positive")
        won_fix = manager.get_annotations_by_state("won't-fix")

        assert len(false_positives) == 2
        assert len(won_fix) == 1

    def test_get_statistics(self, tmp_path):
        """Test getting annotation statistics."""
        os.chdir(tmp_path)
        manager = AnnotationManager()

        manager.set_annotation("ACR-2025-0001", "open")
        manager.set_annotation("ACR-2025-0002", "in-progress")
        manager.set_annotation("ACR-2025-0003", "fixed")
        manager.set_annotation("ACR-2025-0004", "won't-fix")
        manager.set_annotation("ACR-2025-0005", "false-positive")

        stats = manager.get_statistics()

        assert stats["total"] == 5
        assert stats["open"] == 1
        assert stats["in-progress"] == 1
        assert stats["fixed"] == 1
        assert stats["won't-fix"] == 1
        assert stats["false-positive"] == 1


class TestAnnotationManagerReload:
    """Tests for reload functionality."""

    def test_reload(self, tmp_path):
        """Test reloading annotations from file."""
        state_file = tmp_path / ".acr-state.yaml"
        manager = AnnotationManager(state_path=state_file)

        manager.set_annotation("ACR-2025-0001", "false-positive")
        manager.save_annotations()

        state_file.write_text(
            yaml.dump(
                {
                    "version": "1.0",
                    "annotations": [
                        {
                            "finding_id": "ACR-2025-0002",
                            "state": "won't-fix",
                            "notes": "Updated externally",
                            "created_at": "2025-01-19T00:00:00",
                            "updated_at": "2025-01-19T01:00:00",
                        }
                    ],
                }
            )
        )

        manager.reload()

        assert len(manager.annotations) == 1
        assert "ACR-2025-0002" in manager.annotations
        assert manager.annotations["ACR-2025-0002"].state == "won't-fix"
