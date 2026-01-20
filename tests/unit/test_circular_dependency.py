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

"""Tests for circular dependency detection."""

import tempfile
from pathlib import Path

import pytest

from acr.core.circular_dependency import CircularDependency, CircularDependencyDetector


@pytest.fixture
def temp_dir():
    """Create temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestCircularDependencyDetection:
    """Test circular dependency detection."""

    def test_detect_direct_circular_dependency(self, temp_dir):
        """Test detecting direct circular import (A imports B, B imports A)."""
        module_a = temp_dir / "module_a.py"
        module_a.write_text("from module_b import something\n\ndef func_a():\n    pass\n")

        module_b = temp_dir / "module_b.py"
        module_b.write_text("from module_a import func_a\n\ndef something():\n    pass\n")

        detector = CircularDependencyDetector()
        cycles = detector.detect_all(temp_dir)

        assert len(cycles) > 0
        assert any(len(cycle.cycle) == 3 for cycle in cycles)

    def test_detect_no_circular_dependencies(self, temp_dir):
        """Test when no circular dependencies exist."""
        module_a = temp_dir / "module_a.py"
        module_a.write_text("import os\nimport sys\n")
        module_a.write_text("\n\ndef func_a():\n    pass\n")

        module_b = temp_dir / "module_b.py"
        module_b.write_text("import os\n")
        module_b.write_text("\n\ndef func_b():\n    pass\n")

        detector = CircularDependencyDetector()
        cycles = detector.detect_all(temp_dir)

        assert len(cycles) == 0

    def test_detect_indirect_circular_dependency(self, temp_dir):
        """Test detecting indirect circular import (A -> B -> C -> A)."""
        module_a = temp_dir / "module_a.py"
        module_a.write_text("from module_b import func_b\n")

        module_b = temp_dir / "module_b.py"
        module_b.write_text("from module_c import func_c\n")

        module_c = temp_dir / "module_c.py"
        module_c.write_text("from module_a import func_a\n")

        detector = CircularDependencyDetector()
        cycles = detector.detect_all(temp_dir)

        assert len(cycles) > 0
        assert any(len(cycle.cycle) == 4 for cycle in cycles)

    def test_max_depth_limit(self, temp_dir):
        """Test that max_depth limits cycle detection."""
        module_a = temp_dir / "module_a.py"
        module_a.write_text("from module_b import func_b\n")

        module_b = temp_dir / "module_b.py"
        module_b.write_text("from module_c import func_c\n")

        module_c = temp_dir / "module_c.py"
        module_c.write_text("from module_a import func_a\n")

        detector = CircularDependencyDetector(max_depth=2)
        cycles = detector.detect_all(temp_dir)

        assert len(cycles) == 0

    def test_severity_calculation(self, temp_dir):
        """Test severity calculation based on cycle length."""
        module_a = temp_dir / "module_a.py"
        module_a.write_text("from module_b import func_b\n")

        module_b = temp_dir / "module_b.py"
        module_b.write_text("from module_a import func_a\n")

        detector = CircularDependencyDetector()
        cycles = detector.detect_all(temp_dir)

        assert len(cycles) > 0
        assert cycles[0].severity == "medium"

    def test_description_generation(self, temp_dir):
        """Test description generation for cycles."""
        module_a = temp_dir / "module_a.py"
        module_a.write_text("from module_b import func_b\n")

        module_b = temp_dir / "module_b.py"
        module_b.write_text("from module_a import func_a\n")

        detector = CircularDependencyDetector()
        cycles = detector.detect_all(temp_dir)

        assert len(cycles) > 0
        assert "module_a" in cycles[0].description
        assert "module_b" in cycles[0].description
        assert "->" in cycles[0].description

    def test_empty_directory(self, temp_dir):
        """Test handling of empty directory."""
        detector = CircularDependencyDetector()
        cycles = detector.detect_all(temp_dir)

        assert len(cycles) == 0

    def test_self_import(self, temp_dir):
        """Test that self-imports are not detected as cycles."""
        module_a = temp_dir / "module_a.py"
        module_a.write_text("from . import func\n")

        detector = CircularDependencyDetector()
        cycles = detector.detect_all(temp_dir)

        assert len(cycles) == 0

    def test_external_imports_ignored(self, temp_dir):
        """Test that external imports don't create false positives."""
        module_a = temp_dir / "module_a.py"
        module_a.write_text("import os\nimport sys\nfrom typing import List\n")

        module_b = temp_dir / "module_b.py"
        module_b.write_text("import json\nfrom pathlib import Path\n")

        detector = CircularDependencyDetector()
        cycles = detector.detect_all(temp_dir)

        assert len(cycles) == 0

    def test_complex_circular_dependency(self, temp_dir):
        """Test detecting complex circular dependencies."""
        module_a = temp_dir / "module_a.py"
        module_a.write_text("from module_b import func_b\n")

        module_b = temp_dir / "module_b.py"
        module_b.write_text("from module_c import func_c\n")

        module_c = temp_dir / "module_c.py"
        module_c.write_text("from module_d import func_d\n")

        module_d = temp_dir / "module_d.py"
        module_d.write_text("from module_a import func_a\n")

        detector = CircularDependencyDetector()
        cycles = detector.detect_all(temp_dir)

        assert len(cycles) > 0
        assert any(len(cycle.cycle) == 5 for cycle in cycles)

    def test_multiple_cycles(self, temp_dir):
        """Test detecting multiple independent cycles."""
        cycle1_a = temp_dir / "cycle1_a.py"
        cycle1_a.write_text("from cycle1_b import func\n")

        cycle1_b = temp_dir / "cycle1_b.py"
        cycle1_b.write_text("from cycle1_a import func\n")

        cycle2_a = temp_dir / "cycle2_a.py"
        cycle2_a.write_text("from cycle2_b import func\n")

        cycle2_b = temp_dir / "cycle2_b.py"
        cycle2_b.write_text("from cycle2_a import func\n")

        detector = CircularDependencyDetector()
        cycles = detector.detect_all(temp_dir)

        assert len(cycles) >= 2

    def test_package_with_init(self, temp_dir):
        """Test handling of packages with __init__.py."""
        pytest.skip("Package-level imports not fully supported yet")

    def test_detect_cycles_from_start_file(self, temp_dir):
        """Test detect_cycles method with specific start file."""
        module_a = temp_dir / "module_a.py"
        module_a.write_text("from module_b import func_b\n")

        module_b = temp_dir / "module_b.py"
        module_b.write_text("from module_a import func_a\n")

        detector = CircularDependencyDetector()
        start_file = str(module_a)
        cycles = detector.detect_cycles(start_file, temp_dir)

        assert len(cycles) > 0

    def test_detect_cycles_nonexistent_start_file(self, temp_dir):
        """Test detect_cycles with non-existent start file."""
        detector = CircularDependencyDetector()
        cycles = detector.detect_cycles("nonexistent.py", temp_dir)

        assert len(cycles) == 0


class TestCircularDependencyModel:
    """Test CircularDependency dataclass."""

    def test_create_circular_dependency(self):
        """Test creating a CircularDependency object."""
        cycle = ["a.py", "b.py", "a.py"]
        dep = CircularDependency(cycle=cycle, severity="medium", description="Test cycle")

        assert dep.cycle == cycle
        assert dep.severity == "medium"
        assert dep.description == "Test cycle"
