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

"""Unit tests for data models."""

import pytest
from acr.models.finding import Finding, FindingLocation, FindingImpact, FindingRemediation


def test_finding_creation():
    """Test finding model creation."""
    location = FindingLocation(file="test.py", line=10, function="test_func")
    impact = FindingImpact(confidentiality="high", integrity="high", availability="low")
    remediation = FindingRemediation(description="Use parameterized queries")

    finding = Finding(
        id="ACR-2025-TEST001",
        title="Test Finding",
        severity="high",
        confidence="high",
        category="injection",
        location=location,
        description="Test description",
        attack_vector="Test attack",
        impact=impact,
        remediation=remediation,
    )

    assert finding.id == "ACR-2025-TEST001"
    assert finding.severity == "high"
    assert finding.location.file == "test.py"
    assert finding.state == "open"


def test_finding_location():
    """Test finding location model."""
    location = FindingLocation(
        file="test.py", line=10, column=5, function="test", class_name="TestClass"
    )
    assert location.file == "test.py"
    assert location.line == 10
    assert location.column == 5


def test_finding_impact():
    """Test finding impact model."""
    impact = FindingImpact(confidentiality="critical", integrity="high", availability="medium")
    assert impact.confidentiality == "critical"
    assert impact.integrity == "high"


def test_finding_remediation():
    """Test finding remediation model."""
    remediation = FindingRemediation(
        description="Fix the vulnerability",
        code_before='query = "SELECT * FROM users WHERE id = " + user_id',
        code_after='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    )
    assert remediation.description == "Fix the vulnerability"
    assert remediation.code_before is not None
    assert remediation.code_after is not None
