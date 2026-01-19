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
from typing import cast
from acr.models.finding import (
    Finding,
    FindingLocation,
    FindingImpact,
    FindingRemediation,
)
from acr.models.aggregator import FindingAggregator


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


def create_test_finding(
    id_val: str,
    severity: str,
    confidence: str,
    category: str,
    file: str,
    line: int,
) -> Finding:
    """Helper to create test findings."""
    location = FindingLocation(file=file, line=line)
    impact = FindingImpact(confidentiality="medium", integrity="medium", availability="low")
    remediation = FindingRemediation(description="Fix the issue")

    return Finding(
        id=id_val,
        title=f"Test Finding {id_val}",
        severity=cast(str, severity),
        confidence=cast(str, confidence),
        category=category,
        location=location,
        description="Test description",
        attack_vector="Test attack",
        impact=impact,
        remediation=remediation,
    )


def test_aggregator_add_finding():
    """Test adding a single finding to aggregator."""
    aggregator = FindingAggregator()
    finding = create_test_finding("001", "high", "high", "injection", "test.py", 10)

    aggregator.add_finding(finding)

    assert len(aggregator.findings) == 1
    assert aggregator.findings[0].id == "001"


def test_aggregator_add_findings():
    """Test adding multiple findings to aggregator."""
    aggregator = FindingAggregator()
    findings = [
        create_test_finding("001", "high", "high", "injection", "test.py", 10),
        create_test_finding("002", "medium", "medium", "xss", "test2.py", 20),
    ]

    aggregator.add_findings(findings)

    assert len(aggregator.findings) == 2


def test_aggregator_deduplicate():
    """Test deduplication of findings."""
    aggregator = FindingAggregator()

    findings = [
        create_test_finding("001", "high", "high", "injection", "test.py", 10),
        create_test_finding("002", "medium", "medium", "injection", "test.py", 10),
        create_test_finding("003", "low", "low", "xss", "test2.py", 20),
    ]

    aggregator.add_findings(findings)
    deduplicated = aggregator.deduplicate()

    assert len(deduplicated) == 2
    assert len(aggregator._deduplicated) == 2


def test_aggregator_deduplicate_keeps_higher_severity():
    """Test deduplication keeps finding with higher severity."""
    aggregator = FindingAggregator()

    findings = [
        create_test_finding("001", "high", "medium", "injection", "test.py", 10),
        create_test_finding("002", "critical", "low", "injection", "test.py", 10),
    ]

    aggregator.add_findings(findings)
    deduplicated = aggregator.deduplicate()

    assert len(deduplicated) == 1
    assert deduplicated[0].severity == "critical"


def test_aggregator_deduplicate_keeps_higher_confidence():
    """Test deduplication keeps finding with higher confidence when severity is equal."""
    aggregator = FindingAggregator()

    findings = [
        create_test_finding("001", "high", "low", "injection", "test.py", 10),
        create_test_finding("002", "high", "high", "injection", "test.py", 10),
    ]

    aggregator.add_findings(findings)
    deduplicated = aggregator.deduplicate()

    assert len(deduplicated) == 1
    assert deduplicated[0].confidence == "high"


def test_aggregator_severity_distribution():
    """Test severity distribution calculation."""
    aggregator = FindingAggregator()

    findings = [
        create_test_finding("001", "critical", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "high", "xss", "test2.py", 20),
        create_test_finding("003", "high", "medium", "injection", "test.py", 30),
        create_test_finding("004", "medium", "low", "auth", "test3.py", 40),
        create_test_finding("005", "low", "high", "config", "test4.py", 50),
    ]

    aggregator.add_findings(findings)
    distribution = aggregator.get_severity_distribution()

    assert distribution["critical"] == 1
    assert distribution["high"] == 2
    assert distribution["medium"] == 1
    assert distribution["low"] == 1
    assert distribution["info"] == 0


def test_aggregator_confidence_distribution():
    """Test confidence distribution calculation."""
    aggregator = FindingAggregator()

    findings = [
        create_test_finding("001", "critical", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "high", "xss", "test2.py", 20),
        create_test_finding("003", "high", "medium", "injection", "test.py", 30),
        create_test_finding("004", "medium", "low", "auth", "test3.py", 40),
    ]

    aggregator.add_findings(findings)
    distribution = aggregator.get_confidence_distribution()

    assert distribution["high"] == 2
    assert distribution["medium"] == 1
    assert distribution["low"] == 1


def test_aggregator_category_distribution():
    """Test category distribution calculation."""
    aggregator = FindingAggregator()

    findings = [
        create_test_finding("001", "high", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "high", "injection", "test2.py", 20),
        create_test_finding("003", "medium", "medium", "xss", "test.py", 30),
        create_test_finding("004", "medium", "low", "auth", "test3.py", 40),
    ]

    aggregator.add_findings(findings)
    distribution = aggregator.get_category_distribution()

    assert distribution["injection"] == 2
    assert distribution["xss"] == 1
    assert distribution["auth"] == 1


def test_aggregator_get_findings_by_severity():
    """Test filtering findings by severity."""
    aggregator = FindingAggregator()

    findings = [
        create_test_finding("001", "critical", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "high", "xss", "test2.py", 20),
        create_test_finding("003", "high", "medium", "injection", "test.py", 30),
        create_test_finding("004", "medium", "low", "auth", "test3.py", 40),
    ]

    aggregator.add_findings(findings)
    high_severity = aggregator.get_findings_by_severity("high")

    assert len(high_severity) == 2
    assert all(f.severity == "high" for f in high_severity)


def test_aggregator_get_findings_by_category():
    """Test filtering findings by category."""
    aggregator = FindingAggregator()

    findings = [
        create_test_finding("001", "high", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "high", "xss", "test2.py", 20),
        create_test_finding("003", "medium", "medium", "injection", "test.py", 30),
    ]

    aggregator.add_findings(findings)
    injection_findings = aggregator.get_findings_by_category("injection")

    assert len(injection_findings) == 2
    assert all(f.category == "injection" for f in injection_findings)


def test_aggregator_get_findings_by_state():
    """Test filtering findings by state."""
    aggregator = FindingAggregator()

    findings = [
        create_test_finding("001", "high", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "high", "xss", "test2.py", 20),
    ]

    aggregator.add_findings(findings)
    findings[0].state = "fixed"

    open_findings = aggregator.get_findings_by_state("open")
    fixed_findings = aggregator.get_findings_by_state("fixed")

    assert len(open_findings) == 1
    assert len(fixed_findings) == 1


def test_aggregator_file_summary():
    """Test file summary calculation."""
    aggregator = FindingAggregator()

    findings = [
        create_test_finding("001", "critical", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "high", "xss", "test.py", 20),
        create_test_finding("003", "medium", "medium", "auth", "test2.py", 30),
    ]

    aggregator.add_findings(findings)
    summary = aggregator.get_file_summary()

    assert "test.py" in summary
    assert "test2.py" in summary
    assert summary["test.py"]["total"] == 2
    assert summary["test.py"]["critical"] == 1
    assert summary["test.py"]["high"] == 1
    assert summary["test2.py"]["total"] == 1


def test_aggregator_risk_score():
    """Test risk score calculation."""
    aggregator = FindingAggregator()

    findings = [
        create_test_finding("001", "critical", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "medium", "xss", "test.py", 20),
        create_test_finding("003", "medium", "low", "auth", "test.py", 30),
    ]

    aggregator.add_findings(findings)
    risk_score = aggregator.calculate_risk_score()

    assert risk_score > 0
    assert risk_score == 18.12  # (10*1) + (7.5*0.75) + (5*0.5) = 18.125


def test_aggregator_high_priority_findings():
    """Test high priority findings retrieval."""
    aggregator = FindingAggregator()

    findings = [
        create_test_finding("001", "critical", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "high", "xss", "test.py", 20),
        create_test_finding("003", "high", "medium", "auth", "test.py", 30),
        create_test_finding("004", "critical", "low", "injection", "test2.py", 40),
        create_test_finding("005", "medium", "high", "config", "test3.py", 50),
    ]

    aggregator.add_findings(findings)
    high_priority = aggregator.get_high_priority_findings()

    assert len(high_priority) == 2
    assert all(f.severity in ["critical", "high"] for f in high_priority)
    assert all(f.confidence == "high" for f in high_priority)


def test_aggregator_summary():
    """Test comprehensive summary generation."""
    aggregator = FindingAggregator()

    findings = [
        create_test_finding("001", "critical", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "medium", "xss", "test.py", 20),
    ]

    aggregator.add_findings(findings)
    summary = aggregator.get_summary()

    assert "total_findings" in summary
    assert "severity_distribution" in summary
    assert "confidence_distribution" in summary
    assert "category_distribution" in summary
    assert "risk_score" in summary
    assert "high_priority_count" in summary
    assert "file_summary" in summary

    assert summary["total_findings"] == 2
    assert summary["high_priority_count"] == 1
