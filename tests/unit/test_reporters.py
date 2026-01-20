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

"""Unit tests for report generators."""

from acr.models.finding import Finding, FindingImpact, FindingLocation, FindingRemediation
from acr.reporters.json_reporter import JSONReporter
from acr.reporters.markdown import MarkdownReporter


def create_test_finding(
    id_val: str,
    severity: str,
    confidence: str,
    category: str,
    file: str,
    line: int,
    title: str = "Test Finding",
) -> Finding:
    """Helper to create test findings."""
    location = FindingLocation(file=file, line=line, function="test_func")
    impact = FindingImpact(confidentiality="high", integrity="high", availability="low")
    remediation = FindingRemediation(description="Fix vulnerability")

    return Finding(
        id=id_val,
        title=title,
        severity=severity,
        confidence=confidence,
        category=category,
        location=location,
        description="Test description",
        attack_vector="Test attack",
        impact=impact,
        remediation=remediation,
    )


def test_json_reporter_generate_empty():
    """Test JSON reporter with no findings."""
    reporter = JSONReporter()
    report = reporter.generate([])

    assert '"total_findings": 0' in report
    assert '"findings": []' in report
    assert '"risk_score"' in report
    assert '"metadata"' in report


def test_json_reporter_generate_single_finding():
    """Test JSON reporter with single finding."""
    reporter = JSONReporter()
    finding = create_test_finding("001", "high", "high", "injection", "test.py", 10)
    report = reporter.generate([])

    report = reporter.generate([finding])

    assert '"total_findings": 1' in report
    assert '"id": "001"' in report
    assert '"severity": "high"' in report
    assert '"category": "injection"' in report


def test_json_reporter_generate_multiple_findings():
    """Test JSON reporter with multiple findings."""
    reporter = JSONReporter()
    findings = [
        create_test_finding("001", "critical", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "medium", "xss", "test2.py", 20),
        create_test_finding("003", "medium", "low", "auth", "test.py", 30),
    ]
    report = reporter.generate(findings)

    assert '"total_findings": 3' in report
    assert '"critical"' in report
    assert '"high"' in report
    assert '"medium"' in report


def test_json_reporter_metadata():
    """Test JSON reporter includes metadata."""
    reporter = JSONReporter()
    finding = create_test_finding("001", "high", "high", "injection", "test.py", 10)
    report = reporter.generate([finding])

    assert '"metadata"' in report
    assert '"generated_at"' in report
    assert '"tool": "Adversarial Code Reviewer"' in report


def test_json_reporter_summary():
    """Test JSON reporter includes summary."""
    reporter = JSONReporter()
    findings = [
        create_test_finding("001", "critical", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "medium", "xss", "test2.py", 20),
    ]
    report = reporter.generate(findings)

    assert '"summary"' in report
    assert '"risk_score"' in report
    assert '"severity_distribution"' in report
    assert '"confidence_distribution"' in report


def test_json_reporter_write(tmp_path):
    """Test JSON reporter writes to file."""
    reporter = JSONReporter()
    finding = create_test_finding("001", "high", "high", "injection", "test.py", 10)
    output_path = tmp_path / "report.json"

    reporter.write([finding], output_path)

    assert output_path.exists()
    content = output_path.read_text()
    assert '"id": "001"' in content


def test_markdown_reporter_generate_empty():
    """Test Markdown reporter with no findings."""
    reporter = MarkdownReporter()
    report = reporter.generate([])

    assert "# Adversarial Code Reviewer Report" in report
    assert "**Total Findings:** 0" in report
    assert "## Executive Summary" in report


def test_markdown_reporter_generate_single_finding():
    """Test Markdown reporter with single finding."""
    reporter = MarkdownReporter()
    location = FindingLocation(file="test.py", line=10, function="test_func")
    impact = FindingImpact(confidentiality="high", integrity="high", availability="low")
    remediation = FindingRemediation(description="Fix vulnerability")

    finding = Finding(
        id="001",
        title="SQL Injection",
        severity="high",
        confidence="high",
        category="injection",
        location=location,
        description="Test description",
        attack_vector="Test attack",
        impact=impact,
        remediation=remediation,
    )
    report = reporter.generate([finding])

    assert "# Adversarial Code Reviewer Report" in report
    assert "## High Severity Findings" in report
    assert "### SQL Injection" in report
    assert "**ID:** `001`" in report
    assert "**Confidence:** high" in report
    assert "**Location:** `test.py:10`" in report
    assert "**Description:**" in report
    assert "**Attack Vector:**" in report
    assert "**Remediation:**" in report


def test_markdown_reporter_multiple_severity_levels():
    """Test Markdown reporter organizes findings by severity."""
    reporter = MarkdownReporter()
    findings = [
        create_test_finding("001", "critical", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "medium", "xss", "test2.py", 20),
        create_test_finding("003", "medium", "low", "auth", "test.py", 30),
        create_test_finding("004", "low", "high", "config", "test3.py", 40),
    ]
    report = reporter.generate(findings)

    assert "## Critical Severity Findings" in report
    assert "## High Severity Findings" in report
    assert "## Medium Severity Findings" in report
    assert "## Low Severity Findings" in report


def test_markdown_reporter_executive_summary():
    """Test Markdown reporter includes executive summary."""
    reporter = MarkdownReporter()
    findings = [
        create_test_finding("001", "critical", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "medium", "xss", "test2.py", 20),
    ]
    report = reporter.generate(findings)

    assert "## Executive Summary" in report
    assert "**Total Findings:** 2" in report
    assert "**Risk Score:**" in report
    assert "**High Priority Findings:**" in report
    assert "### Severity Distribution" in report
    assert "### Confidence Distribution" in report
    assert "### Category Distribution" in report


def test_markdown_reporter_finding_details():
    """Test Markdown reporter includes all finding details."""
    reporter = MarkdownReporter()
    finding = create_test_finding("001", "high", "high", "injection", "test.py", 10)
    finding.cwe_id = "CWE-89"
    finding.owasp_id = "A1:2017-Injection"
    finding.state = "in-progress"
    report = reporter.generate([finding])

    assert "**CWE:**" in report
    assert "https://cwe.mitre.org" in report
    assert "**OWASP:**" in report
    assert "**Function:** `test_func`" in report
    assert "**Confidence:** high" in report
    assert "**Category:** injection" in report
    assert "**Impact:**" in report
    assert "**Status:** in-progress" in report


def test_markdown_reporter_code_snippets():
    """Test Markdown reporter includes code snippets."""
    reporter = MarkdownReporter()
    finding = create_test_finding("001", "high", "high", "injection", "test.py", 10)
    finding.remediation.code_before = 'query = "SELECT * FROM users WHERE id = " + user_id'
    finding.remediation.code_after = (
        'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
    )
    report = reporter.generate([finding])

    assert "**Vulnerable Code:**" in report
    assert "```python" in report
    assert "**Fixed Code:**" in report
    assert 'query = "SELECT * FROM users WHERE id = " + user_id' in report


def test_markdown_reporter_references():
    """Test Markdown reporter includes references."""
    reporter = MarkdownReporter()
    finding = create_test_finding("001", "high", "high", "injection", "test.py", 10)
    finding.references = [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
    ]
    report = reporter.generate([finding])

    assert "**References:**" in report
    assert "https://owasp.org/www-community/attacks/SQL_Injection" in report
    assert "https://cwe.mitre.org/data/definitions/89.html" in report


def test_markdown_reporter_related_patterns():
    """Test Markdown reporter includes related patterns."""
    reporter = MarkdownReporter()
    finding = create_test_finding("001", "high", "high", "injection", "test.py", 10)
    finding.related_patterns = ["sql-injection", "command-injection", "xss"]
    report = reporter.generate([finding])

    assert "**Related Patterns:**" in report
    assert "`sql-injection`" in report
    assert "`command-injection`" in report
    assert "`xss`" in report


def test_markdown_reporter_file_summary():
    """Test Markdown reporter includes file summary."""
    reporter = MarkdownReporter()
    findings = [
        create_test_finding("001", "critical", "high", "injection", "test.py", 10),
        create_test_finding("002", "high", "medium", "xss", "test.py", 20),
        create_test_finding("003", "medium", "low", "auth", "test2.py", 30),
    ]
    report = reporter.generate(findings)

    assert "## File Summary" in report
    assert "### `test.py`" in report
    assert "**Total Findings:** 2" in report
    assert "### `test2.py`" in report


def test_markdown_reporter_write(tmp_path):
    """Test Markdown reporter writes to file."""
    reporter = MarkdownReporter()
    location = FindingLocation(file="test.py", line=10, function="test_func")
    impact = FindingImpact(confidentiality="high", integrity="high", availability="low")
    remediation = FindingRemediation(description="Fix vulnerability")

    finding = Finding(
        id="001",
        title="XSS Vulnerability",
        severity="high",
        confidence="high",
        category="xss",
        location=location,
        description="Test description",
        attack_vector="Test attack",
        impact=impact,
        remediation=remediation,
    )
    output_path = tmp_path / "report.md"

    reporter.write([finding], output_path)

    assert output_path.exists()
    content = output_path.read_text()
    assert "# Adversarial Code Reviewer Report" in content
    assert "### XSS Vulnerability" in content
