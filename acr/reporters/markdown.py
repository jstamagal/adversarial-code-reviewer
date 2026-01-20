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

"""Markdown report generator."""

from datetime import datetime
from pathlib import Path
from typing import List

from acr.models.aggregator import FindingAggregator
from acr.models.finding import Finding
from acr.reporters.base import BaseReporter


class MarkdownReporter(BaseReporter):
    """Generate Markdown reports."""

    def generate(self, findings: List[Finding]) -> str:
        """Generate Markdown report.

        Args:
            findings: List of findings to report

        Returns:
            Markdown report string
        """
        aggregator = FindingAggregator()
        aggregator.add_findings(findings)
        summary = aggregator.get_summary()

        lines = []

        lines.append("# Adversarial Code Reviewer Report\n")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        lines.append("\n## Executive Summary\n")
        lines.append(f"- **Total Findings:** {summary['total_findings']}")
        lines.append(f"- **Risk Score:** {summary['risk_score']}")
        lines.append(f"- **High Priority Findings:** {summary['high_priority_count']}\n")

        lines.append("### Severity Distribution\n")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = summary["severity_distribution"].get(severity, 0)
            lines.append(f"- **{severity.capitalize()}:** {count}")
        lines.append("")

        if summary["total_findings"] > 0:
            lines.append("### Confidence Distribution\n")
            for confidence in ["high", "medium", "low"]:
                count = summary["confidence_distribution"].get(confidence, 0)
                lines.append(f"- **{confidence.capitalize()}:** {count}")
            lines.append("")

            lines.append("### Category Distribution\n")
            categories = sorted(
                summary["category_distribution"].items(), key=lambda x: x[1], reverse=True
            )
            for category, count in categories:
                lines.append(f"- **{category}:** {count}")
            lines.append("")

        severity_order = ["critical", "high", "medium", "low", "info"]
        deduplicated = aggregator.deduplicate()

        for severity in severity_order:
            findings_by_severity = [f for f in deduplicated if f.severity == severity]
            if findings_by_severity:
                lines.append(
                    f"\n## {severity.capitalize()} Severity Findings ({len(findings_by_severity)})\n"
                )
                for finding in findings_by_severity:
                    lines.append(f"### {finding.title}\n")
                    lines.append(f"**ID:** `{finding.id}`\n")
                    lines.append(f"**Confidence:** {finding.confidence}")
                    lines.append(f"**Category:** {finding.category}")

                    if finding.cwe_id:
                        lines.append(
                            f"**CWE:** [{finding.cwe_id}](https://cwe.mitre.org/data/definitions/{finding.cwe_id.replace('CWE-', '')}.html)"
                        )
                    if finding.owasp_id:
                        lines.append(f"**OWASP:** {finding.owasp_id}")

                    lines.append(
                        f"\n**Location:** `{finding.location.file}:{finding.location.line}`"
                    )
                    if finding.location.function:
                        lines.append(f"**Function:** `{finding.location.function}`")
                    if finding.location.class_name:
                        lines.append(f"**Class:** `{finding.location.class_name}`")

                    lines.append(f"\n**Description:**\n{finding.description}")

                    lines.append(f"\n**Attack Vector:**\n{finding.attack_vector}")

                    lines.append("\n**Impact:**")
                    lines.append(f"- Confidentiality: {finding.impact.confidentiality}")
                    lines.append(f"- Integrity: {finding.impact.integrity}")
                    lines.append(f"- Availability: {finding.impact.availability}")

                    lines.append(f"\n**Remediation:**\n{finding.remediation.description}")

                    if finding.remediation.code_before:
                        lines.append("\n**Vulnerable Code:**")
                        lines.append("```python")
                        lines.append(finding.remediation.code_before)
                        lines.append("```")

                    if finding.remediation.code_after:
                        lines.append("\n**Fixed Code:**")
                        lines.append("```python")
                        lines.append(finding.remediation.code_after)
                        lines.append("```")

                    if finding.references:
                        lines.append("\n**References:**")
                        for ref in finding.references:
                            lines.append(f"- {ref}")

                    if finding.state != "open":
                        lines.append(f"\n**Status:** {finding.state}")

                    lines.append("\n---")

        if summary["file_summary"]:
            lines.append("\n## File Summary\n")
            for file_path, file_stats in sorted(summary["file_summary"].items()):
                lines.append(f"\n### `{file_path}`")
                lines.append(f"- **Total Findings:** {file_stats['total']}")
                for severity in ["critical", "high", "medium", "low"]:
                    if severity in file_stats:
                        lines.append(f"- **{severity.capitalize()}:** {file_stats[severity]}")

        return "\n".join(lines)

    def write(self, findings: List[Finding], output_path: Path) -> None:
        """Write Markdown report to file.

        Args:
            findings: List of findings to report
            output_path: Path to write report
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report = self.generate(findings)
        output_path.write_text(report)
