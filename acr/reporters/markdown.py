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

from typing import List
from pathlib import Path

from acr.reporters.base import BaseReporter
from acr.models.finding import Finding


class MarkdownReporter(BaseReporter):
    """Generate Markdown reports."""

    def generate(self, findings: List[Finding]) -> str:
        """Generate Markdown report.

        Args:
            findings: List of findings to report

        Returns:
            Markdown report string
        """
        # TODO: Implement Markdown generation
        lines = [
            "# Adversarial Code Reviewer Report\n",
            f"Total Findings: {len(findings)}\n",
        ]

        for finding in findings:
            lines.append(f"## {finding.title}\n")
            lines.append(f"**Severity:** {finding.severity}\n")
            lines.append(f"**File:** {finding.location.file}:{finding.location.line}\n")
            lines.append(f"\n{finding.description}\n")

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
