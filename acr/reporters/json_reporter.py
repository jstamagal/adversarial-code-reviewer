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

"""JSON report generator."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from acr.models.aggregator import FindingAggregator
from acr.models.finding import Finding
from acr.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    """Generate JSON reports."""

    def generate(self, findings: List[Finding]) -> str:
        """Generate JSON report.

        Args:
            findings: List of findings to report

        Returns:
            JSON report string
        """
        aggregator = FindingAggregator()
        aggregator.add_findings(findings)
        summary = aggregator.get_summary()
        deduplicated = aggregator.deduplicate()

        data: Dict[str, Any] = {
            "metadata": {
                "generated_at": datetime.now().isoformat() + "Z",
                "tool": "Adversarial Code Reviewer",
                "version": "0.1.0",
            },
            "summary": {
                "total_findings": summary["total_findings"],
                "risk_score": summary["risk_score"],
                "high_priority_count": summary["high_priority_count"],
                "severity_distribution": summary["severity_distribution"],
                "confidence_distribution": summary["confidence_distribution"],
                "category_distribution": summary["category_distribution"],
            },
            "findings": [finding.model_dump(mode="json") for finding in deduplicated],
        }

        return json.dumps(data, indent=2, default=str)

    def write(self, findings: List[Finding], output_path: Path) -> None:
        """Write JSON report to file.

        Args:
            findings: List of findings to report
            output_path: Path to write report
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report = self.generate(findings)
        output_path.write_text(report)
