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

from typing import List
from pathlib import Path
import json

from acr.reporters.base import BaseReporter
from acr.models.finding import Finding


class JSONReporter(BaseReporter):
    """Generate JSON reports."""

    def generate(self, findings: List[Finding]) -> str:
        """Generate JSON report.

        Args:
            findings: List of findings to report

        Returns:
            JSON report string
        """
        # TODO: Implement JSON generation with proper schema
        data = {
            "total_findings": len(findings),
            "findings": [finding.model_dump() for finding in findings],
        }
        return json.dumps(data, indent=2)

    def write(self, findings: List[Finding], output_path: Path) -> None:
        """Write JSON report to file.

        Args:
            findings: List of findings to report
            output_path: Path to write report
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report = self.generate(findings)
        output_path.write_text(report)
