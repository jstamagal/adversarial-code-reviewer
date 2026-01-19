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

"""Finding aggregation utilities."""

from typing import List, Dict, Tuple
from collections import Counter, defaultdict
import hashlib

from acr.models.finding import Finding, FindingLocation, FindingImpact, FindingRemediation


class FindingAggregator:
    """Aggregates and processes findings."""

    def __init__(self):
        self.findings: List[Finding] = []
        self._deduplicated: Dict[str, Finding] = {}

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_findings(self, findings: List[Finding]) -> None:
        self.findings.extend(findings)

    def deduplicate(self) -> List[Finding]:
        """Deduplicate findings based on location and pattern hash."""
        self._deduplicated = {}

        for finding in self.findings:
            key = self._generate_finding_key(finding)

            if key in self._deduplicated:
                existing = self._deduplicated[key]

                if self._should_replace_finding(existing, finding):
                    self._deduplicated[key] = finding
            else:
                self._deduplicated[key] = finding

        return list(self._deduplicated.values())

    def _generate_finding_key(self, finding: Finding) -> str:
        """Generate unique key for deduplication based on file:line:pattern hash."""
        location_hash = hashlib.md5(
            f"{finding.location.file}:{finding.location.line}:{finding.category}".encode()
        ).hexdigest()

        return location_hash

    def _should_replace_finding(self, existing: Finding, new: Finding) -> bool:
        """Determine if new finding should replace existing based on severity/confidence."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        confidence_order = {"high": 0, "medium": 1, "low": 2}

        if severity_order[new.severity] < severity_order[existing.severity]:
            return True

        if confidence_order[new.confidence] < confidence_order[existing.confidence]:
            return True

        return False

    def get_severity_distribution(self) -> Dict[str, int]:
        """Calculate severity distribution of findings."""
        deduplicated = self.deduplicate()
        severity_counts = Counter(f.severity for f in deduplicated)

        return {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
        }

    def get_confidence_distribution(self) -> Dict[str, int]:
        """Calculate confidence distribution of findings."""
        deduplicated = self.deduplicate()
        confidence_counts = Counter(f.confidence for f in deduplicated)

        return {
            "high": confidence_counts.get("high", 0),
            "medium": confidence_counts.get("medium", 0),
            "low": confidence_counts.get("low", 0),
        }

    def get_category_distribution(self) -> Dict[str, int]:
        """Calculate category distribution of findings."""
        deduplicated = self.deduplicate()
        category_counts = Counter(f.category for f in deduplicated)

        return dict(category_counts)

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get all findings of a specific severity."""
        deduplicated = self.deduplicate()
        return [f for f in deduplicated if f.severity == severity]

    def get_findings_by_category(self, category: str) -> List[Finding]:
        """Get all findings of a specific category."""
        deduplicated = self.deduplicate()
        return [f for f in deduplicated if f.category == category]

    def get_findings_by_state(self, state: str) -> List[Finding]:
        """Get all findings of a specific state."""
        deduplicated = self.deduplicate()
        return [f for f in deduplicated if f.state == state]

    def get_file_summary(self) -> Dict[str, Dict[str, int]]:
        """Get summary of findings per file."""
        deduplicated = self.deduplicate()
        file_summary = defaultdict(lambda: defaultdict(int))

        for finding in deduplicated:
            file_path = finding.location.file
            file_summary[file_path]["total"] += 1
            file_summary[file_path][finding.severity] += 1

        return {k: dict(v) for k, v in file_summary.items()}

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on severity and confidence."""
        deduplicated = self.deduplicate()

        severity_weights = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 1.0}
        confidence_weights = {"high": 1.0, "medium": 0.75, "low": 0.5}

        total_score = 0.0

        for finding in deduplicated:
            sev_weight = severity_weights.get(finding.severity, 1.0)
            conf_weight = confidence_weights.get(finding.confidence, 0.5)
            total_score += sev_weight * conf_weight

        return round(total_score, 2)

    def get_high_priority_findings(self) -> List[Finding]:
        """Get high and critical severity findings with high confidence."""
        deduplicated = self.deduplicate()
        return [
            f for f in deduplicated if f.severity in ["critical", "high"] and f.confidence == "high"
        ]

    def get_summary(self) -> Dict:
        """Get comprehensive summary of all findings."""
        deduplicated = self.deduplicate()

        return {
            "total_findings": len(deduplicated),
            "severity_distribution": self.get_severity_distribution(),
            "confidence_distribution": self.get_confidence_distribution(),
            "category_distribution": self.get_category_distribution(),
            "risk_score": self.calculate_risk_score(),
            "high_priority_count": len(self.get_high_priority_findings()),
            "file_summary": self.get_file_summary(),
        }
