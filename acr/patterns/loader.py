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

"""Pattern loader implementation."""

from typing import List, Optional, Dict, Any
from pathlib import Path
from datetime import datetime

import yaml

from acr.patterns.schema import Pattern, PatternRemediation, PatternImpact


class PatternLoader:
    """Load and manage attack patterns."""

    def __init__(self):
        """Initialize pattern loader."""
        self.patterns: Dict[str, Pattern] = {}

    def load_patterns(self, pattern_dir: Optional[Path] = None) -> Dict[str, Pattern]:
        """Load patterns from directory.

        Args:
            pattern_dir: Directory containing pattern YAML files

        Returns:
            Dictionary of patterns by ID
        """
        if pattern_dir is None:
            pattern_dir = Path(__file__).parent / "library"

        pattern_dir = Path(pattern_dir)

        if not pattern_dir.exists():
            return {}

        patterns: Dict[str, Pattern] = {}

        for pattern_file in pattern_dir.glob("*.yaml"):
            pattern = self.load_pattern(pattern_file)
            if pattern:
                patterns[pattern.id] = pattern

        return patterns

    def load_pattern(self, pattern_path: Path) -> Optional[Pattern]:
        """Load a single pattern from file.

        Args:
            pattern_path: Path to pattern YAML file

        Returns:
            Loaded pattern or None if invalid
        """
        try:
            with open(pattern_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if data is None:
                return None

            return self._parse_pattern(data)

        except yaml.YAMLError:
            return None
        except Exception:
            return None

    def _parse_pattern(self, data: Dict[str, Any]) -> Optional[Pattern]:
        """Parse pattern from YAML data.

        Args:
            data: Parsed YAML data

        Returns:
            Pattern object or None if invalid
        """
        try:
            pattern_id = data.get("id")
            if not pattern_id:
                return None

            remediation_data = data.get("remediation", {})
            remediation = PatternRemediation(
                description=remediation_data.get("description", ""),
                code_before=remediation_data.get("code_before"),
                code_after=remediation_data.get("code_after"),
            )

            templates = self._parse_templates(data.get("detection", {}))
            impact = self._parse_impact(data.get("impact"))

            last_modified = data.get("last_modified")
            if isinstance(last_modified, datetime):
                last_modified = last_modified.isoformat()

            return Pattern(
                id=pattern_id,
                name=data.get("name", pattern_id),
                description=data.get("description", ""),
                severity=data.get("severity", "medium"),
                category=data.get("category", ""),
                cwe_id=data.get("cwe"),
                owasp_id=data.get("owasp"),
                affected_languages=data.get("affected_languages", []),
                affected_frameworks=data.get("affected_frameworks", []),
                templates=templates,
                attack_vector=data.get("attack_vector", ""),
                example_payload=data.get("example_payload"),
                remediation=remediation,
                references=data.get("references", []),
                enabled=data.get("enabled", True),
                version=data.get("version", "1.0.0"),
                author=data.get("author"),
                last_modified=last_modified,
                tags=data.get("tags", []),
                relationships=data.get("relationships", {}),
                dependencies=data.get("dependencies", []),
                impact=impact,
            )

        except Exception:
            return None

    def _parse_templates(self, detection_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse detection templates from YAML.

        Args:
            detection_data: Detection section from YAML

        Returns:
            List of template dictionaries
        """
        templates: List[Dict[str, Any]] = []

        static_patterns = detection_data.get("static", [])
        for pattern_data in static_patterns:
            templates.append({"type": "static", **pattern_data})

        data_flow_patterns = detection_data.get("data_flow", [])
        for pattern_data in data_flow_patterns:
            templates.append({"type": "data_flow", **pattern_data})

        return templates

    def _parse_impact(self, impact_data: Optional[Dict[str, Any]]) -> Optional[PatternImpact]:
        """Parse impact data from YAML.

        Args:
            impact_data: Impact section from YAML

        Returns:
            PatternImpact object or None if not provided
        """
        if not impact_data:
            return None

        return PatternImpact(
            confidentiality=impact_data.get("confidentiality"),
            integrity=impact_data.get("integrity"),
            availability=impact_data.get("availability"),
        )
