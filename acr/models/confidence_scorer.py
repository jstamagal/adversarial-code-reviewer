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

"""Confidence scoring for vulnerability findings."""

import re
from typing import Any, Dict, Literal, Optional

from acr.models.finding import Finding


class ConfidenceScorer:
    """Calculates confidence scores for vulnerability findings."""

    SANITIZATION_FUNCTIONS = {
        "python": [
            "html.escape",
            "urllib.parse.quote",
            "urllib.parse.quote_plus",
            "cgi.escape",
            "werkzeug.utils.escape",
            "markupsafe.escape",
            "bleach.clean",
            "pymysql.escape_string",
            "psycopg2.extensions.adapt",
        ],
        "generic": [
            "sanitize",
            "clean",
            "escape",
            "validate",
            "normalize",
        ],
    }

    PATTERN_SPECIFICITY_WEIGHTS = {
        "data_flow": 0.95,
        "static": 0.7,
        "heuristic": 0.2,
    }

    def __init__(self, language: str = "python"):
        self.language = language

    def calculate_confidence(
        self,
        pattern_template: Dict[str, Any],
        code_context: Optional[str] = None,
        taint_confidence: Optional[float] = None,
    ) -> Literal["high", "medium", "low"]:
        """
        Calculate overall confidence score.

        Args:
            pattern_template: The pattern template from the matcher
            code_context: Code snippet around the match for context analysis
            taint_confidence: Confidence from taint analysis (0.0-1.0)

        Returns:
            Confidence level: "high", "medium", or "low"
        """
        base_confidence = self._calculate_pattern_confidence(pattern_template)
        context_score = self._calculate_context_confidence(code_context)
        taint_score = self._normalize_taint_confidence(taint_confidence)

        final_score = base_confidence * 0.5 + context_score * 0.3 + taint_score * 0.2

        return self._score_to_level(final_score)

    def _calculate_pattern_confidence(self, pattern_template: Dict[str, Any]) -> float:
        """
        Calculate confidence based on pattern match specificity.

        Args:
            pattern_template: Pattern template from matcher

        Returns:
            Confidence score (0.0-1.0)
        """
        pattern_type = pattern_template.get("type", "static")
        specificity = self.PATTERN_SPECIFICITY_WEIGHTS.get(
            pattern_type, self.PATTERN_SPECIFICITY_WEIGHTS["heuristic"]
        )

        specificity_boost = 0.0

        if pattern_template.get("exact_function_match"):
            specificity_boost += 0.1

        if pattern_template.get("exact_import_match"):
            specificity_boost += 0.05

        if pattern_template.get("control_flow_confirmed"):
            specificity_boost += 0.1

        return min(1.0, specificity + specificity_boost)

    def _calculate_context_confidence(self, code_context: Optional[str]) -> float:
        """
        Calculate confidence based on code context.

        Detects if sanitization is present, which reduces confidence.

        Args:
            code_context: Code snippet around the match

        Returns:
            Confidence score (0.0-1.0)
        """
        if not code_context:
            return 0.5

        score = 0.7

        if self._has_sanitization(code_context):
            score -= 0.5

        if self._has_validation(code_context):
            score += 0.1

        if self._has_comment_disclaimer(code_context):
            score -= 0.35

        if self._in_test_code(code_context):
            score -= 0.4

        return max(0.0, min(1.0, score))

    def _has_sanitization(self, code: str) -> bool:
        """
        Check if code contains sanitization functions.

        Args:
            code: Code snippet to check

        Returns:
            True if sanitization detected
        """
        code_lower = code.lower()

        sanitization_list = self.SANITIZATION_FUNCTIONS.get(
            self.language, self.SANITIZATION_FUNCTIONS["generic"]
        )

        for func in sanitization_list:
            if func.lower() in code_lower:
                return True

        common_patterns = [
            r"\.escape\s*\(",
            r"\.sanitize\s*\(",
            r"\.clean\s*\(",
            r"html\s*\.\s*escape",
            r"re\s*\.\s*escape",
        ]

        for pattern in common_patterns:
            if re.search(pattern, code):
                return True

        return False

    def _has_validation(self, code: str) -> bool:
        """
        Check if code contains validation logic.

        Args:
            code: Code snippet to check

        Returns:
            True if validation detected
        """
        validation_patterns = [
            r"if\s+.*\s+in\s+.*:",
            r"validate\s*\(",
            r"check\s*\(",
            r"verify\s*\(",
            r"\.is_valid\s*\(",
            r"assert\s+.*\s+is\s+not\s+None",
            r"\.startswith\s*\(",
            r"\.endswith\s*\(",
        ]

        for pattern in validation_patterns:
            if re.search(pattern, code):
                return True

        return False

    def _has_comment_disclaimer(self, code: str) -> bool:
        """
        Check if code has comments indicating intentional use.

        Args:
            code: Code snippet to check

        Returns:
            True if disclaimer detected
        """
        disclaimer_patterns = [
            r"#\s*TODO.*fix",
            r"#\s*FIXME",
            r"#\s*HACK",
            r"#\s*XSS\s*fix\s*later",
            r"#\s*intentional",
            r"#\s*accepted\s*risk",
            r"#\s*no\s*sanitization",
            r"#\s*trust\s*input",
            r'""".*TODO.*fix',
            r'""".*FIXME',
            r'""".*HACK',
        ]

        for pattern in disclaimer_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return True

        return False

    def _in_test_code(self, code: str) -> bool:
        """
        Check if code is in a test file or test function.

        Args:
            code: Code snippet to check

        Returns:
            True if test code detected
        """
        test_patterns = [
            r"def\s+test_",
            r"class\s+Test[A-Z]",
            r"def\s+.*_test",
            r"\.py.*test",
            r"test_",
            r"@pytest",
            r"@unittest",
        ]

        for pattern in test_patterns:
            if re.search(pattern, code):
                return True

        return False

    def _normalize_taint_confidence(self, taint_confidence: Optional[float]) -> float:
        """
        Normalize taint analysis confidence to 0.0-1.0 range.

        Args:
            taint_confidence: Confidence from taint analysis (0.0-1.0)

        Returns:
            Normalized confidence score (0.0-1.0)
        """
        if taint_confidence is None:
            return 0.5

        if taint_confidence < 0.0:
            taint_confidence = 0.0
        elif taint_confidence > 1.0:
            taint_confidence = 1.0

        return taint_confidence

    def _score_to_level(self, score: float) -> Literal["high", "medium", "low"]:
        """
        Convert numerical score to confidence level.

        Args:
            score: Confidence score (0.0-1.0)

        Returns:
            Confidence level: "high", "medium", or "low"
        """
        if score >= 0.65:
            return "high"
        elif score >= 0.35:
            return "medium"
        else:
            return "low"

    def calculate_for_existing_finding(
        self, finding: Finding, new_confidence: Literal["high", "medium", "low"]
    ) -> Literal["high", "medium", "low"]:
        """
        Calculate combined confidence from existing finding and new analysis.

        Args:
            finding: Existing finding with current confidence
            new_confidence: New confidence from analysis

        Returns:
            Combined confidence level
        """
        level_order = {"high": 2, "medium": 1, "low": 0}

        existing_level = level_order[finding.confidence]
        new_level = level_order[new_confidence]

        if existing_level >= new_level:
            return finding.confidence
        else:
            return new_confidence
