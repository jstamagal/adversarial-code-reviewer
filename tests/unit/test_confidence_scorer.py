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

"""Unit tests for confidence scorer."""

import pytest

from acr.models.confidence_scorer import ConfidenceScorer


class TestPatternConfidence:
    """Tests for pattern-based confidence calculation."""

    def test_data_flow_pattern_high_confidence(self):
        """Test that data flow patterns get high confidence."""
        scorer = ConfidenceScorer()
        template = {
            "type": "data_flow",
            "source": "request.args.get",
            "sink": "execute",
        }

        confidence = scorer.calculate_confidence(template)

        assert confidence == "high"

    def test_static_pattern_medium_confidence(self):
        """Test that static patterns get medium confidence."""
        scorer = ConfidenceScorer()
        template = {
            "type": "static",
            "pattern": r"eval\s*\(",
        }

        confidence = scorer.calculate_confidence(template)

        assert confidence in ["medium", "high"]

    def test_heuristic_pattern_low_confidence(self):
        """Test that heuristic patterns get lower confidence."""
        scorer = ConfidenceScorer()
        template = {
            "type": "heuristic",
        }

        confidence = scorer.calculate_confidence(template)

        assert confidence in ["low", "medium"]

    def test_exact_function_match_boosts_confidence(self):
        """Test that exact function match boosts confidence."""
        scorer = ConfidenceScorer()

        base_template = {"type": "static"}
        base_confidence = scorer.calculate_confidence(base_template)

        boosted_template = {
            "type": "static",
            "exact_function_match": True,
        }
        boosted_confidence = scorer.calculate_confidence(boosted_template)

        assert boosted_confidence >= base_confidence

    def test_exact_import_match_boosts_confidence(self):
        """Test that exact import match boosts confidence."""
        scorer = ConfidenceScorer()

        base_template = {"type": "data_flow"}
        base_confidence = scorer.calculate_confidence(base_template)

        boosted_template = {
            "type": "data_flow",
            "exact_import_match": True,
        }
        boosted_confidence = scorer.calculate_confidence(boosted_template)

        assert boosted_confidence >= base_confidence

    def test_control_flow_confirmed_boosts_confidence(self):
        """Test that control flow confirmation boosts confidence."""
        scorer = ConfidenceScorer()

        base_template = {"type": "data_flow"}
        base_confidence = scorer.calculate_confidence(base_template)

        boosted_template = {
            "type": "data_flow",
            "control_flow_confirmed": True,
        }
        boosted_confidence = scorer.calculate_confidence(boosted_template)

        assert boosted_confidence >= base_confidence


class TestContextConfidence:
    """Tests for context-based confidence calculation."""

    def test_no_context_returns_default(self):
        """Test that missing context returns default score."""
        scorer = ConfidenceScorer()
        template = {"type": "data_flow"}

        confidence = scorer.calculate_confidence(template, code_context=None)

        assert confidence in ["medium", "high"]

    def test_sanitization_reduces_confidence(self):
        """Test that sanitization reduces confidence."""
        scorer = ConfidenceScorer()
        template = {"type": "data_flow"}

        unsafe_code = "user_input = request.args.get('user')\nquery = f'SELECT * FROM users WHERE name = {user_input}'"
        unsafe_confidence = scorer.calculate_confidence(template, code_context=unsafe_code)

        safe_code = "user_input = html.escape(request.args.get('user'))\nquery = f'SELECT * FROM users WHERE name = {user_input}'"
        safe_confidence = scorer.calculate_confidence(template, code_context=safe_code)

        confidence_order = {"high": 2, "medium": 1, "low": 0}
        assert confidence_order[unsafe_confidence] >= confidence_order[safe_confidence]

    def test_bleach_sanitization_reduces_confidence(self):
        """Test that bleach.clean reduces confidence."""
        scorer = ConfidenceScorer()
        template = {"type": "data_flow"}

        code = "user_input = bleach.clean(request.args.get('user'))"
        confidence = scorer.calculate_confidence(template, code_context=code)

        assert confidence == "medium"

    def test_validation_increases_confidence(self):
        """Test that validation increases confidence."""
        scorer = ConfidenceScorer()
        template = {"type": "data_flow"}

        no_validation = "user_input = request.args.get('user')"
        no_val_confidence = scorer.calculate_confidence(template, code_context=no_validation)

        with_validation = "user_input = request.args.get('user')\nif user_input in allowed_users:"
        with_val_confidence = scorer.calculate_confidence(template, code_context=with_validation)

        assert with_val_confidence >= no_val_confidence

    def test_startswith_validation_increases_confidence(self):
        """Test that startswith validation increases confidence."""
        scorer = ConfidenceScorer()
        template = {"type": "data_flow"}

        code = "filename = request.args.get('file')\nif filename.startswith('/uploads/'):"
        confidence = scorer.calculate_confidence(template, code_context=code)

        assert confidence in ["medium", "high"]

    def test_disclaimer_reduces_confidence(self):
        """Test that TODO/HACK comments reduce confidence."""
        scorer = ConfidenceScorer()
        template = {"type": "data_flow"}

        code = "user_input = request.args.get('user')  # TODO fix later"
        confidence = scorer.calculate_confidence(template, code_context=code)

        assert confidence in ["medium", "high"]

    def test_intentional_comment_reduces_confidence(self):
        """Test that intentional use comment reduces confidence."""
        scorer = ConfidenceScorer()
        template = {"type": "data_flow"}

        code = "user_input = request.args.get('user')  # intentional, no sanitization"
        confidence = scorer.calculate_confidence(template, code_context=code)

        assert confidence in ["medium", "high"]

    def test_test_code_reduces_confidence(self):
        """Test that test code reduces confidence."""
        scorer = ConfidenceScorer()
        template = {"type": "data_flow"}

        test_code = "def test_sql_injection():\n    user_input = request.args.get('user')"
        confidence = scorer.calculate_confidence(template, code_context=test_code)

        assert confidence in ["medium", "high"]

    def test_pytest_decorator_reduces_confidence(self):
        """Test that @pytest decorator reduces confidence."""
        scorer = ConfidenceScorer()
        template = {"type": "data_flow"}

        code = "@pytest.fixture\ndef user_input():\n    return request.args.get('user')"
        confidence = scorer.calculate_confidence(template, code_context=code)

        assert confidence in ["medium", "high"]


class TestTaintConfidence:
    """Tests for taint-based confidence calculation."""

    def test_high_taint_confidence_increases_score(self):
        """Test that high taint confidence increases overall confidence."""
        scorer = ConfidenceScorer()
        template = {"type": "static"}

        low_taint = scorer.calculate_confidence(template, taint_confidence=0.2)
        high_taint = scorer.calculate_confidence(template, taint_confidence=0.9)

        confidence_order = {"high": 2, "medium": 1, "low": 0}
        assert confidence_order[high_taint] >= confidence_order[low_taint]

    def test_taint_confidence_none_uses_default(self):
        """Test that None taint confidence uses default."""
        scorer = ConfidenceScorer()
        template = {"type": "data_flow"}

        confidence = scorer.calculate_confidence(template, taint_confidence=None)

        assert confidence in ["medium", "high"]

    def test_negative_taint_confidence_clamped(self):
        """Test that negative taint confidence is clamped to 0.0."""
        scorer = ConfidenceScorer()
        template = {"type": "data_flow"}

        confidence = scorer.calculate_confidence(template, taint_confidence=-0.5)

        assert confidence in ["medium", "high"]

    def test_taint_confidence_above_one_clamped(self):
        """Test that taint confidence > 1.0 is clamped."""
        scorer = ConfidenceScorer()
        template = {"type": "data_flow"}

        confidence1 = scorer.calculate_confidence(template, taint_confidence=1.0)
        confidence2 = scorer.calculate_confidence(template, taint_confidence=2.0)

        assert confidence1 == confidence2


class TestCombinedScoring:
    """Tests for combined scoring across all factors."""

    def test_data_flow_plus_no_sanitization_plus_high_taint_equals_high(
        self,
    ):
        """Test optimal combination yields high confidence."""
        scorer = ConfidenceScorer()

        template = {"type": "data_flow", "control_flow_confirmed": True}
        code = "user_input = request.args.get('user')"
        taint_conf = 0.9

        confidence = scorer.calculate_confidence(
            template, code_context=code, taint_confidence=taint_conf
        )

        assert confidence == "high"

    def test_static_plus_sanitization_plus_low_taint_equals_low(
        self,
    ):
        """Test poor combination yields low confidence."""
        scorer = ConfidenceScorer()

        template = {"type": "static"}
        code = "user_input = html.escape(request.args.get('user'))"
        taint_conf = 0.2

        confidence = scorer.calculate_confidence(
            template, code_context=code, taint_confidence=taint_conf
        )

        assert confidence in ["low", "medium"]

    def test_context_has_more_weight_than_taint(self):
        """Test that context (0.3) has more weight than taint (0.2)."""
        scorer = ConfidenceScorer()

        template = {"type": "data_flow"}

        code1 = "user_input = html.escape(request.args.get('user'))"
        conf1 = scorer.calculate_confidence(template, code_context=code1, taint_confidence=0.9)

        code2 = "user_input = request.args.get('user')"
        conf2 = scorer.calculate_confidence(template, code_context=code2, taint_confidence=0.2)

        assert conf2 >= conf1

    def test_pattern_specificity_has_highest_weight(self):
        """Test that pattern specificity (0.4) has highest weight."""
        scorer = ConfidenceScorer()

        low_specificity = {"type": "heuristic"}
        high_specificity = {"type": "data_flow"}

        low_conf = scorer.calculate_confidence(low_specificity)
        high_conf = scorer.calculate_confidence(high_specificity)

        confidence_order = {"high": 2, "medium": 1, "low": 0}
        assert confidence_order[high_conf] >= confidence_order[low_conf]


class TestCalculateForExistingFinding:
    """Tests for updating confidence on existing findings."""

    def test_high_confidence_kept(self):
        """Test that high confidence is kept if new confidence is lower."""
        from acr.models.finding import Finding, FindingLocation, FindingImpact, FindingRemediation

        scorer = ConfidenceScorer()

        location = FindingLocation(file="test.py", line=10)
        impact = FindingImpact(confidentiality="high", integrity="high", availability="low")
        remediation = FindingRemediation(description="Fix issue")

        finding = Finding(
            id="001",
            title="Test",
            severity="high",
            confidence="high",
            category="injection",
            location=location,
            description="Test",
            attack_vector="Test",
            impact=impact,
            remediation=remediation,
        )

        result = scorer.calculate_for_existing_finding(finding, "low")

        assert result == "high"

    def test_low_confidence_updated(self):
        """Test that low confidence is updated if new confidence is higher."""
        from acr.models.finding import Finding, FindingLocation, FindingImpact, FindingRemediation

        scorer = ConfidenceScorer()

        location = FindingLocation(file="test.py", line=10)
        impact = FindingImpact(confidentiality="high", integrity="high", availability="low")
        remediation = FindingRemediation(description="Fix issue")

        finding = Finding(
            id="001",
            title="Test",
            severity="high",
            confidence="low",
            category="injection",
            location=location,
            description="Test",
            attack_vector="Test",
            impact=impact,
            remediation=remediation,
        )

        result = scorer.calculate_for_existing_finding(finding, "high")

        assert result == "high"

    def test_equal_confidence_unchanged(self):
        """Test that equal confidence remains unchanged."""
        from acr.models.finding import Finding, FindingLocation, FindingImpact, FindingRemediation

        scorer = ConfidenceScorer()

        location = FindingLocation(file="test.py", line=10)
        impact = FindingImpact(confidentiality="high", integrity="high", availability="low")
        remediation = FindingRemediation(description="Fix issue")

        finding = Finding(
            id="001",
            title="Test",
            severity="high",
            confidence="medium",
            category="injection",
            location=location,
            description="Test",
            attack_vector="Test",
            impact=impact,
            remediation=remediation,
        )

        result = scorer.calculate_for_existing_finding(finding, "medium")

        assert result == "medium"


class TestLanguageSupport:
    """Tests for language-specific confidence scoring."""

    def test_python_sanitization_detected(self):
        """Test that Python-specific sanitization is detected."""
        scorer = ConfidenceScorer(language="python")
        template = {"type": "data_flow"}

        code = "user_input = markupsafe.escape(request.args.get('user'))"
        confidence = scorer.calculate_confidence(template, code_context=code)

        assert confidence in ["low", "medium"]

    def test_generic_language_fallback(self):
        """Test that generic language uses generic sanitization list."""
        scorer = ConfidenceScorer(language="generic")
        template = {"type": "data_flow"}

        code = "user_input = sanitize(request.args.get('user'))"
        confidence = scorer.calculate_confidence(template, code_context=code)

        assert confidence in ["low", "medium"]
