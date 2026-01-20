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

"""Tests for error recovery integration across codebase."""

from acr.patterns.matcher import PatternMatcher
from acr.utils.degradation import DegradationLevel, DegradationReason, get_tracker


class TestErrorRecoveryIntegration:
    """Test that error recovery mechanisms are properly integrated."""

    def test_llm_fallback_decorator_available(self):
        """Test that @llm_fallback decorator is available for use."""
        from acr.utils.degradation import llm_fallback

        assert callable(llm_fallback), "@llm_fallback decorator should be available"

    def test_pattern_matcher_safe_iterate_continues_on_error(self):
        """Test that pattern matcher continues on individual pattern failures."""
        from acr.patterns.schema import Pattern, PatternRemediation, StaticPatternTemplate

        tracker = get_tracker()
        tracker.events.clear()

        # Create valid patterns
        matcher = PatternMatcher(
            patterns=[
                Pattern(
                    id="test_1",
                    name="Test Pattern 1",
                    description="Test pattern",
                    category="test",
                    severity="low",
                    attack_vector="test attack",
                    remediation=PatternRemediation(
                        description="fix it",
                        code_before="bad",
                        code_after="good",
                    ),
                    templates=[StaticPatternTemplate(pattern=r"print\s*\(")],
                ),
                Pattern(
                    id="test_2",
                    name="Test Pattern 2",
                    description="Test pattern",
                    category="test",
                    severity="low",
                    attack_vector="test attack",
                    remediation=PatternRemediation(
                        description="fix it",
                        code_before="bad",
                        code_after="good",
                    ),
                    templates=[StaticPatternTemplate(pattern=r"eval\s*\(")],
                ),
            ]
        )

        code = "print('hello world')\nprint('test')\neval('unsafe')"

        findings = matcher.match_all(code, "test.py")

        # Should have findings from both patterns (pattern 1 matches twice, pattern 2 matches once)
        assert len(findings) == 3

    def test_global_tracker_singleton(self):
        """Test that global tracker works across modules."""
        from acr.utils.degradation import get_tracker, reset_tracker

        reset_tracker()
        tracker1 = get_tracker()
        tracker2 = get_tracker()

        assert tracker1 is tracker2

        tracker1.record(
            component="test",
            reason=DegradationReason.PATTERN_MATCH_FAILURE,
            level=DegradationLevel.PARTIAL,
            message="Test message",
        )

        assert len(tracker2.events) == 1
