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
# See the License for specific language governing permissions and
# limitations under the License.

"""Tests for graceful degradation system."""


import pytest

from acr.utils.degradation import (
    DegradationContext,
    DegradationLevel,
    DegradationReason,
    DegradationTracker,
    analysis_fallback,
    get_tracker,
    graceful_fallback,
    llm_fallback,
    parse_fallback,
    reset_tracker,
    safe_iterate,
    with_partial_results,
)
from acr.utils.errors import AnalysisError, LLMError, ParseError


class TestDegradationTracker:
    """Test DegradationTracker functionality."""

    def test_record_event(self):
        """Test recording degradation events."""
        tracker = DegradationTracker()
        tracker.record(
            component="test_component",
            reason=DegradationReason.LLM_UNAVAILABLE,
            level=DegradationLevel.PARTIAL,
            message="Test degradation",
            fallback_value=None,
            original_exception=Exception("test"),
        )

        assert len(tracker.events) == 1
        assert tracker.events[0].component == "test_component"
        assert tracker.events[0].reason == DegradationReason.LLM_UNAVAILABLE
        assert tracker.events[0].level == DegradationLevel.PARTIAL

    def test_get_max_level_no_events(self):
        """Test max level with no events."""
        tracker = DegradationTracker()
        assert tracker.get_max_level() == DegradationLevel.NONE

    def test_get_max_level_with_events(self):
        """Test max level with multiple events."""
        tracker = DegradationTracker()
        tracker.record(
            component="comp1",
            reason=DegradationReason.PATTERN_MATCH_FAILURE,
            level=DegradationLevel.PARTIAL,
            message="Test",
        )
        tracker.record(
            component="comp2",
            reason=DegradationReason.LLM_UNAVAILABLE,
            level=DegradationLevel.CRITICAL,
            message="Test",
        )

        assert tracker.get_max_level() == DegradationLevel.CRITICAL

    def test_get_events_by_component(self):
        """Test filtering events by component."""
        tracker = DegradationTracker()
        tracker.record(
            component="comp1",
            reason=DegradationReason.PATTERN_MATCH_FAILURE,
            level=DegradationLevel.PARTIAL,
            message="Test",
        )
        tracker.record(
            component="comp2",
            reason=DegradationReason.LLM_UNAVAILABLE,
            level=DegradationLevel.CRITICAL,
            message="Test",
        )
        tracker.record(
            component="comp1",
            reason=DegradationReason.PARSE_ERROR,
            level=DegradationLevel.SIGNIFICANT,
            message="Test",
        )

        events = tracker.get_events_by_component("comp1")
        assert len(events) == 2
        assert all(e.component == "comp1" for e in events)

    def test_get_events_by_reason(self):
        """Test filtering events by reason."""
        tracker = DegradationTracker()
        tracker.record(
            component="comp1",
            reason=DegradationReason.LLM_UNAVAILABLE,
            level=DegradationLevel.PARTIAL,
            message="Test",
        )
        tracker.record(
            component="comp2",
            reason=DegradationReason.PATTERN_MATCH_FAILURE,
            level=DegradationLevel.CRITICAL,
            message="Test",
        )
        tracker.record(
            component="comp3",
            reason=DegradationReason.LLM_UNAVAILABLE,
            level=DegradationLevel.SIGNIFICANT,
            message="Test",
        )

        events = tracker.get_events_by_reason(DegradationReason.LLM_UNAVAILABLE)
        assert len(events) == 2
        assert all(e.reason == DegradationReason.LLM_UNAVAILABLE for e in events)

    def test_summary(self):
        """Test degradation summary generation."""
        tracker = DegradationTracker()
        tracker.record(
            component="comp1",
            reason=DegradationReason.LLM_UNAVAILABLE,
            level=DegradationLevel.PARTIAL,
            message="Test",
        )
        tracker.record(
            component="comp2",
            reason=DegradationReason.PATTERN_MATCH_FAILURE,
            level=DegradationLevel.CRITICAL,
            message="Test",
        )

        summary = tracker.summary()
        assert summary["total_events"] == 2
        assert summary["max_level"] == DegradationLevel.CRITICAL.value
        assert "by_reason" in summary
        assert "by_level" in summary


class TestGlobalTracker:
    """Test global tracker functionality."""

    def test_get_tracker_singleton(self):
        """Test global tracker is singleton."""
        reset_tracker()
        tracker1 = get_tracker()
        tracker2 = get_tracker()
        assert tracker1 is tracker2

    def test_reset_tracker(self):
        """Test resetting global tracker."""
        reset_tracker()
        tracker = get_tracker()
        tracker.record(
            component="test",
            reason=DegradationReason.PATTERN_MATCH_FAILURE,
            level=DegradationLevel.PARTIAL,
            message="Test",
        )
        assert len(tracker.events) == 1

        reset_tracker()
        tracker = get_tracker()
        assert len(tracker.events) == 0


class TestGracefulFallback:
    """Test graceful_fallback decorator."""

    def test_successful_execution(self):
        """Test function executes normally when no exception."""

        @graceful_fallback(component="test", fallback_value="fallback")
        def test_func():
            return "success"

        result = test_func()
        assert result == "success"

    def test_exception_returns_fallback(self):
        """Test exception returns fallback value."""

        @graceful_fallback(component="test", fallback_value="fallback")
        def test_func():
            raise ValueError("test error")

        result = test_func()
        assert result == "fallback"

    def test_exception_records_event(self):
        """Test exception records degradation event."""
        reset_tracker()
        tracker = get_tracker()

        @graceful_fallback(component="test", fallback_value="fallback", tracker=tracker)
        def test_func():
            raise ValueError("test error")

        test_func()
        assert len(tracker.events) == 1
        assert tracker.events[0].component == "test"
        assert tracker.events[0].fallback_value == "fallback"

    def test_callable_fallback(self):
        """Test callable fallback value."""

        @graceful_fallback(component="test", fallback_value=lambda: "dynamic_fallback")
        def test_func():
            raise ValueError("test error")

        result = test_func()
        assert result == "dynamic_fallback"

    def test_specific_exception_type(self):
        """Test catching specific exception types."""

        @graceful_fallback(component="test", fallback_value="fallback", exceptions=(ValueError,))
        def test_func():
            raise KeyError("not caught")

        with pytest.raises(KeyError):
            test_func()

    def test_default_fallback_is_none(self):
        """Test default fallback is None."""

        @graceful_fallback(component="test")
        def test_func():
            raise ValueError("test error")

        result = test_func()
        assert result is None


class TestLLMFallback:
    """Test llm_fallback decorator."""

    def test_llm_error_fallback(self):
        """Test LLM error returns fallback."""

        @llm_fallback(component="llm_test", fallback_value="no_llm")
        def test_func():
            raise LLMError("LLM unavailable")

        result = test_func()
        assert result == "no_llm"

    def test_llm_fallback_records_correct_reason(self):
        """Test LLM fallback records correct reason."""
        reset_tracker()
        tracker = get_tracker()

        @llm_fallback(component="llm_test", fallback_value="no_llm", tracker=tracker)
        def test_func():
            raise LLMError("LLM unavailable")

        test_func()
        assert tracker.events[0].reason == DegradationReason.LLM_UNAVAILABLE
        assert tracker.events[0].level == DegradationLevel.SIGNIFICANT

    def test_llm_fallback_catches_connection_error(self):
        """Test LLM fallback catches connection errors."""

        @llm_fallback(component="llm_test", fallback_value="no_llm")
        def test_func():
            raise ConnectionError("Network error")

        result = test_func()
        assert result == "no_llm"

    def test_llm_fallback_catches_timeout(self):
        """Test LLM fallback catches timeout errors."""

        @llm_fallback(component="llm_test", fallback_value="no_llm")
        def test_func():
            raise TimeoutError("Request timeout")

        result = test_func()
        assert result == "no_llm"


class TestParseFallback:
    """Test parse_fallback decorator."""

    def test_parse_error_fallback(self):
        """Test parse error returns fallback."""

        @parse_fallback(component="parse_test", fallback_value="no_parse")
        def test_func():
            raise ParseError("Parse failed", "test.py", 10)

        result = test_func()
        assert result == "no_parse"

    def test_parse_fallback_records_correct_reason(self):
        """Test parse fallback records correct reason."""
        reset_tracker()
        tracker = get_tracker()

        @parse_fallback(component="parse_test", fallback_value="no_parse", tracker=tracker)
        def test_func():
            raise ParseError("Parse failed", "test.py", 10)

        test_func()
        assert tracker.events[0].reason == DegradationReason.PARSE_ERROR
        assert tracker.events[0].level == DegradationLevel.PARTIAL

    def test_parse_fallback_catches_syntax_error(self):
        """Test parse fallback catches syntax errors."""

        @parse_fallback(component="parse_test", fallback_value="no_parse")
        def test_func():
            raise SyntaxError("Invalid syntax")

        result = test_func()
        assert result == "no_parse"


class TestAnalysisFallback:
    """Test analysis_fallback decorator."""

    def test_analysis_error_fallback(self):
        """Test analysis error returns fallback."""

        @analysis_fallback(component="analysis_test", fallback_value="no_analysis")
        def test_func():
            raise AnalysisError("Analysis failed")

        result = test_func()
        assert result == "no_analysis"

    def test_analysis_fallback_records_correct_reason(self):
        """Test analysis fallback records correct reason."""
        reset_tracker()
        tracker = get_tracker()

        @analysis_fallback(component="analysis_test", fallback_value="no_analysis", tracker=tracker)
        def test_func():
            raise AnalysisError("Analysis failed")

        test_func()
        assert tracker.events[0].reason == DegradationReason.PATTERN_MATCH_FAILURE
        assert tracker.events[0].level == DegradationLevel.PARTIAL


class TestWithPartialResults:
    """Test with_partial_results decorator."""

    def test_successful_execution(self):
        """Test function executes normally when no exception."""

        @with_partial_results(component="test")
        def test_func():
            return [1, 2, 3]

        result = test_func()
        assert result == [1, 2, 3]

    def test_exception_reraises(self):
        """Test exception is reraised for partial results handling."""

        @with_partial_results(component="test")
        def test_func():
            raise LLMError("LLM error")

        with pytest.raises(LLMError):
            test_func()

    def test_exception_records_event_before_reraise(self):
        """Test exception records degradation event before reraising."""
        reset_tracker()
        tracker = get_tracker()

        @with_partial_results(component="test", tracker=tracker)
        def test_func():
            raise LLMError("LLM error")

        with pytest.raises(LLMError):
            test_func()

        assert len(tracker.events) == 1
        assert tracker.events[0].component == "test"


class TestSafeIterate:
    """Test safe_iterate decorator."""

    def test_successful_execution(self):
        """Test function executes normally when no exception."""

        @safe_iterate(component="test")
        def test_func():
            return [1, 2, 3]

        result = test_func()
        assert result == [1, 2, 3]

    def test_exception_returns_empty_list(self):
        """Test exception returns empty list."""

        @safe_iterate(component="test")
        def test_func():
            raise ValueError("Iteration failed")

        result = test_func()
        assert result == []

    def test_exception_records_event(self):
        """Test exception records degradation event."""
        reset_tracker()
        tracker = get_tracker()

        @safe_iterate(component="test", tracker=tracker)
        def test_func():
            raise ValueError("Iteration failed")

        test_func()
        assert len(tracker.events) == 1
        assert tracker.events[0].component == "test"


class TestDegradationContext:
    """Test DegradationContext context manager."""

    def test_context_creates_tracker(self):
        """Test context creates its own tracker."""
        reset_tracker()
        global_tracker = get_tracker()
        global_tracker.record(
            component="global",
            reason=DegradationReason.PATTERN_MATCH_FAILURE,
            level=DegradationLevel.PARTIAL,
            message="Test",
        )
        assert len(global_tracker.events) == 1

        with DegradationContext("test_context") as ctx:
            context_tracker = get_tracker()
            assert context_tracker is not global_tracker
            assert len(context_tracker.events) == 0

        assert len(global_tracker.events) == 1

    def test_context_get_events(self):
        """Test getting events from context."""
        with DegradationContext("test_context") as ctx:
            tracker = get_tracker()
            tracker.record(
                component="test",
                reason=DegradationReason.PATTERN_MATCH_FAILURE,
                level=DegradationLevel.PARTIAL,
                message="Test",
            )

            events = ctx.get_events()
            assert len(events) == 1

    def test_context_summary(self):
        """Test getting summary from context."""
        with DegradationContext("test_context") as ctx:
            tracker = get_tracker()
            tracker.record(
                component="test",
                reason=DegradationReason.PATTERN_MATCH_FAILURE,
                level=DegradationLevel.PARTIAL,
                message="Test",
            )

            summary = ctx.summary()
            assert summary["total_events"] == 1

    def test_context_catches_exception(self):
        """Test context records exceptions before reraising."""
        with pytest.raises(ValueError):
            with DegradationContext("test_context") as ctx:
                raise ValueError("Test error")

        events = ctx.get_events()
        assert len(events) == 1
        assert events[0].reason == DegradationReason.PATTERN_MATCH_FAILURE
        assert events[0].level == DegradationLevel.SIGNIFICANT

    def test_nested_contexts(self):
        """Test nested degradation contexts."""
        with DegradationContext("outer") as outer_ctx:
            outer_tracker = get_tracker()
            outer_tracker.record(
                component="outer",
                reason=DegradationReason.PATTERN_MATCH_FAILURE,
                level=DegradationLevel.PARTIAL,
                message="Test",
            )

            with DegradationContext("inner") as inner_ctx:
                inner_tracker = get_tracker()
                assert inner_tracker is not outer_tracker
                inner_tracker.record(
                    component="inner",
                    reason=DegradationReason.LLM_UNAVAILABLE,
                    level=DegradationLevel.CRITICAL,
                    message="Test",
                )

            assert len(outer_tracker.events) == 1
            assert len(inner_ctx.get_events()) == 1
