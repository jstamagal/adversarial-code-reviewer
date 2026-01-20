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

"""Graceful degradation strategies for ACR."""

import logging
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Callable, TypeVar, Optional, Any, List, Dict
from typing_extensions import ParamSpec

from acr.utils.errors import ACRError, LLMError, AnalysisError, ParseError

P = ParamSpec("P")
R = TypeVar("R")

logger = logging.getLogger(__name__)


class DegradationLevel(Enum):
    """Degradation severity levels."""

    NONE = "none"
    PARTIAL = "partial"
    SIGNIFICANT = "significant"
    CRITICAL = "critical"


class DegradationReason(Enum):
    """Reasons for degradation."""

    LLM_UNAVAILABLE = "llm_unavailable"
    PARSE_ERROR = "parse_error"
    PATTERN_MATCH_FAILURE = "pattern_match_failure"
    ANALYSIS_TIMEOUT = "analysis_timeout"
    DEPENDENCY_MISSING = "dependency_missing"
    MEMORY_LIMIT = "memory_limit"
    FEATURE_NOT_SUPPORTED = "feature_not_supported"
    CONFIGURATION_ERROR = "configuration_error"


@dataclass
class DegradationEvent:
    """Record of a degradation event."""

    component: str
    reason: DegradationReason
    level: DegradationLevel
    message: str
    fallback_value: Optional[Any] = None
    original_exception: Optional[Exception] = None
    timestamp: float = field(default_factory=lambda: __import__("time").time())


class DegradationTracker:
    """Track degradation events during analysis."""

    def __init__(self):
        """Initialize degradation tracker."""
        self.events: List[DegradationEvent] = []

    def record(
        self,
        component: str,
        reason: DegradationReason,
        level: DegradationLevel,
        message: str,
        fallback_value: Optional[Any] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        """Record a degradation event.

        Args:
            component: Component that degraded
            reason: Reason for degradation
            level: Severity level
            message: Human-readable message
            fallback_value: Value used as fallback
            original_exception: Original exception that caused degradation
        """
        event = DegradationEvent(
            component=component,
            reason=reason,
            level=level,
            message=message,
            fallback_value=fallback_value,
            original_exception=original_exception,
        )
        self.events.append(event)

        log_method = logger.error if level == DegradationLevel.CRITICAL else logger.warning
        log_method(
            f"Degradation in {component}: {message} (reason: {reason.value}, level: {level.value})"
        )

    def get_max_level(self) -> DegradationLevel:
        """Get maximum degradation level.

        Returns:
            Maximum degradation level encountered
        """
        if not self.events:
            return DegradationLevel.NONE

        level_priority = {
            DegradationLevel.NONE: 0,
            DegradationLevel.PARTIAL: 1,
            DegradationLevel.SIGNIFICANT: 2,
            DegradationLevel.CRITICAL: 3,
        }

        return max(self.events, key=lambda e: level_priority[e.level]).level

    def get_events_by_component(self, component: str) -> List[DegradationEvent]:
        """Get all events for a specific component.

        Args:
            component: Component name

        Returns:
            List of events for the component
        """
        return [e for e in self.events if e.component == component]

    def get_events_by_reason(self, reason: DegradationReason) -> List[DegradationEvent]:
        """Get all events for a specific reason.

        Args:
            reason: Degradation reason

        Returns:
            List of events with the given reason
        """
        return [e for e in self.events if e.reason == reason]

    def summary(self) -> Dict[str, Any]:
        """Generate summary of degradation events.

        Returns:
            Dictionary with summary statistics
        """
        return {
            "total_events": len(self.events),
            "max_level": self.get_max_level().value,
            "by_reason": {
                reason.value: len(self.get_events_by_reason(reason)) for reason in DegradationReason
            },
            "by_level": {
                level.value: len([e for e in self.events if e.level == level])
                for level in DegradationLevel
            },
        }


_global_tracker: Optional[DegradationTracker] = None


def get_tracker() -> DegradationTracker:
    """Get global degradation tracker.

    Returns:
        Global degradation tracker instance
    """
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = DegradationTracker()
    return _global_tracker


def reset_tracker() -> None:
    """Reset global degradation tracker."""
    global _global_tracker
    _global_tracker = DegradationTracker()


def graceful_fallback(
    component: str,
    fallback_value: Any = None,
    reason: DegradationReason = DegradationReason.PATTERN_MATCH_FAILURE,
    level: DegradationLevel = DegradationLevel.PARTIAL,
    tracker: Optional[DegradationTracker] = None,
    exceptions: tuple = (Exception,),
):
    """Decorator to add graceful fallback to functions.

    Args:
        component: Component name for tracking
        fallback_value: Value to return on exception
        reason: Reason for degradation
        level: Severity level
        tracker: Degradation tracker to use (uses global if None)
        exceptions: Exception types to catch

    Returns:
        Decorated function with fallback behavior
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            nonlocal fallback_value
            try:
                return func(*args, **kwargs)
            except exceptions as e:
                _tracker = tracker or get_tracker()
                message = f"Function {func.__name__} failed: {str(e)}"
                _tracker.record(
                    component=component,
                    reason=reason,
                    level=level,
                    message=message,
                    fallback_value=fallback_value,
                    original_exception=e,
                )

                if callable(fallback_value):
                    result = fallback_value(*args, **kwargs)
                else:
                    result = fallback_value
                return result  # type: ignore[return-value]

        return wrapper

    return decorator


def llm_fallback(
    component: str,
    fallback_value: Any = None,
    tracker: Optional[DegradationTracker] = None,
):
    """Decorator specifically for LLM operations with static analysis fallback.

    Args:
        component: Component name for tracking
        fallback_value: Value to return if LLM fails
        tracker: Degradation tracker to use

    Returns:
        Decorated function with LLM fallback behavior
    """
    return graceful_fallback(
        component=component,
        fallback_value=fallback_value,
        reason=DegradationReason.LLM_UNAVAILABLE,
        level=DegradationLevel.SIGNIFICANT,
        tracker=tracker,
        exceptions=(LLMError, ConnectionError, TimeoutError),
    )


def parse_fallback(
    component: str,
    fallback_value: Any = None,
    tracker: Optional[DegradationTracker] = None,
):
    """Decorator specifically for parsing operations.

    Args:
        component: Component name for tracking
        fallback_value: Value to return if parsing fails
        tracker: Degradation tracker to use

    Returns:
        Decorated function with parse fallback behavior
    """
    return graceful_fallback(
        component=component,
        fallback_value=fallback_value,
        reason=DegradationReason.PARSE_ERROR,
        level=DegradationLevel.PARTIAL,
        tracker=tracker,
        exceptions=(ParseError, SyntaxError, ValueError),
    )


def analysis_fallback(
    component: str,
    fallback_value: Any = None,
    tracker: Optional[DegradationTracker] = None,
):
    """Decorator specifically for analysis operations.

    Args:
        component: Component name for tracking
        fallback_value: Value to return if analysis fails
        tracker: Degradation tracker to use

    Returns:
        Decorated function with analysis fallback behavior
    """
    return graceful_fallback(
        component=component,
        fallback_value=fallback_value,
        reason=DegradationReason.PATTERN_MATCH_FAILURE,
        level=DegradationLevel.PARTIAL,
        tracker=tracker,
        exceptions=(AnalysisError, ACRError),
    )


def with_partial_results(
    component: str,
    tracker: Optional[DegradationTracker] = None,
):
    """Decorator that returns partial results on individual item failures.

    Unlike graceful_fallback, this continues processing other items
    even when some items fail.

    Args:
        component: Component name for tracking
        tracker: Degradation tracker to use

    Returns:
        Decorated function that handles partial results
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            _tracker = tracker or get_tracker()
            try:
                return func(*args, **kwargs)
            except (LLMError, AnalysisError, ParseError) as e:
                _tracker.record(
                    component=component,
                    reason=DegradationReason.PATTERN_MATCH_FAILURE,
                    level=DegradationLevel.PARTIAL,
                    message=f"Partial results returned in {func.__name__}: {str(e)}",
                    original_exception=e,
                )
                raise

        return wrapper

    return decorator


def safe_iterate(
    component: str,
    tracker: Optional[DegradationTracker] = None,
):
    """Decorator for iteration functions that continues on individual failures.

    This is useful for batch operations where one failure shouldn't
    stop the entire batch.

    Args:
        component: Component name for tracking
        tracker: Degradation tracker to use

    Returns:
        Decorated function that continues iteration on failures
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            _tracker = tracker or get_tracker()
            try:
                return func(*args, **kwargs)
            except Exception as e:
                _tracker.record(
                    component=component,
                    reason=DegradationReason.PATTERN_MATCH_FAILURE,
                    level=DegradationLevel.PARTIAL,
                    message=f"Error during iteration in {func.__name__}: {str(e)}",
                    original_exception=e,
                )
                return []  # type: ignore[return-value]

        return wrapper

    return decorator


class DegradationContext:
    """Context manager for scoped degradation tracking."""

    def __init__(self, component: str):
        """Initialize degradation context.

        Args:
            component: Component name for this context
        """
        self.component = component
        self.tracker = DegradationTracker()
        self._parent_tracker: Optional[DegradationTracker] = None

    def __enter__(self) -> "DegradationContext":
        """Enter degradation context.

        Returns:
            Self
        """
        global _global_tracker
        self._parent_tracker = _global_tracker
        _global_tracker = self.tracker
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit degradation context.

        Args:
            exc_type: Exception type
            exc_val: Exception value
            exc_tb: Exception traceback
        """
        global _global_tracker
        _global_tracker = self._parent_tracker

        if exc_type is not None:
            self.tracker.record(
                component=self.component,
                reason=DegradationReason.PATTERN_MATCH_FAILURE,
                level=DegradationLevel.SIGNIFICANT,
                message=f"Context failed with exception: {str(exc_val)}",
                original_exception=exc_val,
            )

        return False

    def get_events(self) -> List[DegradationEvent]:
        """Get all events in this context.

        Returns:
            List of degradation events
        """
        return self.tracker.events

    def summary(self) -> Dict[str, Any]:
        """Get summary of degradation in this context.

        Returns:
            Dictionary with summary statistics
        """
        return self.tracker.summary()
