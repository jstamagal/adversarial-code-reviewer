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

"""Tests for taint tracker module."""

import pytest
from acr.core.taint_tracker import TaintTracker, TaintedVar


class MockDFG:
    """Mock Data Flow Graph for testing."""

    def __init__(self, edges):
        """Initialize mock DFG."""
        self.edges = edges


class TestTaintedVar:
    """Test TaintedVar class."""

    def test_tainted_var_initialization(self):
        """Test TaintedVar initialization."""
        tvar = TaintedVar("user_input", 42, "handle_request")
        assert tvar.name == "user_input"
        assert tvar.source_line == 42
        assert tvar.source_function == "handle_request"
        assert not tvar.sanitized

    def test_tainted_var_sanitization_flag(self):
        """Test TaintedVar sanitization flag can be set."""
        tvar = TaintedVar("data", 10)
        assert not tvar.sanitized
        tvar.sanitized = True
        assert tvar.sanitized


class TestTaintTrackerInitialization:
    """Test TaintTracker initialization."""

    def test_initial_state(self):
        """Test tracker starts with empty state."""
        tracker = TaintTracker()
        assert tracker.tainted_vars == {}
        assert tracker.sanitized_vars == set()
        assert tracker.taint_flows == []


class TestTaintSourceManagement:
    """Test adding and managing taint sources."""

    def test_add_taint_source(self):
        """Test adding a taint source."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10, "process_request")
        assert "user_input" in tracker.tainted_vars
        assert tracker.tainted_vars["user_input"].name == "user_input"
        assert tracker.tainted_vars["user_input"].source_line == 10
        assert tracker.tainted_vars["user_input"].source_function == "process_request"

    def test_add_multiple_taint_sources(self):
        """Test adding multiple taint sources."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)
        tracker.add_taint_source("request_data", 15, "api_handler")
        tracker.add_taint_source("form_field", 20, "form_submit")
        assert len(tracker.tainted_vars) == 3
        assert all(isinstance(v, TaintedVar) for v in tracker.tainted_vars.values())

    def test_add_taint_source_default_function(self):
        """Test adding taint source with default function name."""
        tracker = TaintTracker()
        tracker.add_taint_source("data", 5)
        assert tracker.tainted_vars["data"].source_function == ""


class TestSanitizerManagement:
    """Test adding and managing sanitizers."""

    def test_add_sanitizer(self):
        """Test adding a sanitizer."""
        tracker = TaintTracker()
        tracker.add_sanitizer("cleaned_data")
        assert "cleaned_data" in tracker.sanitized_vars

    def test_add_multiple_sanitizers(self):
        """Test adding multiple sanitizers."""
        tracker = TaintTracker()
        tracker.add_sanitizer("var1")
        tracker.add_sanitizer("var2")
        tracker.add_sanitizer("var3")
        assert len(tracker.sanitized_vars) == 3

    def test_sanitizer_overrides_taint(self):
        """Test that sanitizer marks tainted var as sanitized."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)
        tracker.add_sanitizer("user_input")
        assert "user_input" in tracker.sanitized_vars
        assert tracker.tainted_vars["user_input"].sanitized


class TestIsTainted:
    """Test checking if variables are tainted."""

    def test_is_tainted_true(self):
        """Test is_tainted returns True for tainted var."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)
        assert tracker.is_tainted("user_input")

    def test_is_tainted_false_not_added(self):
        """Test is_tainted returns False for non-existent var."""
        tracker = TaintTracker()
        assert not tracker.is_tainted("non_existent")

    def test_is_tainted_false_sanitized(self):
        """Test is_tainted returns False for sanitized var."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)
        tracker.add_sanitizer("user_input")
        assert not tracker.is_tainted("user_input")

    def test_is_tainted_after_sanitizer_added(self):
        """Test is_tainted updates after sanitizer is added."""
        tracker = TaintTracker()
        tracker.add_taint_source("data", 5)
        assert tracker.is_tainted("data")
        tracker.add_sanitizer("data")
        assert not tracker.is_tainted("data")


class TestTaintPropagation:
    """Test taint propagation through DFG."""

    def test_propagate_with_none_dfg(self):
        """Test propagate handles None DFG gracefully."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)
        result = tracker.propagate(None)
        assert result == []

    def test_propagate_with_simple_dfg(self):
        """Test propagate with simple DFG."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)

        edges = [
            ("user_input", "query", {"type": "assignment"}),
            ("query", "cursor.execute", {"type": "sink"}),
        ]
        dfg = MockDFG(edges)

        result = tracker.propagate(dfg)
        assert len(result) > 0
        assert result[0]["source"] == "user_input"
        tainted_names = [tvar.name for tvar in result[0]["tainted_vars"]]
        assert "user_input" in tainted_names

    def test_propagate_with_sanitized_target(self):
        """Test propagate stops at sanitized target."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)
        tracker.add_sanitizer("cleaned_input")

        edges = [
            ("user_input", "cleaned_input", {"type": "assignment"}),
            ("cleaned_input", "query", {"type": "assignment"}),
        ]
        dfg = MockDFG(edges)

        result = tracker.propagate(dfg)
        # Should not propagate through sanitized var
        # Only the first edge might be included
        for flow in result:
            assert "cleaned_input" not in str(flow.get("source", ""))

    def test_propagate_tracks_taint_flows(self):
        """Test that propagate tracks taint flows."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)

        edges = [
            ("user_input", "data", {"type": "assignment"}),
        ]
        dfg = MockDFG(edges)

        assert len(tracker.taint_flows) == 0
        tracker.propagate(dfg)
        assert len(tracker.taint_flows) > 0

    def test_propagate_with_empty_dfg(self):
        """Test propagate with empty DFG."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)
        dfg = MockDFG([])
        result = tracker.propagate(dfg)
        assert result == []

    def test_propagate_with_non_string_source(self):
        """Test propagate handles non-string source nodes."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)

        edges = [
            (123, "query", {"type": "assignment"}),
        ]
        dfg = MockDFG(edges)

        result = tracker.propagate(dfg)
        # Should not find taint in non-string source
        assert result == []

    def test_propagate_multiple_flows(self):
        """Test propagate tracks multiple taint flows."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)
        tracker.add_taint_source("form_data", 20)

        edges = [
            ("user_input", "query1", {"type": "assignment"}),
            ("form_data", "query2", {"type": "assignment"}),
        ]
        dfg = MockDFG(edges)

        result = tracker.propagate(dfg)
        assert len(result) >= 1


class TestGetTaintedVariables:
    """Test getting list of tainted variables."""

    def test_get_tainted_variables_empty(self):
        """Test get_tainted_variables returns empty list."""
        tracker = TaintTracker()
        assert tracker.get_tainted_variables() == []

    def test_get_tainted_variables_with_data(self):
        """Test get_tainted_variables returns tainted vars."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)
        tracker.add_taint_source("form_data", 20)
        tracker.add_sanitizer("sanitized")

        result = tracker.get_tainted_variables()
        assert "user_input" in result
        assert "form_data" in result
        assert "sanitized" not in result
        assert len(result) == 2

    def test_get_tainted_variables_excludes_sanitized(self):
        """Test get_tainted_variables excludes sanitized vars."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)
        tracker.add_taint_source("safe_data", 20)
        tracker.add_sanitizer("user_input")

        result = tracker.get_tainted_variables()
        assert "user_input" not in result
        assert "safe_data" in result
        assert len(result) == 1


class TestGetTaintSourceInfo:
    """Test getting taint source information."""

    def test_get_taint_source_info_for_tainted_var(self):
        """Test get_taint_source_info returns info for tainted var."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 42, "handler")

        info = tracker.get_taint_source_info("user_input")
        assert info is not None
        assert info["name"] == "user_input"
        assert info["source_line"] == 42
        assert info["source_function"] == "handler"
        assert not info["sanitized"]

    def test_get_taint_source_info_for_nonexistent_var(self):
        """Test get_taint_source_info returns None for nonexistent var."""
        tracker = TaintTracker()
        info = tracker.get_taint_source_info("nonexistent")
        assert info is None

    def test_get_taint_source_info_for_sanitized_var(self):
        """Test get_taint_source_info shows sanitized status."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)
        tracker.add_sanitizer("user_input")

        info = tracker.get_taint_source_info("user_input")
        assert info is not None
        assert info["sanitized"]


class TestReset:
    """Test resetting taint tracker state."""

    def test_reset_clears_all_state(self):
        """Test reset clears all tracking state."""
        tracker = TaintTracker()
        tracker.add_taint_source("user_input", 10)
        tracker.add_sanitizer("cleaned")
        tracker.propagate(MockDFG([]))

        tracker.reset()

        assert tracker.tainted_vars == {}
        assert tracker.sanitized_vars == set()
        assert tracker.taint_flows == []

    def test_reset_after_operations(self):
        """Test reset after multiple operations."""
        tracker = TaintTracker()
        tracker.add_taint_source("var1", 10)
        tracker.add_taint_source("var2", 20)
        tracker.add_sanitizer("var1")
        tracker.propagate(MockDFG([("var2", "query", {})]))

        assert len(tracker.tainted_vars) == 2
        assert len(tracker.sanitized_vars) == 1
        assert len(tracker.taint_flows) > 0

        tracker.reset()

        assert len(tracker.tainted_vars) == 0
        assert len(tracker.sanitized_vars) == 0
        assert len(tracker.taint_flows) == 0


class TestIdentifySanitization:
    """Test identifying sanitization in code nodes."""

    def test_identify_html_escape(self):
        """Test identifying html.escape sanitization."""
        tracker = TaintTracker()
        result = tracker.identify_sanitization("html.escape(user_input)")
        assert result == "html_escape"

    def test_identify_url_escape(self):
        """Test identifying urllib.parse.quote sanitization."""
        tracker = TaintTracker()
        result = tracker.identify_sanitization("urllib.parse.quote(url)")
        assert result == "url_escape"

    def test_identify_regex_escape(self):
        """Test identifying re.escape sanitization."""
        tracker = TaintTracker()
        result = tracker.identify_sanitization("re.escape(pattern)")
        assert result == "regex_escape"

    def test_identify_validate_function(self):
        """Test identifying validate function."""
        tracker = TaintTracker()
        result = tracker.identify_sanitization("validate_input(data)")
        assert result == "validate"

    def test_identify_sanitize_function(self):
        """Test identifying sanitize function."""
        tracker = TaintTracker()
        result = tracker.identify_sanitization("sanitize(user_input)")
        assert result == "sanitize"

    def test_identify_strip_function(self):
        """Test identifying strip function."""
        tracker = TaintTracker()
        result = tracker.identify_sanitization("data.strip()")
        assert result == "strip"

    def test_identify_none_for_non_sanitizing_code(self):
        """Test identify_sanitization returns None for regular code."""
        tracker = TaintTracker()
        result = tracker.identify_sanitization("x = y + z")
        assert result is None

    def test_identify_sanitization_with_none_input(self):
        """Test identify_sanitization handles None gracefully."""
        tracker = TaintTracker()
        result = tracker.identify_sanitization(None)
        assert result is None

    def test_identify_clean_function(self):
        """Test identifying clean function."""
        tracker = TaintTracker()
        result = tracker.identify_sanitization("clean_data(input)")
        assert result == "clean"

    def test_identify_general_escape(self):
        """Test identifying general escape pattern."""
        tracker = TaintTracker()
        result = tracker.identify_sanitization("some_escape_function(data)")
        assert result == "escape"


class TestTaintTrackerIntegration:
    """Integration tests for taint tracker."""

    def test_full_taint_tracking_workflow(self):
        """Test complete taint tracking workflow."""
        tracker = TaintTracker()

        # Add taint sources
        tracker.add_taint_source("user_input", 10, "handle_request")
        tracker.add_taint_source("form_data", 15, "process_form")

        # Add sanitizer
        tracker.add_sanitizer("cleaned_input")

        # Check tainted vars
        assert tracker.is_tainted("user_input")
        assert tracker.is_tainted("form_data")
        assert not tracker.is_tainted("cleaned_input")

        # Get tainted variables
        tainted = tracker.get_tainted_variables()
        assert len(tainted) == 2

        # Get source info
        info = tracker.get_taint_source_info("user_input")
        assert info is not None
        assert info["source_line"] == 10

        # Propagate through DFG
        edges = [
            ("user_input", "query", {"type": "assignment"}),
            ("form_data", "data", {"type": "assignment"}),
        ]
        dfg = MockDFG(edges)
        sinks = tracker.propagate(dfg)

        assert len(sinks) >= 1

        # Reset
        tracker.reset()
        assert len(tracker.get_tainted_variables()) == 0

    def test_taint_tracking_with_sanitization_chain(self):
        """Test taint tracking with multiple sanitization points."""
        tracker = TaintTracker()

        tracker.add_taint_source("raw_input", 5)
        tracker.add_sanitizer("cleaned")
        tracker.add_sanitizer("validated")

        # Initially tainted
        assert tracker.is_tainted("raw_input")

        # After sanitization
        assert not tracker.is_tainted("cleaned")
        assert not tracker.is_tainted("validated")

        # Get tainted should only return raw_input
        tainted = tracker.get_tainted_variables()
        assert tainted == ["raw_input"]

    def test_identify_sanitization_adds_to_sanitize_list(self):
        """Test that identify_sanitization informs sanitization tracking."""
        tracker = TaintTracker()

        # Identify sanitization pattern
        sanitization = tracker.identify_sanitization("html.escape(user_input)")

        # The pattern is identified
        assert sanitization == "html_escape"

        # Add taint source first
        tracker.add_taint_source("user_input", 10)
        assert tracker.is_tainted("user_input")

        # Add sanitizer - should mark as not tainted
        tracker.add_sanitizer("user_input")
        assert not tracker.is_tainted("user_input")

        # Trying to add the same var as tainted after it's sanitized
        # should fail (return False) and not mark it as tainted
        result = tracker.add_taint_source("user_input", 10)
        assert result is False
        assert not tracker.is_tainted("user_input")
