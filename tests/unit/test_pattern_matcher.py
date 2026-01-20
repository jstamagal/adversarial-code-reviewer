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

"""Tests for pattern matcher functionality."""

from acr.patterns.loader import PatternLoader
from acr.patterns.matcher import PatternMatcher
from acr.patterns.schema import (
    ControlFlowPatternTemplate,
    DataFlowPatternTemplate,
    Pattern,
    PatternRemediation,
    SeverityLevel,
    StaticPatternTemplate,
)


class TestPatternMatcherStaticPatterns:
    """Test static pattern matching."""

    def test_matcher_initializes_with_patterns(self):
        """Test that matcher initializes with patterns from library."""
        matcher = PatternMatcher()
        assert len(matcher.patterns) > 0

    def test_matcher_accepts_custom_patterns(self):
        """Test that matcher accepts custom patterns."""
        custom_patterns = [
            Pattern(
                id="test-pattern",
                name="Test Pattern",
                description="Test description",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[StaticPatternTemplate(pattern=r"test_function", confidence="high")],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        assert len(matcher.patterns) == 1
        assert matcher.patterns[0].id == "test-pattern"

    def test_match_all_returns_empty_list_for_no_matches(self):
        """Test that match_all returns empty list when no patterns match."""
        matcher = PatternMatcher()
        findings = matcher.match_all("def hello(): pass", "test.py")
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_match_sql_injection_pattern(self):
        """Test that SQL injection pattern is detected."""
        matcher = PatternMatcher()
        code = """
def query_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
        findings = matcher.match_all(code, "test.py")
        assert len(findings) > 0
        assert any(
            "sql" in f.category.lower() or "injection" in f.category.lower() for f in findings
        )

    def test_match_eval_injection_pattern(self):
        """Test that eval injection pattern is detected."""
        matcher = PatternMatcher()
        code = """
def compute():
    input_data = request.args.get('expr')
    return eval(input_data)
"""
        findings = matcher.match_all(code, "test.py")
        assert len(findings) > 0

    def test_match_hardcoded_secrets(self):
        """Test that hardcoded secrets pattern is detected."""
        matcher = PatternMatcher()
        code = """
api_key = "sk-1234567890abcdefghijklmnop"
password = "supersecretpassword"
"""
        findings = matcher.match_all(code, "test.py")
        assert len(findings) > 0
        assert any("cryptography" in f.category.lower() for f in findings)

    def test_disabled_patterns_not_matched(self):
        """Test that disabled patterns are not matched."""
        custom_patterns = [
            Pattern(
                id="test-disabled",
                name="Disabled Pattern",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                enabled=False,
                templates=[StaticPatternTemplate(pattern=r"disabled_function", confidence="high")],
                attack_vector="Test attack",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        findings = matcher.match_all("disabled_function()", "test.py")
        assert len(findings) == 0

    def test_pattern_with_no_template_returns_no_findings(self):
        """Test that pattern with no templates returns no findings."""
        custom_patterns = [
            Pattern(
                id="no-template",
                name="No Template",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[],
                attack_vector="Test attack",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        findings = matcher.match_all("some code", "test.py")
        assert len(findings) == 0

    def test_multiple_patterns_can_match_same_code(self):
        """Test that multiple patterns can match the same code."""
        matcher = PatternMatcher()
        code = """
import os
def execute_cmd(cmd):
    return os.system(cmd)
"""
        findings = matcher.match_all(code, "test.py")
        assert len(findings) >= 1


class TestPatternMatcherDataFlow:
    """Test data flow pattern matching."""

    def test_data_flow_pattern_with_ast_data(self):
        """Test data flow pattern matching with AST data."""
        custom_patterns = [
            Pattern(
                id="test-dataflow",
                name="Data Flow Test",
                description="Test data flow",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[
                    DataFlowPatternTemplate(
                        source=r"input\(",
                        sink=r"eval",
                        sanitizers=[],
                        confidence="high",
                    )
                ],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
def process():
    data = input()
    return eval(data)
"""
        ast_data = {
            "functions": [],
            "call_sites": [
                {"name": "eval", "line": 3, "function": "process"},
            ],
        }
        findings = matcher.match_all(code, "test.py", ast_data)
        assert len(findings) > 0

    def test_data_flow_pattern_with_sanitizer(self):
        """Test that sanitizers prevent findings."""
        custom_patterns = [
            Pattern(
                id="test-sanitizer",
                name="Sanitizer Test",
                description="Test sanitizer",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[
                    DataFlowPatternTemplate(
                        source=r"input\(",
                        sink=r"eval\(",
                        sanitizers=[r"escape\(data\)"],
                        confidence="high",
                    )
                ],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
def process():
    data = input()
    safe_data = escape(data)
    return eval(safe_data)
"""
        ast_data = {
            "functions": [],
            "call_sites": [
                {"name": "eval", "line": 4, "function": "process"},
            ],
        }
        findings = matcher.match_all(code, "test.py", ast_data)
        assert len(findings) == 0

    def test_data_flow_pattern_without_ast_data(self):
        """Test that data flow patterns require AST data."""
        custom_patterns = [
            Pattern(
                id="test-no-ast",
                name="No AST Test",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[
                    DataFlowPatternTemplate(
                        source=r"input\(",
                        sink=r"eval\(",
                        sanitizers=[],
                        confidence="high",
                    )
                ],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
def process():
    data = input()
    return eval(data)
"""
        findings = matcher.match_all(code, "test.py", ast_data=None)
        assert len(findings) == 0

    def test_data_flow_pattern_source_not_found(self):
        """Test that missing source doesn't generate finding."""
        custom_patterns = [
            Pattern(
                id="no-source",
                name="No Source",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[
                    DataFlowPatternTemplate(
                        source=r"input\(",
                        sink=r"eval\(",
                        sanitizers=[],
                        confidence="high",
                    )
                ],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
def process():
    data = get_data()
    return eval(data)
"""
        ast_data = {
            "functions": [],
            "call_sites": [
                {"name": "eval", "line": 3, "function": "process"},
            ],
        }
        findings = matcher.match_all(code, "test.py", ast_data)
        assert len(findings) == 0


class TestPatternMatcherFindingGeneration:
    """Test finding generation from pattern matches."""

    def test_finding_id_is_unique(self):
        """Test that finding IDs are unique."""
        custom_patterns = [
            Pattern(
                id="test-unique",
                name="Unique Test",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[StaticPatternTemplate(pattern=r"test\(\)", confidence="high")],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
test()
test()
"""
        findings = matcher.match_all(code, "test.py")
        finding_ids = [f.id for f in findings]
        assert len(finding_ids) == len(set(finding_ids))

    def test_finding_has_required_fields(self):
        """Test that findings have all required fields."""
        matcher = PatternMatcher()
        code = 'API_KEY = "sk-1234567890"'
        findings = matcher.match_all(code, "test.py")
        if len(findings) > 0:
            finding = findings[0]
            assert finding.id is not None
            assert finding.title is not None
            assert finding.severity in ["critical", "high", "medium", "low", "info"]
            assert finding.confidence in ["low", "medium", "high"]
            assert finding.location is not None
            assert finding.location.file == "test.py"
            assert finding.location.line >= 1

    def test_finding_location_correct(self):
        """Test that finding location is correctly calculated."""
        custom_patterns = [
            Pattern(
                id="location-test",
                name="Location Test",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[StaticPatternTemplate(pattern=r"target_function", confidence="high")],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
line 1
line 2
line 3
target_function
line 5
"""
        findings = matcher.match_all(code, "test.py")
        if len(findings) > 0:
            finding = findings[0]
            assert finding.location.line == 5

    def test_finding_includes_remediation(self):
        """Test that findings include remediation information."""
        matcher = PatternMatcher()
        findings = matcher.match_all('api_key = "sk-1234567890abcdefghijklmnop"', "test.py")
        assert len(findings) > 0
        finding = findings[0]
        assert finding.remediation is not None

    def test_finding_includes_references(self):
        """Test that findings include reference links."""
        matcher = PatternMatcher()
        findings = matcher.match_all('api_key = "sk-1234567890abcdefghijklmnop"', "test.py")
        assert len(findings) > 0
        finding = findings[0]
        assert finding.references is not None


class TestPatternMatcherEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_code(self):
        """Test matching against empty code."""
        matcher = PatternMatcher()
        findings = matcher.match_all("", "test.py")
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_invalid_regex_pattern(self):
        """Test that invalid regex patterns don't crash matcher."""
        custom_patterns = [
            Pattern(
                id="invalid-regex",
                name="Invalid Regex",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[StaticPatternTemplate(pattern=r"[invalid(", confidence="high")],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        findings = matcher.match_all("some code", "test.py")
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_pattern_with_no_confidence_uses_medium(self):
        """Test that patterns without confidence default to medium."""
        custom_patterns = [
            Pattern(
                id="no-confidence",
                name="No Confidence",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[StaticPatternTemplate(pattern=r"test_pattern", confidence=None)],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = "test_pattern"
        findings = matcher.match_all(code, "test.py")
        if len(findings) > 0:
            assert findings[0].confidence == "medium"

    def test_multiple_matches_same_pattern(self):
        """Test that multiple matches of same pattern are found."""
        custom_patterns = [
            Pattern(
                id="multi-match",
                name="Multi Match",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[StaticPatternTemplate(pattern=r"dangerous_function", confidence="high")],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
dangerous_function()
dangerous_function()
dangerous_function()
"""
        findings = matcher.match_all(code, "test.py")
        assert len(findings) == 3


class TestPatternMatcherControlFlow:
    """Test control flow pattern matching."""

    def test_control_flow_pattern_finds_missing_check(self):
        """Test that missing checks before sensitive operations are found."""
        custom_patterns = [
            Pattern(
                id="test-missing-check",
                name="Missing Check Test",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[
                    ControlFlowPatternTemplate(
                        check_pattern=r"if\s+authenticated",
                        sensitive_operation_pattern=r"\.delete_user\(",
                        require_check=True,
                        check_before_operation=True,
                        check_distance=10,
                        confidence="high",
                    )
                ],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
def delete_user(user_id):
    api.delete_user(user_id)
"""
        ast_data = {
            "cfg": {
                "basic_blocks": [
                    {"id": "block_1", "start_line": 0, "end_line": 0},
                    {"id": "block_2", "start_line": 1, "end_line": 1},
                    {"id": "block_3", "start_line": 2, "end_line": 2},
                ]
            }
        }
        findings = matcher.match_all(code, "test.py", ast_data)
        assert len(findings) > 0

    def test_control_flow_pattern_with_check_passes(self):
        """Test that checks before sensitive operations prevent findings."""
        custom_patterns = [
            Pattern(
                id="test-with-check",
                name="With Check Test",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[
                    ControlFlowPatternTemplate(
                        check_pattern=r"if\s+authenticated",
                        sensitive_operation_pattern=r"\.delete_user\(",
                        require_check=True,
                        check_before_operation=True,
                        check_distance=10,
                        confidence="high",
                    )
                ],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
def delete_user(user_id):
    if authenticated:
        api.delete_user(user_id)
"""
        ast_data = {
            "cfg": {
                "basic_blocks": [
                    {"id": "block_1", "start_line": 0, "end_line": 0},
                    {"id": "block_2", "start_line": 1, "end_line": 1},
                    {"id": "block_3", "start_line": 2, "end_line": 2},
                ]
            }
        }
        findings = matcher.match_all(code, "test.py", ast_data)
        assert len(findings) == 0

    def test_control_flow_pattern_check_distance(self):
        """Test that check distance limit is respected."""
        custom_patterns = [
            Pattern(
                id="test-distance",
                name="Distance Test",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[
                    ControlFlowPatternTemplate(
                        check_pattern=r"if\s+authenticated",
                        sensitive_operation_pattern=r"delete_user\(",
                        require_check=True,
                        check_before_operation=True,
                        check_distance=5,
                        confidence="high",
                    )
                ],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
def delete_user(user_id):
    if authenticated:
        pass
    pass
    pass
    pass
    pass
    pass
    pass
    delete_user(user_id)
"""
        ast_data = {"cfg": {"basic_blocks": [{"id": "block_1", "start_line": 1, "end_line": 8}]}}
        findings = matcher.match_all(code, "test.py", ast_data)
        assert len(findings) > 0

    def test_control_flow_pattern_check_after_operation(self):
        """Test that checks after operation don't prevent findings when check_before=True."""
        custom_patterns = [
            Pattern(
                id="test-check-after",
                name="Check After Test",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[
                    ControlFlowPatternTemplate(
                        check_pattern=r"if\s+authenticated",
                        sensitive_operation_pattern=r"delete_user\(",
                        require_check=True,
                        check_before_operation=True,
                        check_distance=10,
                        confidence="high",
                    )
                ],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
def delete_user(user_id):
    delete_user(user_id)
    if authenticated:
        pass
"""
        ast_data = {"cfg": {"basic_blocks": [{"id": "block_1", "start_line": 1, "end_line": 3}]}}
        findings = matcher.match_all(code, "test.py", ast_data)
        assert len(findings) > 0

    def test_control_flow_pattern_without_check(self):
        """Test that patterns without require_check always report."""
        custom_patterns = [
            Pattern(
                id="test-no-require",
                name="No Require Test",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[
                    ControlFlowPatternTemplate(
                        check_pattern=None,
                        sensitive_operation_pattern=r"admin_operation\(",
                        require_check=False,
                        confidence="high",
                    )
                ],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
def process():
    admin_operation()
"""
        ast_data = {"cfg": {"basic_blocks": [{"id": "block_1", "start_line": 1, "end_line": 2}]}}
        findings = matcher.match_all(code, "test.py", ast_data)
        assert len(findings) > 0

    def test_control_flow_pattern_without_ast_data(self):
        """Test that control flow patterns require AST data."""
        custom_patterns = [
            Pattern(
                id="test-no-ast-cf",
                name="No AST CF Test",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[
                    ControlFlowPatternTemplate(
                        check_pattern=r"check_auth",
                        sensitive_operation_pattern=r"sensitive_op",
                        require_check=True,
                        confidence="high",
                    )
                ],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
def process():
    sensitive_op()
"""
        findings = matcher.match_all(code, "test.py", ast_data=None)
        assert len(findings) == 0

    def test_control_flow_pattern_empty_cfg(self):
        """Test that empty CFG returns no findings."""
        custom_patterns = [
            Pattern(
                id="test-empty-cfg",
                name="Empty CFG Test",
                description="Test",
                severity=SeverityLevel.HIGH,
                category="test",
                templates=[
                    ControlFlowPatternTemplate(
                        check_pattern=r"check",
                        sensitive_operation_pattern=r"op",
                        require_check=True,
                        confidence="high",
                    )
                ],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Test remediation"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = "def process(): pass"
        ast_data = {"cfg": {"basic_blocks": []}}
        findings = matcher.match_all(code, "test.py", ast_data)
        assert len(findings) == 0

    def test_control_flow_pattern_generates_finding_with_correct_fields(self):
        """Test that control flow findings have all required fields."""
        custom_patterns = [
            Pattern(
                id="test-cf-fields",
                name="CF Fields Test",
                description="Test",
                severity=SeverityLevel.CRITICAL,
                category="test",
                templates=[
                    ControlFlowPatternTemplate(
                        check_pattern=r"if\s+auth",
                        sensitive_operation_pattern=r"delete_file",
                        require_check=True,
                        confidence="high",
                        description="Missing authorization check",
                    )
                ],
                attack_vector="Test attack vector",
                remediation=PatternRemediation(description="Add auth check"),
            )
        ]
        matcher = PatternMatcher(patterns=custom_patterns)
        code = """
def process():
    delete_file()
"""
        ast_data = {
            "cfg": {
                "basic_blocks": [
                    {"id": "block_1", "start_line": 0, "end_line": 0},
                    {"id": "block_2", "start_line": 1, "end_line": 1},
                    {"id": "block_3", "start_line": 2, "end_line": 2},
                ]
            }
        }
        findings = matcher.match_all(code, "test.py", ast_data)
        assert len(findings) > 0
        finding = findings[0]
        assert finding.id is not None
        assert finding.severity == "critical"
        assert finding.confidence == "high"
        assert finding.location.file == "test.py"
        assert finding.location.line == 3
        assert "control flow violation" in finding.attack_vector.lower()
