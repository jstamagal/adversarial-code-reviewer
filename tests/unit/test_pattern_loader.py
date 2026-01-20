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

"""Tests for pattern loader functionality."""

import tempfile
from pathlib import Path

from acr.patterns.loader import PatternLoader
from acr.patterns.schema import (
    DataFlowPatternTemplate,
    Pattern,
    SeverityLevel,
    StaticPatternTemplate,
)


class TestPatternLoader:
    """Test pattern loading and validation."""

    def test_load_all_patterns(self):
        """Test that all patterns can be loaded."""
        loader = PatternLoader()
        patterns = loader.load_patterns()

        assert isinstance(patterns, dict)
        assert len(patterns) >= 17
        assert "sql-injection" in patterns
        assert "xss" in patterns
        assert "command-injection" in patterns
        assert "path-traversal" in patterns
        assert "hardcoded-secrets" in patterns
        assert "broken-authentication" in patterns
        assert "insecure-deserialization" in patterns
        assert "csrf" in patterns
        assert "format-string" in patterns
        assert "eval-injection" in patterns
        assert "sensitive_data_exposure" in patterns
        assert "xxe" in patterns
        assert "broken_access_control" in patterns
        assert "security_misconfiguration" in patterns
        assert "known_vulnerabilities" in patterns
        assert "insufficient-logging-monitoring" in patterns
        assert "template-injection" in patterns

    def test_sensitive_data_exposure_pattern_loaded(self):
        """Test that sensitive_data_exposure pattern loads correctly."""
        loader = PatternLoader()
        patterns = loader.load_patterns()

        assert "sensitive_data_exposure" in patterns
        pattern = patterns["sensitive_data_exposure"]

        assert pattern.id == "sensitive_data_exposure"
        assert pattern.name == "Sensitive Data Exposure"
        assert pattern.category == "cryptography"
        assert pattern.severity == SeverityLevel.HIGH
        assert pattern.cwe_id == "CWE-200"
        assert pattern.owasp_id == "A02:2021-Cryptographic Failures"
        assert len(pattern.affected_languages) > 0
        assert "python" in pattern.affected_languages
        assert len(pattern.affected_frameworks) > 0
        assert "flask" in pattern.affected_frameworks

    def test_sensitive_data_exposure_has_templates(self):
        """Test that sensitive_data_exposure pattern has detection templates."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["sensitive_data_exposure"]

        assert len(pattern.templates) > 0

        static_templates = [t for t in pattern.templates if isinstance(t, StaticPatternTemplate)]
        data_flow_templates = [
            t for t in pattern.templates if isinstance(t, DataFlowPatternTemplate)
        ]

        assert len(static_templates) > 0
        assert len(data_flow_templates) > 0

    def test_sensitive_data_exposure_has_remediation(self):
        """Test that sensitive_data_exposure pattern has remediation information."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["sensitive_data_exposure"]

        assert pattern.remediation is not None
        assert pattern.remediation.description != ""
        assert pattern.remediation.code_before is not None
        assert pattern.remediation.code_after is not None

    def test_sensitive_data_exposure_has_references(self):
        """Test that sensitive_data_exposure pattern has references."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["sensitive_data_exposure"]

        assert len(pattern.references) > 0
        assert any("owasp.org" in ref for ref in pattern.references)
        assert any("cwe.mitre.org" in ref for ref in pattern.references)

    def test_sensitive_data_exposure_templates_have_required_fields(self):
        """Test that all templates have required fields."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["sensitive_data_exposure"]

        for template in pattern.templates:
            if isinstance(template, StaticPatternTemplate):
                assert hasattr(template, "type")
                assert hasattr(template, "pattern")
                assert hasattr(template, "description")
                assert hasattr(template, "confidence")
            elif isinstance(template, DataFlowPatternTemplate):
                assert hasattr(template, "type")
                assert hasattr(template, "source")
                assert hasattr(template, "sink")

    def test_load_pattern_from_file(self):
        """Test loading a single pattern from file."""
        loader = PatternLoader()
        pattern_path = (
            Path(__file__).parent.parent.parent
            / "acr"
            / "patterns"
            / "library"
            / "sensitive_data_exposure.yaml"
        )

        pattern = loader.load_pattern(pattern_path)

        assert pattern is not None
        assert pattern.id == "sensitive_data_exposure"
        assert pattern.name == "Sensitive Data Exposure"

    def test_pattern_attributes(self):
        """Test that pattern has all expected attributes."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["sensitive_data_exposure"]

        assert hasattr(pattern, "id")
        assert hasattr(pattern, "name")
        assert hasattr(pattern, "description")
        assert hasattr(pattern, "severity")
        assert hasattr(pattern, "category")
        assert hasattr(pattern, "cwe_id")
        assert hasattr(pattern, "owasp_id")
        assert hasattr(pattern, "affected_languages")
        assert hasattr(pattern, "affected_frameworks")
        assert hasattr(pattern, "templates")
        assert hasattr(pattern, "remediation")
        assert hasattr(pattern, "references")
        assert hasattr(pattern, "enabled")

    def test_pattern_enabled_by_default(self):
        """Test that patterns are enabled by default."""
        loader = PatternLoader()
        patterns = loader.load_patterns()

        for pattern in patterns.values():
            assert pattern.enabled is True

    def test_sensitive_data_exposure_severity(self):
        """Test that sensitive_data_exposure has correct severity."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["sensitive_data_exposure"]

        assert pattern.severity == SeverityLevel.HIGH

    def test_sensitive_data_exposure_owasp_reference(self):
        """Test that sensitive_data_exposure has correct OWASP reference."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["sensitive_data_exposure"]

        assert "A02:2021" in pattern.owasp_id
        assert "Cryptographic Failures" in pattern.owasp_id

    def test_sensitive_data_exposure_cwe_reference(self):
        """Test that sensitive_data_exposure has correct CWE reference."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["sensitive_data_exposure"]

        assert pattern.cwe_id == "CWE-200"

    def test_sensitive_data_exposure_description(self):
        """Test that sensitive_data_exposure has meaningful description."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["sensitive_data_exposure"]

        assert len(pattern.description) > 50
        assert "sensitive" in pattern.description.lower()
        assert "password" in pattern.description.lower()

    def test_sensitive_data_exposure_remediation_examples(self):
        """Test that remediation has code examples."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["sensitive_data_exposure"]

        assert pattern.remediation.code_before is not None
        assert pattern.remediation.code_after is not None
        assert "logging" in pattern.remediation.code_before.lower()
        assert "bcrypt" in pattern.remediation.code_after.lower()

    def test_xxe_pattern_loaded(self):
        """Test that xxe pattern loads correctly."""
        loader = PatternLoader()
        patterns = loader.load_patterns()

        assert "xxe" in patterns
        pattern = patterns["xxe"]

        assert pattern.id == "xxe"
        assert pattern.name == "XML External Entity (XXE) Injection"
        assert pattern.category == "injection"
        assert pattern.severity == SeverityLevel.CRITICAL
        assert pattern.cwe_id == "CWE-611"
        assert "A5:2017" in pattern.owasp_id
        assert len(pattern.affected_languages) > 0
        assert "python" in pattern.affected_languages
        assert "javascript" in pattern.affected_languages

    def test_xxe_has_templates(self):
        """Test that xxe pattern has detection templates."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["xxe"]

        assert len(pattern.templates) > 0

        static_templates = [t for t in pattern.templates if isinstance(t, StaticPatternTemplate)]
        data_flow_templates = [
            t for t in pattern.templates if isinstance(t, DataFlowPatternTemplate)
        ]

        assert len(static_templates) > 0
        assert len(data_flow_templates) > 0

    def test_xxe_has_remediation(self):
        """Test that xxe pattern has remediation information."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["xxe"]

        assert pattern.remediation is not None
        assert pattern.remediation.description != ""
        assert pattern.remediation.code_before is not None
        assert pattern.remediation.code_after is not None

    def test_xxe_has_references(self):
        """Test that xxe pattern has references."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["xxe"]

        assert len(pattern.references) > 0
        assert any("owasp.org" in ref for ref in pattern.references)
        assert any("cwe.mitre.org" in ref for ref in pattern.references)

    def test_xxe_severity(self):
        """Test that xxe has correct severity."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["xxe"]

        assert pattern.severity == SeverityLevel.CRITICAL

    def test_xxe_cwe_reference(self):
        """Test that xxe has correct CWE reference."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["xxe"]

        assert pattern.cwe_id == "CWE-611"

    def test_xxe_description(self):
        """Test that xxe has meaningful description."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["xxe"]

        assert len(pattern.description) > 50
        assert "xml" in pattern.description.lower()
        assert "entity" in pattern.description.lower()

    def test_xxe_remediation_examples(self):
        """Test that remediation has code examples."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["xxe"]

        assert pattern.remediation.code_before is not None
        assert pattern.remediation.code_after is not None
        assert (
            "etree" in pattern.remediation.code_before.lower()
            or "xml" in pattern.remediation.code_before.lower()
        )
        assert "defusedxml" in pattern.remediation.code_after.lower()

    def test_broken_access_control_pattern_loaded(self):
        """Test that broken_access_control pattern loads correctly."""
        loader = PatternLoader()
        patterns = loader.load_patterns()

        assert "broken_access_control" in patterns
        pattern = patterns["broken_access_control"]

        assert pattern.id == "broken_access_control"
        assert pattern.name == "Broken Access Control"
        assert pattern.category == "access_control"
        assert pattern.severity == SeverityLevel.CRITICAL
        assert pattern.cwe_id == "CWE-284"
        assert "A01:2021" in pattern.owasp_id
        assert len(pattern.affected_languages) > 0
        assert "python" in pattern.affected_languages
        assert "javascript" in pattern.affected_languages
        assert "typescript" in pattern.affected_languages

    def test_broken_access_control_has_templates(self):
        """Test that broken_access_control pattern has detection templates."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["broken_access_control"]

        assert len(pattern.templates) > 0

        static_templates = [t for t in pattern.templates if isinstance(t, StaticPatternTemplate)]
        data_flow_templates = [
            t for t in pattern.templates if isinstance(t, DataFlowPatternTemplate)
        ]

        assert len(static_templates) > 0 or len(data_flow_templates) > 0

    def test_broken_access_control_has_remediation(self):
        """Test that broken_access_control pattern has remediation information."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["broken_access_control"]

        assert pattern.remediation is not None
        assert pattern.remediation.description != ""
        assert pattern.remediation.code_before is not None
        assert pattern.remediation.code_after is not None

    def test_broken_access_control_has_references(self):
        """Test that broken_access_control pattern has references."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["broken_access_control"]

        assert len(pattern.references) > 0
        assert any("owasp.org" in ref for ref in pattern.references)
        assert any("cwe.mitre.org" in ref for ref in pattern.references)

    def test_broken_access_control_severity(self):
        """Test that broken_access_control has correct severity."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["broken_access_control"]

        assert pattern.severity == SeverityLevel.CRITICAL

    def test_broken_access_control_cwe_reference(self):
        """Test that broken_access_control has correct CWE reference."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["broken_access_control"]

        assert pattern.cwe_id == "CWE-284"

    def test_broken_access_control_description(self):
        """Test that broken_access_control has meaningful description."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["broken_access_control"]

        assert len(pattern.description) > 50
        assert "access" in pattern.description.lower()
        assert "authorization" in pattern.description.lower()

    def test_broken_access_control_remediation_examples(self):
        """Test that remediation has code examples."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["broken_access_control"]

        assert pattern.remediation.code_before is not None
        assert pattern.remediation.code_after is not None
        assert (
            "login_required" in pattern.remediation.code_before.lower()
            or "owner" not in pattern.remediation.code_before.lower()
        )
        assert "owner" in pattern.remediation.code_after.lower()

    def test_pattern_consistency(self):
        """Test that all patterns have consistent structure."""
        loader = PatternLoader()
        patterns = loader.load_patterns()

        for _pattern_id, pattern in patterns.items():
            assert isinstance(pattern, Pattern)
            assert isinstance(pattern.id, str)
            assert isinstance(pattern.name, str)
            assert isinstance(pattern.description, str)
            assert isinstance(pattern.severity, str)
            assert isinstance(pattern.category, str)
            assert isinstance(pattern.affected_languages, list)
            assert isinstance(pattern.affected_frameworks, list)
            assert isinstance(pattern.references, list)
            assert isinstance(pattern.enabled, bool)

    def test_security_misconfiguration_pattern_loaded(self):
        """Test that security_misconfiguration pattern loads correctly."""
        loader = PatternLoader()
        patterns = loader.load_patterns()

        assert "security_misconfiguration" in patterns
        pattern = patterns["security_misconfiguration"]

        assert pattern.id == "security_misconfiguration"
        assert pattern.name == "Security Misconfiguration"
        assert pattern.category == "misconfiguration"
        assert pattern.severity == SeverityLevel.HIGH
        assert pattern.cwe_id == "CWE-2"
        assert "A05:2021" in pattern.owasp_id
        assert len(pattern.affected_languages) > 0
        assert "python" in pattern.affected_languages
        assert "javascript" in pattern.affected_languages
        assert "typescript" in pattern.affected_languages

    def test_security_misconfiguration_has_templates(self):
        """Test that security_misconfiguration pattern has detection templates."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["security_misconfiguration"]

        assert len(pattern.templates) > 0

        static_templates = [t for t in pattern.templates if isinstance(t, StaticPatternTemplate)]
        data_flow_templates = [
            t for t in pattern.templates if isinstance(t, DataFlowPatternTemplate)
        ]

        assert len(static_templates) > 0 or len(data_flow_templates) > 0

    def test_security_misconfiguration_has_remediation(self):
        """Test that security_misconfiguration pattern has remediation information."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["security_misconfiguration"]

        assert pattern.remediation is not None
        assert pattern.remediation.description != ""
        assert pattern.remediation.code_before is not None
        assert pattern.remediation.code_after is not None

    def test_security_misconfiguration_has_references(self):
        """Test that security_misconfiguration pattern has references."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["security_misconfiguration"]

        assert len(pattern.references) > 0
        assert any("owasp.org" in ref for ref in pattern.references)
        assert any("cwe.mitre.org" in ref for ref in pattern.references)

    def test_security_misconfiguration_severity(self):
        """Test that security_misconfiguration has correct severity."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["security_misconfiguration"]

        assert pattern.severity == SeverityLevel.HIGH

    def test_security_misconfiguration_cwe_reference(self):
        """Test that security_misconfiguration has correct CWE reference."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["security_misconfiguration"]

        assert pattern.cwe_id == "CWE-2"

    def test_security_misconfiguration_description(self):
        """Test that security_misconfiguration has meaningful description."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["security_misconfiguration"]

        assert len(pattern.description) > 50
        assert "configuration" in pattern.description.lower()
        assert "default" in pattern.description.lower()

    def test_security_misconfiguration_remediation_examples(self):
        """Test that remediation has code examples."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["security_misconfiguration"]

        assert pattern.remediation.code_before is not None
        assert pattern.remediation.code_after is not None
        assert "debug" in pattern.remediation.code_before.lower()
        assert (
            "helmet" in pattern.remediation.code_after.lower()
            or "secret" in pattern.remediation.code_after.lower()
        )

    def test_known_vulnerabilities_pattern_loaded(self):
        """Test that known_vulnerabilities pattern loads correctly."""
        loader = PatternLoader()
        patterns = loader.load_patterns()

        assert "known_vulnerabilities" in patterns
        pattern = patterns["known_vulnerabilities"]

        assert pattern.id == "known_vulnerabilities"
        assert pattern.name == "Using Components with Known Vulnerabilities"
        assert pattern.category == "supply_chain"
        assert pattern.severity == SeverityLevel.HIGH
        assert pattern.cwe_id == "CWE-937"
        assert pattern.owasp_id == "A06:2021-Using Components with Known Vulnerabilities"
        assert len(pattern.affected_languages) > 0
        assert "python" in pattern.affected_languages

    def test_known_vulnerabilities_has_templates(self):
        """Test that known_vulnerabilities pattern has detection templates."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["known_vulnerabilities"]

        assert len(pattern.templates) > 0

        static_templates = [t for t in pattern.templates if isinstance(t, StaticPatternTemplate)]
        data_flow_templates = [
            t for t in pattern.templates if isinstance(t, DataFlowPatternTemplate)
        ]

        assert len(static_templates) > 0 or len(data_flow_templates) > 0

    def test_insufficient_logging_monitoring_has_remediation(self):
        """Test that insufficient_logging_monitoring pattern has remediation."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["insufficient-logging-monitoring"]

        assert pattern.remediation is not None
        assert len(pattern.remediation.description) > 0

    def test_insufficient_logging_monitoring_has_references(self):
        """Test that insufficient_logging_monitoring has references."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["insufficient-logging-monitoring"]

        assert len(pattern.references) > 0
        references = pattern.references
        assert any("owasp.org" in ref for ref in references)
        assert any("cwe.mitre.org" in ref for ref in references)

    def test_insufficient_logging_monitoring_severity(self):
        """Test that insufficient_logging_monitoring has correct severity."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["insufficient-logging-monitoring"]

        assert pattern.severity == SeverityLevel.MEDIUM

    def test_insufficient_logging_monitoring_cwe_reference(self):
        """Test that insufficient_logging_monitoring has correct CWE reference."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["insufficient-logging-monitoring"]

        assert pattern.cwe_id == "CWE-778"

    def test_insufficient_logging_monitoring_description(self):
        """Test that insufficient_logging_monitoring has meaningful description."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["insufficient-logging-monitoring"]

        assert len(pattern.description) > 50
        assert "logging" in pattern.description.lower()
        assert "monitoring" in pattern.description.lower()

    def test_insufficient_logging_monitoring_remediation_examples(self):
        """Test that remediation has code examples."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["insufficient-logging-monitoring"]

        assert pattern.remediation.code_before is not None
        assert pattern.remediation.code_after is not None
        assert (
            "login" in pattern.remediation.code_before.lower()
            or "auth" in pattern.remediation.code_before.lower()
        )

    def test_format_string_pattern_loaded(self):
        """Test that format_string pattern loads correctly."""
        loader = PatternLoader()
        patterns = loader.load_patterns()

        assert "format-string" in patterns
        pattern = patterns["format-string"]

        assert pattern.id == "format-string"
        assert pattern.name == "Format String Vulnerability"
        assert pattern.category == "injection"
        assert pattern.severity == SeverityLevel.MEDIUM
        assert pattern.cwe_id == "CWE-134"
        assert "A03:2021" in pattern.owasp_id
        assert len(pattern.affected_languages) > 0
        assert "python" in pattern.affected_languages

    def test_format_string_has_templates(self):
        """Test that format_string pattern has detection templates."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["format-string"]

        assert len(pattern.templates) > 0

        static_templates = [t for t in pattern.templates if isinstance(t, StaticPatternTemplate)]
        data_flow_templates = [
            t for t in pattern.templates if isinstance(t, DataFlowPatternTemplate)
        ]

        assert len(static_templates) > 0
        assert len(data_flow_templates) > 0

    def test_format_string_has_remediation(self):
        """Test that format_string pattern has remediation."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["format-string"]

        assert pattern.remediation is not None
        assert len(pattern.remediation.description) > 0

    def test_format_string_has_references(self):
        """Test that format_string has references."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["format-string"]

        assert len(pattern.references) > 0
        references = pattern.references
        assert any("owasp.org" in ref for ref in references)
        assert any("cwe.mitre.org" in ref for ref in references)

    def test_format_string_severity(self):
        """Test that format_string has correct severity."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["format-string"]

        assert pattern.severity == SeverityLevel.MEDIUM

    def test_format_string_cwe_reference(self):
        """Test that format_string has correct CWE reference."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["format-string"]

        assert pattern.cwe_id == "CWE-134"

    def test_format_string_description(self):
        """Test that format_string has meaningful description."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["format-string"]

        assert len(pattern.description) > 50
        assert "format" in pattern.description.lower()

    def test_format_string_remediation_examples(self):
        """Test that remediation has code examples."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["format-string"]

        assert pattern.remediation.code_before is not None
        assert pattern.remediation.code_after is not None
        assert "format" in pattern.remediation.code_after.lower()

    def test_template_injection_pattern_loaded(self):
        """Test that template_injection pattern loads correctly."""
        loader = PatternLoader()
        patterns = loader.load_patterns()

        assert "template-injection" in patterns
        pattern = patterns["template-injection"]

        assert pattern.id == "template-injection"
        assert pattern.name == "Server-Side Template Injection (SSTI)"
        assert pattern.category == "injection"
        assert pattern.severity == SeverityLevel.CRITICAL
        assert pattern.cwe_id == "CWE-94"
        assert "A03:2021" in pattern.owasp_id
        assert len(pattern.affected_languages) > 0
        assert "python" in pattern.affected_languages
        assert "javascript" in pattern.affected_languages

    def test_template_injection_has_templates(self):
        """Test that template_injection pattern has detection templates."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["template-injection"]

        assert len(pattern.templates) > 0

        static_templates = [t for t in pattern.templates if isinstance(t, StaticPatternTemplate)]
        data_flow_templates = [
            t for t in pattern.templates if isinstance(t, DataFlowPatternTemplate)
        ]

        assert len(static_templates) > 0
        assert len(data_flow_templates) > 0

    def test_template_injection_has_remediation(self):
        """Test that template_injection pattern has remediation."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["template-injection"]

        assert pattern.remediation is not None
        assert len(pattern.remediation.description) > 0

    def test_template_injection_has_references(self):
        """Test that template_injection has references."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["template-injection"]

        assert len(pattern.references) > 0
        references = pattern.references
        assert any("owasp.org" in ref for ref in references)
        assert any("cwe.mitre.org" in ref for ref in references)

    def test_template_injection_severity(self):
        """Test that template_injection has correct severity."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["template-injection"]

        assert pattern.severity == SeverityLevel.CRITICAL

    def test_template_injection_cwe_reference(self):
        """Test that template_injection has correct CWE reference."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["template-injection"]

        assert pattern.cwe_id == "CWE-94"

    def test_template_injection_description(self):
        """Test that template_injection has meaningful description."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["template-injection"]

        assert len(pattern.description) > 50
        assert "template" in pattern.description.lower()

    def test_template_injection_remediation_examples(self):
        """Test that remediation has code examples."""
        loader = PatternLoader()
        patterns = loader.load_patterns()
        pattern = patterns["template-injection"]

        assert pattern.remediation.code_before is not None
        assert pattern.remediation.code_after is not None
        assert (
            "render_template_string" in pattern.remediation.code_before.lower()
            or "Template" in pattern.remediation.code_before.lower()
        )
        assert "render_template" in pattern.remediation.code_after.lower()

    def test_load_custom_patterns(self):
        """Test that custom patterns can be loaded from a custom directory."""
        loader = PatternLoader()

        with tempfile.TemporaryDirectory() as tmpdir:
            custom_dir = Path(tmpdir)

            custom_pattern_content = """id: custom-pattern
name: Custom Pattern
description: A custom security pattern
category: test
severity: medium
cwe: CWE-000
owasp: A00:2021-Test
affected_languages:
  - python
attack_vector: Custom attack
remediation:
  description: Fix it
  code_before: bad_code()
  code_after: good_code()
detection:
  static:
    - type: regex
      pattern: custom_function\\(\\)
      description: Custom function call
      confidence: high
"""
            pattern_file = custom_dir / "custom-pattern.yaml"
            pattern_file.write_text(custom_pattern_content)

            patterns = loader.load_patterns(custom_patterns_dir=custom_dir)

            assert "custom-pattern" in patterns
            assert patterns["custom-pattern"].name == "Custom Pattern"
            assert patterns["custom-pattern"].category == "test"

    def test_custom_patterns_extend_builtin_patterns(self):
        """Test that custom patterns extend built-in patterns."""
        loader = PatternLoader()

        with tempfile.TemporaryDirectory() as tmpdir:
            custom_dir = Path(tmpdir)

            custom_pattern_content = """id: my-custom-pattern
name: My Custom Pattern
description: A custom security pattern
category: test
severity: high
cwe: CWE-999
owasp: A99:2021-Custom
affected_languages:
  - python
attack_vector: Custom attack
remediation:
  description: Fix it
  code_before: bad_code()
  code_after: good_code()
detection:
  static:
    - type: regex
      pattern: my_custom_function\\(\\)
      description: My custom function call
      confidence: high
"""
            pattern_file = custom_dir / "my-custom-pattern.yaml"
            pattern_file.write_text(custom_pattern_content)

            patterns = loader.load_patterns(custom_patterns_dir=custom_dir)

            assert "sql-injection" in patterns
            assert "my-custom-pattern" in patterns
            assert patterns["sql-injection"].name == "SQL Injection"
            assert patterns["my-custom-pattern"].name == "My Custom Pattern"

    def test_custom_patterns_override_builtin_patterns(self):
        """Test that custom patterns can override built-in patterns."""
        loader = PatternLoader()

        with tempfile.TemporaryDirectory() as tmpdir:
            custom_dir = Path(tmpdir)

            custom_pattern_content = """id: sql-injection
name: Custom SQL Injection
description: Custom SQL injection pattern
category: test
severity: critical
cwe: CWE-89
owasp: A01:2017-Injection
affected_languages:
  - python
attack_vector: Custom SQL injection attack
remediation:
  description: Custom fix
  code_before: custom_bad_code()
  code_after: custom_good_code()
detection:
  static:
    - type: regex
      pattern: custom_sql\\(\\)
      description: Custom SQL function
      confidence: high
"""
            pattern_file = custom_dir / "sql-injection.yaml"
            pattern_file.write_text(custom_pattern_content)

            patterns = loader.load_patterns(custom_patterns_dir=custom_dir)

            assert "sql-injection" in patterns
            assert patterns["sql-injection"].name == "Custom SQL Injection"
            assert patterns["sql-injection"].category == "test"

    def test_load_patterns_with_invalid_custom_directory(self):
        """Test that invalid custom directory is handled gracefully."""
        loader = PatternLoader()

        patterns = loader.load_patterns(custom_patterns_dir=Path("/nonexistent/path"))

        assert isinstance(patterns, dict)
        assert len(patterns) >= 17
        assert "sql-injection" in patterns

    def test_load_patterns_from_multiple_custom_directories(self):
        """Test loading patterns from two custom directories sequentially."""
        loader = PatternLoader()

        with tempfile.TemporaryDirectory() as tmpdir1, tempfile.TemporaryDirectory() as tmpdir2:
            custom_dir1 = Path(tmpdir1)
            custom_dir2 = Path(tmpdir2)

            custom_pattern1 = """id: custom-pattern-1
name: Custom Pattern 1
description: First custom pattern
category: test
severity: medium
cwe: CWE-001
owasp: A00:2021-Test
affected_languages:
  - python
attack_vector: Attack 1
remediation:
  description: Fix 1
  code_before: bad1()
  code_after: good1()
detection:
  static:
    - type: regex
      pattern: custom1\\(\\)
      description: Custom 1
      confidence: high
"""
            custom_pattern2 = """id: custom-pattern-2
name: Custom Pattern 2
description: Second custom pattern
category: test
severity: high
cwe: CWE-002
owasp: A00:2021-Test
affected_languages:
  - python
attack_vector: Attack 2
remediation:
  description: Fix 2
  code_before: bad2()
  code_after: good2()
detection:
  static:
    - type: regex
      pattern: custom2\\(\\)
      description: Custom 2
      confidence: high
"""
            (custom_dir1 / "custom-pattern-1.yaml").write_text(custom_pattern1)
            (custom_dir2 / "custom-pattern-2.yaml").write_text(custom_pattern2)

            patterns1 = loader.load_patterns(custom_patterns_dir=custom_dir1)
            assert "custom-pattern-1" in patterns1
            assert "custom-pattern-2" not in patterns1

            patterns2 = loader.load_patterns(custom_patterns_dir=custom_dir2)
            assert "custom-pattern-1" not in patterns2
            assert "custom-pattern-2" in patterns2

    def test_custom_pattern_with_data_flow_template(self):
        """Test that custom patterns can have data flow templates."""
        loader = PatternLoader()

        with tempfile.TemporaryDirectory() as tmpdir:
            custom_dir = Path(tmpdir)

            custom_pattern_content = """id: custom-dataflow-pattern
name: Custom Data Flow Pattern
description: Custom pattern with data flow
category: test
severity: high
cwe: CWE-000
owasp: A00:2021-Test
affected_languages:
  - python
attack_vector: Custom data flow attack
remediation:
  description: Fix data flow
  code_before: bad()
  code_after: good()
detection:
  data_flow:
    - source: request
      sink: execute
      sanitizers: []
"""
            pattern_file = custom_dir / "custom-dataflow-pattern.yaml"
            pattern_file.write_text(custom_pattern_content)

            patterns = loader.load_patterns(custom_patterns_dir=custom_dir)

            assert "custom-dataflow-pattern" in patterns
            pattern = patterns["custom-dataflow-pattern"]
            data_flow_templates = [
                t for t in pattern.templates if isinstance(t, DataFlowPatternTemplate)
            ]
            assert len(data_flow_templates) > 0
            assert data_flow_templates[0].source == "request"
            assert data_flow_templates[0].sink == "execute"

    def test_custom_pattern_disabled(self):
        """Test that custom patterns can be disabled."""
        loader = PatternLoader()

        with tempfile.TemporaryDirectory() as tmpdir:
            custom_dir = Path(tmpdir)

            custom_pattern_content = """id: custom-disabled-pattern
name: Custom Disabled Pattern
description: A custom pattern that is disabled
category: test
severity: medium
cwe: CWE-000
owasp: A00:2021-Test
affected_languages:
  - python
attack_vector: Custom attack
remediation:
  description: Fix it
  code_before: bad_code()
  code_after: good_code()
enabled: false
detection:
  static:
    - type: regex
      pattern: custom_disabled\\(\\)
      description: Disabled pattern
      confidence: high
"""
            pattern_file = custom_dir / "custom-disabled-pattern.yaml"
            pattern_file.write_text(custom_pattern_content)

            patterns = loader.load_patterns(custom_patterns_dir=custom_dir)

            assert "custom-disabled-pattern" in patterns
            assert patterns["custom-disabled-pattern"].enabled is False

    def test_pattern_caching_enabled(self):
        """Test that patterns are cached when caching is enabled."""
        PatternLoader.clear_cache()

        loader = PatternLoader(cache_enabled=True)

        patterns1 = loader.load_patterns()
        patterns2 = loader.load_patterns()

        assert patterns1 == patterns2
        assert len(PatternLoader._cache) == 1

    def test_pattern_caching_disabled(self):
        """Test that patterns are not cached when caching is disabled."""
        PatternLoader.clear_cache()

        loader = PatternLoader(cache_enabled=False)

        patterns1 = loader.load_patterns()
        patterns2 = loader.load_patterns()

        assert patterns1 == patterns2
        assert len(PatternLoader._cache) == 0

    def test_cache_different_directories(self):
        """Test that different directories have separate cache entries."""
        PatternLoader.clear_cache()

        loader = PatternLoader(cache_enabled=True)

        patterns1 = loader.load_patterns()

        with tempfile.TemporaryDirectory() as tmpdir:
            custom_dir = Path(tmpdir)

            custom_pattern_content = """id: custom-cache-test
name: Custom Cache Test Pattern
description: A pattern for testing caching
category: test
severity: medium
cwe: CWE-000
owasp: A00:2021-Test
affected_languages:
  - python
attack_vector: Custom attack
remediation:
  description: Fix it
  code_before: bad_code()
  code_after: good_code()
detection:
  static:
    - type: regex
      pattern: custom_cache_test\\(\\)
      description: Cache test pattern
      confidence: high
"""
            pattern_file = custom_dir / "custom-cache-test.yaml"
            pattern_file.write_text(custom_pattern_content)

            patterns2 = loader.load_patterns(custom_patterns_dir=custom_dir)

        assert "custom-cache-test" not in patterns1
        assert "custom-cache-test" in patterns2
        assert len(PatternLoader._cache) == 2

    def test_cache_clear(self):
        """Test that cache can be cleared."""
        PatternLoader.clear_cache()

        loader = PatternLoader(cache_enabled=True)

        patterns1 = loader.load_patterns()

        assert len(PatternLoader._cache) == 1

        PatternLoader.clear_cache()

        assert len(PatternLoader._cache) == 0

        patterns2 = loader.load_patterns()

        assert len(PatternLoader._cache) == 1
        assert patterns1 == patterns2

    def test_cache_key_includes_custom_directory(self):
        """Test that cache key includes custom directory."""
        PatternLoader.clear_cache()

        loader = PatternLoader(cache_enabled=True)

        with tempfile.TemporaryDirectory() as tmpdir:
            custom_dir1 = Path(tmpdir) / "custom1"
            custom_dir2 = Path(tmpdir) / "custom2"
            custom_dir1.mkdir()
            custom_dir2.mkdir()

            custom_pattern_content = """id: custom-key-test
name: Custom Key Test Pattern
description: A pattern for testing cache keys
category: test
severity: medium
cwe: CWE-000
owasp: A00:2021-Test
affected_languages:
  - python
attack_vector: Custom attack
remediation:
  description: Fix it
  code_before: bad_code()
  code_after: good_code()
detection:
  static:
    - type: regex
      pattern: custom_key_test\\(\\)
      description: Key test pattern
      confidence: high
"""
            (custom_dir1 / "custom-key-test.yaml").write_text(custom_pattern_content)
            (custom_dir2 / "custom-key-test.yaml").write_text(custom_pattern_content)

            patterns1 = loader.load_patterns(custom_patterns_dir=custom_dir1)
            patterns2 = loader.load_patterns(custom_patterns_dir=custom_dir2)

            assert len(PatternLoader._cache) == 2
            assert "custom-key-test" in patterns1
            assert "custom-key-test" in patterns2

    def test_default_cache_enabled(self):
        """Test that caching is enabled by default."""
        loader = PatternLoader()

        assert loader._cache_enabled is True
