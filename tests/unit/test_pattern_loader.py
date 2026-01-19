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

import pytest
from pathlib import Path

from acr.patterns.loader import PatternLoader
from acr.patterns.schema import Pattern, SeverityLevel


class TestPatternLoader:
    """Test pattern loading and validation."""

    def test_load_all_patterns(self):
        """Test that all patterns can be loaded."""
        loader = PatternLoader()
        patterns = loader.load_patterns()

        assert isinstance(patterns, dict)
        assert len(patterns) >= 12
        assert "sql-injection" in patterns
        assert "xss" in patterns
        assert "command-injection" in patterns
        assert "path-traversal" in patterns
        assert "hardcoded-secrets" in patterns
        assert "broken-authentication" in patterns
        assert "insecure-deserialization" in patterns
        assert "csrf" in patterns
        assert "eval-injection" in patterns
        assert "sensitive_data_exposure" in patterns
        assert "xxe" in patterns
        assert "broken_access_control" in patterns

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

        static_templates = [t for t in pattern.templates if t.get("type") == "static"]
        data_flow_templates = [t for t in pattern.templates if t.get("type") == "data_flow"]

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
            assert "type" in template
            if template["type"] == "static":
                assert "pattern" in template
                assert "description" in template
                assert "confidence" in template
            elif template["type"] == "data_flow":
                assert "source" in template
                assert "sink" in template

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

        static_templates = [t for t in pattern.templates if t.get("type") == "static"]
        data_flow_templates = [t for t in pattern.templates if t.get("type") == "data_flow"]

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

        static_templates = [t for t in pattern.templates if t.get("type") == "static"]
        data_flow_templates = [t for t in pattern.templates if t.get("type") == "data_flow"]

        assert len(static_templates) > 0
        assert len(data_flow_templates) > 0

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

        for pattern_id, pattern in patterns.items():
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
