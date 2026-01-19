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

"""Unit tests for CLI commands."""

import sys
from click.testing import CliRunner


def test_cli_version():
    """Test version command."""
    from acr.cli import version

    runner = CliRunner()
    result = runner.invoke(version.cli)
    assert result.exit_code == 0
    assert "Adversarial Code Reviewer" in result.output
    assert "v0.1.0" in result.output


def test_cli_scan_help():
    """Test scan command help."""
    from acr.cli import scan

    runner = CliRunner()
    result = runner.invoke(scan.cli, ["--help"])
    assert result.exit_code == 0
    assert "Scan" in result.output
    assert "PATH" in result.output


def test_cli_report_help():
    """Test report command help."""
    from acr.cli import report

    runner = CliRunner()
    result = runner.invoke(report.cli, ["--help"])
    assert result.exit_code == 0
    assert "vulnerability report" in result.output


def test_cli_init_help():
    """Test init command help."""
    from acr.cli import init

    runner = CliRunner()
    result = runner.invoke(init.cli, ["--help"])
    assert result.exit_code == 0
    assert "Initialize" in result.output


def test_cli_attack_help():
    """Test attack command help."""
    from acr.cli import attack

    runner = CliRunner()
    result = runner.invoke(attack.cli, ["--help"])
    assert result.exit_code == 0
    assert "Generate attack vectors" in result.output
    assert "PATH" in result.output


def test_cli_attack_no_findings():
    """Test attack command with no findings."""
    from acr.cli import attack

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("safe.py", "w") as f:
            f.write('print("Hello, World!")')

        result = runner.invoke(attack.cli, ["safe.py"])
        assert result.exit_code == 0
        assert "No vulnerabilities found" in result.output


def test_cli_attack_invalid_file():
    """Test attack command with invalid file."""
    from acr.cli import attack

    runner = CliRunner()
    result = runner.invoke(attack.cli, ["nonexistent.py"])
    assert result.exit_code != 0


def test_cli_attack_export_json():
    """Test attack command with JSON export."""
    from acr.cli import attack

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("test.py", "w") as f:
            f.write('API_KEY = "sk-test1234567890abcdef"')

        result = runner.invoke(attack.cli, ["test.py", "--export", "attacks.json"])
        assert result.exit_code in [0, 4]
        assert "exported to:" in result.output.lower()


def test_cli_attack_export_txt():
    """Test attack command with TXT export."""
    from acr.cli import attack

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("test.py", "w") as f:
            f.write('API_KEY = "sk-test1234567890abcdef"')

        result = runner.invoke(
            attack.cli, ["test.py", "--export", "attacks.txt", "--format", "txt"]
        )
        assert result.exit_code in [0, 4]
        assert "exported to:" in result.output.lower()


def test_cli_attack_export_markdown():
    """Test attack command with Markdown export."""
    from acr.cli import attack

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("test.py", "w") as f:
            f.write('API_KEY = "sk-test1234567890abcdef"')

        result = runner.invoke(
            attack.cli, ["test.py", "--export", "attacks.md", "--format", "markdown"]
        )
        assert result.exit_code in [0, 4]
        assert "exported to:" in result.output.lower()


def test_cli_report_generate_markdown():
    """Test report command generating Markdown."""
    from acr.cli import report

    runner = CliRunner()
    with runner.isolated_filesystem():
        findings_data = [
            {
                "id": "ACR-2024-0001",
                "title": "SQL Injection in user authentication",
                "severity": "critical",
                "confidence": "high",
                "category": "injection",
                "cwe_id": "CWE-89",
                "owasp_id": "A1:2021-Injection",
                "location": {
                    "file": "app.py",
                    "line": 42,
                    "function": "authenticate_user",
                },
                "description": "SQL injection vulnerability",
                "attack_vector": "Bypass authentication via ' OR 1=1 --",
                "impact": {
                    "confidentiality": "high",
                    "integrity": "high",
                    "availability": "low",
                },
                "remediation": {
                    "description": "Use parameterized queries",
                    "code_before": 'query = "SELECT * FROM users WHERE username=\\"" + username + "\\"',
                    "code_after": 'query = "SELECT * FROM users WHERE username=%s"',
                },
                "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                "related_findings": [],
                "state": "open",
                "created_at": "",
                "updated_at": "",
            }
        ]

        with open("findings.json", "w") as f:
            import json

            json.dump(findings_data, f)

        result = runner.invoke(report.cli, ["findings.json", "report.md"])
        assert result.exit_code == 0
        assert "Report written to:" in result.output


def test_cli_report_generate_json():
    """Test report command generating JSON."""
    from acr.cli import report

    runner = CliRunner()
    with runner.isolated_filesystem():
        findings_data = [
            {
                "id": "ACR-2024-0001",
                "title": "SQL Injection",
                "severity": "critical",
                "confidence": "high",
                "category": "injection",
                "cwe_id": "CWE-89",
                "owasp_id": None,
                "location": {"file": "app.py", "line": 42},
                "description": "SQL injection vulnerability",
                "attack_vector": "Bypass authentication",
                "impact": {
                    "confidentiality": "high",
                    "integrity": "high",
                    "availability": "low",
                },
                "remediation": {
                    "description": "Use parameterized queries",
                    "code_before": None,
                    "code_after": None,
                },
                "references": [],
                "related_findings": [],
                "state": "open",
                "created_at": "",
                "updated_at": "",
            }
        ]

        with open("findings.json", "w") as f:
            import json

            json.dump(findings_data, f)

        result = runner.invoke(report.cli, ["findings.json", "report.json", "--format", "json"])
        assert result.exit_code == 0
        assert "Report written to:" in result.output


def test_cli_report_stdout():
    """Test report command outputting to stdout."""
    from acr.cli import report

    runner = CliRunner()
    with runner.isolated_filesystem():
        findings_data = [
            {
                "id": "ACR-2024-0001",
                "title": "SQL Injection",
                "severity": "critical",
                "confidence": "high",
                "category": "injection",
                "cwe_id": "CWE-89",
                "owasp_id": None,
                "location": {"file": "app.py", "line": 42},
                "description": "SQL injection vulnerability",
                "attack_vector": "Bypass authentication",
                "impact": {
                    "confidentiality": "high",
                    "integrity": "high",
                    "availability": "low",
                },
                "remediation": {
                    "description": "Use parameterized queries",
                    "code_before": None,
                    "code_after": None,
                },
                "references": [],
                "related_findings": [],
                "state": "open",
                "created_at": "",
                "updated_at": "",
            }
        ]

        with open("findings.json", "w") as f:
            import json

            json.dump(findings_data, f)

        result = runner.invoke(report.cli, ["findings.json"])
        assert result.exit_code == 0
        assert "Security Report" in result.output


def test_cli_report_invalid_json():
    """Test report command with invalid JSON."""
    from acr.cli import report

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("invalid.json", "w") as f:
            f.write("{ invalid json")

        result = runner.invoke(report.cli, ["invalid.json"])
        assert result.exit_code == 1


def test_cli_report_empty_findings():
    """Test report command with empty findings."""
    from acr.cli import report

    runner = CliRunner()
    with runner.isolated_filesystem():
        import json

        with open("empty.json", "w") as f:
            json.dump([], f)

        result = runner.invoke(report.cli, ["empty.json"])
        assert result.exit_code == 0
        assert "No findings found" in result.output


def test_cli_config_help():
    """Test config command help."""
    from acr.cli import config

    runner = CliRunner()
    result = runner.invoke(config.cli, ["--help"])
    assert result.exit_code == 0
    assert "Manage ACR configuration" in result.output


def test_cli_config_show_defaults():
    """Test config show with defaults (no config file)."""
    from acr.cli import config

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(config.cli, ["show"])
        assert result.exit_code == 0
        assert "Configuration: (defaults)" in result.output


def test_cli_config_show_with_file():
    """Test config show with existing config file."""
    from acr.cli import config

    runner = CliRunner()
    with runner.isolated_filesystem():
        config_data = """
project:
  name: test-project
  root: .
languages:
  python:
    enabled: true
    version: "3.10"
patterns:
  enabled:
    - sql-injection
  severity_threshold: medium
"""
        with open(".acrrc.yaml", "w") as f:
            f.write(config_data)

        result = runner.invoke(config.cli, ["show"])
        assert result.exit_code == 0
        assert "test-project" in result.output
        assert "sql-injection" in result.output


def test_cli_config_validate_no_file():
    """Test config validate with no config file."""
    from acr.cli import config

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(config.cli, ["validate"])
        assert result.exit_code == 0
        assert "No configuration file found" in result.output


def test_cli_config_validate_valid():
    """Test config validate with valid configuration."""
    from acr.cli import config

    runner = CliRunner()
    with runner.isolated_filesystem():
        config_data = """
project:
  name: test-project
  root: .
languages:
  python:
    enabled: true
    version: "3.10"
patterns:
  enabled:
    - sql-injection
  severity_threshold: medium
"""
        with open(".acrrc.yaml", "w") as f:
            f.write(config_data)

        result = runner.invoke(config.cli, ["validate"])
        assert result.exit_code == 0
        assert "Configuration is valid" in result.output
        assert "test-project" in result.output


def test_cli_config_validate_invalid_yaml():
    """Test config validate with invalid YAML."""
    from acr.cli import config

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open(".acrrc.yaml", "w") as f:
            f.write("{ invalid yaml")

        result = runner.invoke(config.cli, ["validate"])
        assert result.exit_code != 0
        assert "Invalid YAML" in result.output


def test_cli_config_validate_invalid_severity():
    """Test config validate with invalid severity threshold."""
    from acr.cli import config

    runner = CliRunner()
    with runner.isolated_filesystem():
        config_data = """
project:
  name: test-project
  root: .
languages:
  python:
    enabled: true
    version: "3.10"
patterns:
  enabled:
    - sql-injection
  severity_threshold: invalid
"""
        with open(".acrrc.yaml", "w") as f:
            f.write(config_data)

        result = runner.invoke(config.cli, ["validate"])
        assert result.exit_code != 0
        assert "Validation failed" in result.output


def test_cli_patterns_help():
    """Test patterns command help."""
    from acr.cli import patterns

    runner = CliRunner()
    result = runner.invoke(patterns.cli, ["--help"])
    assert result.exit_code == 0
    assert "Manage attack patterns" in result.output


def test_cli_doctor_help():
    """Test doctor command help."""
    from acr.cli import doctor

    runner = CliRunner()
    result = runner.invoke(doctor.cli, ["--help"])
    assert result.exit_code == 0
    assert "Run diagnostics" in result.output


def test_cli_doctor_basic():
    """Test doctor command runs basic checks."""
    from acr.cli import doctor

    runner = CliRunner()
    result = runner.invoke(doctor.cli)

    assert result.exit_code in [0, 1]
    assert "Python Version:" in result.output
    assert "Dependencies:" in result.output
    assert "Tree-sitter:" in result.output
    assert "Configuration:" in result.output
    assert "LLM API:" in result.output
    assert "Disk Space:" in result.output
    assert "Diagnostics Summary:" in result.output


def test_cli_doctor_python_version():
    """Test doctor checks Python version."""
    from acr.cli import doctor

    runner = CliRunner()
    result = runner.invoke(doctor.cli)

    assert "Python Version:" in result.output
    assert str(sys.version_info.major) in result.output


def test_cli_doctor_dependencies():
    """Test doctor checks dependencies."""
    from acr.cli import doctor

    runner = CliRunner()
    result = runner.invoke(doctor.cli)

    assert "Dependencies:" in result.output
    assert "click" in result.output.lower()
    assert "pydantic" in result.output.lower()


def test_cli_doctor_tree_sitter():
    """Test doctor checks tree-sitter."""
    from acr.cli import doctor

    runner = CliRunner()
    result = runner.invoke(doctor.cli)

    assert "Tree-sitter:" in result.output


def test_cli_doctor_configuration_no_file():
    """Test doctor with no config file."""
    from acr.cli import doctor

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(doctor.cli)

        assert result.exit_code in [0, 1]
        assert "Configuration:" in result.output


def test_cli_doctor_configuration_with_file():
    """Test doctor with valid config file."""
    from acr.cli import doctor

    runner = CliRunner()
    with runner.isolated_filesystem():
        config_data = """
project:
  name: test-project
  root: .
languages:
  python:
    enabled: true
    version: "3.10"
patterns:
  enabled:
    - sql-injection
  severity_threshold: medium
"""
        with open(".acrrc.yaml", "w") as f:
            f.write(config_data)

        result = runner.invoke(doctor.cli)

        assert result.exit_code in [0, 1]
        assert "Configuration:" in result.output
        assert (
            "Configuration valid" in result.output
            or "Configuration file not found" in result.output
        )


def test_cli_doctor_disk_space():
    """Test doctor checks disk space."""
    from acr.cli import doctor

    runner = CliRunner()
    result = runner.invoke(doctor.cli)

    assert "Disk Space:" in result.output
    assert "Total:" in result.output or "Failed to check disk space" in result.output


def test_cli_doctor_llm_api():
    """Test doctor checks LLM API configuration."""
    from acr.cli import doctor

    runner = CliRunner()
    result = runner.invoke(doctor.cli)

    assert "LLM API:" in result.output
