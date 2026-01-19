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
from pathlib import Path

from click.testing import CliRunner


def test_cli_version():
    """Test version command."""
    from acr.cli import version

    runner = CliRunner()
    result = runner.invoke(version.cli)
    assert result.exit_code == 0
    assert "Adversarial Code Reviewer" in result.output
    assert "v0.1.0" in result.output


def test_cli_version_shows_python():
    """Test version command shows Python version."""
    from acr.cli import version

    runner = CliRunner()
    result = runner.invoke(version.cli)
    assert result.exit_code == 0
    assert "Python" in result.output
    assert str(sys.version_info.major) in result.output


def test_cli_version_shows_platform():
    """Test version command shows platform."""
    from acr.cli import version

    runner = CliRunner()
    result = runner.invoke(version.cli)
    assert result.exit_code == 0
    assert "Platform:" in result.output


def test_cli_version_shows_dependencies():
    """Test version command shows dependency versions."""
    from acr.cli import version

    runner = CliRunner()
    result = runner.invoke(version.cli)
    assert result.exit_code == 0
    assert "Dependencies:" in result.output
    assert "click:" in result.output
    assert "pydantic:" in result.output
    assert "pyyaml:" in result.output


def test_cli_version_check_updates_newer_available():
    """Test version check with newer version available."""
    from acr.cli import version
    from unittest.mock import patch

    runner = CliRunner()
    with patch("acr.cli.version.check_for_updates", return_value="0.2.0"):
        result = runner.invoke(version.cli, ["--check-updates"])
        assert result.exit_code == 0
        assert "Checking for updates" in result.output
        assert "A newer version is available" in result.output
        assert "v0.2.0" in result.output


def test_cli_version_check_updates_latest():
    """Test version check when already on latest version."""
    from acr.cli import version
    from unittest.mock import patch

    runner = CliRunner()
    with patch("acr.cli.version.check_for_updates", return_value="0.1.0"):
        result = runner.invoke(version.cli, ["--check-updates"])
        assert result.exit_code == 0
        assert "Checking for updates" in result.output
        assert "You are running the latest version" in result.output


def test_cli_version_check_updates_offline():
    """Test version check when offline (error handling)."""
    from acr.cli import version
    from unittest.mock import patch

    runner = CliRunner()
    with patch("acr.cli.version.check_for_updates", return_value=None):
        result = runner.invoke(version.cli, ["--check-updates"])
        assert result.exit_code == 0
        assert "Checking for updates" in result.output
        assert "Unable to check for updates" in result.output


def test_cli_version_help():
    """Test version command help."""
    from acr.cli import version

    runner = CliRunner()
    result = runner.invoke(version.cli, ["--help"])
    assert result.exit_code == 0
    assert "Show version information" in result.output
    assert "--check-updates" in result.output


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


def test_cli_init_basic():
    """Test init command creates configuration file."""
    import yaml

    from acr.cli import init

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(init.cli)
        assert result.exit_code == 0
        assert ".acrrc.yaml" in result.output
        assert "Configuration file created successfully!" in result.output
        assert "Next steps:" in result.output

        assert Path(".acrrc.yaml").exists()

        with open(".acrrc.yaml") as f:
            config = yaml.safe_load(f)
            assert config is not None
            assert "project" in config
            assert "patterns" in config
            assert "languages" in config


def test_cli_init_with_project_name():
    """Test init command with custom project name."""
    import yaml

    from acr.cli import init

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(init.cli, ["--project-name", "my-awesome-project"])
        assert result.exit_code == 0

        with open(".acrrc.yaml") as f:
            config = yaml.safe_load(f)
            assert config["project"]["name"] == "my-awesome-project"


def test_cli_init_overwrite_existing():
    """Test init command refuses to overwrite existing config without force."""
    from acr.cli import init

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open(".acrrc.yaml", "w") as f:
            f.write("existing: config")

        result = runner.invoke(init.cli)
        assert result.exit_code != 0
        assert "already exists" in result.output
        assert "--force" in result.output


def test_cli_init_force_overwrite():
    """Test init command overwrites with force flag."""
    import yaml

    from acr.cli import init

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open(".acrrc.yaml", "w") as f:
            f.write("existing: config")

        result = runner.invoke(init.cli, ["--force"])
        assert result.exit_code == 0
        assert "Created .acrrc.yaml" in result.output

        with open(".acrrc.yaml") as f:
            config = yaml.safe_load(f)
            assert config is not None
            assert "project" in config


def test_cli_init_config_structure():
    """Test init command creates valid configuration structure."""
    import yaml

    from acr.cli import init

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(init.cli)
        assert result.exit_code == 0

        with open(".acrrc.yaml") as f:
            config = yaml.safe_load(f)

            assert "project" in config
            assert "name" in config["project"]
            assert "root" in config["project"]

            assert "languages" in config
            assert "python" in config["languages"]

            assert "frameworks" in config
            assert "flask" in config["frameworks"]
            assert "django" in config["frameworks"]
            assert "fastapi" in config["frameworks"]

            assert "patterns" in config
            assert "enabled" in config["patterns"]
            assert "severity_threshold" in config["patterns"]
            assert "custom_patterns" in config["patterns"]

            assert "llm" in config
            assert "provider" in config["llm"]
            assert "model" in config["llm"]

            assert "analysis" in config
            assert "max_depth" in config["analysis"]
            assert "timeout" in config["analysis"]

            assert "reporting" in config
            assert "formats" in config["reporting"]
            assert "output_dir" in config["reporting"]

            assert "exclude" in config
            assert "paths" in config["exclude"]
            assert "files" in config["exclude"]


def test_cli_init_default_patterns():
    """Test init command includes default patterns."""
    import yaml

    from acr.cli import init

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(init.cli)
        assert result.exit_code == 0

        with open(".acrrc.yaml") as f:
            config = yaml.safe_load(f)
            enabled_patterns = config["patterns"]["enabled"]
            assert "sql-injection" in enabled_patterns
            assert "xss" in enabled_patterns
            assert "csrf" in enabled_patterns
            assert "command-injection" in enabled_patterns


def test_cli_init_default_severity():
    """Test init command sets default severity threshold."""
    import yaml

    from acr.cli import init

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(init.cli)
        assert result.exit_code == 0

        with open(".acrrc.yaml") as f:
            config = yaml.safe_load(f)
            assert config["patterns"]["severity_threshold"] == "medium"


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


def test_cli_config_list_help():
    """Test config list command help."""
    from acr.cli import config

    runner = CliRunner()
    result = runner.invoke(config.cli, ["list", "--help"])
    assert result.exit_code == 0
    assert "List all available configuration options" in result.output


def test_cli_config_list_basic():
    """Test config list shows main options."""
    from acr.cli import config

    runner = CliRunner()
    result = runner.invoke(config.cli, ["list"])
    assert result.exit_code == 0
    assert "Available Configuration Options" in result.output
    assert "Project" in result.output
    assert "Patterns" in result.output
    assert "Llm" in result.output
    assert "Analysis" in result.output
    assert "Reporting" in result.output
    assert "Exclude" in result.output


def test_cli_config_list_shows_specific_options():
    """Test config list shows specific option details."""
    from acr.cli import config

    runner = CliRunner()
    result = runner.invoke(config.cli, ["list"])
    assert result.exit_code == 0
    assert "project.name" in result.output
    assert "patterns.severity_threshold" in result.output
    assert "llm.provider" in result.output
    assert "analysis.max_depth" in result.output


def test_cli_config_list_with_all():
    """Test config list --all shows nested options."""
    from acr.cli import config

    runner = CliRunner()
    result = runner.invoke(config.cli, ["list", "--all"])
    assert result.exit_code == 0
    assert "Languages" in result.output
    assert "languages.<lang>.enabled" in result.output
    assert "Frameworks" in result.output
    assert "frameworks.<framework>.enabled" in result.output


def test_cli_patterns_list_basic():
    """Test patterns list shows all patterns."""
    from acr.cli import patterns

    runner = CliRunner()
    result = runner.invoke(patterns.cli, ["list"])

    assert result.exit_code == 0
    assert "Available Attack Patterns" in result.output
    assert "sql-injection" in result.output
    assert "xss" in result.output
    assert "command-injection" in result.output
    assert "Total:" in result.output


def test_cli_patterns_list_with_category():
    """Test patterns list filters by category."""
    from acr.cli import patterns

    runner = CliRunner()
    result = runner.invoke(patterns.cli, ["list", "--category", "injection"])

    assert result.exit_code == 0
    assert "sql-injection" in result.output
    assert "xss" in result.output
    assert "command-injection" in result.output
    assert "broken-authentication" not in result.output


def test_cli_patterns_list_with_severity():
    """Test patterns list filters by severity."""
    from acr.cli import patterns

    runner = CliRunner()
    result = runner.invoke(patterns.cli, ["list", "--severity", "critical"])

    assert result.exit_code == 0
    assert "sql-injection" in result.output
    assert "command-injection" in result.output
    assert "broken-authentication" in result.output


def test_cli_patterns_list_custom_only():
    """Test patterns list with --custom-only flag."""
    from acr.cli import patterns

    runner = CliRunner()
    result = runner.invoke(patterns.cli, ["list", "--custom-only"])

    assert result.exit_code == 0
    assert "No custom patterns found" in result.output or "Custom" in result.output


def test_cli_patterns_list_empty_result():
    """Test patterns list with no matching patterns."""
    from acr.cli import patterns

    runner = CliRunner()
    result = runner.invoke(patterns.cli, ["list", "--category", "nonexistent"])

    assert result.exit_code == 0
    assert "No patterns found matching criteria" in result.output


def test_cli_patterns_show_basic():
    """Test patterns show command."""
    from acr.cli import patterns

    runner = CliRunner()
    result = runner.invoke(patterns.cli, ["show", "sql-injection"])

    assert result.exit_code == 0
    assert "SQL Injection" in result.output
    assert "ID: sql-injection" in result.output
    assert "Category: injection" in result.output
    assert "Severity:" in result.output
    assert "CWE: CWE-89" in result.output
    assert "Description:" in result.output


def test_cli_patterns_show_verbose():
    """Test patterns show with verbose flag."""
    from acr.cli import patterns

    runner = CliRunner()
    result = runner.invoke(patterns.cli, ["show", "sql-injection", "--verbose"])

    assert result.exit_code == 0
    assert "SQL Injection" in result.output
    assert "Attack Vector:" in result.output or "Remediation:" in result.output
    assert "References:" in result.output


def test_cli_patterns_show_invalid_pattern():
    """Test patterns show with invalid pattern ID."""
    from acr.cli import patterns

    runner = CliRunner()
    result = runner.invoke(patterns.cli, ["show", "nonexistent-pattern"])

    assert result.exit_code == 1
    assert "Pattern 'nonexistent-pattern' not found" in result.output
