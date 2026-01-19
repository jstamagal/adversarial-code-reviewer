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

import pytest
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
