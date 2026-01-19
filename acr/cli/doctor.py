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

"""Doctor command implementation."""

import shutil
import sys
from pathlib import Path

import click
import yaml

from acr.config.loader import find_config_file, load_config
from acr.config.validator import validate_config
from acr.utils.logger import get_logger

logger = get_logger(__name__)


@click.command()
@click.pass_context
def cli(_ctx: click.Context) -> None:
    """Run diagnostics and display system status."""
    issues = []

    click.echo("[bold]Adversarial Code Reviewer - Doctor Diagnostics[/bold]")
    click.echo("")

    check_python_version(issues)
    click.echo("")

    check_dependencies(issues)
    click.echo("")

    check_tree_sitter(issues)
    click.echo("")

    check_configuration(issues)
    click.echo("")

    check_llm_connectivity(issues)
    click.echo("")

    check_disk_space(issues)
    click.echo("")

    display_summary(issues)


def check_python_version(issues: list) -> None:
    """Check Python version.

    Args:
        issues: List to append any issues found
    """
    click.echo("[bold]Python Version:[/bold]")
    version_str = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    click.echo(f"  Version: {version_str}")
    click.echo(f"  Platform: {sys.platform}")
    click.echo(f"  Executable: {sys.executable}")

    min_version = (3, 8, 0)
    current_version = (sys.version_info.major, sys.version_info.minor, sys.version_info.micro)

    if current_version < min_version:
        error_msg = f"Python {min_version[0]}.{min_version[1]}.{min_version[2]} or higher required"
        click.echo(f"  [bold red]✗ {error_msg}[/bold red]")
        issues.append(("Python version", error_msg))
    else:
        click.echo("  [green]✓ Python version OK[/green]")


def check_dependencies(issues: list) -> None:
    """Check if required dependencies are installed.

    Args:
        issues: List to append any issues found
    """
    click.echo("[bold]Dependencies:[/bold]")

    required_packages = [
        "click",
        "pydantic",
        "yaml",
        "networkx",
        "anthropic",
        "openai",
        "rich",
        "jinja2",
        "tree-sitter",
        "tree-sitter-languages",
        "diskcache",
        "keyring",
    ]

    all_ok = True
    for package in required_packages:
        try:
            __import__(package)
            click.echo(f"  [green]✓ {package}[/green]")
        except ImportError:
            click.echo(f"  [red]✗ {package} - NOT INSTALLED[/red]")
            issues.append(("Dependencies", f"Missing package: {package}"))
            all_ok = False

    if all_ok:
        click.echo("  [green]All dependencies OK[/green]")


def check_tree_sitter(issues: list) -> None:
    """Check tree-sitter installation and language parsers.

    Args:
        issues: List to append any issues found
    """
    click.echo("[bold]Tree-sitter:[/bold]")

    try:
        import importlib

        tree_sitter_spec = importlib.util.find_spec("tree_sitter")
        if tree_sitter_spec is not None:
            click.echo("  [green]✓ tree-sitter installed[/green]")

            try:
                from tree_sitter import Language

                _ = Language

                click.echo("  [green]✓ Language parser available[/green]")
            except ImportError as e:
                error_msg = f"Language parser not available: {e}"
                click.echo(f"  [red]✗ {error_msg}[/red]")
                issues.append(("Tree-sitter", error_msg))
        else:
            raise ImportError("tree-sitter not found")

    except ImportError:
        error_msg = "tree-sitter not installed"
        click.echo(f"  [red]✗ {error_msg}[/red]")
        issues.append(("Tree-sitter", error_msg))


def check_configuration(issues: list) -> None:
    """Check configuration file validity.

    Args:
        issues: List to append any issues found
    """
    click.echo("[bold]Configuration:[/bold]")

    config_path = find_config_file()

    if config_path is None:
        click.echo("  [yellow]⚠ No configuration file found (using defaults)[/yellow]")
        click.echo("  Run 'acr init' to create a configuration file")
        return

    click.echo(f"  Config file: {config_path}")

    path = Path(config_path)

    if not path.exists():
        error_msg = f"Configuration file not found: {config_path}"
        click.echo(f"  [red]✗ {error_msg}[/red]")
        issues.append(("Configuration", error_msg))
        return

    try:
        with open(path, encoding="utf-8") as f:
            config_data = yaml.safe_load(f)

        if config_data is None:
            config_data = {}

        validate_config(config_data)
        click.echo("  [green]✓ Configuration valid[/green]")

    except yaml.YAMLError as e:
        error_msg = f"Invalid YAML: {e}"
        click.echo(f"  [red]✗ {error_msg}[/red]")
        issues.append(("Configuration", error_msg))

    except Exception as e:
        error_msg = f"Validation failed: {e}"
        click.echo(f"  [red]✗ {error_msg}[/red]")
        issues.append(("Configuration", error_msg))


def check_llm_connectivity(issues: list) -> None:
    """Check LLM API configuration and connectivity.

    Args:
        issues: List to append any issues found
    """
    click.echo("[bold]LLM API:[/bold]")

    try:
        loaded_config = load_config(None)

        if not loaded_config.llm.enabled:
            click.echo("  [yellow]⚠ LLM disabled in configuration[/yellow]")
            return

        click.echo(f"  Provider: {loaded_config.llm.provider}")
        click.echo(f"  Model: {loaded_config.llm.model}")
        click.echo(f"  API key env: {loaded_config.llm.api_key_env}")

        api_key = loaded_config.llm.api_key_env
        if api_key:
            import os

            key_value = os.environ.get(api_key)
            if key_value:
                click.echo(f"  [green]✓ API key set ({api_key})[/green]")
            else:
                warning_msg = f"API key not set: {api_key}"
                click.echo(f"  [yellow]⚠ {warning_msg}[/yellow]")
                issues.append(("LLM API", warning_msg))
        else:
            click.echo("  [yellow]⚠ No API key environment variable configured[/yellow]")

    except Exception as e:
        error_msg = f"Failed to check LLM configuration: {e}"
        click.echo(f"  [red]✗ {error_msg}[/red]")
        issues.append(("LLM API", error_msg))


def check_disk_space(issues: list) -> None:
    """Check available disk space.

    Args:
        issues: List to append any issues found
    """
    click.echo("[bold]Disk Space:[/bold]")

    try:
        usage = shutil.disk_usage("/")
        total_gb = usage.total / (1024**3)
        used_gb = usage.used / (1024**3)
        free_gb = usage.free / (1024**3)
        free_percent = (usage.free / usage.total) * 100

        click.echo(f"  Total: {total_gb:.1f} GB")
        click.echo(f"  Used: {used_gb:.1f} GB ({100 - free_percent:.1f}%)")
        click.echo(f"  Free: {free_gb:.1f} GB ({free_percent:.1f}%)")

        if free_gb < 1.0:
            warning_msg = f"Low disk space: {free_gb:.1f} GB free"
            click.echo(f"  [yellow]⚠ {warning_msg}[/yellow]")
            issues.append(("Disk Space", warning_msg))
        else:
            click.echo("  [green]✓ Disk space OK[/green]")

    except Exception as e:
        error_msg = f"Failed to check disk space: {e}"
        click.echo(f"  [red]✗ {error_msg}[/red]")
        issues.append(("Disk Space", error_msg))


def display_summary(issues: list) -> None:
    """Display diagnostic summary.

    Args:
        issues: List of issues found
    """
    click.echo("")
    click.echo("[bold]Diagnostics Summary:[/bold]")

    if not issues:
        click.echo("  [green]✓ All checks passed[/green]")
        click.echo("")
        click.echo("Your ACR installation is healthy!")
        sys.exit(0)
    else:
        click.echo(f"  [red]✗ Found {len(issues)} issue(s)[/red]")
        click.echo("")
        click.echo("[bold]Issues:[/bold]")

        for category, message in issues:
            click.echo(f"  [red]•[/red] {category}: {message}")

        click.echo("")
        click.echo("Please address the issues above.")
        sys.exit(1)
