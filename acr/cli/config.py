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

"""Config command implementation."""

import sys
from pathlib import Path
from typing import Optional

import click
import yaml

from acr.config.loader import find_config_file, load_config
from acr.config.validator import validate_config
from acr.utils.logger import get_logger

logger = get_logger(__name__)


@click.group()
def cli() -> None:
    """Manage ACR configuration."""
    pass


@cli.command("show")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to config file")
@click.pass_context
def show(_ctx: click.Context, config: Optional[str]) -> None:
    """Show current configuration."""
    try:
        loaded_config = load_config(config)

        config_path = find_config_file() if config is None else config

        if config_path:
            click.echo(f"Configuration: {config_path}")
        else:
            click.echo("Configuration: (defaults)")

        config_dict = loaded_config.model_dump()
        click.echo(yaml.dump(config_dict, default_flow_style=False, sort_keys=False))

    except Exception as e:
        logger.error(f"Failed to show configuration: {e}")
        raise click.ClickException(f"Failed to show configuration: {e}") from e


@cli.command("validate")
@click.option("--config", "-c", type=click.Path(), help="Path to config file")
@click.option("--fix", is_flag=True, help="Attempt to fix common issues")
@click.pass_context
def validate(_ctx: click.Context, config: Optional[str], fix: bool) -> None:
    """Validate configuration file."""
    config_path = config

    if config_path is None:
        config_path = find_config_file()

    if config_path is None:
        click.echo("No configuration file found (using defaults)")
        click.echo("Run 'acr init' to create a configuration file")
        return

    path = Path(config_path)

    if not path.exists():
        click.echo(f"Error: Configuration file not found: {config_path}")
        raise click.Abort()

    try:
        click.echo(f"Validating configuration: {config_path}")
        click.echo("")

        with open(path, encoding="utf-8") as f:
            try:
                config_data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                click.echo("[bold red]❌ Invalid YAML[/bold red]")
                click.echo(f"Error: {e}")
                raise click.Abort() from e

        if config_data is None:
            config_data = {}

        loaded_config = validate_config(config_data)

        click.echo("[bold green]✓ Configuration is valid[/bold green]")
        click.echo("")

        _display_config_summary(loaded_config)

        if fix:
            click.echo("")
            click.echo("[yellow]Auto-fix not yet implemented[/yellow]")
            click.echo("Please manually fix any issues")

    except click.Abort:
        raise
    except Exception as e:
        click.echo("[bold red]❌ Validation failed[/bold red]")
        click.echo(f"Error: {e}")
        sys.exit(1)


def _display_config_summary(config) -> None:
    """Display a summary of the validated configuration.

    Args:
        config: Validated configuration model
    """
    click.echo("[bold]Configuration Summary:[/bold]")
    click.echo(f"  Project: {config.project.name}")
    click.echo(f"  Root: {config.project.root}")
    click.echo("")

    click.echo("[bold]Languages:[/bold]")
    for lang, lang_config in config.languages.items():
        status = "enabled" if lang_config.enabled else "disabled"
        click.echo(f"  {lang}: {status} (v{lang_config.version})")
    click.echo("")

    click.echo("[bold]Frameworks:[/bold]")
    for framework, framework_config in config.frameworks.items():
        status = "enabled" if framework_config.enabled else "disabled"
        click.echo(f"  {framework}: {status}")
    click.echo("")

    click.echo("[bold]Patterns:[/bold]")
    click.echo(f"  Severity threshold: {config.patterns.severity_threshold}")
    click.echo(f"  Enabled patterns: {len(config.patterns.enabled)}")
    if config.patterns.custom_patterns:
        click.echo(f"  Custom patterns: {config.patterns.custom_patterns}")
    click.echo("")

    click.echo("[bold]LLM:[/bold]")
    status = "enabled" if config.llm.enabled else "disabled"
    click.echo(f"  Status: {status}")
    if config.llm.enabled:
        click.echo(f"  Provider: {config.llm.provider}")
        click.echo(f"  Model: {config.llm.model}")
        click.echo(f"  API key env: {config.llm.api_key_env}")
        click.echo(f"  Cache: {'enabled' if config.llm.cache_enabled else 'disabled'}")
    click.echo("")

    click.echo("[bold]Analysis:[/bold]")
    click.echo(f"  Max depth: {config.analysis.max_depth}")
    click.echo(f"  Timeout: {config.analysis.timeout}s")
    click.echo(f"  Parallel: {'enabled' if config.analysis.parallel else 'disabled'}")
    click.echo("")

    click.echo("[bold]Reporting:[/bold]")
    click.echo(f"  Formats: {', '.join(config.reporting.formats)}")
    click.echo(f"  Output dir: {config.reporting.output_dir}")
    click.echo(f"  Include snippets: {config.reporting.include_code_snippets}")
    click.echo("")

    click.echo("[bold]Exclusions:[/bold]")
    click.echo(f"  Paths: {len(config.exclude.paths)}")
    click.echo(f"  Files: {len(config.exclude.files)}")
