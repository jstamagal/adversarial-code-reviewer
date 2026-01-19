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

"""Patterns command implementation."""

from typing import List, Optional

import click
from rich.console import Console
from rich.table import Table

from acr.patterns.loader import PatternLoader
from acr.utils.logger import get_logger

logger = get_logger(__name__)
console = Console()


@click.group()
def cli() -> None:
    """Manage attack patterns."""
    pass


@cli.command("list")
@click.option("--category", "-c", type=str, help="Filter by category")
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Filter by severity",
)
@click.pass_context
def list_cmd(ctx: click.Context, category: str, severity: str) -> None:
    """List available attack patterns."""
    try:
        loader = PatternLoader()
        patterns_dict = loader.load_patterns()
        patterns = list(patterns_dict.values())

        if category:
            patterns = [p for p in patterns if p.category == category]

        if severity:
            patterns = [p for p in patterns if p.severity == severity]

        if not patterns:
            click.echo("No patterns found matching criteria.")
            return

        table = Table(title="Available Attack Patterns")
        table.add_column("Pattern ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="green")
        table.add_column("Category", style="yellow")
        table.add_column("Severity", style="bold")
        table.add_column("Description", max_width=60)

        for pattern in sorted(patterns, key=lambda p: p.id):
            severity_color = {
                "critical": "red",
                "high": "bright_red",
                "medium": "yellow",
                "low": "blue",
            }.get(pattern.severity, "white")

            table.add_row(
                pattern.id,
                pattern.name,
                pattern.category,
                f"[{severity_color}]{pattern.severity}[/{severity_color}]",
                pattern.description[:60] + "..."
                if len(pattern.description) > 60
                else pattern.description,
            )

        console.print(table)
        click.echo(f"\nTotal: {len(patterns)} pattern(s)")

    except Exception as e:
        logger.error(f"Failed to list patterns: {e}")
        raise click.ClickException(f"Failed to list patterns: {e}")


@cli.command("show")
@click.argument("pattern_id", type=str)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed pattern information")
@click.pass_context
def show(ctx: click.Context, pattern_id: str, verbose: bool) -> None:
    """Show details of a specific pattern.

    PATTERN_ID: Pattern identifier (e.g., sql-injection)
    """
    try:
        loader = PatternLoader()
        patterns_dict = loader.load_patterns()
        pattern = patterns_dict.get(pattern_id)

        if not pattern:
            click.echo(f"Pattern '{pattern_id}' not found.")
            click.echo("Run 'acr patterns list' to see available patterns.")
            raise click.Abort()

        click.echo(f"\n[bold cyan]{pattern.name}[/bold cyan]")
        click.echo(f"ID: {pattern.id}")
        click.echo(f"Category: {pattern.category}")
        click.echo(f"Severity: [bold red]{pattern.severity}[/bold red]")
        click.echo(f"CWE: {pattern.cwe_id if pattern.cwe_id else 'N/A'}")
        click.echo(f"OWASP: {pattern.owasp_id if pattern.owasp_id else 'N/A'}")

        click.echo(f"\n[bold]Description:[/bold]")
        click.echo(pattern.description)

        if verbose and pattern.attack_vector:
            click.echo(f"\n[bold]Attack Vector:[/bold]")
            click.echo(pattern.attack_vector)

        if verbose and pattern.example_payload:
            click.echo(f"\n[bold]Example Payload:[/bold]")
            click.echo(pattern.example_payload)

        if verbose and pattern.remediation:
            click.echo(f"\n[bold]Remediation:[/bold]")
            if pattern.remediation.description:
                click.echo(pattern.remediation.description)
            if pattern.remediation.code_before:
                click.echo("\nVulnerable Code:")
                click.echo(pattern.remediation.code_before)
            if pattern.remediation.code_after:
                click.echo("\nFixed Code:")
                click.echo(pattern.remediation.code_after)

        if verbose and pattern.references:
            click.echo(f"\n[bold]References:[/bold]")
            for ref in pattern.references:
                click.echo(f"  • {ref}")

    except Exception as e:
        logger.error(f"Failed to show pattern: {e}")
        raise click.ClickException(f"Failed to show pattern: {e}")
