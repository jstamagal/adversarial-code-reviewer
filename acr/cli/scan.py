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

"""Scan command implementation."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from acr.config.loader import load_config
from acr.core.analyzer import Analyzer
from acr.models.finding import Finding


console = Console()


@click.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Filter by severity",
)
@click.option("--category", "-c", type=str, help="Filter by vulnerability category")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    help="Output format",
)
@click.option("--exclude", "-e", multiple=True, help="Exclude file patterns")
@click.option("--max-depth", "-d", type=int, default=10, help="Maximum recursion depth")
@click.option("--parallel", is_flag=True, help="Enable parallel processing")
@click.option("--dry-run", is_flag=True, help="Preview without writing reports")
@click.pass_context
def cli(
    ctx: click.Context,
    path: str,
    severity: Optional[str],
    category: Optional[str],
    output: Optional[str],
    format: str,
    exclude: tuple,
    max_depth: int,
    parallel: bool,
    dry_run: bool,
) -> None:
    """Scan a codebase for security vulnerabilities.

    PATH: Path to file or directory to scan
    """
    verbose = ctx.obj.get("verbose", False)
    quiet = ctx.obj.get("quiet", False)

    config = load_config(ctx.obj.get("config"))

    analyzer = Analyzer(config)

    if verbose:
        console.print(f"[bold]Scanning {path}...[/bold]")

    findings = analyzer.analyze(path)

    if severity:
        findings = [f for f in findings if f.severity == severity]

    if category:
        findings = [f for f in findings if f.category == category]

    if exclude:
        findings = [f for f in findings if not any(excl in f.location.file for excl in exclude)]

    if dry_run:
        console.print(f"[yellow]Dry run mode - {len(findings)} findings detected[/yellow]")
        if findings:
            _display_findings_summary(findings, verbose)
        return

    _output_findings(findings, format, output, verbose, quiet)

    _set_exit_code(findings)


def _display_findings_summary(findings: list, verbose: bool) -> None:
    """Display summary of findings.

    Args:
        findings: List of findings to display
        verbose: Whether to show verbose output
    """
    if not findings:
        console.print("[green]No findings detected.[/green]")
        return

    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    table = Table(title="Findings Summary")
    table.add_column("Severity", style="bold")
    table.add_column("Count")

    for sev, count in sorted(
        severity_counts.items(),
        key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0]),
    ):
        color = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }.get(sev, "white")
        table.add_row(f"[{color}]{sev}[/]", str(count))

    console.print(table)

    if verbose:
        for finding in findings:
            console.print(f"\n[bold]Finding:[/bold] {finding.title}")
            console.print(f"  [dim]ID:[/dim] {finding.id}")
            console.print(f"  [dim]File:[/dim] {finding.location.file}:{finding.location.line}")
            console.print(f"  [dim]Severity:[/dim] {finding.severity}")
            console.print(f"  [dim]Category:[/dim] {finding.category}")
            console.print(f"\n  [bold]Description:[/bold] {finding.description}")
            console.print(f"\n  [bold]Attack Vector:[/bold] {finding.attack_vector}")


def _output_findings(
    findings: list, format: str, output: Optional[str], verbose: bool, quiet: bool
) -> None:
    """Output findings to file or console.

    Args:
        findings: List of findings to output
        format: Output format
        output: Output file path
        verbose: Whether to show verbose output
        quiet: Suppress normal output
    """
    if not findings:
        if not quiet:
            console.print("[green]No findings detected.[/green]")
        return

    if not quiet:
        console.print(f"[bold]{len(findings)} findings detected.[/bold]")

    if output:
        _write_findings_to_file(findings, output, format)
    else:
        if not quiet:
            _display_findings_summary(findings, verbose)


def _write_findings_to_file(findings: list, output: str, format: str) -> None:
    """Write findings to file.

    Args:
        findings: List of findings to write
        output: Output file path
        format: Output format
    """
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if format == "json":
        import json

        data = [f.model_dump(mode="json") for f in findings]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(_generate_markdown_report(findings))

    console.print(f"[green]Report written to: {output_path}[/green]")


def _generate_markdown_report(findings: list) -> str:
    """Generate markdown report from findings.

    Args:
        findings: List of findings

    Returns:
        Markdown formatted report
    """
    lines = [
        "# Security Vulnerability Report\n",
        f"**Total Findings:** {len(findings)}\n",
        "## Findings by Severity\n",
    ]

    severity_order = ["critical", "high", "medium", "low", "info"]
    for severity in severity_order:
        severity_findings = [f for f in findings if f.severity == severity]
        if not severity_findings:
            continue

        lines.append(f"### {severity.upper()}\n")
        for f in severity_findings:
            lines.append(f"#### {f.title}\n")
            lines.append(f"- **ID:** `{f.id}`\n")
            lines.append(f"- **File:** {f.location.file}:{f.location.line}\n")
            lines.append(f"- **CWE:** `{f.cwe_id or 'N/A'}`\n")
            lines.append(f"- **Confidence:** {f.confidence}\n")
            lines.append(f"\n**Description:**\n{f.description}\n")
            lines.append(f"\n**Attack Vector:**\n{f.attack_vector}\n")

            if f.remediation.description:
                lines.append(f"\n**Remediation:**\n{f.remediation.description}\n")
            if f.remediation.code_before:
                lines.append(f"\n**Vulnerable Code:**\n```\n{f.remediation.code_before}\n```\n")
            if f.remediation.code_after:
                lines.append(f"\n**Fixed Code:**\n```\n{f.remediation.code_after}\n```\n")

            lines.append("\n---\n")

    return "\n".join(lines)


def _set_exit_code(findings: list) -> None:
    """Set exit code based on highest severity finding.

    Args:
        findings: List of findings
    """
    if not findings:
        sys.exit(0)

    severity_order = ["critical", "high", "medium", "low", "info"]
    highest_severity = max(
        (f.severity for f in findings),
        key=lambda s: severity_order.index(s),
    )

    exit_codes = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }

    sys.exit(exit_codes.get(highest_severity, 0))
