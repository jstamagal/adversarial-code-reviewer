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

"""Attack command implementation."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax

from acr.config.loader import load_config
from acr.core.analyzer import Analyzer
from acr.models.finding import Finding

console = Console()


@click.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--function", "-f", type=str, help="Generate attacks for specific function")
@click.option("--pattern", "-p", type=str, help="Generate attacks for specific pattern")
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Filter by severity",
)
@click.option("--export", "-e", type=click.Path(), help="Export attack payloads to file")
@click.option(
    "--format",
    type=click.Choice(["json", "txt", "markdown"]),
    default="txt",
    help="Export format",
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed attack information")
@click.pass_context
def cli(
    ctx: click.Context,
    path: str,
    function: Optional[str],
    pattern: Optional[str],
    severity: Optional[str],
    export: Optional[str],
    format: str,
    verbose: bool,
) -> None:
    """Generate attack vectors for specific vulnerabilities.

    PATH: Path to file or directory to analyze
    """
    ctx.ensure_object(dict)
    verbose = verbose or ctx.obj.get("verbose", False)
    quiet = ctx.obj.get("quiet", False)

    config = load_config(ctx.obj.get("config"))

    analyzer = Analyzer(config)

    if not quiet:
        console.print(f"[bold]Analyzing {path} for vulnerabilities...[/bold]")

    findings = analyzer.analyze(path)

    if function:
        findings = [f for f in findings if f.location.function == function]

    if pattern:
        findings = [
            f
            for f in findings
            if pattern.lower() in f.title.lower() or pattern.lower() in f.category.lower()
        ]

    if severity:
        findings = [f for f in findings if f.severity == severity]

    if not findings:
        console.print("[yellow]No vulnerabilities found matching criteria.[/yellow]")
        sys.exit(0)

    if not quiet:
        console.print(f"[bold green]Found {len(findings)} vulnerabilities[/bold green]\n")

    if export:
        _export_attacks(findings, export, format, verbose)
    else:
        _display_attacks(findings, verbose)

    _set_exit_code(findings)


def _display_attacks(findings: list, verbose: bool) -> None:
    """Display attack vectors for findings.

    Args:
        findings: List of findings to display
        verbose: Whether to show verbose output
    """
    for i, finding in enumerate(findings, 1):
        _display_finding_attack(finding, i, verbose)
        if i < len(findings):
            console.print()


def _display_finding_attack(finding: Finding, index: int, verbose: bool) -> None:
    """Display attack details for a single finding.

    Args:
        finding: Finding to display
        index: Finding index
        verbose: Whether to show verbose output
    """
    severity_colors = {
        "critical": "red",
        "high": "orange3",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    color = severity_colors.get(finding.severity, "white")

    console.print(Panel.fit(f"[bold {color}]Finding #{index}[/bold {color}]"))

    console.print(f"[bold]Title:[/bold] {finding.title}")
    console.print(f"[bold]Severity:[/bold] [{color}]{finding.severity}[/{color}]")
    console.print(f"[bold]Category:[/bold] {finding.category}")
    if finding.cwe_id:
        console.print(f"[bold]CWE:[/bold] {finding.cwe_id}")
    if finding.owasp_id:
        console.print(f"[bold]OWASP:[/bold] {finding.owasp_id}")

    console.print(f"\n[bold]Location:[/bold]")
    console.print(f"  File: {finding.location.file}")
    console.print(f"  Line: {finding.location.line}")
    if finding.location.function:
        console.print(f"  Function: {finding.location.function}")
    if finding.location.class_name:
        console.print(f"  Class: {finding.location.class_name}")

    console.print(f"\n[bold]Description:[/bold]")
    console.print(finding.description)

    console.print(f"\n[bold cyan]Attack Vector:[/bold cyan]")
    if finding.attack_vector:
        md = Markdown(finding.attack_vector)
        console.print(md)

    if finding.remediation:
        console.print(f"\n[bold green]Remediation:[/bold green]")
        if finding.remediation.description:
            console.print(finding.remediation.description)

        if verbose and finding.remediation.code_before:
            console.print(f"\n[bold red]Vulnerable Code:[/bold red]")
            try:
                syntax = Syntax(finding.remediation.code_before, "python", theme="monokai")
                console.print(syntax)
            except Exception:
                console.print(finding.remediation.code_before)

        if verbose and finding.remediation.code_after:
            console.print(f"\n[bold green]Secure Code:[/bold green]")
            try:
                syntax = Syntax(finding.remediation.code_after, "python", theme="monokai")
                console.print(syntax)
            except Exception:
                console.print(finding.remediation.code_after)

    if finding.references:
        console.print(f"\n[bold]References:[/bold]")
        for ref in finding.references:
            console.print(f"  - {ref}")


def _export_attacks(findings: list, export_path: str, format: str, verbose: bool) -> None:
    """Export attack vectors to file.

    Args:
        findings: List of findings to export
        export_path: Path to export file
        format: Export format
        verbose: Whether to show verbose information
    """
    output_path = Path(export_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if format == "json":
        _export_json(findings, output_path)
    elif format == "markdown":
        _export_markdown(findings, output_path)
    else:
        _export_txt(findings, output_path)

    console.print(f"[green]Attacks exported to: {output_path}[/green]")

    if verbose:
        console.print(f"[dim]Format: {format}[/dim]")
        console.print(f"[dim]Findings: {len(findings)}[/dim]")


def _export_json(findings: list, output_path: Path) -> None:
    """Export findings as JSON.

    Args:
        findings: List of findings to export
        output_path: Path to output file
    """
    import json

    data = {
        "total_findings": len(findings),
        "attacks": [f.model_dump(mode="json") for f in findings],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _export_markdown(findings: list, output_path: Path) -> None:
    """Export findings as Markdown.

    Args:
        findings: List of findings to export
        output_path: Path to output file
    """
    lines = [
        "# Attack Vectors Report\n",
        f"**Total Findings:** {len(findings)}\n",
        "---\n",
    ]

    for i, finding in enumerate(findings, 1):
        lines.append(f"## Finding #{i}: {finding.title}\n")
        lines.append(f"- **Severity:** {finding.severity}\n")
        lines.append(f"- **Category:** {finding.category}\n")
        if finding.cwe_id:
            lines.append(f"- **CWE:** {finding.cwe_id}\n")
        lines.append(f"- **File:** {finding.location.file}:{finding.location.line}\n")
        if finding.location.function:
            lines.append(f"- **Function:** {finding.location.function}\n")

        lines.append("\n### Description\n")
        lines.append(f"{finding.description}\n")

        lines.append("\n### Attack Vector\n")
        if finding.attack_vector:
            lines.append(f"{finding.attack_vector}\n")

        if finding.remediation and finding.remediation.description:
            lines.append("\n### Remediation\n")
            lines.append(f"{finding.remediation.description}\n")

        if finding.references:
            lines.append("\n### References\n")
            for ref in finding.references:
                lines.append(f"- {ref}\n")

        lines.append("\n---\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _export_txt(findings: list, output_path: Path) -> None:
    """Export findings as plain text.

    Args:
        findings: List of findings to export
        output_path: Path to output file
    """
    lines = [
        "Attack Vectors Report",
        "=" * 80,
        f"Total Findings: {len(findings)}",
        "=" * 80,
        "",
    ]

    for i, finding in enumerate(findings, 1):
        lines.append(f"\n{'=' * 80}")
        lines.append(f"Finding #{i}: {finding.title}")
        lines.append(f"{'=' * 80}")
        lines.append(f"Severity: {finding.severity}")
        lines.append(f"Category: {finding.category}")
        if finding.cwe_id:
            lines.append(f"CWE: {finding.cwe_id}")
        lines.append(f"Location: {finding.location.file}:{finding.location.line}")
        if finding.location.function:
            lines.append(f"Function: {finding.location.function}")

        lines.append(f"\nDescription:\n{finding.description}")

        lines.append(f"\nAttack Vector:\n{finding.attack_vector}")

        if finding.remediation and finding.remediation.description:
            lines.append(f"\nRemediation:\n{finding.remediation.description}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _set_exit_code(findings: list) -> None:
    """Set exit code based on highest severity finding.

    Args:
        findings: List of findings
    """
    if not findings:
        sys.exit(0)

    severity_order = ["critical", "high", "medium", "low", "info"]
    highest_severity = max((f.severity for f in findings), key=lambda s: severity_order.index(s))

    exit_codes = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    sys.exit(exit_codes.get(highest_severity, 0))
