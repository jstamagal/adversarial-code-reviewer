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
from typing import Optional, Tuple

import click
from rich.console import Console
from rich.table import Table

from acr.config.loader import load_config
from acr.core.analyzer import Analyzer
from acr.models.finding import Finding


console = Console()


LLM_PRICING = {
    "anthropic": {
        "claude-3-5-sonnet-20241022": 0.015,
        "claude-3-5-haiku-20241022": 0.001,
        "claude-3-opus-20240229": 0.015,
        "claude-3-sonnet-20240229": 0.003,
    },
    "openai": {
        "gpt-4o": 0.01,
        "gpt-4o-mini": 0.00015,
        "gpt-4-turbo": 0.03,
        "gpt-4": 0.06,
    },
}


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
        _display_dry_run_info(findings, config, path, verbose)
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


def _estimate_llm_cost(findings: list, config) -> Tuple[float, str]:
    """Estimate LLM costs for analyzing findings.

    Args:
        findings: List of findings
        config: ACR configuration

    Returns:
        Tuple of (estimated_cost, currency)
    """
    if not config.llm.enabled or not findings:
        return 0.0, "USD"

    avg_tokens_per_finding = 800
    total_tokens = len(findings) * avg_tokens_per_finding

    provider = config.llm.provider
    model = config.llm.model

    pricing_table = LLM_PRICING.get(provider, {})
    cost_per_1k_tokens = pricing_table.get(model, 0.01)

    estimated_cost = (total_tokens / 1000) * cost_per_1k_tokens
    return estimated_cost, "USD"


def _estimate_analysis_time(findings: list, path: str, config) -> Tuple[float, str]:
    """Estimate analysis time.

    Args:
        findings: List of findings
        path: Path being scanned
        config: ACR configuration

    Returns:
        Tuple of (estimated_seconds, unit)
    """
    path_obj = Path(path)
    if path_obj.is_file():
        file_count = 1
    else:
        file_count = len(list(path_obj.rglob("*.py")))

    base_time_per_file = 0.3
    time_per_finding = 0.15

    static_analysis_time = (file_count * base_time_per_file) + (len(findings) * time_per_finding)

    if config.llm.enabled and findings:
        avg_llm_response_time = 5.0
        llm_time = len(findings) * avg_llm_response_time
        total_time = static_analysis_time + llm_time
    else:
        total_time = static_analysis_time

    if total_time > 60:
        return total_time / 60, "minutes"
    return total_time, "seconds"


def _display_dry_run_info(findings: list, config, path: str, verbose: bool) -> None:
    """Display dry run information including cost and time estimates.

    Args:
        findings: List of findings
        config: ACR configuration
        path: Path being scanned
        verbose: Whether to show verbose output
    """
    info_table = Table(title="Dry Run Analysis Information")
    info_table.add_column("Metric", style="bold")
    info_table.add_column("Value")

    info_table.add_row("Total Findings", str(len(findings)))
    info_table.add_row("LLM Integration", "Enabled" if config.llm.enabled else "Disabled")

    if config.llm.enabled:
        estimated_cost, currency = _estimate_llm_cost(findings, config)
        cost_str = f"${estimated_cost:.4f}" if estimated_cost > 0 else "$0.00"
        info_table.add_row(f"Estimated LLM Cost ({currency})", cost_str)

    estimated_time, time_unit = _estimate_analysis_time(findings, path, config)
    info_table.add_row(f"Estimated Analysis Time", f"{estimated_time:.2f} {time_unit}")

    console.print(info_table)

    if config.llm.enabled and len(findings) > 0:
        estimated_cost, _ = _estimate_llm_cost(findings, config)
        if estimated_cost > 1.00:
            console.print(
                f"\n[yellow]⚠ Warning: Estimated LLM cost exceeds $1.00. "
                f"Consider using --severity or --category filters to reduce scope.[/yellow]"
            )
    elif len(findings) == 0:
        console.print(
            "\n[green]✓ No findings detected. Run scan again without --dry-run to generate reports.[/green]"
        )
    else:
        console.print(
            "\n[dim]Run scan again without --dry-run to generate reports and exit codes.[/dim]"
        )
