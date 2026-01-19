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

"""Report command implementation."""

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from acr.models.finding import Finding

console = Console()


@click.command()
@click.argument("input", type=click.Path(exists=True))
@click.argument("output", type=click.Path(), required=False)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    help="Output format",
)
@click.option("--include-sections", help="Comma-separated sections to include")
@click.option("--exclude-sections", help="Comma-separated sections to exclude")
@click.option("--stdout", is_flag=True, help="Output to stdout instead of file")
@click.pass_context
def cli(
    ctx: click.Context,
    input: str,
    output: Optional[str],
    format: str,
    include_sections: str,
    exclude_sections: str,
    stdout: bool,
) -> None:
    """Generate a vulnerability report from findings JSON.

    INPUT: Path to findings JSON file
    OUTPUT: Output file path (optional, outputs to stdout if not specified)
    """
    ctx.ensure_object(dict)
    quiet = ctx.obj.get("quiet", False)

    if not quiet:
        console.print(f"[bold]Reading findings from {input}...[/bold]")

    findings = _load_findings(input)

    if not findings:
        if not quiet:
            console.print("[yellow]No findings found in input file.[/yellow]")
        sys.exit(0)

    if not quiet:
        console.print(f"[bold]Found {len(findings)} findings.[/bold]")

    sections = _parse_sections(include_sections, exclude_sections)

    report = _generate_report(findings, format, sections)

    if stdout or not output:
        click.echo(report)
    else:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report)
        if not quiet:
            console.print(f"[green]Report written to: {output_path}[/green]")


def _load_findings(input_path: str) -> list[Finding]:
    """Load findings from JSON file.

    Args:
        input_path: Path to findings JSON file

    Returns:
        List of Finding objects
    """
    try:
        with open(input_path) as f:
            data = json.load(f)

        if isinstance(data, list):
            findings_data = data
        elif isinstance(data, dict) and "findings" in data:
            findings_data = data["findings"]
        else:
            console.print(f"[red]Invalid findings format in {input_path}[/red]")
            sys.exit(1)

        return [Finding(**f) for f in findings_data]
    except json.JSONDecodeError as e:
        console.print(f"[red]Error parsing JSON: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error loading findings: {e}[/red]")
        sys.exit(1)


def _parse_sections(include_sections: Optional[str], exclude_sections: Optional[str]) -> dict:
    """Parse include/exclude section options.

    Args:
        include_sections: Comma-separated sections to include
        exclude_sections: Comma-separated sections to exclude

    Returns:
        Dictionary with include and exclude lists
    """
    sections = {"include": [], "exclude": []}

    if include_sections:
        sections["include"] = [s.strip().lower() for s in include_sections.split(",")]

    if exclude_sections:
        sections["exclude"] = [s.strip().lower() for s in exclude_sections.split(",")]

    return sections


def _generate_report(findings: list[Finding], format: str, sections: dict) -> str:
    """Generate report in specified format.

    Args:
        findings: List of findings
        format: Output format (markdown or json)
        sections: Include/exclude section filters

    Returns:
        Report string
    """
    if format == "json":
        return _generate_json_report(findings)
    else:
        return _generate_markdown_report(findings, sections)


def _generate_json_report(findings: list[Finding]) -> str:
    """Generate JSON report.

    Args:
        findings: List of findings

    Returns:
        JSON report string
    """
    data = {
        "total_findings": len(findings),
        "severity_distribution": _get_severity_distribution(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    return json.dumps(data, indent=2)


def _get_severity_distribution(findings: list[Finding]) -> dict:
    """Calculate severity distribution.

    Args:
        findings: List of findings

    Returns:
        Dictionary with counts per severity
    """
    distribution = dict.fromkeys(["critical", "high", "medium", "low", "info"], 0)
    for f in findings:
        if f.severity in distribution:
            distribution[f.severity] += 1
    return distribution


def _generate_markdown_report(findings: list[Finding], sections: dict) -> str:
    """Generate Markdown report.

    Args:
        findings: List of findings
        sections: Include/exclude section filters

    Returns:
        Markdown report string
    """
    lines = []

    if _should_include_section("summary", sections):
        lines.extend(_generate_summary_section(findings))

    if _should_include_section("findings", sections):
        lines.extend(_generate_findings_section(findings))

    return "\n".join(lines)


def _should_include_section(section: str, sections: dict) -> bool:
    """Check if section should be included in report.

    Args:
        section: Section name
        sections: Include/exclude filters

    Returns:
        True if section should be included
    """
    return not (
        sections["exclude"]
        and section in sections["exclude"]
        or sections["include"]
        and section not in sections["include"]
    )


def _generate_summary_section(findings: list[Finding]) -> list[str]:
    """Generate summary section of report.

    Args:
        findings: List of findings

    Returns:
        List of Markdown lines
    """
    lines = [
        "# Adversarial Code Reviewer - Security Report\n",
        f"**Total Findings:** {len(findings)}\n",
        "## Severity Distribution\n",
    ]

    distribution = _get_severity_distribution(findings)
    table_lines = ["| Severity | Count |", "|----------|-------|"]
    for sev in ["critical", "high", "medium", "low", "info"]:
        table_lines.append(f"| {sev.capitalize()} | {distribution[sev]} |")

    lines.extend(table_lines)
    lines.append("")

    return lines


def _generate_findings_section(findings: list[Finding]) -> list[str]:
    """Generate findings section of report.

    Args:
        findings: List of findings

    Returns:
        List of Markdown lines
    """
    lines = ["## Detailed Findings\n"]

    severity_order = ["critical", "high", "medium", "low", "info"]

    for severity in severity_order:
        severity_findings = [f for f in findings if f.severity == severity]
        if not severity_findings:
            continue

        lines.append(f"### {severity.upper()}\n")

        for f in severity_findings:
            lines.append(f"#### {f.title}\n")
            lines.append(f"- **ID:** `{f.id}`\n")
            lines.append(f"- **Severity:** {f.severity}\n")
            lines.append(f"- **Confidence:** {f.confidence}\n")
            lines.append(f"- **Category:** {f.category}\n")
            lines.append(f"- **CWE:** `{f.cwe_id or 'N/A'}`\n")
            lines.append(f"- **OWASP:** `{f.owasp_id or 'N/A'}`\n")
            lines.append(f"- **Location:** `{f.location.file}:{f.location.line}`\n")

            if f.location.function:
                lines.append(f"- **Function:** `{f.location.function}`\n")

            lines.append(f"\n**Description:**\n{f.description}\n")
            lines.append(f"\n**Attack Vector:**\n{f.attack_vector}\n")

            if f.impact:
                lines.append(
                    f"\n**Impact:** Confidentiality: {f.impact.confidentiality}, "
                    f"Integrity: {f.impact.integrity}, "
                    f"Availability: {f.impact.availability}\n"
                )

            if f.remediation.description:
                lines.append(f"\n**Remediation:**\n{f.remediation.description}\n")

            if f.remediation.code_before:
                lines.append(
                    f"\n**Vulnerable Code:**\n```python\n{f.remediation.code_before}\n```\n"
                )

            if f.remediation.code_after:
                lines.append(f"\n**Fixed Code:**\n```python\n{f.remediation.code_after}\n```\n")

            if f.references:
                lines.append("\n**References:**\n")
                for ref in f.references:
                    lines.append(f"- {ref}\n")

            lines.append("\n---\n")

    return lines
