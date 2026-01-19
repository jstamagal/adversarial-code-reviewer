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

"""Main CLI entry point for Adversarial Code Reviewer."""

import sys
from typing import Optional

import click
from click.testing import CliRunner

from acr.cli import scan, report, init, config, patterns, version


def cli() -> None:
    """Main CLI entry point."""
    main()


@click.group()
@click.version_option(version="0.1.0", prog_name="acr")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--quiet", "-q", is_flag=True, help="Suppress output except errors")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to config file")
@click.pass_context
def main(ctx: click.Context, verbose: bool, quiet: bool, config: Optional[str]) -> None:
    """Adversarial Code Reviewer - AI-powered security analysis.

    ACR thinks like an attacker to find vulnerabilities in your code.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet
    ctx.obj["config"] = config


main.add_command(scan.cli, name="scan")
main.add_command(report.cli, name="report")
main.add_command(init.cli, name="init")
main.add_command(config.cli, name="config")
main.add_command(patterns.cli, name="patterns")
main.add_command(version.cli, name="version")


if __name__ == "__main__":
    cli()
