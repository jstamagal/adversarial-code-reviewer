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

"""Shell completion command implementation."""

import os
import sys
from typing import Optional

import click


@click.command()
@click.option(
    "--shell",
    "-s",
    type=click.Choice(["bash", "zsh", "fish", "powershell"]),
    help="Shell to generate completion for",
)
@click.option("--install", "-i", is_flag=True, help="Install completion script for detected shell")
@click.option(
    "--path",
    "-p",
    type=click.Path(),
    help="Custom path to write completion script to",
)
def cli(shell: Optional[str], install: bool, path: Optional[str]) -> None:
    """Generate shell completion scripts for ACR.

    To enable completion for your shell, run:

    \b
    Bash:
      eval "$(_ACR_COMPLETE=bash_source acr)"

    \b
    Zsh:
      eval "$(_ACR_COMPLETE=zsh_source acr)"

    \b
    Fish:
      _ACR_COMPLETE=fish_source acr | source

    \b
    Powershell:
      Invoke-Expression (_ACR_COMPLETE=powershell_source acr)

    To install permanently:

    \b
    Bash:
      acr completion --install --shell bash

    \b
    Zsh:
      acr completion --install --shell zsh

    \b
    Fish:
      acr completion --install --shell fish

    \b
    Powershell:
      acr completion --install --shell powershell

    For more information, visit: https://click.palletsprojects.com/en/latest/shell-completion/
    """
    from acr.__main__ import main

    if install:
        if shell is None:
            shell = _detect_shell()

        if shell is None:
            click.echo(
                "Could not auto-detect shell. Please specify --shell bash|zsh|fish|powershell",
                err=True,
            )
            sys.exit(1)

        _install_completion(main, shell, path)
    else:
        if shell is None:
            click.echo("Please specify --shell bash|zsh|fish|powershell")
            click.echo("")
            _show_completion_instructions()
            sys.exit(1)

        _print_completion(main, shell)


def _detect_shell() -> Optional[str]:
    """Detect the current shell."""
    shell = None
    if "SHELL" in os.environ:
        shell_path = os.environ["SHELL"]
        if "bash" in shell_path:
            shell = "bash"
        elif "zsh" in shell_path:
            shell = "zsh"
        elif "fish" in shell_path:
            shell = "fish"
        elif "powershell" in shell_path or "pwsh" in shell_path:
            shell = "powershell"
    return shell


def _print_completion(cli_group: click.Group, shell: str) -> None:
    """Print completion script for specified shell."""
    if shell == "bash":
        click.echo('eval "$(_ACR_COMPLETE=bash_source acr)"')
    elif shell == "zsh":
        click.echo('eval "$(_ACR_COMPLETE=zsh_source acr)"')
    elif shell == "fish":
        click.echo("_ACR_COMPLETE=fish_source acr | source")
    elif shell == "powershell":
        click.echo("Invoke-Expression (_ACR_COMPLETE=powershell_source acr)")


def _install_completion(cli_group: click.Group, shell: str, path: Optional[str]) -> None:
    """Install completion script for specified shell."""
    from pathlib import Path

    target_file = None
    rc_file = None
    source_line = None

    if shell == "bash":
        target_file = path or "~/.local/share/bash-completion/completions/acr"
        source_line = 'eval "$(_ACR_COMPLETE=bash_source acr)"'
        rc_file = "~/.bashrc"
    elif shell == "zsh":
        target_file = path or "~/.zsh/completion/_acr"
        source_line = 'eval "$(_ACR_COMPLETE=zsh_source acr)"'
        rc_file = "~/.zshrc"
    elif shell == "fish":
        target_file = path or "~/.config/fish/completions/acr.fish"
        source_line = "_ACR_COMPLETE=fish_source acr | source"
        rc_file = "~/.config/fish/config.fish"
    elif shell == "powershell":
        target_file = path or "~/Documents/PowerShell/acr-completion.ps1"
        source_line = "Invoke-Expression (_ACR_COMPLETE=powershell_source acr)"
        rc_file = "~/Documents/PowerShell/Microsoft.PowerShell_profile.ps1"
    else:
        click.echo(f"Unsupported shell: {shell}", err=True)
        sys.exit(1)

    target_file = Path(target_file).expanduser()
    rc_file = Path(rc_file).expanduser()

    # Create completion script (wrapper that enables completion)
    completion_script = f"""# ACR shell completion for {shell}
# To enable completion, add this to your shell profile:
# {source_line}

# Or source this file directly:
{source_line}
"""

    # Create directory if needed
    target_file.parent.mkdir(parents=True, exist_ok=True)

    # Write completion script
    target_file.write_text(completion_script)

    click.echo(f"Completion script written to: {target_file}")

    # Add source line to rc file if not already present
    if rc_file.exists():
        rc_content = rc_file.read_text()
        if source_line not in rc_content:
            with open(rc_file, "a") as f:
                f.write(f"\n# ACR completion\n{source_line}\n")
            click.echo(f"Added completion source to: {rc_file}")
    else:
        click.echo(f"Please add the following line to your shell profile ({rc_file}):")
        click.echo(source_line)

    click.echo("")
    click.echo("Reload your shell or restart your terminal for changes to take effect.")


def _show_completion_instructions() -> None:
    """Show instructions for enabling shell completion."""
    click.echo(
        "To enable completion for your shell, add one of the following to your shell profile:"
    )
    click.echo("")

    click.echo(click.style("Bash:", bold=True))
    click.echo('  eval "$(_ACR_COMPLETE=bash_source acr)"')
    click.echo("")

    click.echo(click.style("Zsh:", bold=True))
    click.echo('  eval "$(_ACR_COMPLETE=zsh_source acr)"')
    click.echo("")

    click.echo(click.style("Fish:", bold=True))
    click.echo("  _ACR_COMPLETE=fish_source acr | source")
    click.echo("")

    click.echo(click.style("PowerShell:", bold=True))
    click.echo("  Invoke-Expression (_ACR_COMPLETE=powershell_source acr)")
    click.echo("")

    click.echo("For permanent installation, use:")
    click.echo("  acr completion --install --shell <bash|zsh|fish|powershell>")
