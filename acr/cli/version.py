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

"""Version command implementation."""

import importlib.metadata as metadata
import sys
from typing import Dict, Optional

import click
import httpx

from acr import __version__


def get_dependency_versions() -> Dict[str, str]:
    """Get versions of key dependencies."""
    deps = {}
    key_packages = [
        "click",
        "pydantic",
        "pyyaml",
        "networkx",
        "anthropic",
        "openai",
        "rich",
        "jinja2",
        "tree-sitter",
        "diskcache",
    ]
    for pkg in key_packages:
        try:
            version = metadata.version(pkg)
            deps[pkg] = version
        except metadata.PackageNotFoundError:
            deps[pkg] = "not installed"
    return deps


def check_for_updates() -> Optional[str]:
    """Check if a newer version is available on PyPI."""
    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.get("https://pypi.org/pypi/adversarial-code-reviewer/json")
            response.raise_for_status()
            data = response.json()
            latest_version = data["info"]["version"]
            return latest_version
    except Exception:
        return None


@click.command()
@click.option(
    "--check-updates",
    is_flag=True,
    help="Check for available updates from PyPI",
)
@click.pass_context
def cli(ctx: click.Context, check_updates: bool) -> None:
    """Show version information."""
    click.echo(f"Adversarial Code Reviewer v{__version__}")
    click.echo(f"Python {sys.version.split()[0]}")
    click.echo(f"Platform: {sys.platform}")

    click.echo("\nDependencies:")
    deps = get_dependency_versions()
    for pkg, version in deps.items():
        click.echo(f"  {pkg}: {version}")

    if check_updates:
        click.echo("\nChecking for updates...")
        latest_version = check_for_updates()
        if latest_version:
            if latest_version != __version__:
                click.echo(
                    f"⚠️  A newer version is available: v{latest_version} (you have v{__version__})"
                )
                click.echo("Update with: pip install --upgrade adversarial-code-reviewer")
            else:
                click.echo("✓ You are running the latest version!")
        else:
            click.echo("Unable to check for updates. Please check manually at:")
            click.echo("https://pypi.org/project/adversarial-code-reviewer/")
