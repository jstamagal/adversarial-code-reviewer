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

"""Init command implementation."""

import os
from pathlib import Path
from typing import Optional

import click
import yaml
from acr.utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_CONFIG = {
    "project": {"name": "my-project", "root": "."},
    "languages": {"python": {"enabled": True, "version": "3.10"}},
    "frameworks": {
        "flask": {"enabled": False},
        "django": {"enabled": False},
        "fastapi": {"enabled": False},
    },
    "patterns": {
        "enabled": [
            "sql-injection",
            "xss",
            "csrf",
            "command-injection",
            "path-traversal",
            "hardcoded-secrets",
        ],
        "severity_threshold": "medium",
        "custom_patterns": "./patterns/",
    },
    "llm": {
        "enabled": False,
        "provider": "anthropic",
        "model": "claude-3-5-sonnet-20241022",
        "api_key_env": "ANTHROPIC_API_KEY",
        "max_tokens": 4096,
        "cache_enabled": True,
    },
    "analysis": {"max_depth": 10, "timeout": 300, "parallel": False},
    "reporting": {
        "formats": ["markdown", "json"],
        "output_dir": "./acr-reports",
        "include_code_snippets": True,
        "max_snippet_lines": 10,
    },
    "exclude": {
        "paths": ["tests/", "venv/", ".venv/", "__pycache__/", "migrations/", "node_modules/"],
        "files": ["*.pyc", "*.pyo", "*.db", "*.sqlite"],
    },
}


@click.command()
@click.option("--force", "-f", is_flag=True, help="Overwrite existing configuration")
@click.option("--project-name", "-n", type=str, help="Project name")
@click.pass_context
def cli(ctx: click.Context, force: bool, project_name: Optional[str]) -> None:
    """Initialize ACR configuration.

    Creates a .acrrc.yaml file in the current directory.
    """
    config_file = Path(".acrrc.yaml")

    if config_file.exists() and not force:
        click.echo(f"Error: {config_file} already exists.")
        click.echo("Use --force to overwrite existing configuration.")
        raise click.Abort()

    logger.info(f"Initializing ACR configuration...")

    if config_file.exists():
        logger.warning(f"Overwriting existing {config_file}")

    config = DEFAULT_CONFIG.copy()

    if project_name:
        config["project"]["name"] = project_name

    try:
        config_file.write_text(yaml.dump(config, default_flow_style=False, sort_keys=False))
        click.echo(f"✓ Created {config_file}")

        click.echo("")
        click.echo("Configuration file created successfully!")
        click.echo("")
        click.echo("Next steps:")
        click.echo("  1. Review and customize .acrrc.yaml for your project")
        click.echo("  2. Set up LLM integration (optional):")
        click.echo("     export ANTHROPIC_API_KEY='your-api-key'")
        click.echo("  3. Run your first scan:")
        click.echo("     acr scan .")
        click.echo("")
        click.echo("For more information, see:")
        click.echo("  acr config help")
        click.echo("  acr patterns list")

    except OSError as e:
        logger.error(f"Failed to create {config_file}: {e}")
        raise click.ClickException(f"Failed to create configuration file: {e}")
