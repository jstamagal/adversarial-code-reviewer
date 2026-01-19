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

"""Configuration loader implementation."""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from acr.config.schema import ACRConfig
from acr.utils.errors import ConfigurationError


def load_config(config_path: Optional[str] = None) -> ACRConfig:
    """Load ACR configuration from file.

    Args:
        config_path: Path to config file. If None, searches for .acrrc.yaml

    Returns:
        Loaded configuration

    Raises:
        ConfigurationError: If config file not found or invalid
    """
    if config_path is None:
        config_path = find_config_file()

    if config_path is None:
        return ACRConfig()

    path = Path(config_path)

    if not path.exists():
        raise ConfigurationError(f"Configuration file not found: {config_path}")

    try:
        with open(path, encoding="utf-8") as f:
            config_data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in configuration file: {e}") from e
    except Exception as e:
        raise ConfigurationError(f"Error reading configuration file: {e}") from e

    if config_data is None:
        config_data = {}

    from acr.config.validator import validate_config

    return validate_config(config_data)


def find_config_file(start_dir: Optional[Path] = None) -> Optional[str]:
    """Find .acrrc.yaml configuration file.

    Searches for .acrrc.yaml starting from start_dir and moving up the directory tree.

    Args:
        start_dir: Directory to start search from. Defaults to current working directory.

    Returns:
        Path to config file if found, None otherwise
    """
    if start_dir is None:
        start_dir = Path.cwd()

    config_filenames = [".acrrc.yaml", ".acrrc.yml", "acrrc.yaml"]

    current_dir = start_dir.resolve()

    while current_dir != current_dir.parent:
        for filename in config_filenames:
            config_path = current_dir / filename
            if config_path.exists():
                return str(config_path)

        current_dir = current_dir.parent

    return None


def merge_configs(base_config: ACRConfig, override_config: Dict[str, Any]) -> ACRConfig:
    """Merge override configuration into base configuration.

    Args:
        base_config: Base configuration
        override_config: Override values as dictionary

    Returns:
        Merged configuration
    """
    base_dict = base_config.model_dump()

    def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    merged_dict = deep_merge(base_dict, override_config)

    return ACRConfig(**merged_dict)


def get_env_config() -> Dict[str, Any]:
    """Get configuration values from environment variables.

    Environment variables are prefixed with ACR_ and use double underscores
    to denote nested keys (e.g., ACR_LLM__ENABLED=true).

    Returns:
        Configuration dictionary from environment variables
    """
    config: Dict[str, Any] = {}

    for key, value in os.environ.items():
        if key.startswith("ACR_"):
            config_key = key[4:].lower()
            parts = config_key.split("__")

            current = config
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]

            last_part = parts[-1]
            current[last_part] = convert_env_value(value)

    return config


def convert_env_value(value: str) -> Any:
    """Convert environment variable string to appropriate type.

    Args:
        value: String value from environment variable

    Returns:
        Converted value
    """
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False

    try:
        return int(value)
    except ValueError:
        pass

    try:
        return float(value)
    except ValueError:
        pass

    return value
