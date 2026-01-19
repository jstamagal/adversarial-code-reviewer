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

"""Configuration validator implementation."""

from pathlib import Path
from typing import Any, Dict, List

from acr.config.schema import ACRConfig
from acr.utils.errors import ConfigurationError


def validate_config(config: Dict[str, Any]) -> ACRConfig:
    """Validate configuration dictionary.

    Args:
        config: Configuration dictionary

    Returns:
        Validated configuration model

    Raises:
        ConfigurationError: If configuration is invalid
    """
    try:
        validated = ACRConfig(**config)
    except Exception as e:
        raise ConfigurationError(f"Configuration validation failed: {e}") from e

    _validate_paths(validated)
    _validate_severity(validated)
    _validate_patterns(validated)
    _validate_llm_config(validated)

    return validated


def _validate_paths(config: ACRConfig) -> None:
    """Validate file paths in configuration.

    Args:
        config: Configuration to validate

    Raises:
        ConfigurationError: If paths are invalid
    """
    project_root = Path(config.project.root).resolve()

    if not project_root.exists():
        raise ConfigurationError(f"Project root does not exist: {config.project.root}")

    if not project_root.is_dir():
        raise ConfigurationError(f"Project root is not a directory: {config.project.root}")

    custom_patterns = config.patterns.custom_patterns
    if custom_patterns:
        patterns_path = Path(custom_patterns)
        if not patterns_path.exists():
            raise ConfigurationError(f"Custom patterns directory does not exist: {custom_patterns}")

    output_dir = config.reporting.output_dir
    if output_dir:
        output_path = Path(output_dir)
        if not output_path.parent.exists():
            raise ConfigurationError(f"Report output directory parent does not exist: {output_dir}")


def _validate_severity(config: ACRConfig) -> None:
    """Validate severity threshold.

    Args:
        config: Configuration to validate

    Raises:
        ConfigurationError: If severity is invalid
    """
    valid_severities = {"critical", "high", "medium", "low", "info"}

    if config.patterns.severity_threshold not in valid_severities:
        raise ConfigurationError(
            f"Invalid severity threshold '{config.patterns.severity_threshold}'. "
            f"Must be one of: {', '.join(sorted(valid_severities))}"
        )


def _validate_patterns(config: ACRConfig) -> None:
    """Validate pattern configuration.

    Args:
        config: Configuration to validate

    Raises:
        ConfigurationError: If pattern configuration is invalid
    """
    enabled_patterns = config.patterns.enabled

    if enabled_patterns:
        if not isinstance(enabled_patterns, list):
            raise ConfigurationError("patterns.enabled must be a list")

        pattern_set = set(enabled_patterns)
        if len(pattern_set) != len(enabled_patterns):
            raise ConfigurationError("Duplicate patterns in patterns.enabled")


def _validate_llm_config(config: ACRConfig) -> None:
    """Validate LLM configuration.

    Args:
        config: Configuration to validate

    Raises:
        ConfigurationError: If LLM configuration is invalid
    """
    llm_config = config.llm

    if not llm_config.enabled:
        return

    valid_providers = {"anthropic", "openai"}
    if llm_config.provider not in valid_providers:
        raise ConfigurationError(
            f"Invalid LLM provider '{llm_config.provider}'. "
            f"Must be one of: {', '.join(sorted(valid_providers))}"
        )

    if llm_config.max_tokens <= 0:
        raise ConfigurationError("llm.max_tokens must be positive")

    if not llm_config.api_key_env or not llm_config.api_key_env.strip():
        raise ConfigurationError("llm.api_key_env must be specified when LLM is enabled")

    if llm_config.cache_enabled and llm_config.max_tokens < 100:
        raise ConfigurationError("llm.max_tokens should be at least 100 when caching is enabled")


def validate_exclusion_patterns(exclude_paths: List[str], exclude_files: List[str]) -> None:
    """Validate exclusion patterns.

    Args:
        exclude_paths: Path exclusion patterns
        exclude_files: File exclusion patterns

    Raises:
        ConfigurationError: If patterns are invalid
    """
    for pattern in exclude_paths:
        if not pattern or not isinstance(pattern, str):
            raise ConfigurationError(f"Invalid exclusion path pattern: {pattern}")

        if not pattern.startswith(("/", "./", "../")) and not pattern.endswith("/"):
            raise ConfigurationError(
                f"Exclusion path pattern should be a directory path (end with /): {pattern}"
            )

    for pattern in exclude_files:
        if not pattern or not isinstance(pattern, str):
            raise ConfigurationError(f"Invalid exclusion file pattern: {pattern}")

        if "*" not in pattern and "." not in pattern:
            raise ConfigurationError(
                f"Exclusion file pattern should contain wildcards or extension: {pattern}"
            )


def validate_language_config(config: ACRConfig) -> None:
    """Validate language-specific configuration.

    Args:
        config: Configuration to validate

    Raises:
        ConfigurationError: If language configuration is invalid
    """
    supported_languages = {"python", "javascript", "typescript", "java", "go", "rust"}

    for lang_name, lang_config in config.languages.items():
        if lang_name not in supported_languages:
            raise ConfigurationError(
                f"Unsupported language '{lang_name}'. "
                f"Supported languages: {', '.join(sorted(supported_languages))}"
            )

        if not isinstance(lang_config.enabled, bool):
            raise ConfigurationError(f"languages.{lang_name}.enabled must be a boolean")


def validate_reporting_formats(config: ACRConfig) -> None:
    """Validate reporting format configuration.

    Args:
        config: Configuration to validate

    Raises:
        ConfigurationError: If format configuration is invalid
    """
    valid_formats = {"markdown", "json", "yaml", "sarif", "html"}

    for fmt in config.reporting.formats:
        if fmt not in valid_formats:
            raise ConfigurationError(
                f"Invalid report format '{fmt}'. Must be one of: {', '.join(sorted(valid_formats))}"
            )
