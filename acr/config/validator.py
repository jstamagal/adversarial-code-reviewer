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
from typing import Any, Dict, List, Tuple

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


def get_fix_suggestions(error: Exception, config_data: Dict[str, Any]) -> List[str]:
    """Get fix suggestions for configuration validation errors.

    Args:
        error: The validation error that occurred
        config_data: Configuration data that was being validated

    Returns:
        List of fix suggestions
    """
    suggestions = []
    error_message = str(error)

    if "Invalid severity threshold" in error_message:
        suggestions.append(
            "Change 'patterns.severity_threshold' to one of: critical, high, medium, low, info"
        )
        if "severity_threshold" in config_data.get("patterns", {}):
            current = config_data["patterns"]["severity_threshold"]
            suggestions.append(f"Current value '{current}' is not valid")

    elif "Invalid LLM provider" in error_message:
        suggestions.append("Change 'llm.provider' to one of: anthropic, openai")
        if "provider" in config_data.get("llm", {}):
            current = config_data["llm"]["provider"]
            suggestions.append(f"Current value '{current}' is not a valid provider")

    elif "api_key_env must be specified" in error_message:
        suggestions.append("Set 'llm.api_key_env' to your API key environment variable name")
        suggestions.append("Example: api_key_env: 'ANTHROPIC_API_KEY'")
        suggestions.append("Or set 'llm.enabled' to false if you don't want to use LLM features")

    elif "max_tokens must be positive" in error_message:
        suggestions.append(
            "Set 'llm.max_tokens' to a positive number (recommended: 4096 or higher)"
        )
        if "max_tokens" in config_data.get("llm", {}):
            current = config_data["llm"]["max_tokens"]
            suggestions.append(f"Current value '{current}' is invalid")

    elif "max_tokens should be at least 100" in error_message:
        suggestions.append("Increase 'llm.max_tokens' to at least 100 when caching is enabled")
        suggestions.append("Recommended: Set max_tokens to 4096 or disable caching")
        suggestions.append("Example: max_tokens: 4096 or cache_enabled: false")

    elif "Project root does not exist" in error_message:
        suggestions.append("Verify 'project.root' points to an existing directory")
        suggestions.append("Use '.' for current directory or an absolute path")
        if "root" in config_data.get("project", {}):
            current = config_data["project"]["root"]
            suggestions.append(f"Current value: {current}")

    elif "Project root is not a directory" in error_message:
        suggestions.append("'project.root' must be a directory, not a file")
        if "root" in config_data.get("project", {}):
            current = config_data["project"]["root"]
            suggestions.append(f"Current value: {current}")

    elif "Custom patterns directory does not exist" in error_message:
        suggestions.append(
            "Create the custom patterns directory or remove 'patterns.custom_patterns'"
        )
        suggestions.append(
            "To disable custom patterns, set 'patterns.custom_patterns' to empty string"
        )

    elif "Duplicate patterns" in error_message:
        suggestions.append("Remove duplicate entries from 'patterns.enabled' list")
        if "enabled" in config_data.get("patterns", {}):
            patterns = config_data["patterns"]["enabled"]
            if isinstance(patterns, list):
                seen = set()
                duplicates = [p for p in patterns if p in seen or seen.add(p)]
                if duplicates:
                    suggestions.append(f"Duplicate patterns found: {', '.join(duplicates)}")

    elif "Invalid report format" in error_message:
        suggestions.append(
            "Change 'reporting.formats' to contain only: markdown, json, yaml, sarif, html"
        )
        if "formats" in config_data.get("reporting", {}):
            formats = config_data["reporting"]["formats"]
            valid_formats = {"markdown", "json", "yaml", "sarif", "html"}
            invalid = [f for f in formats if f not in valid_formats]
            if invalid:
                suggestions.append(f"Invalid formats: {', '.join(invalid)}")

    elif "Unsupported language" in error_message:
        suggestions.append("Remove unsupported language from 'languages' section")
        suggestions.append("Supported languages: python, javascript, typescript, java, go, rust")

    elif "patterns.enabled must be a list" in error_message:
        suggestions.append("Set 'patterns.enabled' to a list of pattern names")
        suggestions.append("Example: patterns.enabled: ['sql-injection', 'xss']")

    elif "should be a directory path" in error_message:
        suggestions.append("Exclusion path patterns should end with '/' to indicate a directory")
        suggestions.append("Example: exclude.paths: ['tests/', 'build/']")

    elif "should contain wildcards or extension" in error_message:
        suggestions.append(
            "Exclusion file patterns should contain wildcards (*) or have an extension"
        )
        suggestions.append("Example: exclude.files: ['*.pyc', '*.log']")

    elif "Invalid YAML" in error_message:
        suggestions.append("Fix YAML syntax errors in the configuration file")
        suggestions.append("Common issues:")
        suggestions.append("  - Incorrect indentation (use 2 spaces)")
        suggestions.append("  - Missing colons after keys")
        suggestions.append("  - Unbalanced quotes or brackets")
        suggestions.append("  - Use YAML linter: https://www.yamllint.com/")

    elif "patterns.enabled" in error_message:
        suggestions.append("Check 'patterns.enabled' is a valid list of pattern names")

    else:
        suggestions.append("Check configuration file syntax and values")
        suggestions.append("Run 'acr config list' to see all available options")
        suggestions.append("Run 'acr config show' to see current configuration")

    return suggestions


def try_auto_fix(error: Exception, config_data: Dict[str, Any], config_path: Path) -> bool:
    """Attempt to automatically fix common configuration issues.

    Args:
        error: The validation error that occurred
        config_data: Configuration data that was being validated
        config_path: Path to the configuration file

    Returns:
        True if auto-fix was applied, False otherwise
    """
    error_message = str(error)

    if "Duplicate patterns" in error_message:
        if "enabled" in config_data.get("patterns", {}):
            patterns = config_data["patterns"]["enabled"]
            if isinstance(patterns, list):
                seen = set()
                unique_patterns = []
                for p in patterns:
                    if p not in seen:
                        seen.add(p)
                        unique_patterns.append(p)

                if len(unique_patterns) != len(patterns):
                    config_data["patterns"]["enabled"] = unique_patterns
                    return True

    return False
