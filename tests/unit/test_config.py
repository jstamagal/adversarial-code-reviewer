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

"""Unit tests for configuration."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from acr.config.loader import (
    convert_env_value,
    find_config_file,
    get_env_config,
    load_config,
    merge_configs,
)
from acr.config.schema import ACRConfig, LLMConfig, PatternConfig
from acr.config.validator import validate_config
from acr.utils.errors import ConfigurationError


def test_default_config(sample_config):
    """Test default configuration values."""
    assert isinstance(sample_config, ACRConfig)
    assert sample_config.patterns.severity_threshold == "medium"
    assert sample_config.llm.enabled is False


def test_pattern_config():
    """Test pattern configuration."""
    config = PatternConfig(enabled=["sql-injection", "xss"], severity_threshold="high")
    assert "sql-injection" in config.enabled
    assert config.severity_threshold == "high"


def test_llm_config():
    """Test LLM configuration."""
    config = LLMConfig(enabled=True, provider="anthropic", model="claude-3-5-sonnet-20241022")
    assert config.enabled is True
    assert config.provider == "anthropic"
    assert config.cache_enabled is True


def test_load_default_config():
    """Test loading default config when no config file exists."""
    config = load_config(config_path=None)
    assert isinstance(config, ACRConfig)
    assert config.patterns.severity_threshold == "medium"


def test_load_config_from_file():
    """Test loading config from file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        config_data = {
            "patterns": {"severity_threshold": "high"},
            "llm": {"enabled": True, "provider": "anthropic"},
        }
        yaml.dump(config_data, f)
        f.flush()
        config_path = f.name

    try:
        config = load_config(config_path=config_path)
        assert config.patterns.severity_threshold == "high"
        assert config.llm.enabled is True
        assert config.llm.provider == "anthropic"
    finally:
        os.unlink(config_path)


def test_load_config_invalid_yaml():
    """Test loading invalid YAML config."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("invalid: yaml: content:\n  - broken")
        f.flush()
        config_path = f.name

    try:
        with pytest.raises(ConfigurationError, match="Invalid YAML"):
            load_config(config_path=config_path)
    finally:
        os.unlink(config_path)


def test_load_config_file_not_found():
    """Test loading non-existent config file."""
    with pytest.raises(ConfigurationError, match="not found"):
        load_config(config_path="/nonexistent/config.yaml")


def test_load_config_invalid_values():
    """Test loading config with invalid values."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        config_data = {"patterns": {"severity_threshold": "invalid"}}
        yaml.dump(config_data, f)
        f.flush()
        config_path = f.name

    try:
        with pytest.raises(ConfigurationError):
            load_config(config_path=config_path)
    finally:
        os.unlink(config_path)


def test_find_config_file_in_current_dir():
    """Test finding config file in current directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / ".acrrc.yaml"
        with open(config_path, "w") as f:
            yaml.dump({}, f)

        found = find_config_file(start_dir=Path(tmpdir))
        assert found == str(config_path)


def test_find_config_file_in_parent_dir():
    """Test finding config file in parent directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        parent_dir = Path(tmpdir)
        config_path = parent_dir / ".acrrc.yaml"
        with open(config_path, "w") as f:
            yaml.dump({}, f)

        child_dir = parent_dir / "child" / "grandchild"
        child_dir.mkdir(parents=True)

        found = find_config_file(start_dir=child_dir)
        assert found == str(config_path)


def test_find_config_file_not_found():
    """Test config file not found."""
    with tempfile.TemporaryDirectory() as tmpdir:
        found = find_config_file(start_dir=Path(tmpdir))
        assert found is None


def test_merge_configs_simple():
    """Test simple config merge."""
    base = ACRConfig()
    override = {"patterns": {"severity_threshold": "critical"}}

    merged = merge_configs(base, override)
    assert merged.patterns.severity_threshold == "critical"


def test_merge_configs_nested():
    """Test nested config merge."""
    base = ACRConfig()
    override = {
        "llm": {"enabled": True, "model": "gpt-4"},
        "reporting": {"formats": ["json"]},
    }

    merged = merge_configs(base, override)
    assert merged.llm.enabled is True
    assert merged.llm.model == "gpt-4"
    assert merged.reporting.formats == ["json"]


def test_get_env_config():
    """Test getting config from environment variables."""
    os.environ["ACR_LLM__ENABLED"] = "true"
    os.environ["ACR_LLM__PROVIDER"] = "openai"
    os.environ["ACR_PATTERNS__SEVERITY_THRESHOLD"] = "critical"

    try:
        config = get_env_config()
        assert config["llm"]["enabled"] is True
        assert config["llm"]["provider"] == "openai"
        assert config["patterns"]["severity_threshold"] == "critical"
    finally:
        del os.environ["ACR_LLM__ENABLED"]
        del os.environ["ACR_LLM__PROVIDER"]
        del os.environ["ACR_PATTERNS__SEVERITY_THRESHOLD"]


def test_convert_env_value_boolean():
    """Test converting environment values to booleans."""
    assert convert_env_value("true") is True
    assert convert_env_value("True") is True
    assert convert_env_value("TRUE") is True
    assert convert_env_value("false") is False
    assert convert_env_value("False") is False


def test_convert_env_value_integer():
    """Test converting environment values to integers."""
    assert convert_env_value("123") == 123
    assert convert_env_value("0") == 0
    assert convert_env_value("-42") == -42


def test_convert_env_value_float():
    """Test converting environment values to floats."""
    assert convert_env_value("3.14") == 3.14
    assert convert_env_value("0.0") == 0.0


def test_convert_env_value_string():
    """Test converting environment values to strings."""
    assert convert_env_value("hello") == "hello"
    assert convert_env_value("test_value") == "test_value"


def test_validate_config_valid():
    """Test validating valid config."""
    config_data = {
        "project": {"name": "test", "root": "."},
        "patterns": {"severity_threshold": "high"},
    }
    config = validate_config(config_data)
    assert config.patterns.severity_threshold == "high"


def test_validate_config_invalid_severity():
    """Test validating config with invalid severity."""
    config_data = {"patterns": {"severity_threshold": "invalid"}}
    with pytest.raises(ConfigurationError, match="Invalid severity threshold"):
        validate_config(config_data)


def test_validate_config_invalid_project_root():
    """Test validating config with non-existent project root."""
    config_data = {"project": {"root": "/nonexistent/path"}}
    with pytest.raises(ConfigurationError, match="Project root does not exist"):
        validate_config(config_data)


def test_validate_config_invalid_llm_provider():
    """Test validating config with invalid LLM provider."""
    config_data = {"llm": {"enabled": True, "provider": "invalid", "api_key_env": "TEST_KEY"}}
    with pytest.raises(ConfigurationError, match="Invalid LLM provider"):
        validate_config(config_data)


def test_validate_config_empty_llm_api_key():
    """Test validating config with LLM enabled but empty API key env."""
    config_data = {"llm": {"enabled": True, "provider": "anthropic", "api_key_env": ""}}
    with pytest.raises(ConfigurationError, match="api_key_env must be specified"):
        validate_config(config_data)


def test_validate_config_duplicate_patterns():
    """Test validating config with duplicate patterns."""
    config_data = {"patterns": {"enabled": ["sql-injection", "sql-injection"]}}
    with pytest.raises(ConfigurationError, match="Duplicate patterns"):
        validate_config(config_data)


def test_project_config_defaults():
    """Test ProjectConfig default values."""
    from acr.config.schema import ProjectConfig

    config = ProjectConfig()
    assert config.name == ""
    assert config.root == "."


def test_project_config_with_values():
    """Test ProjectConfig with custom values."""
    from acr.config.schema import ProjectConfig

    config = ProjectConfig(name="myproject", root="/path/to/project")
    assert config.name == "myproject"
    assert config.root == "/path/to/project"


def test_language_config_defaults():
    """Test LanguageConfig default values."""
    from acr.config.schema import LanguageConfig

    config = LanguageConfig()
    assert config.enabled is True
    assert config.version == ""
    assert config.legacy_mode is False


def test_language_config_with_values():
    """Test LanguageConfig with custom values."""
    from acr.config.schema import LanguageConfig

    config = LanguageConfig(enabled=False, version="3.11", legacy_mode=True)
    assert config.enabled is False
    assert config.version == "3.11"
    assert config.legacy_mode is True


def test_redaction_pattern_config():
    """Test RedactionPatternConfig."""
    from acr.config.schema import RedactionPatternConfig

    config = RedactionPatternConfig(
        name="custom_api_key", pattern=r"API_KEY_[A-Z0-9]{32}", description="Custom API key pattern"
    )
    assert config.name == "custom_api_key"
    assert config.pattern == r"API_KEY_[A-Z0-9]{32}"
    assert config.description == "Custom API key pattern"


def test_redaction_config_defaults():
    """Test RedactionConfig default values."""
    from acr.config.schema import RedactionConfig

    config = RedactionConfig()
    assert config.enabled is True
    assert config.entropy_threshold == 4.5
    assert config.entropy_min_length == 20
    assert config.custom_patterns == []
    assert config.log_redactions is True
    assert config.verify_redaction is True


def test_redaction_config_with_values():
    """Test RedactionConfig with custom values."""
    from acr.config.schema import RedactionConfig, RedactionPatternConfig

    custom_pattern = RedactionPatternConfig(
        name="test", pattern="test.*", description="Test pattern"
    )
    config = RedactionConfig(
        enabled=False,
        entropy_threshold=3.5,
        entropy_min_length=15,
        custom_patterns=[custom_pattern],
        log_redactions=False,
        verify_redaction=False,
    )
    assert config.enabled is False
    assert config.entropy_threshold == 3.5
    assert config.entropy_min_length == 15
    assert len(config.custom_patterns) == 1
    assert config.custom_patterns[0].name == "test"
    assert config.log_redactions is False
    assert config.verify_redaction is False


def test_llm_config_keyring_defaults():
    """Test LLMConfig keyring-related default values."""
    config = LLMConfig()
    assert config.use_keyring is True
    assert config.keyring_name == "api_key"


def test_llm_config_with_keyring_settings():
    """Test LLMConfig with custom keyring settings."""
    config = LLMConfig(
        enabled=True, provider="anthropic", use_keyring=False, keyring_name="custom_key"
    )
    assert config.use_keyring is False
    assert config.keyring_name == "custom_key"


def test_analysis_config_defaults():
    """Test AnalysisConfig default values."""
    from acr.config.schema import AnalysisConfig

    config = AnalysisConfig()
    assert config.max_depth == 10
    assert config.timeout == 300
    assert config.parallel is False
    assert config.analyze_generated_code is False


def test_analysis_config_with_values():
    """Test AnalysisConfig with custom values."""
    from acr.config.schema import AnalysisConfig

    config = AnalysisConfig(max_depth=20, timeout=600, parallel=True, analyze_generated_code=True)
    assert config.max_depth == 20
    assert config.timeout == 600
    assert config.parallel is True
    assert config.analyze_generated_code is True


def test_reporting_config_defaults():
    """Test ReportingConfig default values."""
    from acr.config.schema import ReportingConfig

    config = ReportingConfig()
    assert config.formats == ["markdown"]
    assert config.output_dir == "./acr-reports"
    assert config.include_code_snippets is True
    assert config.max_snippet_lines == 10


def test_reporting_config_with_values():
    """Test ReportingConfig with custom values."""
    from acr.config.schema import ReportingConfig

    config = ReportingConfig(
        formats=["json", "yaml"],
        output_dir="/tmp/reports",
        include_code_snippets=False,
        max_snippet_lines=20,
    )
    assert config.formats == ["json", "yaml"]
    assert config.output_dir == "/tmp/reports"
    assert config.include_code_snippets is False
    assert config.max_snippet_lines == 20


def test_exclusion_config_defaults():
    """Test ExclusionConfig default values."""
    from acr.config.schema import ExclusionConfig

    config = ExclusionConfig()
    assert config.paths == ["tests/", "venv/", ".venv/", "__pycache__/"]
    assert config.files == ["*.pyc", "*.pyo"]
    assert config.generated_code_patterns == []


def test_exclusion_config_with_values():
    """Test ExclusionConfig with custom values."""
    from acr.config.schema import ExclusionConfig

    config = ExclusionConfig(
        paths=["custom/tests/", "build/"],
        files=["*.log", "*.tmp"],
        generated_code_patterns=[r"generated_.*", r"__init__\.py"],
    )
    assert config.paths == ["custom/tests/", "build/"]
    assert config.files == ["*.log", "*.tmp"]
    assert config.generated_code_patterns == [r"generated_.*", r"__init__\.py"]


def test_validate_config_invalid_max_tokens():
    """Test validating config with invalid max_tokens."""
    from acr.config.validator import validate_config

    config_data = {
        "llm": {
            "enabled": True,
            "provider": "anthropic",
            "api_key_env": "TEST_KEY",
            "max_tokens": -1,
        }
    }
    with pytest.raises(ConfigurationError, match="max_tokens must be positive"):
        validate_config(config_data)


def test_validate_config_cache_enabled_small_max_tokens():
    """Test validating config with cache enabled but max_tokens too small."""
    from acr.config.validator import validate_config

    config_data = {
        "llm": {
            "enabled": True,
            "provider": "anthropic",
            "api_key_env": "TEST_KEY",
            "max_tokens": 50,
            "cache_enabled": True,
        }
    }
    with pytest.raises(
        ConfigurationError, match="max_tokens should be at least 100 when caching is enabled"
    ):
        validate_config(config_data)


def test_validate_config_cache_enabled_valid_max_tokens():
    """Test validating config with cache enabled and valid max_tokens."""
    from acr.config.validator import validate_config

    config_data = {
        "llm": {
            "enabled": True,
            "provider": "anthropic",
            "api_key_env": "TEST_KEY",
            "max_tokens": 100,
            "cache_enabled": True,
        }
    }
    config = validate_config(config_data)
    assert config.llm.max_tokens == 100
    assert config.llm.cache_enabled is True


def test_validate_exclusion_patterns_valid():
    """Test validating valid exclusion patterns."""
    from acr.config.validator import validate_exclusion_patterns

    paths = ["tests/", "build/", "./tmp/", "../other/"]
    files = ["*.pyc", "*.log", "test_*.tmp"]
    validate_exclusion_patterns(paths, files)


def test_validate_exclusion_patterns_invalid_path_no_slash():
    """Test validating exclusion path without trailing slash."""
    from acr.config.validator import validate_exclusion_patterns

    paths = ["tests", "build"]
    with pytest.raises(ConfigurationError, match="should be a directory path"):
        validate_exclusion_patterns(paths, [])


def test_validate_exclusion_patterns_invalid_path_empty():
    """Test validating empty exclusion path pattern."""
    from acr.config.validator import validate_exclusion_patterns

    paths = [""]
    with pytest.raises(ConfigurationError, match="Invalid exclusion path pattern"):
        validate_exclusion_patterns(paths, [])


def test_validate_exclusion_patterns_invalid_file_pattern():
    """Test validating file pattern without wildcard or extension."""
    from acr.config.validator import validate_exclusion_patterns

    files = ["testfile"]
    with pytest.raises(ConfigurationError, match="should contain wildcards or extension"):
        validate_exclusion_patterns([], files)


def test_validate_exclusion_patterns_invalid_file_empty():
    """Test validating empty file pattern."""
    from acr.config.validator import validate_exclusion_patterns

    files = [""]
    with pytest.raises(ConfigurationError, match="Invalid exclusion file pattern"):
        validate_exclusion_patterns([], files)


def test_validate_language_config_valid():
    """Test validating valid language configuration."""
    from acr.config.validator import validate_language_config
    from acr.config.schema import ACRConfig

    config_data = {
        "languages": {
            "python": {"enabled": True, "version": "3.11"},
            "javascript": {"enabled": False, "version": "18"},
        }
    }
    config = ACRConfig(**config_data)
    validate_language_config(config)


def test_validate_language_config_unsupported_language():
    """Test validating unsupported language."""
    from acr.config.validator import validate_language_config
    from acr.config.schema import ACRConfig

    config_data = {"languages": {"cobol": {"enabled": True}}}
    config = ACRConfig(**config_data)
    with pytest.raises(ConfigurationError, match="Unsupported language"):
        validate_language_config(config)


def test_validate_reporting_formats_valid():
    """Test validating valid reporting formats."""
    from acr.config.validator import validate_reporting_formats
    from acr.config.schema import ACRConfig

    config_data = {"reporting": {"formats": ["markdown", "json", "sarif"]}}
    config = ACRConfig(**config_data)
    validate_reporting_formats(config)


def test_validate_reporting_formats_invalid():
    """Test validating invalid reporting format."""
    from acr.config.validator import validate_reporting_formats
    from acr.config.schema import ACRConfig

    config_data = {"reporting": {"formats": ["pdf", "markdown"]}}
    config = ACRConfig(**config_data)
    with pytest.raises(ConfigurationError, match="Invalid report format"):
        validate_reporting_formats(config)


def test_full_config_with_all_sections():
    """Test loading and validating a complete configuration."""
    from acr.config.validator import validate_config

    config_data = {
        "project": {"name": "test-project", "root": "."},
        "patterns": {
            "enabled": ["sql-injection", "xss"],
            "severity_threshold": "high",
            "custom_patterns": "",
        },
        "llm": {
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-3-5-sonnet-20241022",
            "api_key_env": "ANTHROPIC_API_KEY",
            "use_keyring": True,
            "keyring_name": "api_key",
            "max_tokens": 4096,
            "cache_enabled": True,
            "redaction": {
                "enabled": True,
                "entropy_threshold": 4.5,
                "entropy_min_length": 20,
                "log_redactions": True,
                "verify_redaction": True,
            },
        },
        "analysis": {
            "max_depth": 10,
            "timeout": 300,
            "parallel": False,
            "analyze_generated_code": False,
        },
        "reporting": {
            "formats": ["markdown", "json"],
            "output_dir": "./reports",
            "include_code_snippets": True,
            "max_snippet_lines": 10,
        },
        "languages": {
            "python": {"enabled": True, "version": "3.11", "legacy_mode": False},
            "javascript": {"enabled": False, "version": "18"},
        },
        "exclude": {
            "paths": ["tests/", "venv/"],
            "files": ["*.pyc"],
            "generated_code_patterns": [r"generated_.*"],
        },
    }
    config = validate_config(config_data)
    assert config.project.name == "test-project"
    assert config.patterns.severity_threshold == "high"
    assert config.llm.enabled is True
    assert config.llm.use_keyring is True
    assert config.analysis.analyze_generated_code is False
    assert config.reporting.max_snippet_lines == 10
    assert "python" in config.languages
