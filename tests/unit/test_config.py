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
