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

"""Tests for legacy code support."""

import pytest
from pathlib import Path
from acr.core.legacy_support import LegacySupport
from acr.config.schema import ACRConfig, LanguageConfig


class TestLegacySupport:
    """Tests for LegacySupport class."""

    def test_minimum_version_constant(self):
        """Test that minimum supported version is 3.8."""
        assert LegacySupport.MINIMUM_SUPPORTED_VERSION == (3, 8)

    def test_init_without_config(self):
        """Test initialization without configuration."""
        support = LegacySupport()
        assert support.config is None
        assert support._target_python_version is None
        assert support._has_warned is False

    def test_init_with_config(self):
        """Test initialization with configuration."""
        config = ACRConfig()
        support = LegacySupport(config)
        assert support.config == config
        assert support._has_warned is False

    def test_check_python_version_current(self, caplog):
        """Test checking current Python version (should be supported)."""
        support = LegacySupport()
        current, is_supported, message = support.check_python_version()

        assert isinstance(current, tuple)
        assert len(current) == 2
        assert is_supported is True
        assert message == ""
        assert support._has_warned is False

    def test_check_python_version_with_target(self, caplog):
        """Test checking specific target Python version."""
        support = LegacySupport()
        current, is_supported, message = support.check_python_version(target_version=(3, 7))

        assert current[0] >= 3
        assert is_supported is False
        assert "Warning" in message
        assert "Python 3.7" in message
        assert "minimum supported version (3.8)" in message
        assert support._has_warned is True

    def test_check_python_version_unsupported_no_duplicate_warning(self, caplog):
        """Test that warning is only shown once for unsupported version."""
        support = LegacySupport()

        _, is_supported1, message1 = support.check_python_version(target_version=(3, 5))
        _, is_supported2, message2 = support.check_python_version(target_version=(3, 5))

        assert is_supported1 is False
        assert message1 != ""

        assert is_supported2 is False
        assert message2 == ""
        assert support._has_warned is True

    def test_detect_version_from_code_dataclass(self):
        """Detect Python 3.7+ from dataclass usage."""
        support = LegacySupport()
        source_code = """
from dataclasses import dataclass

@dataclass
class User:
    name: str
    age: int
"""
        version = support.detect_version_from_code(Path("test.py"), source_code)
        assert version == (3, 7)

    def test_detect_version_from_code_literal_type(self):
        """Detect Python 3.8+ from typing.Literal."""
        support = LegacySupport()
        source_code = """
from typing import Literal

def process(action: Literal["create", "delete"]):
    pass
"""
        version = support.detect_version_from_code(Path("test.py"), source_code)
        assert version == (3, 8)

    def test_detect_version_from_code_walrus_operator(self):
        """Detect Python 3.8+ from walrus operator."""
        support = LegacySupport()
        source_code = """
def process():
    while (line := input()):
        print(line)
"""
        version = support.detect_version_from_code(Path("test.py"), source_code)
        assert version == (3, 8)

    def test_detect_version_from_code_match_statement(self):
        """Detect Python 3.10+ from match statement."""
        support = LegacySupport()
        source_code = """
def process(value):
    match value:
        case 1:
            return "one"
        case _:
            return "other"
"""
        version = support.detect_version_from_code(Path("test.py"), source_code)
        assert version == (3, 10)

    def test_detect_version_from_code_multiple_features(self):
        """Detect highest version from multiple features."""
        support = LegacySupport()
        source_code = """
from typing import Literal
from dataclasses import dataclass

def process():
    if (x := 5):
        pass
"""
        version = support.detect_version_from_code(Path("test.py"), source_code)
        assert version == (3, 8)

    def test_detect_version_from_code_no_features(self):
        """Return None when no version-specific features found."""
        support = LegacySupport()
        source_code = """
def hello():
    return "world"
"""
        version = support.detect_version_from_code(Path("test.py"), source_code)
        assert version is None

    def test_detect_version_from_code_future_import(self):
        """Detect Python 3.7+ from __future__ import."""
        support = LegacySupport()
        source_code = """
from __future__ import annotations

def hello() -> str:
    return "world"
"""
        version = support.detect_version_from_code(Path("test.py"), source_code)
        assert version == (3, 7)

    def test_check_file_no_version_detected(self):
        """Check file when version cannot be detected."""
        support = LegacySupport()
        source_code = "def hello(): return 'world'"

        warnings = support.check_file(Path("test.py"), source_code)
        assert len(warnings) == 0

    def test_check_file_legacy_version_detected(self, caplog):
        """Check file when legacy version is detected."""
        support = LegacySupport()
        source_code = """
from dataclasses import dataclass

@dataclass
class User:
    name: str
"""

        warnings = support.check_file(Path("legacy_test.py"), source_code)
        assert len(warnings) == 1
        assert "Python 3.7" in warnings[0]
        assert "below minimum supported version (3.8)" in warnings[0]

    def test_check_file_current_version_detected(self, caplog):
        """Check file when current version features are used."""
        support = LegacySupport()
        source_code = """
from typing import Literal

def process(action: Literal["create", "delete"]):
    pass
"""

        warnings = support.check_file(Path("test.py"), source_code)
        assert len(warnings) == 0

    def test_is_legacy_mode_enabled_no_config(self):
        """Test legacy mode when no config provided."""
        support = LegacySupport()
        assert support.is_legacy_mode_enabled() is False

    def test_is_legacy_mode_enabled_without_flag(self):
        """Test legacy mode when flag is not set."""
        config = ACRConfig()
        config.languages["python"] = LanguageConfig()
        support = LegacySupport(config)

        assert support.is_legacy_mode_enabled() is False

    def test_is_legacy_mode_enabled_with_flag(self):
        """Test legacy mode when flag is enabled."""
        config = ACRConfig()
        config.languages["python"] = LanguageConfig(legacy_mode=True)
        support = LegacySupport(config)

        assert support.is_legacy_mode_enabled() is True

    def test_is_legacy_mode_enabled_for_other_language(self):
        """Test legacy mode for non-Python language."""
        config = ACRConfig()
        config.languages["javascript"] = LanguageConfig(legacy_mode=True)
        support = LegacySupport(config)

        assert support.is_legacy_mode_enabled() is False

    def test_should_analyze_legacy_no_config(self):
        """Test analysis decision without config."""
        support = LegacySupport()
        assert support.should_analyze_legacy(Path("test.py")) is False

    def test_should_analyze_legacy_disabled(self):
        """Test analysis when legacy mode is disabled."""
        config = ACRConfig()
        config.languages["python"] = LanguageConfig(legacy_mode=False)
        support = LegacySupport(config)

        assert support.should_analyze_legacy(Path("test.py")) is False

    def test_should_analyze_legacy_enabled(self):
        """Test analysis when legacy mode is enabled."""
        config = ACRConfig()
        config.languages["python"] = LanguageConfig(legacy_mode=True)
        support = LegacySupport(config)

        assert support.should_analyze_legacy(Path("test.py")) is True

    def test_get_known_limitations_35(self):
        """Test known limitations for Python 3.5."""
        support = LegacySupport()
        limitations = support.get_known_limitations((3, 5))

        assert len(limitations) > 0
        assert "async/await syntax is not fully supported" in limitations

    def test_get_known_limitations_36(self):
        """Test known limitations for Python 3.6."""
        support = LegacySupport()
        limitations = support.get_known_limitations((3, 6))

        assert len(limitations) > 0
        assert "Dataclasses are not supported" in limitations

    def test_get_known_limitations_37(self):
        """Test known limitations for Python 3.7."""
        support = LegacySupport()
        limitations = support.get_known_limitations((3, 7))

        assert "Positional-only parameters not supported" in limitations

    def test_get_known_limitations_38(self):
        """Test known limitations for Python 3.8 (minimum supported)."""
        support = LegacySupport()
        limitations = support.get_known_limitations((3, 8))

        assert "f-strings are not supported" not in limitations

    def test_get_known_limitations_39(self):
        """Test known limitations for Python 3.9."""
        support = LegacySupport()
        limitations = support.get_known_limitations((3, 9))

        assert "f-strings are not supported" not in limitations

    def test_get_known_limitations_310(self):
        """Test known limitations for Python 3.10."""
        support = LegacySupport()
        limitations = support.get_known_limitations((3, 10))

        assert "f-strings are not supported" not in limitations
        assert "f-string debug syntax" not in limitations
        assert "str.removeprefix" not in limitations

    def test_get_known_limitations_current(self):
        """Test known limitations for current Python version."""
        support = LegacySupport()
        limitations = support.get_known_limitations((3, 12))

        assert len([l for l in limitations if "3.12" in l or "3.11" in l]) == 0

    def test_get_known_limitations_comprehensive_37(self):
        """Test that Python 3.7 has expected limitations."""
        support = LegacySupport()
        limitations = support.get_known_limitations((3, 7))

        expected_present = [
            "Positional-only parameters",
            "Assignment expressions",
            "typing.Literal",
            "F-string debug",
            "asyncio.run()",
            "Dictionary union",
            "str.removeprefix",
            "PEP 585",
            "Structural pattern matching",
            "Parenthesized context managers",
            "Exception groups",
            "tomllib",
            "Self type",
            "f-string improvements",
            "Override decorator",
        ]

        for feature in expected_present:
            assert any(feature in limitation for limitation in limitations)

    def test_check_python_version_sets_target(self):
        """Test that check_python_version sets target version."""
        support = LegacySupport()

        support.check_python_version(target_version=(3, 6))
        assert support._target_python_version == (3, 6)

        _, is_supported, _ = support.check_python_version()
        assert is_supported is False

    def test_multiple_version_features_detects_latest(self):
        """Test detection returns the latest version from multiple features."""
        support = LegacySupport()
        source_code = """
from __future__ import annotations  # 3.7
from typing import Literal  # 3.8
from dataclasses import dataclass  # 3.7
"""

        version = support.detect_version_from_code(Path("test.py"), source_code)
        assert version == (3, 8)

    def test_detect_version_from_code_typing_extensions(self):
        """Detect Python 3.6+ from typing_extensions."""
        support = LegacySupport()
        source_code = """
from typing_extensions import Literal

def process():
    pass
"""
        version = support.detect_version_from_code(Path("test.py"), source_code)
        assert version == (3, 6)

    def test_detect_version_from_code_async_future(self):
        """Detect Python 3.7+ from async __future__ import."""
        support = LegacySupport()
        source_code = """
from __future__ import async_function

async def process():
    pass
"""
        version = support.detect_version_from_code(Path("test.py"), source_code)
        assert version == (3, 7)

    def test_target_version_persists(self):
        """Test that target version persists across calls."""
        support = LegacySupport()
        support.check_python_version(target_version=(3, 7))

        _, is_supported1, _ = support.check_python_version()
        assert is_supported1 is False

        support._has_warned = False
        _, is_supported2, _ = support.check_python_version()
        assert is_supported2 is False
        assert support._has_warned is True
