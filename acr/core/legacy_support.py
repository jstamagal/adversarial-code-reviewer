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

"""Legacy code support for Python versions < 3.8."""

import sys
from typing import Optional, List
from pathlib import Path
import re

from acr.utils.logger import get_logger

log = get_logger(__name__)


class LegacySupport:
    """Handle legacy Python code detection and warnings."""

    MINIMUM_SUPPORTED_VERSION = (3, 8)

    def __init__(self, config=None):
        """Initialize legacy support.

        Args:
            config: ACR configuration object
        """
        self.config = config
        self._target_python_version: Optional[tuple] = None
        self._has_warned: bool = False

    def check_python_version(
        self, target_version: Optional[tuple] = None
    ) -> tuple[tuple[int, int], bool, str]:
        """Check if Python version meets minimum requirements.

        Args:
            target_version: Optional target Python version (major, minor)

        Returns:
            Tuple of (current_version, is_supported, message)
        """
        current_version = (sys.version_info.major, sys.version_info.minor)

        if target_version:
            self._target_python_version = target_version

        target = self._target_python_version or current_version
        is_supported = target >= self.MINIMUM_SUPPORTED_VERSION

        message = ""
        if not is_supported and not self._has_warned:
            message = (
                f"Warning: Python {target[0]}.{target[1]} is below the minimum "
                f"supported version ({self.MINIMUM_SUPPORTED_VERSION[0]}.{self.MINIMUM_SUPPORTED_VERSION[1]}). "
                "Some features may not work correctly. Consider upgrading to Python 3.8 or later."
            )
            log.warning(message)
            self._has_warned = True

        return current_version, is_supported, message

    def detect_version_from_code(
        self, file_path: Path, source_code: str
    ) -> Optional[tuple[int, int]]:
        """Detect Python version target from source code.

        Args:
            file_path: Path to Python file
            source_code: Source code content

        Returns:
            Detected Python version as (major, minor) tuple, or None if undetermined
        """
        version = None

        patterns = [
            (r"__future__.*annotations", (3, 7)),
            (r"__future__.*async", (3, 7)),
            (r"__future__.*generator_stop", (3, 7)),
            (r"dataclass", (3, 7)),
            (r"from typing import.*Literal", (3, 8)),
            (r"from typing_extensions import", (3, 6)),
            (r":=.*$", (3, 8)),
            (r"@dataclass_transform", (3, 11)),
            (r"@override", (3, 12)),
            (r"\.bit_count\(", (3, 8)),
            (r"\.bit_length\(\)", (3, 1)),
            (r"match\s+\w+\s*:", (3, 10)),
            (r"case\s+.*:", (3, 10)),
        ]

        for pattern, min_version in patterns:
            if re.search(pattern, source_code, re.MULTILINE):
                if version is None or min_version > version:
                    version = min_version

        return version

    def check_file(self, file_path: Path, source_code: str) -> List[str]:
        """Check a Python file for legacy code issues.

        Args:
            file_path: Path to Python file
            source_code: Source code content

        Returns:
            List of warning messages
        """
        warnings = []

        detected_version = self.detect_version_from_code(file_path, source_code)

        if detected_version and detected_version < self.MINIMUM_SUPPORTED_VERSION:
            warning = (
                f"{file_path}: Targets Python {detected_version[0]}.{detected_version[1]}, "
                f"which is below minimum supported version ({self.MINIMUM_SUPPORTED_VERSION[0]}.{self.MINIMUM_SUPPORTED_VERSION[1]}). "
                "Analysis may be incomplete."
            )
            warnings.append(warning)
            log.warning(warning)

        return warnings

    def is_legacy_mode_enabled(self) -> bool:
        """Check if legacy analysis mode is enabled in configuration.

        Returns:
            True if legacy mode is enabled
        """
        if not self.config:
            return False

        if hasattr(self.config, "languages") and "python" in self.config.languages:
            python_config = self.config.languages["python"]
            return getattr(python_config, "legacy_mode", False)

        return False

    def get_known_limitations(self, python_version: tuple[int, int]) -> List[str]:
        """Get list of known limitations for a specific Python version.

        Args:
            python_version: Python version as (major, minor) tuple

        Returns:
            List of limitation descriptions
        """
        limitations = []

        if python_version < (3, 6):
            limitations.extend(
                [
                    "async/await syntax is not fully supported",
                    "Type hints using 'typing' module may be limited",
                ]
            )

        if python_version < (3, 7):
            limitations.extend(
                [
                    "Dataclasses are not supported",
                    "OrderedDict guarantees may not be preserved",
                    "Postponed evaluation of annotations not available",
                ]
            )

        if python_version < (3, 8):
            limitations.extend(
                [
                    "Positional-only parameters not supported",
                    "Assignment expressions (walrus operator :=) not supported",
                    "typing.Literal not available",
                    "typing.TypedDict may have limited functionality",
                    "F-string debug syntax (f'{var=}') not supported",
                    "asyncio.run() not available",
                    "ContextVars may not be available",
                ]
            )

        if python_version < (3, 9):
            limitations.extend(
                [
                    "Dictionary union operators (|) not supported",
                    "str.removeprefix/removesuffix not supported",
                    "PEP 585 generic types not available",
                    "Unpacking in list/dict comprehensions not supported",
                ]
            )

        if python_version < (3, 10):
            limitations.extend(
                [
                    "Structural pattern matching (match/case) not supported",
                    "Parenthesized context managers not supported",
                    "Type union operators (|) not supported in typing",
                    "zip(*strict=True) not supported",
                ]
            )

        if python_version < (3, 11):
            limitations.extend(
                [
                    "Exception groups not supported",
                    "tomllib module not available",
                    "Self type not supported in typing",
                ]
            )

        if python_version < (3, 12):
            limitations.extend(
                [
                    "f-string improvements (debugging, self-doc) not available",
                    "Override decorator not available",
                    "Type parameter syntax not supported",
                ]
            )

        return limitations

    def should_analyze_legacy(self, file_path: Path) -> bool:
        """Determine if legacy code should be analyzed.

        Args:
            file_path: Path to Python file

        Returns:
            True if file should be analyzed
        """
        if not self.is_legacy_mode_enabled():
            return False

        return True
