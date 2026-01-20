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

"""Parser for .acr-ignore allowlist files."""

import re
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from acr.utils.logger import get_logger

logger = get_logger(__name__)


class AllowlistEntry(BaseModel):
    """Single allowlist entry."""

    pattern: str = Field(description="Pattern to match (file:line, regex, or pattern name)")
    entry_type: str = Field(description="Entry type: 'line', 'regex', 'pattern'")
    comment: Optional[str] = Field(
        default=None, description="Optional comment explaining the exclusion"
    )


class AllowlistParser:
    """Parser for .acr-ignore files."""

    def __init__(self, file_path: Path):
        """Initialize parser with allowlist file path.

        Args:
            file_path: Path to .acr-ignore file
        """
        self.file_path = file_path
        self.entries: List[AllowlistEntry] = []
        self.line_exclusions: Dict[str, set] = {}
        self.regex_exclusions: List[re.Pattern] = []
        self.pattern_exclusions: List[str] = []

    def parse(self) -> None:
        """Parse .acr-ignore file and populate exclusion lists."""
        if not self.file_path.exists():
            logger.debug(f"Allowlist file not found: {self.file_path}")
            return

        try:
            with open(self.file_path, encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            logger.warning(f"Failed to read allowlist file {self.file_path}: {e}")
            return

        for line_num, line in enumerate(lines, 1):
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            comment = None
            if "#" in line:
                line, comment = line.split("#", 1)
                line = line.strip()
                comment = comment.strip()

            if not line:
                continue

            entry_type = self._detect_entry_type(line)
            entry = AllowlistEntry(pattern=line, entry_type=entry_type, comment=comment)
            self.entries.append(entry)

            if entry_type == "line":
                self._parse_line_exclusion(line)
            elif entry_type == "regex":
                self._parse_regex_exclusion(line)
            elif entry_type == "pattern":
                self._parse_pattern_exclusion(line)

        logger.debug(f"Parsed {len(self.entries)} allowlist entries from {self.file_path}")

    def _detect_entry_type(self, pattern: str) -> str:
        """Detect type of allowlist entry.

        Args:
            pattern: Pattern string

        Returns:
            Entry type: 'line', 'regex', or 'pattern'
        """
        if ":" in pattern and pattern.count(":") == 1:
            parts = pattern.split(":")
            if len(parts) == 2 and self._is_valid_line_number(parts[1]):
                return "line"

        if pattern.startswith("regex:"):
            return "regex"

        if pattern.startswith("pattern:"):
            return "pattern"

        return "pattern"

    def _is_valid_line_number(self, value: str) -> bool:
        """Check if string is a valid line number.

        Args:
            value: String to check

        Returns:
            True if valid line number
        """
        try:
            num = int(value)
            return num > 0
        except ValueError:
            return False

    def _parse_line_exclusion(self, pattern: str) -> None:
        """Parse file:line exclusion.

        Args:
            pattern: Pattern in format "file_path:line_number"
        """
        parts = pattern.split(":")
        if len(parts) != 2:
            logger.warning(f"Invalid line exclusion format: {pattern}")
            return

        file_path, line_num = parts
        try:
            line_num = int(line_num)
        except ValueError:
            logger.warning(f"Invalid line number in: {pattern}")
            return

        if file_path not in self.line_exclusions:
            self.line_exclusions[file_path] = set()
        self.line_exclusions[file_path].add(line_num)

    def _parse_regex_exclusion(self, pattern: str) -> None:
        """Parse regex exclusion.

        Args:
            pattern: Pattern starting with "regex:"
        """
        if not pattern.startswith("regex:"):
            return

        regex_pattern = pattern[6:]
        try:
            compiled = re.compile(regex_pattern)
            self.regex_exclusions.append(compiled)
        except re.error as e:
            logger.warning(f"Invalid regex in allowlist: {regex_pattern} - {e}")

    def _parse_pattern_exclusion(self, pattern: str) -> None:
        """Parse pattern type exclusion.

        Args:
            pattern: Pattern name or "pattern:name" format
        """
        if pattern.startswith("pattern:"):
            pattern = pattern[8:]

        self.pattern_exclusions.append(pattern)

    def is_line_excluded(self, file_path: str, line_number: int) -> bool:
        """Check if a specific line is excluded.

        Args:
            file_path: File path to check
            line_number: Line number to check

        Returns:
            True if line is excluded
        """
        if file_path in self.line_exclusions:
            return line_number in self.line_exclusions[file_path]
        return False

    def is_regex_excluded(self, file_path: str) -> bool:
        """Check if file path matches any regex exclusion.

        Args:
            file_path: File path to check

        Returns:
            True if file path is excluded by regex
        """
        for pattern in self.regex_exclusions:
            if pattern.search(file_path):
                return True
        return False

    def is_pattern_excluded(self, pattern_name: str) -> bool:
        """Check if a pattern type is excluded.

        Args:
            pattern_name: Pattern name to check

        Returns:
            True if pattern is excluded
        """
        return pattern_name in self.pattern_exclusions

    def get_entries(self) -> List[AllowlistEntry]:
        """Get all parsed allowlist entries.

        Returns:
            List of allowlist entries
        """
        return self.entries
