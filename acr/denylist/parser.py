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

"""Parser for .acr-denylist files."""

import re
from pathlib import Path
from typing import Optional, List
from pydantic import BaseModel, Field
from acr.utils.logger import get_logger

logger = get_logger(__name__)


class DenylistEntry(BaseModel):
    """Single denylist entry."""

    pattern: str = Field(description="Pattern to match (file or function)")
    entry_type: str = Field(description="Entry type: 'file' or 'function'")
    comment: Optional[str] = Field(
        default=None, description="Optional comment explaining the denial"
    )


class DenylistParser:
    """Parser for .acr-denylist files."""

    def __init__(self, file_path: Path):
        """Initialize parser with denylist file path.

        Args:
            file_path: Path to .acr-denylist file
        """
        self.file_path = file_path
        self.entries: List[DenylistEntry] = []
        self.file_patterns: List[re.Pattern] = []
        self.function_patterns: List[re.Pattern] = []

    def parse(self) -> None:
        """Parse .acr-denylist file and populate pattern lists."""
        if not self.file_path.exists():
            logger.debug(f"Denylist file not found: {self.file_path}")
            return

        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            logger.warning(f"Failed to read denylist file {self.file_path}: {e}")
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
            entry = DenylistEntry(pattern=line, entry_type=entry_type, comment=comment)
            self.entries.append(entry)

            if entry_type == "file":
                self._parse_file_pattern(line)
            elif entry_type == "function":
                self._parse_function_pattern(line)

        logger.debug(f"Parsed {len(self.entries)} denylist entries from {self.file_path}")

    def _detect_entry_type(self, pattern: str) -> str:
        """Detect type of denylist entry.

        Args:
            pattern: Pattern string

        Returns:
            Entry type: 'file' or 'function'
        """
        if pattern.startswith("function:"):
            return "function"

        if pattern.startswith("file:"):
            return "file"

        if "->" in pattern or pattern.endswith("()"):
            return "function"

        if ":" in pattern:
            parts = pattern.split(":")
            if len(parts) == 2:
                file_part = parts[0]
                func_part = parts[1]
                if file_part.endswith(".py") or file_part.endswith(".js"):
                    return "function"

        return "file"

    def _parse_file_pattern(self, pattern: str) -> None:
        """Parse file pattern.

        Args:
            pattern: File pattern, optionally starting with "file:"
        """
        if pattern.startswith("file:"):
            pattern = pattern[5:]

        try:
            compiled = re.compile(pattern)
            self.file_patterns.append(compiled)
        except re.error as e:
            logger.warning(f"Invalid file pattern in denylist: {pattern} - {e}")

    def _parse_function_pattern(self, pattern: str) -> None:
        """Parse function pattern.

        Args:
            pattern: Function pattern in format "file.py:function_name" or "file.py->function_name"
        """
        if pattern.startswith("function:"):
            pattern = pattern[9:]

        try:
            compiled = re.compile(pattern)
            self.function_patterns.append(compiled)
        except re.error as e:
            logger.warning(f"Invalid function pattern in denylist: {pattern} - {e}")

    def is_file_denied(self, file_path: str) -> bool:
        """Check if a file matches any denylist pattern.

        Args:
            file_path: File path to check

        Returns:
            True if file is denied (should always be analyzed)
        """
        for pattern in self.file_patterns:
            if pattern.search(file_path):
                return True
        return False

    def is_function_denied(self, file_path: str, function_name: str) -> bool:
        """Check if a function in a file matches any denylist pattern.

        Args:
            file_path: File path
            function_name: Function name

        Returns:
            True if function is denied (should always be analyzed)
        """
        function_full_path = f"{file_path}:{function_name}"
        function_full_path_arrow = f"{file_path}->{function_name}"
        function_call = f"{function_name}()"

        for pattern in self.function_patterns:
            if (
                pattern.search(function_full_path)
                or pattern.search(function_full_path_arrow)
                or pattern.search(function_call)
            ):
                return True
        return False

    def get_entries(self) -> List[DenylistEntry]:
        """Get all parsed denylist entries.

        Returns:
            List of denylist entries
        """
        return self.entries
