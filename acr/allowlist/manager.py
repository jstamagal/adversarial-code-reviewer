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

"""Manager for checking if findings should be excluded based on allowlist."""

from pathlib import Path
from typing import Optional
from acr.models.finding import Finding
from acr.allowlist.parser import AllowlistParser
from acr.utils.logger import get_logger

logger = get_logger(__name__)


class AllowlistManager:
    """Manager for checking if findings should be excluded."""

    def __init__(self, allowlist_path: Optional[Path] = None):
        """Initialize allowlist manager.

        Args:
            allowlist_path: Path to .acr-ignore file. If None, uses default search paths.
        """
        self.allowlist_path = allowlist_path
        self.parser: Optional[AllowlistParser] = None
        self._load_allowlist()

    def _load_allowlist(self) -> None:
        """Load allowlist from file."""
        if self.allowlist_path and self.allowlist_path.exists():
            self.parser = AllowlistParser(self.allowlist_path)
            self.parser.parse()
            return

        default_paths = [
            Path(".acr-ignore"),
            Path(".acrignore"),
            Path(".acr/ignore"),
        ]

        for path in default_paths:
            if path.exists():
                self.parser = AllowlistParser(path)
                self.parser.parse()
                logger.debug(f"Loaded allowlist from {path}")
                return

        logger.debug("No allowlist file found")

    def should_exclude_finding(self, finding: Finding) -> bool:
        """Check if a finding should be excluded based on allowlist.

        Args:
            finding: Finding to check

        Returns:
            True if finding should be excluded
        """
        if not self.parser:
            return False

        file_path = finding.location.file
        line_number = finding.location.line

        if self.parser.is_line_excluded(file_path, line_number):
            logger.debug(f"Excluded finding at {file_path}:{line_number} (line exclusion)")
            return True

        if self.parser.is_regex_excluded(file_path):
            logger.debug(f"Excluded finding in {file_path} (regex exclusion)")
            return True

        if self.parser.is_pattern_excluded(finding.category):
            logger.debug(f"Excluded finding with category {finding.category} (pattern exclusion)")
            return True

        return False

    def get_exclusion_reason(self, finding: Finding) -> Optional[str]:
        """Get reason for why a finding is excluded.

        Args:
            finding: Finding to check

        Returns:
            Exclusion reason or None if not excluded
        """
        if not self.parser:
            return None

        file_path = finding.location.file
        line_number = finding.location.line

        if self.parser.is_line_excluded(file_path, line_number):
            return f"Line {line_number} in {file_path} is excluded"

        if self.parser.is_regex_excluded(file_path):
            return f"File {file_path} matches regex exclusion"

        if self.parser.is_pattern_excluded(finding.category):
            return f"Pattern '{finding.category}' is excluded"

        return None

    def reload(self) -> None:
        """Reload allowlist from file."""
        self._load_allowlist()
