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

"""Manager for ensuring findings are always reported based on denylist."""

from pathlib import Path
from typing import Optional
from acr.models.finding import Finding
from acr.denylist.parser import DenylistParser
from acr.utils.logger import get_logger

logger = get_logger(__name__)


class DenylistManager:
    """Manager for checking if findings should always be reported."""

    def __init__(self, denylist_path: Optional[Path] = None):
        """Initialize denylist manager.

        Args:
            denylist_path: Path to .acr-denylist file. If None, uses default search paths.
        """
        self.denylist_path = denylist_path
        self.parser: Optional[DenylistParser] = None
        self._load_denylist()

    def _load_denylist(self) -> None:
        """Load denylist from file."""
        if self.denylist_path and self.denylist_path.exists():
            self.parser = DenylistParser(self.denylist_path)
            self.parser.parse()
            return

        default_paths = [
            Path(".acr-denylist"),
            Path(".acrdenylist"),
            Path(".acr/denylist"),
        ]

        for path in default_paths:
            if path.exists():
                self.parser = DenylistParser(path)
                self.parser.parse()
                logger.debug(f"Loaded denylist from {path}")
                return

        logger.debug("No denylist file found")

    def should_force_include_finding(self, finding: Finding) -> bool:
        """Check if a finding should be forced to be included based on denylist.

        Args:
            finding: Finding to check

        Returns:
            True if finding should be forced to be included (even if low confidence)
        """
        if not self.parser:
            return False

        file_path = finding.location.file

        if self.parser.is_file_denied(file_path):
            logger.debug(f"Force including finding in {file_path} (file denylist)")
            return True

        function_name = finding.location.function if finding.location.function else ""
        if function_name and self.parser.is_function_denied(file_path, function_name):
            logger.debug(
                f"Force including finding in {file_path}:{function_name} (function denylist)"
            )
            return True

        return False

    def get_deny_reason(self, finding: Finding) -> Optional[str]:
        """Get reason for why a finding is forced to be included.

        Args:
            finding: Finding to check

        Returns:
            Deny reason or None if not forced
        """
        if not self.parser:
            return None

        file_path = finding.location.file

        if self.parser.is_file_denied(file_path):
            return f"File {file_path} is in denylist"

        function_name = finding.location.function if finding.location.function else ""
        if function_name and self.parser.is_function_denied(file_path, function_name):
            return f"Function {function_name} in {file_path} is in denylist"

        return None

    def reload(self) -> None:
        """Reload denylist from file."""
        self._load_denylist()
