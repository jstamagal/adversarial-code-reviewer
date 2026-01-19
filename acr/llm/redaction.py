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

"""Sensitive data redaction for LLM calls."""

import re
from typing import Tuple, Dict


class DataRedactor:
    """Redact sensitive data before sending to LLM."""

    PATTERNS = {
        "api_key": re.compile(
            r'(?:api[_-]?key|apikey|key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})', re.IGNORECASE
        ),
        "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "aws_secret": re.compile(
            r'(?:aws[_-]?secret[_-]?access[_-]?key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+]{40})',
            re.IGNORECASE,
        ),
        "private_key": re.compile(r"-----BEGIN[A-Z\s]+PRIVATE KEY-----"),
        "password": re.compile(
            r'(?:password|pass|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'\s]+)', re.IGNORECASE
        ),
        "token": re.compile(
            r'(?:token|bearer|auth)["\']?\s*[:=]\s*["\']?([A-Za-z0-9._-]{15,})', re.IGNORECASE
        ),
        "database_url": re.compile(
            r'(?:database[_-]?url|db[_-]?url|mongodb|postgres|mysql)["\']?\s*[:=]\s*["\']?([^"\']{20,})',
            re.IGNORECASE,
        ),
    }

    def __init__(self):
        """Initialize redactor."""
        self.redaction_count = 0

    def redact(self, text: str) -> Tuple[str, Dict[str, int]]:
        """Redact sensitive data from text.

        Args:
            text: Text to redact

        Returns:
            Tuple of (redacted text, counts by type)
        """
        redacted_text = text
        counts = {}

        for name, pattern in self.PATTERNS.items():
            matches = pattern.findall(redacted_text)
            if matches:
                counts[name] = len(matches)
                self.redaction_count += len(matches)
                redacted_text = pattern.sub(lambda m: self._replace(m), redacted_text)

        return redacted_text, counts

    def _replace(self, match) -> str:
        """Replace match with placeholder.

        Args:
            match: Regex match object

        Returns:
            Replacement string
        """
        return "[REDACTED]"

    def get_redaction_count(self) -> int:
        """Get total number of redactions.

        Returns:
            Total count
        """
        return self.redaction_count
