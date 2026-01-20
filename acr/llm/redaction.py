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
# See the License for specific language governing permissions and
# limitations under the License.

"""Sensitive data redaction for LLM calls."""

import logging
import math
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from acr.config.schema import RedactionConfig

logger = logging.getLogger(__name__)


@dataclass
class RedactionEvent:
    """Data class for redaction event logging."""

    pattern_name: str
    match_count: int
    redacted_text: str
    original_length: int


class DataRedactor:
    """Redact sensitive data before sending to LLM."""

    DEFAULT_PATTERNS = {
        "api_key": re.compile(
            r'(?:api[_-]?key|apikey|key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})', re.IGNORECASE
        ),
        "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "aws_secret": re.compile(
            r'(?:aws[_-]?secret[_-]?access[_-]?key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+]{40})',
            re.IGNORECASE,
        ),
        "private_key": re.compile(r"-----BEGIN[A-Z\s]+PRIVATE KEY-----"),
        "certificate": re.compile(r"-----BEGIN\s*(?:RSA\s+)?CERTIFICATE-----"),
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
        "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        "github_token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        "stripe_key": re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
        "redis_url": re.compile(r'redis://[^"\'>\s]{10,}', re.IGNORECASE),
        "mongodb_connection": re.compile(r'mongodb://[^"\'>\s]{10,}', re.IGNORECASE),
        "postgres_connection": re.compile(r'postgres(?:ql)?://[^"\'>\s]{10,}', re.IGNORECASE),
        "mysql_connection": re.compile(r'mysql://[^"\'>\s]{10,}', re.IGNORECASE),
        "ssh_key": re.compile(r"ssh-(?:rsa|ed25519|dss|ecdsa)\s+[A-Za-z0-9+/]+[=]{0,2}"),
        "authorization_header": re.compile(r"Authorization:\s*[Bb]earer\s+[A-Za-z0-9._-]+"),
        "cookie_header": re.compile(r"Cookie:\s*[A-Za-z0-9_%+-]+=*[;\s]*"),
        "credit_card": re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
        ),
        "email_address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "ip_address": re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
        "phone_number": re.compile(
            r"\b(?:\+?1[-.\s]?)?\(?[2-9][0-9]{2}\)?[-.\s]?[2-9][0-9]{2}[-.\s]?[0-9]{4}\b"
        ),
        "ssn": re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b"),
    }

    def __init__(self, config: Optional[RedactionConfig] = None):
        """Initialize redactor.

        Args:
            config: Redaction configuration
        """
        self.config = config or RedactionConfig()
        self.redaction_count = 0
        self.redaction_events: List[RedactionEvent] = []
        self.custom_patterns: Dict[str, re.Pattern] = {}
        self._load_custom_patterns()

    def _load_custom_patterns(self):
        """Load custom patterns from configuration."""
        for pattern_config in self.config.custom_patterns:
            try:
                self.custom_patterns[pattern_config.name] = re.compile(pattern_config.pattern)
                logger.debug(f"Loaded custom redaction pattern: {pattern_config.name}")
            except re.error as e:
                logger.warning(f"Failed to compile custom pattern '{pattern_config.name}': {e}")

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text.

        High entropy strings are likely to be keys, tokens, or encrypted data.

        Args:
            text: Text to analyze

        Returns:
            Entropy value (0-8 for typical ASCII text)
        """
        if not text:
            return 0.0

        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        length = len(text)
        entropy = 0.0

        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _detect_high_entropy_strings(self, text: str, redacted_parts: Set[str]) -> Tuple[str, int]:
        """Detect and redact high-entropy strings.

        Args:
            text: Text to analyze
            redacted_parts: Set of already redacted parts to avoid duplicate redaction

        Returns:
            Tuple of (redacted text, count of new redactions)
        """
        if not self.config.entropy_threshold > 0:
            return text, 0

        words = re.findall(r"\b[A-Za-z0-9/_-]+\b", text)
        new_redactions = 0

        for word in words:
            if word in redacted_parts:
                continue

            if len(word) < self.config.entropy_min_length:
                continue

            if "[REDACTED" in word:
                continue

            entropy = self.calculate_entropy(word)

            if entropy >= self.config.entropy_threshold:
                text = text.replace(word, "[REDACTED:HIGH_ENTROPY]")
                redacted_parts.add(word)
                new_redactions += 1

                if self.config.log_redactions:
                    logger.info(
                        f"Redacted high-entropy string (entropy={entropy:.2f}): {word[:10]}..."
                    )

        return text, new_redactions

    def redact(self, text: str) -> Tuple[str, Dict[str, int]]:
        """Redact sensitive data from text.

        Args:
            text: Text to redact

        Returns:
            Tuple of (redacted text, counts by type)
        """
        redacted_text = text
        counts = {}
        redacted_parts: Set[str] = set()

        all_patterns = {**self.DEFAULT_PATTERNS, **self.custom_patterns}

        for name, pattern in all_patterns.items():
            matches = list(pattern.finditer(redacted_text))
            if matches:
                match_count = len(matches)
                counts[name] = match_count
                self.redaction_count += match_count

                redacted_text = pattern.sub("[REDACTED]", redacted_text)

                if self.config.log_redactions:
                    logger.info(f"Redacted {match_count} occurrence(s) of pattern '{name}'")
                    self.redaction_events.append(
                        RedactionEvent(
                            pattern_name=name,
                            match_count=match_count,
                            redacted_text=redacted_text[:200],
                            original_length=len(text),
                        )
                    )

        redacted_text, entropy_redactions = self._detect_high_entropy_strings(
            redacted_text, redacted_parts
        )

        if entropy_redactions > 0:
            counts["high_entropy"] = entropy_redactions
            self.redaction_count += entropy_redactions

        return redacted_text, counts

    def verify_redaction(self, original: str, redacted: str) -> bool:
        """Verify that sensitive data is fully redacted.

        Checks that known sensitive patterns are not present in redacted text.

        Args:
            original: Original text before redaction
            redacted: Text after redaction

        Returns:
            True if redaction is complete, False otherwise
        """
        if not self.config.verify_redaction:
            return True

        all_patterns = {**self.DEFAULT_PATTERNS, **self.custom_patterns}

        for name, pattern in all_patterns.items():
            if name in ["certificate", "private_key", "authorization_header"]:
                continue

            matches = pattern.findall(redacted)
            if matches:
                logger.warning(
                    f"Redaction verification failed: Found {len(matches)} unredacted match(es) for pattern '{name}'"
                )
                return False

        return True

    def get_redaction_count(self) -> int:
        """Get total number of redactions.

        Returns:
            Total count
        """
        return self.redaction_count

    def get_redaction_events(self) -> List[RedactionEvent]:
        """Get all redaction events.

        Returns:
            List of redaction events
        """
        return self.redaction_events.copy()

    def clear_redaction_events(self):
        """Clear redaction event history."""
        self.redaction_events.clear()

    def add_custom_pattern(self, name: str, pattern: str):
        """Add a custom redaction pattern.

        Args:
            name: Pattern name
            pattern: Regex pattern

        Raises:
            ValueError: If pattern is invalid
        """
        try:
            self.custom_patterns[name] = re.compile(pattern)
            logger.info(f"Added custom redaction pattern: {name}")
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}") from e
