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

"""Helper utility functions."""

import hashlib
from pathlib import Path
from typing import Any


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        file_path: Path to file

    Returns:
        Hexadecimal hash string
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_content_hash(content: str) -> str:
    """Compute SHA-256 hash of content string.

    Args:
        content: String content

    Returns:
        Hexadecimal hash string
    """
    return hashlib.sha256(content.encode()).hexdigest()


def generate_finding_id(file: str, line: int, pattern: str) -> str:
    """Generate unique finding ID.

    Args:
        file: File path
        line: Line number
        pattern: Pattern ID

    Returns:
        Unique finding ID
    """
    content = f"{file}:{line}:{pattern}"
    hash_str = compute_content_hash(content)[:8]
    return f"ACR-2025-{hash_str.upper()}"


def truncate_string(s: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate string to max length.

    Args:
        s: String to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated

    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s
    return s[: max_length - len(suffix)] + suffix
