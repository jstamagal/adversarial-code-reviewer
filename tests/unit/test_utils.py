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

"""Unit tests for utilities."""

import pytest
from acr.utils.helpers import compute_content_hash, generate_finding_id, truncate_string
from acr.utils.logger import setup_logger, get_logger


def test_content_hash():
    """Test content hash computation."""
    hash1 = compute_content_hash("test content")
    hash2 = compute_content_hash("test content")
    hash3 = compute_content_hash("different content")

    assert hash1 == hash2
    assert hash1 != hash3
    assert len(hash1) == 64  # SHA-256 hex length


def test_finding_id_generation():
    """Test finding ID generation."""
    id1 = generate_finding_id("test.py", 10, "sql-injection")
    id2 = generate_finding_id("test.py", 10, "sql-injection")
    id3 = generate_finding_id("test.py", 11, "sql-injection")

    assert id1.startswith("ACR-2025-")
    assert id1 == id2
    assert id1 != id3


def test_string_truncation():
    """Test string truncation."""
    short = "short"
    long = "a" * 200

    assert truncate_string(short, 100) == "short"
    assert truncate_string(long, 100, "...") == "a" * 97 + "..."
    assert len(truncate_string(long, 100, "...")) == 100


def test_logger_setup():
    """Test logger setup."""
    logger = setup_logger("test")
    assert logger.name == "test"
    assert logger.level >= 0

    verbose_logger = setup_logger("test_verbose", verbose=True)
    assert verbose_logger.name == "test_verbose"

    quiet_logger = setup_logger("test_quiet", quiet=True)
    assert quiet_logger.name == "test_quiet"


def test_logger_get():
    """Test getting existing logger."""
    logger = get_logger("acr")
    assert logger is not None
    assert logger.name == "acr"
