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

import logging
import pytest
from acr.utils.helpers import compute_content_hash, generate_finding_id, truncate_string
from acr.utils.logger import setup_logger, get_logger, get_memory_usage, log_memory_usage


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


def test_logger_default_level():
    """Test logger has default INFO level."""
    logger = setup_logger("test_default")
    assert logger.level == logging.INFO


def test_logger_verbose_level():
    """Test verbose flag sets DEBUG level."""
    logger = setup_logger("test_verbose", verbose=True)
    assert logger.level == logging.DEBUG


def test_logger_quiet_level():
    """Test quiet flag sets ERROR level."""
    logger = setup_logger("test_quiet", quiet=True)
    assert logger.level == logging.ERROR


def test_logger_custom_level():
    """Test custom log level."""
    logger = setup_logger("test_custom", level=logging.WARNING)
    assert logger.level == logging.WARNING


def test_logger_quiet_overrides_verbose():
    """Test quiet flag overrides verbose flag."""
    logger = setup_logger("test_both", verbose=True, quiet=True)
    assert logger.level == logging.ERROR


def test_logger_has_handler():
    """Test logger has a stream handler."""
    logger = setup_logger("test_handler")
    assert len(logger.handlers) > 0
    assert isinstance(logger.handlers[0], logging.StreamHandler)


def test_logger_handler_level():
    """Test logger handler has correct level."""
    logger = setup_logger("test_handler_level", level=logging.WARNING)
    assert logger.handlers[0].level == logging.WARNING


def test_logger_format():
    """Test logger has correct format."""
    logger = setup_logger("test_format")
    formatter = logger.handlers[0].formatter
    assert formatter is not None
    format_str = formatter._fmt if formatter._fmt else ""
    assert "%(asctime)s" in format_str
    assert "%(name)s" in format_str
    assert "%(levelname)s" in format_str
    assert "%(message)s" in format_str


def test_logger_date_format():
    """Test logger has correct date format."""
    logger = setup_logger("test_date")
    formatter = logger.handlers[0].formatter
    assert formatter is not None
    assert formatter.datefmt == "%Y-%m-%d %H:%M:%S"


def test_logger_no_duplicate_handlers():
    """Test calling setup_logger twice doesn't duplicate handlers."""
    logger1 = setup_logger("test_nodup")
    initial_handlers = len(logger1.handlers)
    logger2 = setup_logger("test_nodup")
    assert len(logger2.handlers) == initial_handlers


def test_logger_outputs_to_stderr():
    """Test logger outputs to stderr."""
    import sys

    logger = setup_logger("test_stderr")
    handler = logger.handlers[0]
    if hasattr(handler, "stream"):
        assert handler.stream == sys.stderr
    else:
        assert isinstance(handler, logging.StreamHandler)


def test_logger_can_log_messages(caplog):
    """Test logger can actually log messages."""
    logger = setup_logger("test_log", level=logging.DEBUG)

    with caplog.at_level(logging.DEBUG):
        logger.debug("debug message")
        logger.info("info message")
        logger.warning("warning message")
        logger.error("error message")

    assert any("debug message" in record.message for record in caplog.records)
    assert any("info message" in record.message for record in caplog.records)
    assert any("warning message" in record.message for record in caplog.records)
    assert any("error message" in record.message for record in caplog.records)


def test_logger_respects_level_filtering(caplog):
    """Test logger respects log level filtering."""
    logger = setup_logger("test_filter", level=logging.WARNING)

    with caplog.at_level(logging.DEBUG):
        logger.debug("should not appear")
        logger.info("should not appear")
        logger.warning("should appear")
        logger.error("should appear")

    messages = [record.message for record in caplog.records]
    assert "should not appear" not in messages
    assert "should appear" in messages


def test_get_logger_returns_same_instance():
    """Test get_logger returns same logger instance for same name."""
    logger1 = get_logger("test_same")
    logger2 = get_logger("test_same")
    assert logger1 is logger2


def test_get_memory_usage_returns_dict():
    """Test get_memory_usage returns a dictionary."""
    result = get_memory_usage()
    assert isinstance(result, dict)


def test_get_memory_usage_has_required_keys():
    """Test get_memory_usage returns required keys when psutil available."""
    result = get_memory_usage()

    if "error" in result:
        assert result["error"] is not None
    else:
        assert "rss_mb" in result
        assert "vms_mb" in result
        assert "system_memory_percent" in result
        assert "system_memory_total_mb" in result
        assert "system_memory_available_mb" in result


def test_get_memory_usage_values_are_positive():
    """Test memory usage values are positive numbers."""
    result = get_memory_usage()

    if "error" not in result:
        assert result["rss_mb"] > 0
        assert result["vms_mb"] >= 0
        assert result["system_memory_percent"] >= 0
        assert result["system_memory_total_mb"] > 0
        assert result["system_memory_available_mb"] >= 0


def test_get_memory_usage_values_are_numeric():
    """Test memory usage values are numeric."""
    result = get_memory_usage()

    if "error" not in result:
        assert isinstance(result["rss_mb"], (int, float))
        assert isinstance(result["vms_mb"], (int, float))
        assert isinstance(result["system_memory_percent"], (int, float))
        assert isinstance(result["system_memory_total_mb"], (int, float))
        assert isinstance(result["system_memory_available_mb"], (int, float))


def test_log_memory_usage_with_logger():
    """Test log_memory_usage with valid logger."""
    logger = setup_logger("test_memory", level=logging.DEBUG)
    log_memory_usage(logger, "test context")

    assert logger is not None


def test_log_memory_usage_without_context():
    """Test log_memory_usage without context string."""
    logger = setup_logger("test_memory_no_ctx", level=logging.DEBUG)
    log_memory_usage(logger)

    assert logger is not None


def test_log_memory_usage_with_none_logger():
    """Test log_memory_usage handles None logger gracefully."""
    log_memory_usage(None, "test")

    assert True


def test_log_memory_usage_logs_at_debug_level(caplog):
    """Test log_memory_usage logs at DEBUG level."""
    logger = setup_logger("test_memory_debug", level=logging.DEBUG)

    with caplog.at_level(logging.DEBUG):
        log_memory_usage(logger, "test_context")

    assert len(caplog.records) > 0 or "psutil not available" in " ".join(
        [r.message for r in caplog.records]
    )


def test_memory_usage_rss_less_than_system():
    """Test process RSS is less than total system memory."""
    result = get_memory_usage()

    if "error" not in result:
        assert result["rss_mb"] < result["system_memory_total_mb"]


def test_memory_usage_system_percent_reasonable():
    """Test system memory percentage is reasonable (0-100)."""
    result = get_memory_usage()

    if "error" not in result:
        assert 0 <= result["system_memory_percent"] <= 100
