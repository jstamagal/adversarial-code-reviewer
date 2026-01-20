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

"""Logging infrastructure."""

import logging
import os
import sys
from typing import Optional, Union

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


def setup_logger(
    name: str = "acr", level: int = logging.INFO, verbose: bool = False, quiet: bool = False
) -> logging.Logger:
    """Set up logger for ACR.

    Args:
        name: Logger name
        level: Log level
        verbose: Enable verbose output (DEBUG level)
        quiet: Suppress output (ERROR level)

    Returns:
        Configured logger
    """
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(level)

        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)

        logger.addHandler(handler)

    return logger


def get_logger(name: str = "acr") -> logging.Logger:
    """Get existing logger.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def get_memory_usage() -> dict:
    """Get current memory usage information.

    Returns:
        Dictionary containing memory usage statistics in MB
    """
    memory_info = {}

    if PSUTIL_AVAILABLE:
        process = psutil.Process(os.getpid())

        try:
            memory_info["rss_mb"] = process.memory_info().rss / (1024 * 1024)
            memory_info["vms_mb"] = process.memory_info().vms / (1024 * 1024)

            memory_info["system_memory_percent"] = psutil.virtual_memory().percent
            memory_info["system_memory_total_mb"] = psutil.virtual_memory().total / (1024 * 1024)
            memory_info["system_memory_available_mb"] = psutil.virtual_memory().available / (
                1024 * 1024
            )

            return memory_info
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            memory_info["error"] = "Failed to access process memory information"
            return memory_info

    memory_info["error"] = "psutil not available"
    return memory_info


def log_memory_usage(logger: Optional[logging.Logger], context: str = "") -> None:
    """Log current memory usage.

    Args:
        logger: Logger instance (can be None)
        context: Optional context string to include in log message
    """
    if not logger:
        return

    memory_info = get_memory_usage()

    if "error" in memory_info:
        logger.warning(f"Memory logging unavailable: {memory_info['error']}")
        return

    context_str = f" [{context}]" if context else ""
    logger.debug(
        f"Memory usage{context_str}: RSS={memory_info['rss_mb']:.2f}MB, "
        f"VMS={memory_info['vms_mb']:.2f}MB, "
        f"System={memory_info['system_memory_percent']:.1f}% used"
    )
