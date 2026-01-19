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
import sys
from typing import Optional


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
