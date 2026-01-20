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

"""Keyring-based secure credential storage."""

import logging
from typing import Optional

import keyring

logger = logging.getLogger(__name__)

KEYRING_SERVICE = "adversarial-code-reviewer"


def set_credential(name: str, value: str, service: Optional[str] = None) -> bool:
    """Store a credential securely in keyring.

    Args:
        name: Credential name/identifier
        value: Credential value to store
        service: Keyring service name (defaults to KEYRING_SERVICE)

    Returns:
        True if successful, False otherwise
    """
    if service is None:
        service = KEYRING_SERVICE

    try:
        keyring.set_password(service, name, value)
        logger.info(f"Stored credential '{name}' in keyring")
        return True
    except Exception as e:
        logger.error(f"Failed to store credential '{name}' in keyring: {e}")
        return False


def get_credential(name: str, service: Optional[str] = None) -> Optional[str]:
    """Retrieve a credential from keyring.

    Args:
        name: Credential name/identifier
        service: Keyring service name (defaults to KEYRING_SERVICE)

    Returns:
        Credential value if found, None otherwise
    """
    if service is None:
        service = KEYRING_SERVICE

    try:
        value = keyring.get_password(service, name)
        if value is not None:
            logger.debug(f"Retrieved credential '{name}' from keyring")
        return value
    except Exception as e:
        logger.error(f"Failed to retrieve credential '{name}' from keyring: {e}")
        return None


def delete_credential(name: str, service: Optional[str] = None) -> bool:
    """Delete a credential from keyring.

    Args:
        name: Credential name/identifier
        service: Keyring service name (defaults to KEYRING_SERVICE)

    Returns:
        True if successful or not found, False on error
    """
    if service is None:
        service = KEYRING_SERVICE

    try:
        keyring.delete_password(service, name)
        logger.info(f"Deleted credential '{name}' from keyring")
        return True
    except keyring.errors.PasswordDeleteError:
        logger.debug(f"Credential '{name}' not found in keyring")
        return True
    except Exception as e:
        logger.error(f"Failed to delete credential '{name}' from keyring: {e}")
        return False


def list_credentials(service: Optional[str] = None) -> list[str]:
    """List all credential names stored in keyring.

    Args:
        service: Keyring service name (defaults to KEYRING_SERVICE)

    Returns:
        List of credential names
    """
    if service is None:
        service = KEYRING_SERVICE

    try:
        if hasattr(keyring, "get_credential"):
            items = []
            for item in keyring.get_password(service, "") or []:
                items.append(item.username)
            return items
    except Exception as e:
        logger.warning(f"Failed to list credentials from keyring: {e}")

    return []


def is_keyring_available() -> bool:
    """Check if keyring backend is available and functional.

    Returns:
        True if keyring is available, False otherwise
    """
    try:
        backend = keyring.get_keyring()
        return backend is not None
    except Exception:
        return False
