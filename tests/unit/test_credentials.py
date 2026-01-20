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

"""Tests for keyring credential storage."""

import pytest
from unittest.mock import patch, MagicMock

from acr.config.credentials import (
    set_credential,
    get_credential,
    delete_credential,
    list_credentials,
    is_keyring_available,
    KEYRING_SERVICE,
)


class TestCredentialStorage:
    """Tests for secure credential storage using keyring."""

    def test_set_credential_success(self):
        """Test successful credential storage."""
        with patch("acr.config.credentials.keyring.set_password") as mock_set:
            mock_set.return_value = None

            result = set_credential("test_key", "test_value")

            assert result is True
            mock_set.assert_called_once_with(KEYRING_SERVICE, "test_key", "test_value")

    def test_set_credential_failure(self):
        """Test credential storage failure."""
        with patch("acr.config.credentials.keyring.set_password") as mock_set:
            mock_set.side_effect = Exception("Keyring error")

            result = set_credential("test_key", "test_value")

            assert result is False

    def test_set_credential_custom_service(self):
        """Test credential storage with custom service name."""
        with patch("acr.config.credentials.keyring.set_password") as mock_set:
            result = set_credential("test_key", "test_value", service="custom-service")

            assert result is True
            mock_set.assert_called_once_with("custom-service", "test_key", "test_value")

    def test_get_credential_success(self):
        """Test successful credential retrieval."""
        with patch("acr.config.credentials.keyring.get_password") as mock_get:
            mock_get.return_value = "secret_value"

            result = get_credential("test_key")

            assert result == "secret_value"
            mock_get.assert_called_once_with(KEYRING_SERVICE, "test_key")

    def test_get_credential_not_found(self):
        """Test credential retrieval when not found."""
        with patch("acr.config.credentials.keyring.get_password") as mock_get:
            mock_get.return_value = None

            result = get_credential("test_key")

            assert result is None

    def test_get_credential_failure(self):
        """Test credential retrieval failure."""
        with patch("acr.config.credentials.keyring.get_password") as mock_get:
            mock_get.side_effect = Exception("Keyring error")

            result = get_credential("test_key")

            assert result is None

    def test_get_credential_custom_service(self):
        """Test credential retrieval with custom service name."""
        with patch("acr.config.credentials.keyring.get_password") as mock_get:
            mock_get.return_value = "secret_value"

            result = get_credential("test_key", service="custom-service")

            assert result == "secret_value"
            mock_get.assert_called_once_with("custom-service", "test_key")

    def test_delete_credential_success(self):
        """Test successful credential deletion."""
        with patch("acr.config.credentials.keyring.delete_password") as mock_delete:
            mock_delete.return_value = None

            result = delete_credential("test_key")

            assert result is True
            mock_delete.assert_called_once_with(KEYRING_SERVICE, "test_key")

    def test_delete_credential_not_found(self):
        """Test credential deletion when not found."""
        from keyring.errors import PasswordDeleteError

        with patch("acr.config.credentials.keyring.delete_password") as mock_delete:
            mock_delete.side_effect = PasswordDeleteError("Not found")

            result = delete_credential("test_key")

            assert result is True

    def test_delete_credential_failure(self):
        """Test credential deletion failure."""
        with patch("acr.config.credentials.keyring.delete_password") as mock_delete:
            mock_delete.side_effect = Exception("Keyring error")

            result = delete_credential("test_key")

            assert result is False

    def test_delete_credential_custom_service(self):
        """Test credential deletion with custom service name."""
        with patch("acr.config.credentials.keyring.delete_password") as mock_delete:
            result = delete_credential("test_key", service="custom-service")

            assert result is True
            mock_delete.assert_called_once_with("custom-service", "test_key")

    def test_list_credentials(self):
        """Test listing credentials."""
        result = list_credentials()
        assert isinstance(result, list)

    def test_list_credentials_failure(self):
        """Test listing credentials failure."""
        with patch("acr.config.credentials.keyring.get_password") as mock_get_pass:
            mock_get_pass.side_effect = Exception("Keyring error")

            result = list_credentials()

            assert result == []

    def test_list_credentials_no_method(self):
        """Test listing credentials when get_credential not available."""
        with patch("acr.config.credentials.keyring") as mock_keyring:
            delattr(mock_keyring, "get_credential")

            result = list_credentials()

            assert result == []

    def test_is_keyring_available_true(self):
        """Test keyring availability check when available."""
        with patch("acr.config.credentials.keyring.get_keyring") as mock_get:
            mock_get.return_value = MagicMock()

            result = is_keyring_available()

            assert result is True

    def test_is_keyring_available_false(self):
        """Test keyring availability check when not available."""
        with patch("acr.config.credentials.keyring.get_keyring") as mock_get:
            mock_get.return_value = None

            result = is_keyring_available()

            assert result is False

    def test_is_keyring_available_exception(self):
        """Test keyring availability check when exception occurs."""
        with patch("acr.config.credentials.keyring.get_keyring") as mock_get:
            mock_get.side_effect = Exception("Keyring error")

            result = is_keyring_available()

            assert result is False


class TestGetAPIKey:
    """Tests for get_api_key function in LLM client."""

    def test_get_api_key_from_env(self):
        """Test getting API key from environment variable."""
        with patch.dict(
            "os.environ",
            {"ANTHROPIC_API_KEY": "sk-test-key-from-env"},
            clear=True,
        ):
            from acr.llm.client import get_api_key

            result = get_api_key(
                api_key_env="ANTHROPIC_API_KEY",
                use_keyring=False,
                keyring_name="api_key",
            )

            assert result == "sk-test-key-from-env"

    def test_get_api_key_from_keyring(self):
        """Test getting API key from keyring."""
        with patch.dict("os.environ", {}, clear=True):
            with patch("acr.config.credentials.get_credential") as mock_get:
                mock_get.return_value = "sk-test-key-from-keyring"

                from acr.llm.client import get_api_key

                result = get_api_key(
                    api_key_env="ANTHROPIC_API_KEY",
                    use_keyring=True,
                    keyring_name="api_key",
                )

                assert result == "sk-test-key-from-keyring"
                mock_get.assert_called_once_with("api_key")

    def test_get_api_key_env_takes_precedence(self):
        """Test that environment variable takes precedence over keyring."""
        with patch.dict(
            "os.environ",
            {"ANTHROPIC_API_KEY": "sk-from-env"},
            clear=True,
        ):
            with patch("acr.config.credentials.get_credential") as mock_get:
                from acr.llm.client import get_api_key

                result = get_api_key(
                    api_key_env="ANTHROPIC_API_KEY",
                    use_keyring=True,
                    keyring_name="api_key",
                )

                assert result == "sk-from-env"
                mock_get.assert_not_called()

    def test_get_api_key_not_found(self):
        """Test error when API key not found."""
        with patch.dict("os.environ", {}, clear=True):
            with patch("acr.config.credentials.get_credential") as mock_get:
                mock_get.return_value = None

                from acr.llm.client import get_api_key

                with pytest.raises(ValueError) as exc_info:
                    get_api_key(
                        api_key_env="ANTHROPIC_API_KEY",
                        use_keyring=True,
                        keyring_name="api_key",
                    )

                assert "API key not found" in str(exc_info.value)

    def test_get_api_key_keyring_error(self):
        """Test that keyring errors are handled gracefully."""
        with patch.dict("os.environ", {}, clear=True):
            with patch("acr.config.credentials.get_credential") as mock_get:
                mock_get.side_effect = Exception("Keyring error")

                from acr.llm.client import get_api_key

                with pytest.raises(ValueError) as exc_info:
                    get_api_key(
                        api_key_env="ANTHROPIC_API_KEY",
                        use_keyring=True,
                        keyring_name="api_key",
                    )

                assert "API key not found" in str(exc_info.value)
