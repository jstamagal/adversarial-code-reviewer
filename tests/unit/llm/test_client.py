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

"""Tests for LLM client implementations."""

import pytest
from unittest.mock import Mock, patch, MagicMock

from acr.llm.client import AnthropicClient, OpenAIClient, create_client, LLMClient


class TestLLMClient:
    """Tests for LLM client base class."""

    def test_base_class_is_abstract(self):
        """Test that LLMClient is abstract and cannot be instantiated."""
        with pytest.raises(TypeError):
            LLMClient(api_key="test-key", model="test-model")


class TestAnthropicClient:
    """Tests for Anthropic Claude client."""

    def test_initialization(self):
        """Test AnthropicClient initialization."""
        client = AnthropicClient(api_key="test-key", model="claude-3-5-sonnet-20241022")
        assert client.api_key == "test-key"
        assert client.model == "claude-3-5-sonnet-20241022"
        assert client.max_retries == 3
        assert client.retry_delay == 1.0

    def test_initialization_custom_retries(self):
        """Test AnthropicClient with custom retry settings."""
        client = AnthropicClient(
            api_key="test-key",
            model="claude-3-opus-20240229",
            max_retries=5,
            retry_delay=2.0,
        )
        assert client.model == "claude-3-opus-20240229"
        assert client.max_retries == 5
        assert client.retry_delay == 2.0

    @patch("acr.llm.client.anthropic.Anthropic")
    def test_generate_success(self, mock_anthropic):
        """Test successful text generation."""
        mock_response = Mock()
        mock_response.content = [Mock(text="Generated text")]
        mock_client = Mock()
        mock_client.messages.create.return_value = mock_response
        mock_anthropic.return_value = mock_client

        client = AnthropicClient(api_key="test-key")
        result = client.generate("Test prompt")

        assert result == "Generated text"
        mock_client.messages.create.assert_called_once_with(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4096,
            messages=[{"role": "user", "content": "Test prompt"}],
        )

    @patch("acr.llm.client.anthropic.Anthropic")
    def test_generate_with_max_tokens(self, mock_anthropic):
        """Test text generation with custom max_tokens."""
        mock_response = Mock()
        mock_response.content = [Mock(text="Generated text")]
        mock_client = Mock()
        mock_client.messages.create.return_value = mock_response
        mock_anthropic.return_value = mock_client

        client = AnthropicClient(api_key="test-key")
        result = client.generate("Test prompt", max_tokens=1024)

        assert result == "Generated text"
        mock_client.messages.create.assert_called_once_with(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Test prompt"}],
        )

    @patch("acr.llm.client.anthropic.Anthropic")
    def test_generate_retry_on_rate_limit(self, mock_anthropic):
        """Test retry logic on rate limit error."""
        from anthropic import RateLimitError

        mock_response = Mock()
        mock_response.content = [Mock(text="Generated text")]
        mock_client = Mock()
        error = RateLimitError(message="Rate limit exceeded", response=Mock(), body=None)
        mock_client.messages.create.side_effect = [error, mock_response]
        mock_anthropic.return_value = mock_client

        client = AnthropicClient(api_key="test-key")
        result = client.generate("Test prompt")

        assert result == "Generated text"
        assert mock_client.messages.create.call_count == 2

    @patch("acr.llm.client.anthropic.Anthropic")
    def test_generate_retry_on_connection_error(self, mock_anthropic):
        """Test retry logic on connection error."""
        from anthropic import APIConnectionError

        mock_response = Mock()
        mock_response.content = [Mock(text="Generated text")]
        mock_client = Mock()
        mock_client.messages.create.side_effect = [
            APIConnectionError(message="Connection failed", request=None),
            mock_response,
        ]
        mock_anthropic.return_value = mock_client

        client = AnthropicClient(api_key="test-key")
        result = client.generate("Test prompt")

        assert result == "Generated text"
        assert mock_client.messages.create.call_count == 2

    @patch("acr.llm.client.anthropic.Anthropic")
    def test_generate_max_retries_exceeded(self, mock_anthropic):
        """Test that max retries are respected."""
        from anthropic import RateLimitError

        mock_client = Mock()
        error = RateLimitError(message="Rate limit exceeded", response=Mock(), body=None)
        mock_client.messages.create.side_effect = error
        mock_anthropic.return_value = mock_client

        client = AnthropicClient(api_key="test-key", max_retries=2)

        with pytest.raises(RateLimitError):
            client.generate("Test prompt")

        assert mock_client.messages.create.call_count == 3

    @patch("acr.llm.client.anthropic.Anthropic")
    def test_generate_empty_response(self, mock_anthropic):
        """Test handling of empty response."""
        mock_response = Mock()
        mock_response.content = []
        mock_client = Mock()
        mock_client.messages.create.return_value = mock_response
        mock_anthropic.return_value = mock_client

        client = AnthropicClient(api_key="test-key")

        with pytest.raises(RuntimeError, match="Empty response"):
            client.generate("Test prompt")


class TestOpenAIClient:
    """Tests for OpenAI GPT client."""

    def test_initialization(self):
        """Test OpenAIClient initialization."""
        client = OpenAIClient(api_key="test-key", model="gpt-4")
        assert client.api_key == "test-key"
        assert client.model == "gpt-4"
        assert client.max_retries == 3
        assert client.retry_delay == 1.0

    def test_initialization_custom_retries(self):
        """Test OpenAIClient with custom retry settings."""
        client = OpenAIClient(
            api_key="test-key",
            model="gpt-3.5-turbo",
            max_retries=5,
            retry_delay=2.0,
        )
        assert client.model == "gpt-3.5-turbo"
        assert client.max_retries == 5
        assert client.retry_delay == 2.0

    @patch("acr.llm.client.openai.OpenAI")
    def test_generate_success(self, mock_openai):
        """Test successful text generation."""
        mock_response = Mock()
        mock_response.choices = [Mock(message=Mock(content="Generated text"))]
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client

        client = OpenAIClient(api_key="test-key")
        result = client.generate("Test prompt")

        assert result == "Generated text"
        mock_client.chat.completions.create.assert_called_once_with(
            model="gpt-4",
            messages=[{"role": "user", "content": "Test prompt"}],
            max_tokens=4096,
        )

    @patch("acr.llm.client.openai.OpenAI")
    def test_generate_with_max_tokens(self, mock_openai):
        """Test text generation with custom max_tokens."""
        mock_response = Mock()
        mock_response.choices = [Mock(message=Mock(content="Generated text"))]
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client

        client = OpenAIClient(api_key="test-key")
        result = client.generate("Test prompt", max_tokens=1024)

        assert result == "Generated text"
        mock_client.chat.completions.create.assert_called_once_with(
            model="gpt-4",
            messages=[{"role": "user", "content": "Test prompt"}],
            max_tokens=1024,
        )

    @patch("acr.llm.client.openai.OpenAI")
    def test_generate_retry_on_rate_limit(self, mock_openai):
        """Test retry logic on rate limit error."""
        from openai import RateLimitError

        mock_response = Mock()
        mock_response.choices = [Mock(message=Mock(content="Generated text"))]
        mock_client = Mock()
        error = RateLimitError(message="Rate limit exceeded", response=Mock(), body=Mock())
        mock_client.chat.completions.create.side_effect = [error, mock_response]
        mock_openai.return_value = mock_client

        client = OpenAIClient(api_key="test-key")
        result = client.generate("Test prompt")

        assert result == "Generated text"
        assert mock_client.chat.completions.create.call_count == 2

    @patch("acr.llm.client.openai.OpenAI")
    def test_generate_retry_on_connection_error(self, mock_openai):
        """Test retry logic on connection error."""
        from openai import APIConnectionError

        mock_response = Mock()
        mock_response.choices = [Mock(message=Mock(content="Generated text"))]
        mock_client = Mock()
        mock_client.chat.completions.create.side_effect = [
            APIConnectionError(message="Connection failed", request=None),
            mock_response,
        ]
        mock_openai.return_value = mock_client

        client = OpenAIClient(api_key="test-key")
        result = client.generate("Test prompt")

        assert result == "Generated text"
        assert mock_client.chat.completions.create.call_count == 2

    @patch("acr.llm.client.openai.OpenAI")
    def test_generate_max_retries_exceeded(self, mock_openai):
        """Test that max retries are respected."""
        from openai import RateLimitError

        mock_client = Mock()
        error = RateLimitError(message="Rate limit exceeded", response=Mock(), body=Mock())
        mock_client.chat.completions.create.side_effect = error
        mock_openai.return_value = mock_client

        client = OpenAIClient(api_key="test-key", max_retries=2)

        with pytest.raises(RateLimitError):
            client.generate("Test prompt")

        assert mock_client.chat.completions.create.call_count == 3

    @patch("acr.llm.client.openai.OpenAI")
    def test_generate_empty_response(self, mock_openai):
        """Test handling of empty response."""
        mock_response = Mock()
        mock_response.choices = []
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client

        client = OpenAIClient(api_key="test-key")

        with pytest.raises(RuntimeError, match="Empty response"):
            client.generate("Test prompt")

    @patch("acr.llm.client.openai.OpenAI")
    def test_generate_null_content(self, mock_openai):
        """Test handling of null content in response."""
        mock_response = Mock()
        mock_response.choices = [Mock(message=Mock(content=None))]
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client

        client = OpenAIClient(api_key="test-key")

        with pytest.raises(RuntimeError, match="Null content"):
            client.generate("Test prompt")


class TestCreateClient:
    """Tests for create_client factory function."""

    def test_create_anthropic_client(self):
        """Test creating Anthropic client."""
        client = create_client("anthropic", "test-api-key")
        assert isinstance(client, AnthropicClient)
        assert client.api_key == "test-api-key"
        assert client.model == "claude-3-5-sonnet-20241022"

    def test_create_anthropic_client_with_custom_model(self):
        """Test creating Anthropic client with custom model."""
        client = create_client("anthropic", "test-api-key", model="claude-3-opus-20240229")
        assert isinstance(client, AnthropicClient)
        assert client.model == "claude-3-opus-20240229"

    def test_create_openai_client(self):
        """Test creating OpenAI client."""
        client = create_client("openai", "test-api-key")
        assert isinstance(client, OpenAIClient)
        assert client.api_key == "test-api-key"
        assert client.model == "gpt-4"

    def test_create_openai_client_with_custom_model(self):
        """Test creating OpenAI client with custom model."""
        client = create_client("openai", "test-api-key", model="gpt-3.5-turbo")
        assert isinstance(client, OpenAIClient)
        assert client.model == "gpt-3.5-turbo"

    def test_create_unsupported_provider(self):
        """Test that unsupported provider raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported provider"):
            create_client("invalid", "test-api-key")

    def test_create_client_with_retry_settings(self):
        """Test creating client with custom retry settings."""
        client = create_client("anthropic", "test-api-key", max_retries=5, retry_delay=2.0)
        assert client.max_retries == 5
        assert client.retry_delay == 2.0
