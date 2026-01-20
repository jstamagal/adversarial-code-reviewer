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

"""LLM client implementation."""

import os
import time
import logging
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod

import anthropic
import openai

logger = logging.getLogger(__name__)


class LLMClient(ABC):
    """Abstract LLM client interface."""

    def __init__(self, api_key: str, model: str, max_retries: int = 3, retry_delay: float = 1.0):
        """Initialize LLM client.

        Args:
            api_key: API key for the provider
            model: Model name
            max_retries: Maximum number of retries for failed requests
            retry_delay: Initial delay between retries (exponential backoff)
        """
        self.api_key = api_key
        self.model = model
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    @abstractmethod
    def generate(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """Generate text from prompt.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text
        """
        pass

    def _retry_with_backoff(self, func, *args, **kwargs):
        """Execute function with exponential backoff retry.

        Args:
            func: Function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function

        Returns:
            Function result

        Raises:
            Exception: If all retries fail
        """
        last_exception = None
        for attempt in range(self.max_retries + 1):
            try:
                return func(*args, **kwargs)
            except (anthropic.APIError, openai.APIError, ConnectionError) as e:
                last_exception = e
                if attempt < self.max_retries:
                    delay = self.retry_delay * (2**attempt)
                    logger.warning(
                        f"LLM API call failed (attempt {attempt + 1}/{self.max_retries + 1}), "
                        f"retrying in {delay}s: {e}"
                    )
                    time.sleep(delay)
                else:
                    logger.error(f"LLM API call failed after {self.max_retries + 1} attempts: {e}")
            except Exception as e:
                logger.error(f"Unexpected error in LLM API call: {e}")
                raise

        if last_exception is not None:
            raise last_exception
        raise RuntimeError("Unknown error in LLM API retry logic")


class AnthropicClient(LLMClient):
    """Anthropic Claude client implementation."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-3-5-sonnet-20241022",
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        """Initialize Anthropic client.

        Args:
            api_key: Anthropic API key
            model: Model name
            max_retries: Maximum number of retries for failed requests
            retry_delay: Initial delay between retries (exponential backoff)
        """
        super().__init__(api_key, model, max_retries, retry_delay)
        self.client = anthropic.Anthropic(api_key=api_key)

    def generate(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """Generate text using Claude.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text
        """
        try:
            result = self._retry_with_backoff(
                self._generate,
                prompt,
                max_tokens or 4096,
            )
            return result
        except Exception as e:
            logger.error(f"Failed to generate response from Anthropic: {e}")
            raise

    def _generate(self, prompt: str, max_tokens: int) -> str:
        """Generate text using Claude (internal method with retry logic).

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text

        Raises:
            anthropic.APIError: If API call fails
        """
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            if not response.content:
                raise RuntimeError("Empty response from Anthropic API")
            return response.content[0].text
        except anthropic.RateLimitError as e:
            logger.warning(f"Anthropic rate limit exceeded: {e}")
            raise
        except anthropic.APITimeoutError as e:
            logger.warning(f"Anthropic API timeout: {e}")
            raise
        except anthropic.APIConnectionError as e:
            logger.warning(f"Anthropic API connection error: {e}")
            raise


class OpenAIClient(LLMClient):
    """OpenAI GPT client implementation."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4",
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        """Initialize OpenAI client.

        Args:
            api_key: OpenAI API key
            model: Model name
            max_retries: Maximum number of retries for failed requests
            retry_delay: Initial delay between retries (exponential backoff)
        """
        super().__init__(api_key, model, max_retries, retry_delay)
        self.client = openai.OpenAI(api_key=api_key)

    def generate(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """Generate text using GPT.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text
        """
        try:
            result = self._retry_with_backoff(
                self._generate,
                prompt,
                max_tokens or 4096,
            )
            return result
        except Exception as e:
            logger.error(f"Failed to generate response from OpenAI: {e}")
            raise

    def _generate(self, prompt: str, max_tokens: int) -> str:
        """Generate text using GPT (internal method with retry logic).

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text

        Raises:
            openai.APIError: If API call fails
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
            )
            if not response.choices:
                raise RuntimeError("Empty response from OpenAI API")
            content = response.choices[0].message.content
            if content is None:
                raise RuntimeError("Null content in OpenAI API response")
            return content
        except openai.RateLimitError as e:
            logger.warning(f"OpenAI rate limit exceeded: {e}")
            raise
        except openai.APITimeoutError as e:
            logger.warning(f"OpenAI API timeout: {e}")
            raise
        except openai.APIConnectionError as e:
            logger.warning(f"OpenAI API connection error: {e}")
            raise


def get_api_key(
    api_key_env: str,
    use_keyring: bool,
    keyring_name: str,
) -> str:
    """Get API key from environment or keyring.

    Args:
        api_key_env: Environment variable name for API key
        use_keyring: Whether to check keyring for API key
        keyring_name: Credential name in keyring

    Returns:
        API key string

    Raises:
        ValueError: If API key cannot be found
    """
    api_key = os.environ.get(api_key_env)

    if not api_key and use_keyring:
        try:
            from acr.config.credentials import get_credential

            api_key = get_credential(keyring_name)
            if api_key:
                logger.info(f"Retrieved API key from keyring (credential: {keyring_name})")
        except Exception as e:
            logger.warning(f"Failed to retrieve API key from keyring: {e}")

    if not api_key:
        raise ValueError(
            f"API key not found. Set {api_key_env} environment variable "
            f"or store it in keyring with name '{keyring_name}'"
        )

    return api_key


def create_client(
    provider: str,
    api_key: str,
    model: Optional[str] = None,
    max_retries: int = 3,
    retry_delay: float = 1.0,
) -> LLMClient:
    """Create LLM client for given provider.

    Args:
        provider: Provider name (anthropic or openai)
        api_key: API key
        model: Model name (optional)
        max_retries: Maximum number of retries for failed requests
        retry_delay: Initial delay between retries (exponential backoff)

    Returns:
        LLM client instance
    """
    if provider == "anthropic":
        return AnthropicClient(
            api_key,
            model or "claude-3-5-sonnet-20241022",
            max_retries,
            retry_delay,
        )
    elif provider == "openai":
        return OpenAIClient(
            api_key,
            model or "gpt-4",
            max_retries,
            retry_delay,
        )
    else:
        raise ValueError(f"Unsupported provider: {provider}")
