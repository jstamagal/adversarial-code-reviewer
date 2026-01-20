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

"""Tests for LLM cache."""

import pytest
from acr.llm.cache import LLMCache
import tempfile
import shutil


@pytest.fixture
def tmp_cache_dir(tmp_path):
    """Create a temporary cache directory."""
    cache_dir = tmp_path / "llm-cache"
    yield str(cache_dir)
    if cache_dir.exists():
        shutil.rmtree(cache_dir)


@pytest.fixture
def cache(tmp_cache_dir):
    """Create a cache instance for testing."""
    return LLMCache(cache_dir=tmp_cache_dir, ttl=60)


class TestLLMCache:
    """Tests for LLMCache class."""

    def test_cache_hit(self, cache):
        """Test that cache returns cached value."""
        prompt = "Analyze this code: def foo(): pass"
        model = "claude-3-5-sonnet-20241022"
        response = "This code looks fine."

        cache.set(prompt, model, response)
        cached = cache.get(prompt, model)

        assert cached == response
        assert cache.hits == 1
        assert cache.misses == 0

    def test_cache_miss(self, cache):
        """Test that cache returns None for missing keys."""
        prompt = "Analyze this code: def foo(): pass"
        model = "claude-3-5-sonnet-20241022"

        cached = cache.get(prompt, model)

        assert cached is None
        assert cache.hits == 0
        assert cache.misses == 1

    def test_cache_different_prompts(self, cache):
        """Test that different prompts have different cache entries."""
        prompt1 = "Analyze this code: def foo(): pass"
        prompt2 = "Analyze this code: def bar(): pass"
        model = "claude-3-5-sonnet-20241022"
        response1 = "Code foo looks fine."
        response2 = "Code bar looks fine."

        cache.set(prompt1, model, response1)
        cache.set(prompt2, model, response2)

        assert cache.get(prompt1, model) == response1
        assert cache.get(prompt2, model) == response2
        assert cache.hits == 2
        assert cache.misses == 0

    def test_cache_different_models(self, cache):
        """Test that different models have different cache entries."""
        prompt = "Analyze this code: def foo(): pass"
        model1 = "claude-3-5-sonnet-20241022"
        model2 = "gpt-4"
        response1 = "Claude says: Code looks fine."
        response2 = "GPT says: Code looks fine."

        cache.set(prompt, model1, response1)
        cache.set(prompt, model2, response2)

        assert cache.get(prompt, model1) == response1
        assert cache.get(prompt, model2) == response2

    def test_cache_with_kwargs(self, cache):
        """Test that different kwargs create different cache entries."""
        prompt = "Analyze this code"
        model = "claude-3-5-sonnet-20241022"

        response1 = "Short response"
        response2 = "Long response"

        cache.set(prompt, model, response1, max_tokens=100)
        cache.set(prompt, model, response2, max_tokens=1000)

        assert cache.get(prompt, model, max_tokens=100) == response1
        assert cache.get(prompt, model, max_tokens=1000) == response2

    def test_cache_with_multiple_kwargs(self, cache):
        """Test caching with multiple kwargs."""
        prompt = "Analyze this code"
        model = "claude-3-5-sonnet-20241022"

        response = "Response with multiple params"

        cache.set(prompt, model, response, max_tokens=100, temperature=0.7, top_p=0.9)

        cached = cache.get(prompt, model, max_tokens=100, temperature=0.7, top_p=0.9)
        assert cached == response

    def test_cache_kwargs_ordering(self, cache):
        """Test that kwargs order doesn't affect cache key."""
        prompt = "Analyze this code"
        model = "claude-3-5-sonnet-20241022"
        response = "Response"

        cache.set(prompt, model, response, a=1, b=2, c=3)

        cached1 = cache.get(prompt, model, a=1, b=2, c=3)
        cached2 = cache.get(prompt, model, c=3, b=2, a=1)

        assert cached1 == response
        assert cached2 == response

    def test_clear(self, cache):
        """Test clearing all cache entries."""
        prompt = "Analyze this code"
        model = "claude-3-5-sonnet-20241022"
        response = "Response"

        cache.set(prompt, model, response)
        assert cache.get(prompt, model) == response

        cache.clear()

        assert cache.get(prompt, model) is None
        assert cache.hits == 0
        assert cache.misses == 1

    def test_get_stats(self, cache):
        """Test getting cache statistics."""
        prompt1 = "Prompt 1"
        prompt2 = "Prompt 2"
        model = "claude-3-5-sonnet-20241022"
        response = "Response"

        cache.set(prompt1, model, response)
        cache.get(prompt1, model)
        cache.get(prompt2, model)

        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate"] == 0.5
        assert stats["total_requests"] == 2

    def test_get_stats_empty_cache(self, cache):
        """Test stats with empty cache."""
        stats = cache.get_stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["hit_rate"] == 0.0
        assert stats["total_requests"] == 0

    def test_key_generation_consistency(self, cache):
        """Test that key generation is consistent."""
        prompt = "Analyze this code"
        model = "claude-3-5-sonnet-20241022"

        key1 = cache._make_key(prompt, model)
        key2 = cache._make_key(prompt, model)

        assert key1 == key2
        assert len(key1) == 64

    def test_key_generation_different_prompts(self, cache):
        """Test that different prompts generate different keys."""
        prompt1 = "Prompt 1"
        prompt2 = "Prompt 2"
        model = "claude-3-5-sonnet-20241022"

        key1 = cache._make_key(prompt1, model)
        key2 = cache._make_key(prompt2, model)

        assert key1 != key2

    def test_key_generation_different_models(self, cache):
        """Test that different models generate different keys."""
        prompt = "Prompt"
        model1 = "claude-3-5-sonnet-20241022"
        model2 = "gpt-4"

        key1 = cache._make_key(prompt, model1)
        key2 = cache._make_key(prompt, model2)

        assert key1 != key2

    def test_key_generation_with_kwargs(self, cache):
        """Test that kwargs are included in key generation."""
        prompt = "Prompt"
        model = "claude-3-5-sonnet-20241022"

        key1 = cache._make_key(prompt, model, max_tokens=100)
        key2 = cache._make_key(prompt, model, max_tokens=1000)

        assert key1 != key2

    def test_custom_cache_dir(self, tmp_path):
        """Test creating cache with custom directory."""
        custom_dir = tmp_path / "custom-llm-cache"
        cache = LLMCache(cache_dir=str(custom_dir), ttl=60)

        assert custom_dir.exists()
        assert cache.cache.directory == str(custom_dir)

    def test_custom_ttl(self, tmp_path):
        """Test creating cache with custom TTL."""
        cache_dir = tmp_path / "ttl-cache"
        cache = LLMCache(cache_dir=str(cache_dir), ttl=300)

        prompt = "Prompt"
        model = "claude-3-5-sonnet-20241022"
        response = "Response"

        cache.set(prompt, model, response)
        cached = cache.get(prompt, model)

        assert cached == response

    def test_cache_unicode_prompt(self, cache):
        """Test caching with Unicode characters in prompt."""
        prompt = "Analyze this code: def foo(): pass # 你好 🚀"
        model = "claude-3-5-sonnet-20241022"
        response = "Code looks fine."

        cache.set(prompt, model, response)
        cached = cache.get(prompt, model)

        assert cached == response

    def test_cache_empty_response(self, cache):
        """Test caching empty response."""
        prompt = "Prompt"
        model = "claude-3-5-sonnet-20241022"
        response = ""

        cache.set(prompt, model, response)
        cached = cache.get(prompt, model)

        assert cached == ""

    def test_cache_multiline_response(self, cache):
        """Test caching multiline response."""
        prompt = "Prompt"
        model = "claude-3-5-sonnet-20241022"
        response = """Line 1
Line 2
Line 3"""

        cache.set(prompt, model, response)
        cached = cache.get(prompt, model)

        assert cached == response

    def test_cache_special_characters_in_response(self, cache):
        """Test caching response with special characters."""
        prompt = "Prompt"
        model = "claude-3-5-sonnet-20241022"
        response = "Response with special chars: \t\n\r\"'\\"

        cache.set(prompt, model, response)
        cached = cache.get(prompt, model)

        assert cached == response

    def test_cache_long_response(self, cache):
        """Test caching long response."""
        prompt = "Prompt"
        model = "claude-3-5-sonnet-20241022"
        response = "x" * 10000

        cache.set(prompt, model, response)
        cached = cache.get(prompt, model)

        assert cached == response
        assert len(cached) == 10000

    def test_cache_hit_rate_calculation(self, cache):
        """Test hit rate calculation with various scenarios."""
        prompt = "Prompt"
        model = "claude-3-5-sonnet-20241022"
        response = "Response"

        cache.set(prompt, model, response)

        cache.get(prompt, model)
        cache.get(prompt, model)
        cache.get("nonexistent", model)

        stats = cache.get_stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert stats["hit_rate"] == 2 / 3

    def test_cache_multiple_sets_same_key(self, cache):
        """Test that setting same key multiple times overwrites."""
        prompt = "Prompt"
        model = "claude-3-5-sonnet-20241022"
        response1 = "First response"
        response2 = "Second response"

        cache.set(prompt, model, response1)
        cache.set(prompt, model, response2)

        cached = cache.get(prompt, model)
        assert cached == response2

    def test_cache_with_no_diskcache(self, tmp_path, monkeypatch):
        """Test that ImportError is raised when diskcache is not available."""
        cache_dir = tmp_path / "cache"

        monkeypatch.setattr("acr.llm.cache.diskcache", None)

        with pytest.raises(ImportError, match="diskcache is required"):
            LLMCache(cache_dir=str(cache_dir))

    def test_stats_after_clear(self, cache):
        """Test that stats are reset after clear."""
        prompt = "Prompt"
        model = "claude-3-5-sonnet-20241022"
        response = "Response"

        cache.set(prompt, model, response)
        cache.get(prompt, model)
        cache.get("nonexistent", model)

        assert cache.hits == 1
        assert cache.misses == 1

        cache.clear()

        assert cache.hits == 0
        assert cache.misses == 0

        stats = cache.get_stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
