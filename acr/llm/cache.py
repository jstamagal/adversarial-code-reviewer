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

"""LLM response caching."""

from typing import Optional, Dict, Any
import hashlib
import json

try:
    import diskcache
except ImportError:
    diskcache = None


class LLMCache:
    """Cache LLM responses to reduce API calls."""

    def __init__(self, cache_dir: str = ".acr-cache", ttl: int = 86400):
        """Initialize LLM cache.

        Args:
            cache_dir: Directory for cache storage
            ttl: Time to live in seconds (default 24 hours)
        """
        if diskcache is None:
            raise ImportError("diskcache is required. Install with: pip install diskcache")
        self.cache = diskcache.Cache(cache_dir, ttl=ttl)
        self.hits = 0
        self.misses = 0

    def get(self, prompt: str, model: str, **kwargs) -> Optional[str]:
        """Get cached response.

        Args:
            prompt: Input prompt
            model: Model name
            **kwargs: Additional parameters affecting output

        Returns:
            Cached response or None
        """
        key = self._make_key(prompt, model, **kwargs)
        result = self.cache.get(key)
        if result:
            self.hits += 1
        else:
            self.misses += 1
        return result

    def set(self, prompt: str, model: str, response: str, **kwargs) -> None:
        """Cache a response.

        Args:
            prompt: Input prompt
            model: Model name
            response: Response to cache
            **kwargs: Additional parameters affecting output
        """
        key = self._make_key(prompt, model, **kwargs)
        self.cache.set(key, response)

    def _make_key(self, prompt: str, model: str, **kwargs) -> str:
        """Create cache key from parameters.

        Args:
            prompt: Input prompt
            model: Model name
            **kwargs: Additional parameters

        Returns:
            Cache key hash
        """
        data = {"prompt": prompt, "model": model, **kwargs}
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        total = self.hits + self.misses
        hit_rate = self.hits / total if total > 0 else 0
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate,
            "total_requests": total,
        }

    def clear(self) -> None:
        """Clear all cached entries."""
        self.cache.clear()
        self.hits = 0
        self.misses = 0
