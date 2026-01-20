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

"""Analysis result caching."""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, TypeVar

try:
    import diskcache
except ImportError:
    diskcache = None

T = TypeVar("T")


class AnalysisCache:
    """Cache for analysis results to avoid redundant processing."""

    DEFAULT_CACHE_DIR = ".acr-cache"
    DEFAULT_TTL = 86400

    def __init__(
        self,
        cache_dir: str = DEFAULT_CACHE_DIR,
        ttl: int = DEFAULT_TTL,
        enabled: bool = True,
    ):
        """Initialize analysis cache.

        Args:
            cache_dir: Directory for cache storage
            ttl: Time to live in seconds (default 24 hours)
            enabled: Whether caching is enabled
        """
        self._enabled = enabled
        self.hits = 0
        self.misses = 0
        self._file_index: Dict[str, str] = {}

        if not enabled:
            self.cache = None
            return

        if diskcache is None:
            raise ImportError("diskcache is required. Install with: pip install diskcache")

        self.cache = diskcache.Cache(cache_dir, ttl=ttl)

    def get(self, file_path: str, cache_type: str, **kwargs) -> Optional[Any]:
        """Get cached analysis result.

        Args:
            file_path: Path to the analyzed file
            cache_type: Type of cached result (ast, cfg, dfg, entry_points, sinks, etc.)
            **kwargs: Additional parameters affecting the result

        Returns:
            Cached result or None
        """
        if not self._enabled or self.cache is None:
            self.misses += 1
            return None

        key = self._make_key(file_path, cache_type, **kwargs)
        result = self.cache.get(key)

        if result is not None:
            self.hits += 1
        else:
            self.misses += 1

        return result

    def set(self, file_path: str, cache_type: str, result: Any, **kwargs) -> None:
        """Cache an analysis result.

        Args:
            file_path: Path to the analyzed file
            cache_type: Type of result (ast, cfg, dfg, entry_points, sinks, etc.)
            result: Result to cache
            **kwargs: Additional parameters affecting result
        """
        if not self._enabled or self.cache is None:
            return

        key = self._make_key(file_path, cache_type, **kwargs)
        self.cache.set(key, result)

        try:
            file_hash = self.get_file_hash(file_path)
        except FileNotFoundError:
            file_hash = hashlib.sha256(file_path.encode()).hexdigest()

        self._file_index[f"{file_hash}:{cache_type}"] = key

    def get_file_hash(self, file_path: str) -> str:
        """Get hash of file content for cache key generation.

        Args:
            file_path: Path to the file

        Returns:
            SHA256 hash of file content
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _make_key(self, file_path: str, cache_type: str, **kwargs) -> str:
        """Create cache key from parameters.

        Args:
            file_path: Path to the analyzed file
            cache_type: Type of cached result
            **kwargs: Additional parameters

        Returns:
            Cache key hash
        """
        try:
            file_hash = self.get_file_hash(file_path)
        except FileNotFoundError:
            file_hash = hashlib.sha256(file_path.encode()).hexdigest()

        data = {
            "file_hash": file_hash,
            "cache_type": cache_type,
            "kwargs": sorted(kwargs.items()),
        }
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()

    def invalidate_file(self, file_path: str) -> None:
        """Invalidate all cached results for a specific file.

        Args:
            file_path: Path to the file
        """
        if not self._enabled or self.cache is None:
            return

        try:
            file_hash = self.get_file_hash(file_path)
        except FileNotFoundError:
            file_hash = hashlib.sha256(file_path.encode()).hexdigest()

        keys_to_delete = []

        for index_key, cache_key in list(self._file_index.items()):
            if index_key.startswith(file_hash):
                keys_to_delete.append(cache_key)
                del self._file_index[index_key]

        for cache_key in keys_to_delete:
            del self.cache[cache_key]

    def clear(self) -> None:
        """Clear all cached entries."""
        if not self._enabled or self.cache is None:
            return

        self.cache.clear()
        self.hits = 0
        self.misses = 0

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        if not self._enabled:
            return {
                "enabled": False,
                "hits": 0,
                "misses": 0,
                "hit_rate": 0.0,
                "total_requests": 0,
            }

        total = self.hits + self.misses
        hit_rate = self.hits / total if total > 0 else 0

        stats = {
            "enabled": self._enabled,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate,
            "total_requests": total,
        }

        if self.cache is not None:
            stats["cache_size"] = len(self.cache)

        return stats

    def is_enabled(self) -> bool:
        """Check if caching is enabled.

        Returns:
            True if caching is enabled
        """
        return self._enabled
