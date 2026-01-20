# Copyright 2026 Adversarial Code Reviewer Contributors
#
# Licensed under the MIT License;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://opensource.org/licenses/MIT
#
# Unless required by applicable applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for analysis cache."""

from pathlib import Path

import pytest

from acr.utils.cache import AnalysisCache


@pytest.fixture
def test_file(tmp_path):
    """Create a test file with content."""
    test_file = tmp_path / "test.py"
    test_file.write_text("def hello():\n    return 'world'")
    return str(test_file)


@pytest.fixture
def cache(tmp_path):
    """Create a cache instance with temporary directory."""
    cache_dir = str(tmp_path / "cache")
    return AnalysisCache(cache_dir=cache_dir, ttl=60)


class TestAnalysisCache:
    """Tests for AnalysisCache class."""

    def test_cache_hit(self, cache, test_file):
        """Test that cache returns cached value."""
        result = {"ast": "mock_ast"}
        cache.set(test_file, "ast", result)

        cached = cache.get(test_file, "ast")
        assert cached == result
        assert cache.hits == 1
        assert cache.misses == 0

    def test_cache_miss(self, cache, test_file):
        """Test that cache returns None for missing keys."""
        cached = cache.get(test_file, "ast")
        assert cached is None
        assert cache.hits == 0
        assert cache.misses == 1

    def test_cache_different_types(self, cache, test_file):
        """Test caching different result types."""
        ast_result = {"ast": "mock_ast"}
        cfg_result = {"cfg": "mock_cfg"}
        dfg_result = {"dfg": "mock_dfg"}

        cache.set(test_file, "ast", ast_result)
        cache.set(test_file, "cfg", cfg_result)
        cache.set(test_file, "dfg", dfg_result)

        assert cache.get(test_file, "ast") == ast_result
        assert cache.get(test_file, "cfg") == cfg_result
        assert cache.get(test_file, "dfg") == dfg_result
        assert cache.hits == 3
        assert cache.misses == 0

    def test_cache_with_kwargs(self, cache, test_file):
        """Test that different kwargs create different cache entries."""
        result1 = {"value": "result1"}
        result2 = {"value": "result2"}

        cache.set(test_file, "pattern_match", result1, pattern_id="sql_injection")
        cache.set(test_file, "pattern_match", result2, pattern_id="xss")

        assert cache.get(test_file, "pattern_match", pattern_id="sql_injection") == result1
        assert cache.get(test_file, "pattern_match", pattern_id="xss") == result2

    def test_file_hash_consistency(self, cache, test_file):
        """Test that file hash is consistent across calls."""
        hash1 = cache.get_file_hash(test_file)
        hash2 = cache.get_file_hash(test_file)
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_file_hash_changes(self, cache, test_file, tmp_path):
        """Test that file hash changes when content changes."""
        hash1 = cache.get_file_hash(test_file)

        path = Path(test_file)
        path.write_text("def modified():\n    return 'changed'")

        hash2 = cache.get_file_hash(test_file)
        assert hash1 != hash2

    def test_get_file_hash_not_found(self, cache, tmp_path):
        """Test that get_file_hash raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            cache.get_file_hash("nonexistent.py")

    def test_invalidate_file(self, cache, test_file):
        """Test invalidating cache for a specific file."""
        result1 = {"ast": "mock_ast"}
        result2 = {"cfg": "mock_cfg"}

        cache.set(test_file, "ast", result1)
        cache.set(test_file, "cfg", result2)

        assert cache.get(test_file, "ast") == result1
        assert cache.get(test_file, "cfg") == result2

        cache.invalidate_file(test_file)

        assert cache.get(test_file, "ast") is None
        assert cache.get(test_file, "cfg") is None

    def test_clear(self, cache, test_file):
        """Test clearing all cache entries."""
        cache.set(test_file, "ast", {"ast": "mock"})
        assert cache.get(test_file, "ast") is not None

        cache.clear()

        assert cache.get(test_file, "ast") is None
        assert cache.hits == 0
        assert cache.misses == 1

    def test_get_stats(self, cache, test_file):
        """Test getting cache statistics."""
        cache.set(test_file, "ast", {"ast": "mock"})
        cache.get(test_file, "ast")
        cache.get(test_file, "cfg")

        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate"] == 0.5
        assert stats["total_requests"] == 2
        assert stats["enabled"] is True
        assert "cache_size" in stats

    def test_cache_disabled(self, test_file, tmp_path):
        """Test that disabled cache doesn't cache."""
        cache_dir = str(tmp_path / "disabled_cache")
        cache = AnalysisCache(cache_dir=cache_dir, enabled=False)

        result = {"ast": "mock_ast"}
        cache.set(test_file, "ast", result)

        cached = cache.get(test_file, "ast")
        assert cached is None
        assert cache.misses == 1

    def test_is_enabled(self, cache, tmp_path):
        """Test is_enabled method."""
        assert cache.is_enabled() is True

        disabled_cache = AnalysisCache(enabled=False)
        assert disabled_cache.is_enabled() is False

    def test_cache_complex_object(self, cache, test_file):
        """Test caching complex Python objects."""
        complex_result = {
            "nested": {
                "list": [1, 2, 3],
                "dict": {"key": "value"},
                "tuple": (4, 5, 6),
            },
            "simple": "string",
            "number": 42,
        }

        cache.set(test_file, "complex", complex_result)
        cached = cache.get(test_file, "complex")

        assert cached == complex_result

    def test_cache_list_result(self, cache, test_file):
        """Test caching list results."""
        list_result = ["item1", "item2", "item3"]

        cache.set(test_file, "list", list_result)
        cached = cache.get(test_file, "list")

        assert cached == list_result

    def test_cache_different_files(self, cache, tmp_path):
        """Test caching results from different files."""
        file1 = tmp_path / "file1.py"
        file1.write_text("def func1():\n    pass")

        file2 = tmp_path / "file2.py"
        file2.write_text("def func2():\n    pass")

        result1 = {"file": "file1"}
        result2 = {"file": "file2"}

        cache.set(str(file1), "ast", result1)
        cache.set(str(file2), "ast", result2)

        assert cache.get(str(file1), "ast") == result1
        assert cache.get(str(file2), "ast") == result2

    def test_cache_kwargs_ordering(self, cache, test_file):
        """Test that kwargs order doesn't affect cache key."""
        result1 = {"value": "result1"}

        cache.set(test_file, "pattern", result1, a=1, b=2, c=3)

        cached1 = cache.get(test_file, "pattern", a=1, b=2, c=3)
        cached2 = cache.get(test_file, "pattern", c=3, b=2, a=1)

        assert cached1 == result1
        assert cached2 == result1

    def test_cache_missing_file_hash_uses_path(self, cache, tmp_path):
        """Test that missing file uses path for hash."""
        nonexistent = "nonexistent.py"

        cache.set(nonexistent, "test", {"value": "result"})

        cached = cache.get(nonexistent, "test")
        assert cached == {"value": "result"}
        assert cache.hits == 1

    def test_stats_with_empty_cache(self, cache):
        """Test stats with empty cache."""
        stats = cache.get_stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["hit_rate"] == 0.0
        assert stats["total_requests"] == 0
        assert stats["enabled"] is True

    def test_stats_disabled_cache(self):
        """Test stats when cache is disabled."""
        disabled_cache = AnalysisCache(enabled=False)
        stats = disabled_cache.get_stats()
        assert stats["enabled"] is False
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["total_requests"] == 0
