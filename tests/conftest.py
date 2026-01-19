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

"""Test configuration for pytest."""

import pytest
from pathlib import Path
from acr.config.schema import ACRConfig


@pytest.fixture
def sample_config() -> ACRConfig:
    """Create sample configuration for testing."""
    return ACRConfig()


@pytest.fixture
def test_data_dir() -> Path:
    """Get path to test data directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_code() -> str:
    """Get sample Python code for testing."""
    return """
def vulnerable_function(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return execute_query(query)
"""
