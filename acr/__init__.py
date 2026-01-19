# Copyright 2026 Adversarial Code Reviewer Contributors
#
# Licensed under MIT License;
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

"""Adversarial Code Reviewer - AI-powered security analysis tool."""

__version__ = "0.1.0"
__author__ = "ACR Contributors"
__license__ = "MIT"

from acr.models.finding import Finding
from acr.models.pattern import Pattern

__all__ = ["Finding", "Pattern", "__version__"]
