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

"""Base reporter interface."""

from abc import ABC, abstractmethod
from typing import List
from pathlib import Path

from acr.models.finding import Finding


class BaseReporter(ABC):
    """Abstract base class for reporters."""

    @abstractmethod
    def generate(self, findings: List[Finding]) -> str:
        """Generate report from findings.

        Args:
            findings: List of findings to report

        Returns:
            Generated report as string
        """
        pass

    @abstractmethod
    def write(self, findings: List[Finding], output_path: Path) -> None:
        """Write report to file.

        Args:
            findings: List of findings to report
            output_path: Path to write report
        """
        pass
