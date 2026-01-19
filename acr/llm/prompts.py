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

"""Prompt templates for LLM interactions."""

from typing import Dict, Any


class PromptTemplates:
    """Prompt templates for various LLM tasks."""

    @staticmethod
    def generate_attack_vector(code: str, pattern: str, context: Dict[str, Any]) -> str:
        """Generate prompt for attack vector generation.

        Args:
            code: Source code snippet
            pattern: Attack pattern description
            context: Additional context

        Returns:
            Prompt string
        """
        # TODO: Implement attack vector prompt
        pass

    @staticmethod
    def explain_vulnerability(code: str, finding: Dict[str, Any]) -> str:
        """Generate prompt for vulnerability explanation.

        Args:
            code: Source code snippet
            finding: Finding details

        Returns:
            Prompt string
        """
        # TODO: Implement explanation prompt
        pass

    @staticmethod
    def suggest_remediation(code: str, pattern: str) -> str:
        """Generate prompt for remediation suggestions.

        Args:
            code: Source code snippet
            pattern: Attack pattern description

        Returns:
            Prompt string
        """
        # TODO: Implement remediation prompt
        pass
