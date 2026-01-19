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

"""Custom exception hierarchy."""


class ACRError(Exception):
    """Base exception for ACR."""

    pass


class ConfigurationError(ACRError):
    """Configuration-related errors."""

    pass


class ParseError(ACRError):
    """Code parsing errors."""

    def __init__(self, message: str, file: str, line: int):
        """Initialize parse error.

        Args:
            message: Error message
            file: File where error occurred
            line: Line number where error occurred
        """
        self.file = file
        self.line = line
        super().__init__(f"{message} at {file}:{line}")


class AnalysisError(ACRError):
    """Analysis errors."""

    pass


class LLMError(ACRError):
    """LLM-related errors."""

    pass


class PatternError(ACRError):
    """Pattern-related errors."""

    pass
