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

"""Main analyzer implementation."""

from pathlib import Path
from typing import Any, List, Union, cast

from acr.core.ast_parser import ASTParser
from acr.models.finding import Finding


class Analyzer:
    """Main code analyzer."""

    def __init__(self, config):
        """Initialize analyzer.

        Args:
            config: ACR configuration
        """
        self.config = config
        self.findings: List[Finding] = []
        self.ast_parser = ASTParser()
        self._pattern_matcher = None

    @property
    def pattern_matcher(self):
        """Lazy load pattern matcher to avoid circular imports."""
        if self._pattern_matcher is None:
            from acr.patterns.matcher import PatternMatcher

            custom_patterns_dir = None
            if self.config.patterns and self.config.patterns.custom_patterns:
                custom_patterns_dir = self.config.patterns.custom_patterns
            self._pattern_matcher = PatternMatcher(custom_patterns_dir=custom_patterns_dir)
        return self._pattern_matcher

    def analyze(self, path: Union[str, Path]) -> List[Finding]:
        """Analyze code at given path.

        Args:
            path: Path to file or directory to analyze

        Returns:
            List of findings
        """
        path = Path(path)

        if not path.exists():
            return []

        if path.is_file():
            return self._analyze_file(path)

        return self._analyze_directory(path)

    def _analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a single file.

        Args:
            file_path: Path to file to analyze

        Returns:
            List of findings
        """
        if not self._is_python_file(file_path):
            return []

        try:
            source_code = file_path.read_text(encoding="utf-8")
            ast_node = self.ast_parser.parse(source_code, str(file_path))

            ast_data = self.ast_parser.extract_analysis_data(ast_node) if ast_node else None

            return self.pattern_matcher.match_all(source_code, str(file_path), cast(Any, ast_data))

        except Exception:
            return []

    def _analyze_directory(self, dir_path: Path) -> List[Finding]:
        """Analyze all files in a directory.

        Args:
            dir_path: Path to directory to analyze

        Returns:
            List of findings
        """
        all_findings: List[Finding] = []

        for file_path in dir_path.rglob("*.py"):
            file_findings = self._analyze_file(file_path)
            all_findings.extend(file_findings)

        return all_findings

    def _is_python_file(self, file_path: Path) -> bool:
        """Check if file is a Python file.

        Args:
            file_path: Path to file

        Returns:
            True if Python file
        """
        return file_path.suffix == ".py"
