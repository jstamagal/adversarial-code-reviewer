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

"""Pattern matcher implementation."""

import re
from typing import List, Optional, Any, Dict, cast
from pathlib import Path
import hashlib

from acr.patterns.schema import Pattern
from acr.models.finding import Finding, FindingLocation, FindingImpact, FindingRemediation
from acr.patterns.loader import PatternLoader
from acr.core.ast_parser import ASTParser


class PatternMatcher:
    """Match attack patterns against code."""

    def __init__(self, patterns: Optional[List[Pattern]] = None):
        """Initialize pattern matcher.

        Args:
            patterns: List of attack patterns to match. If None, loads from default library.
        """
        if patterns is None:
            loader = PatternLoader()
            self.patterns = list(loader.load_patterns().values())
        else:
            self.patterns = patterns

    def match_all(
        self,
        source_code: str,
        file_path: str,
        ast_data: Optional[Dict] = None,
    ) -> List[Finding]:
        """Match all patterns against code.

        Args:
            source_code: Source code to analyze
            file_path: Path to the source file
            ast_data: Optional AST data from parser

        Returns:
            List of findings
        """
        all_findings: List[Finding] = []

        for pattern in self.patterns:
            if not pattern.enabled:
                continue

            findings = self.match_pattern(pattern, source_code, file_path, ast_data)
            all_findings.extend(findings)

        return all_findings

    def match_pattern(
        self,
        pattern: Pattern,
        source_code: str,
        file_path: str,
        ast_data: Optional[Dict] = None,
    ) -> List[Finding]:
        """Match a single pattern against code.

        Args:
            pattern: Attack pattern to match
            source_code: Source code to analyze
            file_path: Path to the source file
            ast_data: Optional AST data from parser

        Returns:
            List of findings for this pattern
        """
        findings: List[Finding] = []

        lines = source_code.split("\n")

        for template in pattern.templates:
            pattern_type = template.get("type", "static")

            if pattern_type == "static":
                matches = self._match_static_pattern(template, source_code, file_path, pattern)
                findings.extend(matches)

            elif pattern_type == "data_flow":
                if ast_data:
                    matches = self._match_data_flow_pattern(
                        template, ast_data, file_path, pattern, lines
                    )
                    findings.extend(matches)

        return findings

    def _match_static_pattern(
        self, template: Dict, source_code: str, file_path: str, pattern: Pattern
    ) -> List[Finding]:
        """Match static regex patterns against source code.

        Args:
            template: Pattern template with regex pattern
            source_code: Source code to analyze
            file_path: Path to the source file
            pattern: Attack pattern metadata

        Returns:
            List of findings
        """
        findings: List[Finding] = []

        pattern_regex = template.get("pattern")
        if not pattern_regex:
            return findings

        try:
            regex = re.compile(pattern_regex, re.MULTILINE | re.DOTALL)

            for match in regex.finditer(source_code):
                line_num = source_code[: match.start()].count("\n") + 1
                col_num = match.start() - source_code.rfind("\n", 0, match.start())

                finding_id = self._generate_finding_id(
                    file_path, line_num, pattern.id, match.group()
                )

                location = FindingLocation(file=file_path, line=line_num, column=col_num)

                impact = FindingImpact(
                    confidentiality=self._severity_to_impact(pattern.severity),
                    integrity=self._severity_to_impact(pattern.severity),
                    availability="low",
                )

                remediation = FindingRemediation(
                    description=pattern.remediation.description,
                    code_before=pattern.remediation.code_before,
                    code_after=pattern.remediation.code_after,
                )

                finding = Finding(
                    id=finding_id,
                    title=pattern.name,
                    severity=pattern.severity,
                    confidence=template.get("confidence", "medium"),
                    category=pattern.category,
                    cwe_id=pattern.cwe_id,
                    owasp_id=pattern.owasp_id,
                    location=location,
                    description=pattern.description,
                    attack_vector=template.get("description", pattern.attack_vector),
                    impact=impact,
                    remediation=remediation,
                    references=pattern.references,
                )

                findings.append(finding)

        except re.error:
            pass

        return findings

    def _match_data_flow_pattern(
        self,
        template: Dict,
        ast_data: Dict,
        file_path: str,
        pattern: Pattern,
        lines: List[str],
    ) -> List[Finding]:
        """Match data flow patterns (taint analysis).

        Args:
            template: Pattern template with source/sink/sanitizers
            ast_data: AST data from parser
            file_path: Path to the source file
            pattern: Attack pattern metadata
            lines: Source code lines

        Returns:
            List of findings
        """
        findings: List[Finding] = []

        source_pattern = template.get("source")
        sink_pattern = template.get("sink")
        sanitizers = template.get("sanitizers", [])

        if not source_pattern or not sink_pattern:
            return findings

        try:
            source_regex = re.compile(source_pattern)
            sink_regex = re.compile(sink_pattern)
            sanitizer_regexes = [re.compile(s) for s in sanitizers if s] if sanitizers else []

            functions = ast_data.get("functions", [])
            function_calls = ast_data.get("call_sites", [])

            for call_site in function_calls:
                sink_match = sink_regex.search(call_site.get("name", ""))

                if sink_match:
                    line_num = call_site.get("line", 0)

                    source_detected = self._check_for_source(source_regex, lines, line_num)

                    if source_detected and not self._check_for_sanitizers(
                        sanitizer_regexes, lines, line_num
                    ):
                        finding_id = self._generate_finding_id(
                            file_path, line_num, pattern.id, call_site.get("name", "")
                        )

                        location = FindingLocation(
                            file=file_path,
                            line=line_num,
                            function=call_site.get("function"),
                        )

                        impact = FindingImpact(
                            confidentiality=self._severity_to_impact(pattern.severity),
                            integrity=self._severity_to_impact(pattern.severity),
                            availability="low",
                        )

                        remediation = FindingRemediation(
                            description=pattern.remediation.description,
                            code_before=pattern.remediation.code_before,
                            code_after=pattern.remediation.code_after,
                        )

                        finding = Finding(
                            id=finding_id,
                            title=pattern.name,
                            severity=pattern.severity,
                            confidence="medium",
                            category=pattern.category,
                            cwe_id=pattern.cwe_id,
                            owasp_id=pattern.owasp_id,
                            location=location,
                            description=pattern.description,
                            attack_vector=f"Taint flow from {source_pattern} to {sink_pattern}",
                            impact=impact,
                            remediation=remediation,
                            references=pattern.references,
                        )

                        findings.append(finding)

        except re.error:
            pass

        return findings

    def _check_for_source(self, source_regex: re.Pattern, lines: List[str], sink_line: int) -> bool:
        """Check if source pattern exists before sink.

        Args:
            source_regex: Compiled regex for source
            lines: Source code lines
            sink_line: Line number of sink

        Returns:
            True if source pattern found
        """
        context_lines = 50
        start_line = max(0, sink_line - context_lines)

        for i in range(start_line, sink_line):
            if source_regex.search(lines[i]):
                return True

        return False

    def _check_for_sanitizers(
        self, sanitizer_regexes: List[re.Pattern], lines: List[str], sink_line: int
    ) -> bool:
        """Check if any sanitizer exists between source and sink.

        Args:
            sanitizer_regexes: List of compiled regex for sanitizers
            lines: Source code lines
            sink_line: Line number of sink

        Returns:
            True if sanitizer pattern found
        """
        if not sanitizer_regexes:
            return False

        context_lines = 50
        start_line = max(0, sink_line - context_lines)

        for i in range(start_line, sink_line):
            for sanitizer_regex in sanitizer_regexes:
                if sanitizer_regex.search(lines[i]):
                    return True

        return False

    def _generate_finding_id(
        self, file_path: str, line_num: int, pattern_id: str, code_snippet: str
    ) -> str:
        """Generate unique finding ID.

        Args:
            file_path: Path to source file
            line_num: Line number
            pattern_id: Pattern identifier
            code_snippet: Matching code snippet

        Returns:
            Unique finding ID
        """
        hash_input = f"{file_path}:{line_num}:{pattern_id}:{code_snippet}"
        hash_obj = hashlib.sha256(hash_input.encode())
        hash_short = hash_obj.hexdigest()[:8]
        return f"ACR-2025-{hash_short.upper()}"

    def _severity_to_impact(self, severity: str) -> str:
        """Convert severity level to impact level.

        Args:
            severity: Severity level

        Returns:
            Impact level
        """
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "low",
        }
        return severity_map.get(severity, "low")
