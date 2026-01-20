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

import hashlib
import re
from typing import Dict, List, Optional

from acr.models.finding import Finding, FindingImpact, FindingLocation, FindingRemediation
from acr.patterns.loader import PatternLoader
from acr.patterns.schema import (
    ControlFlowPatternTemplate,
    DataFlowPatternTemplate,
    Pattern,
    StaticPatternTemplate,
)
from acr.utils.degradation import analysis_fallback, safe_iterate


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

    @safe_iterate(component="pattern_matcher")
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

    @analysis_fallback(component="pattern_matcher", fallback_value=[])
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
            file_path: Path to source file
            ast_data: Optional AST data from parser

        Returns:
            List of findings for this pattern
        """
        findings: List[Finding] = []

        lines = source_code.split("\n")

        for template in pattern.templates:
            if isinstance(template, StaticPatternTemplate):
                matches = self._match_static_pattern(template, source_code, file_path, pattern)
                findings.extend(matches)

            elif isinstance(template, DataFlowPatternTemplate):
                if ast_data:
                    matches = self._match_data_flow_pattern(
                        template, ast_data, file_path, pattern, lines
                    )
                    findings.extend(matches)

            elif isinstance(template, ControlFlowPatternTemplate):
                if ast_data:
                    matches = self._match_control_flow_pattern(
                        template, source_code, ast_data, file_path, pattern, lines
                    )
                    findings.extend(matches)

        return findings

    def _match_static_pattern(
        self, template: StaticPatternTemplate, source_code: str, file_path: str, pattern: Pattern
    ) -> List[Finding]:
        """Match static regex patterns against source code.

        Args:
            template: Static pattern template with regex pattern
            source_code: Source code to analyze
            file_path: Path to source file
            pattern: Attack pattern metadata

        Returns:
            List of findings
        """
        findings: List[Finding] = []

        pattern_regex = template.pattern
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
                    confidence=template.confidence or "medium",
                    category=pattern.category,
                    cwe_id=pattern.cwe_id,
                    owasp_id=pattern.owasp_id,
                    location=location,
                    description=pattern.description,
                    attack_vector=template.description or pattern.attack_vector,
                    impact=impact,
                    remediation=remediation,
                    references=pattern.references,
                )

                findings.append(finding)

        except re.error:
            pass

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
        template: DataFlowPatternTemplate,
        ast_data: Dict,
        file_path: str,
        pattern: Pattern,
        lines: List[str],
    ) -> List[Finding]:
        """Match data flow patterns (taint analysis).

        Args:
            template: Data flow template with source/sink/sanitizers
            ast_data: AST data from parser
            file_path: Path to source file
            pattern: Attack pattern metadata
            lines: Source code lines

        Returns:
            List of findings
        """
        findings: List[Finding] = []

        source_pattern = template.source
        sink_pattern = template.sink
        sanitizers = template.sanitizers or []

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
                            confidence=template.confidence or "medium",
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

    def _match_control_flow_pattern(
        self,
        template: ControlFlowPatternTemplate,
        ast_data: Dict,
        file_path: str,
        pattern: Pattern,
        lines: List[str],
    ) -> List[Finding]:
        """Match control flow patterns (CFG analysis).

        Args:
            template: Control flow template with check/operation patterns
            ast_data: AST data from parser
            file_path: Path to source file
            pattern: Attack pattern metadata
            lines: Source code lines

        Returns:
            List of findings
        """
        findings: List[Finding] = []

        sensitive_operation_pattern = template.sensitive_operation_pattern
        if not sensitive_operation_pattern:
            return findings

        try:
            sensitive_regex = re.compile(sensitive_operation_pattern)
            check_regex = re.compile(template.check_pattern) if template.check_pattern else None

            cfg_data = ast_data.get("cfg", {})
            basic_blocks = cfg_data.get("basic_blocks", [])

            if not basic_blocks:
                return findings

            lines_with_ops: List[tuple[int, int]] = []

            for block in basic_blocks:
                start_line = block.get("start_line", 0)
                end_line = block.get("end_line", 0)

                for line_idx in range(start_line, min(end_line + 1, len(lines))):
                    line_content = lines[line_idx]
                    if sensitive_regex.search(line_content):
                        col_num = line_content.find(sensitive_operation_pattern)
                        if col_num == -1:
                            match = sensitive_regex.search(line_content)
                            col_num = match.start() if match else 0
                        lines_with_ops.append((line_idx, col_num))

            for line_idx, col_num in lines_with_ops:
                check_found = False
                if template.require_check and check_regex:
                    check_dist = template.check_distance or 50
                    if template.check_before_operation:
                        start_line = max(0, line_idx - check_dist)
                        end_line = line_idx
                        check_found = any(
                            check_regex.search(lines[i]) for i in range(start_line, end_line)
                        )
                    else:
                        start_line = line_idx + 1
                        end_line = min(len(lines), line_idx + 1 + check_dist)
                        check_found = any(
                            check_regex.search(lines[i]) for i in range(start_line, end_line)
                        )

                should_report = not template.require_check or (
                    template.require_check and not check_found
                )

                if should_report:
                    finding_id = self._generate_finding_id(
                        file_path, line_idx + 1, pattern.id, lines[line_idx]
                    )

                    location = FindingLocation(
                        file=file_path,
                        line=line_idx + 1,
                        column=col_num,
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
                        confidence=template.confidence or "medium",
                        category=pattern.category,
                        cwe_id=pattern.cwe_id,
                        owasp_id=pattern.owasp_id,
                        location=location,
                        description=pattern.description,
                        attack_vector=f"Control flow violation: {template.description}",
                        impact=impact,
                        remediation=remediation,
                        references=pattern.references,
                    )

                    findings.append(finding)

        except re.error:
            pass

        return findings

    def _check_for_control_flow_check(
        self,
        check_regex: re.Pattern,
        lines: List[str],
        operation_line: int,
        check_before: bool,
        check_distance: int,
    ) -> bool:
        """Check if control flow check exists relative to operation.

        Args:
            check_regex: Compiled regex for security check
            lines: Source code lines
            operation_line: Line number of sensitive operation
            check_before: Whether check must be before operation
            check_distance: Maximum lines between check and operation

        Returns:
            True if check pattern found
        """
        if check_before:
            start_line = max(0, operation_line - check_distance)
            end_line = operation_line
            return any(check_regex.search(lines[i]) for i in range(start_line, end_line))
        else:
            start_line = operation_line + 1
            end_line = min(len(lines), operation_line + 1 + check_distance)
            return any(check_regex.search(lines[i]) for i in range(start_line, end_line))

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
