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

import re
from typing import Dict, Any, List, Optional


class PromptTemplates:
    """Prompt templates for various LLM tasks."""

    SYSTEM_PROMPT = """You are an expert security analyst and penetration tester specializing in identifying vulnerabilities in code. 
Your task is to analyze code from an adversarial perspective - think like an attacker trying to exploit the code.
Provide concrete, actionable attack vectors with specific payloads and exploitation steps.
Be thorough but concise in your analysis."""

    FEW_SHOT_ATTACK_EXAMPLES = """Example 1:
Code:
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

Analysis: This code is vulnerable to SQL injection via the username parameter.
Attack Vector: Submit username: admin' OR '1'='1' --
Expected Behavior: Bypasses authentication and logs in as admin

Example 2:
Code:
@app.route('/api/data', methods=['POST'])
def get_data():
    data = request.get_json()
    return jsonify(eval(data['query']))

Analysis: This code is vulnerable to code injection via eval().
Attack Vector: Submit query: __import__('os').system('rm -rf /')
Expected Behavior: Executes arbitrary shell commands on the server

"""

    FEW_SHOT_REMEDIATION_EXAMPLES = """Example 1:
Vulnerable Code:
query = f"SELECT * FROM users WHERE username='{username}'"

Remediation: Use parameterized queries instead of string concatenation:
query = "SELECT * FROM users WHERE username=%s"
cursor.execute(query, (username,))

Example 2:
Vulnerable Code:
return jsonify(eval(user_input))

Remediation: Use json.loads() for parsing JSON instead of eval():
return jsonify(json.loads(user_input))

"""

    @staticmethod
    def generate_attack_vector(
        code: str, pattern: str, context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate prompt for attack vector generation.

        Args:
            code: Source code snippet
            pattern: Attack pattern description
            context: Additional context (entry points, sinks, data flow, etc.)

        Returns:
            Prompt string
        """
        prompt_parts = [PromptTemplates.SYSTEM_PROMPT]
        prompt_parts.append(PromptTemplates.FEW_SHOT_ATTACK_EXAMPLES)

        context_str = PromptTemplates._format_context(context) if context else ""
        if context_str:
            prompt_parts.append(f"Context:\n{context_str}\n")

        prompt_parts.append(f"""Attack Pattern: {pattern}

Code to Analyze:
{PromptTemplates._format_code_snippet(code)}

Task:
1. Identify the specific vulnerability in this code
2. Explain why it's vulnerable from an attacker's perspective
3. Provide concrete attack vectors with specific payloads
4. Describe expected behavior when attack succeeds
5. Assess potential impact (confidentiality, integrity, availability)

Provide your analysis in the following format:
Vulnerability: [brief description]
Attack Vector 1: [specific payload and steps]
Attack Vector 2: [alternative payload if applicable]
Impact: [confidentiality/integrity/availability impact]""")

        return "\n".join(prompt_parts)

    @staticmethod
    def explain_vulnerability(code: str, finding: Dict[str, Any]) -> str:
        """Generate prompt for vulnerability explanation.

        Args:
            code: Source code snippet
            finding: Finding details (severity, pattern, location, etc.)

        Returns:
            Prompt string
        """
        prompt_parts = [PromptTemplates.SYSTEM_PROMPT]

        finding_str = PromptTemplates._format_finding(finding)
        prompt_parts.append(f"""Vulnerability Finding:
{finding_str}

Code:
{PromptTemplates._format_code_snippet(code)}

Task:
1. Explain the vulnerability in clear, non-technical language
2. Describe the specific security issue
3. Explain how an attacker could exploit it
4. Assess the business impact and potential consequences
5. Provide context on why this is a security concern

Provide a comprehensive explanation that a developer can understand and act upon.""")

        return "\n".join(prompt_parts)

    @staticmethod
    def suggest_remediation(code: str, pattern: str, language: str = "python") -> str:
        """Generate prompt for remediation suggestions.

        Args:
            code: Source code snippet
            pattern: Attack pattern description
            language: Programming language

        Returns:
            Prompt string
        """
        prompt_parts = [PromptTemplates.SYSTEM_PROMPT]
        prompt_parts.append(PromptTemplates.FEW_SHOT_REMEDIATION_EXAMPLES)

        prompt_parts.append(f"""Attack Pattern: {pattern}
Language: {language}

Vulnerable Code:
{PromptTemplates._format_code_snippet(code)}

Task:
1. Identify the specific vulnerability
2. Provide secure remediation code that fixes the issue
3. Explain why your remediation is secure
4. Discuss any trade-offs or considerations
5. Suggest additional defensive measures if applicable

Provide your remediation in the following format:
Vulnerability: [brief description]
Remediation Code:
```{language}
[your secure code here]
```
Explanation: [why this is secure and how it fixes the issue]""")

        return "\n".join(prompt_parts)

    @staticmethod
    def generate_business_logic_abuse(
        code: str, context: Dict[str, Any], business_rules: Optional[List[str]] = None
    ) -> str:
        """Generate prompt for business logic abuse scenarios.

        Args:
            code: Source code snippet
            context: Application context (routes, endpoints, etc.)
            business_rules: Known business rules and invariants

        Returns:
            Prompt string
        """
        prompt_parts = [PromptTemplates.SYSTEM_PROMPT]
        prompt_parts.append("""You specialize in identifying business logic vulnerabilities 
that go beyond standard technical vulnerabilities. Look for ways to subvert business rules,
bypass intended workflows, or abuse the application's logic.""")

        context_str = PromptTemplates._format_context(context)
        prompt_parts.append(f"Context:\n{context_str}\n")

        if business_rules:
            prompt_parts.append(
                "Business Rules:\n" + "\n".join(f"- {rule}" for rule in business_rules) + "\n"
            )

        prompt_parts.append(f"""Code:
{PromptTemplates._format_code_snippet(code)}

Task:
1. Identify the business logic being implemented
2. Find ways to abuse or subvert the intended business rules
3. Identify logical flaws or edge cases that could be exploited
4. Consider sequential operations and state transitions
5. Provide concrete abuse scenarios with step-by-step exploitation

Provide your analysis in the following format:
Business Logic: [description of the logic being implemented]
Abuse Scenario 1: [step-by-step abuse scenario]
Abuse Scenario 2: [alternative abuse scenario]
Business Impact: [how this affects the business]""")

        return "\n".join(prompt_parts)

    @staticmethod
    def _format_code_snippet(code: str, max_lines: int = 100) -> str:
        """Format code snippet for LLM prompts.

        Args:
            code: Source code
            max_lines: Maximum lines to include

        Returns:
            Formatted code snippet
        """
        lines = code.split("\n")[:max_lines]
        snippet = "\n".join(lines)

        if len(code.split("\n")) > max_lines:
            snippet += "\n... (truncated)"

        return snippet

    @staticmethod
    def _format_context(context: Dict[str, Any]) -> str:
        """Format context dictionary for LLM prompts.

        Args:
            context: Context dictionary

        Returns:
            Formatted context string
        """
        if not context:
            return ""

        formatted = []
        for key, value in context.items():
            if isinstance(value, (list, dict)):
                formatted.append(f"{key}: {str(value)}")
            else:
                formatted.append(f"{key}: {value}")

        return "\n".join(formatted)

    @staticmethod
    def _format_finding(finding: Dict[str, Any]) -> str:
        """Format finding dictionary for LLM prompts.

        Args:
            finding: Finding dictionary

        Returns:
            Formatted finding string
        """
        formatted = []
        for key, value in finding.items():
            if key == "code_snippet":
                continue
            formatted.append(f"{key}: {value}")

        return "\n".join(formatted) if formatted else "No additional details"

    @staticmethod
    def gather_context(
        file_path: str,
        line_number: int,
        function_name: Optional[str] = None,
        class_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Gather context for a code location.

        Args:
            file_path: Path to the file
            line_number: Line number of interest
            function_name: Function name (if known)
            class_name: Class name (if known)

        Returns:
            Context dictionary with file, line, function, class info
        """
        context = {
            "file": file_path,
            "line": line_number,
        }
        if function_name:
            context["function"] = function_name
        if class_name:
            context["class"] = class_name

        return context
