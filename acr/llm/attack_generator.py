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

"""Intelligent attack generation using LLM."""

import os
import logging
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)
from acr.llm.client import LLMClient, create_client, get_api_key
from acr.llm.prompts import PromptTemplates
from acr.llm.redaction import DataRedactor
from acr.llm.prompt_injection import (
    PromptInjectorDetector,
    PromptSanitizer,
    OutputMonitor,
    JAILBREAK_PREVENTION_SYSTEM_PROMPT,
)
from acr.models.finding import Finding, FindingLocation, FindingImpact, FindingRemediation
from acr.config.loader import load_config


class AttackGenerator:
    """Generate intelligent attacks using LLM."""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        cache_ttl: int = 86400,
        enable_cache: bool = True,
        enable_prompt_injection_protection: bool = True,
    ):
        """Initialize attack generator.

        Args:
            llm_client: LLM client instance (uses default if None)
            cache_ttl: Cache time-to-live in seconds
            enable_cache: Enable/disable response caching
            enable_prompt_injection_protection: Enable prompt injection protection
        """
        if llm_client is None:
            config = load_config()
            provider = config.llm.provider
            api_key = get_api_key(
                api_key_env=config.llm.api_key_env,
                use_keyring=config.llm.use_keyring,
                keyring_name=config.llm.keyring_name,
            )
            model = config.llm.model
            self.client = create_client(provider, api_key, model)
        else:
            self.client = llm_client

        self.templates = PromptTemplates()
        self.redactor = DataRedactor()
        self.enable_cache = enable_cache
        self._call_count = 0
        self._max_calls_per_scan = 100
        self.enable_prompt_injection_protection = enable_prompt_injection_protection

        self.injector_detector = PromptInjectorDetector(enabled=enable_prompt_injection_protection)
        self.prompt_sanitizer = PromptSanitizer(detector=self.injector_detector)
        self.output_monitor = OutputMonitor()

    def generate_attack_vector(
        self,
        code: str,
        pattern: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate attack vector for code vulnerability.

        Args:
            code: Vulnerable code
            pattern: Attack pattern description
            context: Additional context (file, line, function, class, etc.)

        Returns:
            Generated attack vector description

        Raises:
            RuntimeError: If max LLM calls exceeded
        """
        self._check_call_limit()

        redacted_code, _ = self.redactor.redact(code)
        prompt = self.templates.generate_attack_vector(
            code=redacted_code,
            pattern=pattern,
            context=context or {},
        )

        response = self._generate(prompt)
        return response

    def explain_vulnerability(
        self,
        code: str,
        finding: Dict[str, Any],
    ) -> str:
        """Generate natural language explanation of vulnerability.

        Args:
            code: Vulnerable code
            finding: Finding details (severity, pattern, location, etc.)

        Returns:
            Vulnerability explanation
        """
        self._check_call_limit()

        redacted_code, _ = self.redactor.redact(code)
        prompt = self.templates.explain_vulnerability(
            code=redacted_code,
            finding=finding,
        )

        response = self._generate(prompt)
        return response

    def suggest_remediation(
        self,
        code: str,
        pattern: str,
        language: str = "python",
    ) -> Dict[str, str]:
        """Generate remediation suggestions.

        Args:
            code: Vulnerable code
            pattern: Attack pattern description
            language: Programming language

        Returns:
            Dictionary with 'description', 'code_before', 'code_after'
        """
        self._check_call_limit()

        redacted_code, _ = self.redactor.redact(code)
        prompt = self.templates.suggest_remediation(
            code=redacted_code,
            pattern=pattern,
            language=language,
        )

        response = self._generate(prompt)
        return self._parse_remediation(response)

    def generate_business_logic_abuse(
        self,
        code: str,
        context: Dict[str, Any],
        business_rules: Optional[List[str]] = None,
    ) -> List[str]:
        """Generate business logic abuse scenarios.

        Args:
            code: Code to analyze
            context: Application context (routes, endpoints, etc.)
            business_rules: Known business rules and invariants

        Returns:
            List of abuse scenarios
        """
        self._check_call_limit()

        redacted_code, _ = self.redactor.redact(code)
        prompt = self.templates.generate_business_logic_abuse(
            code=redacted_code,
            context=context,
            business_rules=business_rules,
        )

        response = self._generate(prompt)
        return self._parse_scenarios(response)

    def generate_complete_finding(
        self,
        code: str,
        file_path: str,
        line_number: int,
        pattern: str,
        severity: str,
        category: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        """Generate complete finding with all LLM-generated content.

        Args:
            code: Vulnerable code
            file_path: Path to file
            line_number: Line number
            pattern: Attack pattern description
            severity: Severity level
            category: Vulnerability category
            context: Additional context

        Returns:
            Complete Finding object with LLM-generated content
        """
        attack_vector = self.generate_attack_vector(code, pattern, context or {})

        finding_dict = {
            "severity": severity,
            "pattern": pattern,
            "file": file_path,
            "line": line_number,
        }
        explanation = self.explain_vulnerability(code, finding_dict)

        remediation = self.suggest_remediation(code, pattern)

        from acr.utils.helpers import generate_finding_id

        location = FindingLocation(file=file_path, line=line_number)
        impact = FindingImpact(
            confidentiality=self._map_severity_to_impact(severity),
            integrity=self._map_severity_to_impact(severity),
            availability="low",
        )
        remediation_obj = FindingRemediation(
            description=remediation["description"],
            code_before=remediation.get("code_before"),
            code_after=remediation.get("code_after"),
        )

        finding = Finding(
            id=generate_finding_id(file_path, line_number, pattern),
            title=f"{pattern} in {file_path}:{line_number}",
            severity=severity,
            confidence="medium",
            category=category,
            location=location,
            description=explanation,
            attack_vector=attack_vector,
            impact=impact,
            remediation=remediation_obj,
        )

        return finding

    def _generate(self, prompt: str) -> str:
        """Generate response from LLM.

        Args:
            prompt: Input prompt

        Returns:
            LLM response
        """
        self._call_count += 1

        if self.enable_prompt_injection_protection:
            prompt, sanitization_metadata = self.prompt_sanitizer.sanitize(prompt, mode="strip")

            if sanitization_metadata["has_injection"]:
                logger.warning(
                    f"Prompt injection detected and sanitized: "
                    f"{sanitization_metadata['detected_categories']}"
                )

            prompt = f"{JAILBREAK_PREVENTION_SYSTEM_PROMPT}\n\n{prompt}"

        response = self.client.generate(prompt)

        if self.enable_prompt_injection_protection:
            is_suspicious, matched_pattern = self.output_monitor.monitor(response)
            if is_suspicious:
                logger.warning(f"Suspicious LLM output detected: {matched_pattern}")

        return response

    def _check_call_limit(self) -> None:
        """Check if LLM call limit has been exceeded.

        Raises:
            RuntimeError: If limit exceeded
        """
        if self._call_count >= self._max_calls_per_scan:
            raise RuntimeError(
                f"LLM call limit ({self._max_calls_per_scan}) exceeded for this scan. "
                "Increase limit with --max-llm-calls option."
            )

    def _parse_remediation(self, response: str) -> Dict[str, str]:
        """Parse LLM remediation response.

        Args:
            response: LLM response

        Returns:
            Dictionary with remediation parts
        """
        lines = response.split("\n")
        result = {"description": response}

        for line in lines:
            if line.lower().startswith("before:") or line.lower().startswith("code before:"):
                result["code_before"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("after:") or line.lower().startswith("code after:"):
                result["code_after"] = line.split(":", 1)[1].strip()

        return result

    def _parse_scenarios(self, response: str) -> List[str]:
        """Parse business logic abuse scenarios.

        Args:
            response: LLM response

        Returns:
            List of scenario strings
        """
        scenarios = []
        for line in response.split("\n"):
            stripped = line.strip()
            if stripped and (stripped.startswith("-") or stripped.startswith("*")):
                scenarios.append(stripped[1:].strip())
            elif stripped and not scenarios:
                scenarios.append(stripped)

        return scenarios[:5]

    def _map_severity_to_impact(self, severity: str) -> str:
        """Map severity to impact level.

        Args:
            severity: Severity level

        Returns:
            Impact level
        """
        mapping: Dict[str, str] = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "none",
        }
        return mapping.get(severity, "medium")

    def get_call_count(self) -> int:
        """Get number of LLM calls made.

        Returns:
            Number of calls
        """
        return self._call_count

    def reset_call_count(self) -> None:
        """Reset call count (for new scans)."""
        self._call_count = 0

    def set_max_calls(self, max_calls: int) -> None:
        """Set maximum LLM calls per scan.

        Args:
            max_calls: Maximum number of calls
        """
        self._max_calls_per_scan = max_calls
