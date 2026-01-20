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

"""LLM cost estimation and tracking."""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ModelPricing:
    """Pricing information for LLM models."""

    input_cost_per_1k: float
    output_cost_per_1k: float
    max_context_tokens: int = 4096


@dataclass
class CostEstimate:
    """Cost estimate for an LLM request."""

    input_tokens: int
    estimated_output_tokens: int
    input_cost: float
    estimated_output_cost: float
    total_cost: float
    currency: str = "USD"


@dataclass
class CostTracker:
    """Track LLM API costs."""

    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost: float = 0.0
    currency: str = "USD"
    call_count: int = 0
    model_costs: Dict[str, float] = field(default_factory=dict)


class TokenCounter:
    """Estimate token counts for text."""

    WORDS_PER_TOKEN = 0.75
    CHARS_PER_TOKEN = 4.0

    @staticmethod
    def estimate(text: str) -> int:
        """Estimate token count for text.

        Args:
            text: Text to count tokens for

        Returns:
            Estimated token count
        """
        if not text:
            return 0

        char_count = len(text)
        word_count = len(text.split())

        chars_estimate = int(char_count / TokenCounter.CHARS_PER_TOKEN)
        words_estimate = int(word_count / TokenCounter.WORDS_PER_TOKEN)

        return max(chars_estimate, words_estimate)

    @staticmethod
    def estimate_with_model(text: str, model: str) -> int:
        """Estimate token count with model-specific adjustments.

        Args:
            text: Text to count tokens for
            model: Model name for adjustments

        Returns:
            Estimated token count
        """
        base_estimate = TokenCounter.estimate(text)

        model_adjustments = {
            "claude-3": 0.9,
            "claude-2": 0.95,
            "gpt-4": 1.0,
            "gpt-3.5": 1.1,
        }

        for model_name, factor in model_adjustments.items():
            if model_name in model.lower():
                return int(base_estimate * factor)

        return base_estimate


class CostEstimator:
    """Estimate LLM API costs."""

    DEFAULT_PRICING: Dict[str, ModelPricing] = {
        "claude-3-5-sonnet-20241022": ModelPricing(
            input_cost_per_1k=0.003, output_cost_per_1k=0.015, max_context_tokens=200000
        ),
        "claude-3-opus-20240229": ModelPricing(
            input_cost_per_1k=0.015, output_cost_per_1k=0.075, max_context_tokens=200000
        ),
        "claude-3-haiku-20240307": ModelPricing(
            input_cost_per_1k=0.00025, output_cost_per_1k=0.00125, max_context_tokens=200000
        ),
        "gpt-4": ModelPricing(
            input_cost_per_1k=0.03, output_cost_per_1k=0.06, max_context_tokens=8192
        ),
        "gpt-4-turbo": ModelPricing(
            input_cost_per_1k=0.01, output_cost_per_1k=0.03, max_context_tokens=128000
        ),
        "gpt-3.5-turbo": ModelPricing(
            input_cost_per_1k=0.0005, output_cost_per_1k=0.0015, max_context_tokens=16385
        ),
    }

    def __init__(self, pricing: Optional[Dict[str, ModelPricing]] = None):
        """Initialize cost estimator.

        Args:
            pricing: Custom pricing model (uses defaults if None)
        """
        self.pricing = pricing or self.DEFAULT_PRICING.copy()

    def estimate_cost(
        self, prompt: str, model: str, estimated_output_tokens: Optional[int] = None
    ) -> CostEstimate:
        """Estimate cost for an LLM request.

        Args:
            prompt: Input prompt
            model: Model name
            estimated_output_tokens: Expected output tokens (default: 500)

        Returns:
            Cost estimate
        """
        pricing = self._get_pricing(model)
        input_tokens = TokenCounter.estimate_with_model(prompt, model)

        if estimated_output_tokens is None:
            estimated_output_tokens = 500

        input_cost = (input_tokens / 1000) * pricing.input_cost_per_1k
        output_cost = (estimated_output_tokens / 1000) * pricing.output_cost_per_1k

        return CostEstimate(
            input_tokens=input_tokens,
            estimated_output_tokens=estimated_output_tokens,
            input_cost=input_cost,
            estimated_output_cost=output_cost,
            total_cost=input_cost + output_cost,
        )

    def _get_pricing(self, model: str) -> ModelPricing:
        """Get pricing for model.

        Args:
            model: Model name

        Returns:
            Model pricing

        Raises:
            ValueError: If model not found
        """
        for model_name, pricing in self.pricing.items():
            if model_name in model:
                return pricing

        logger.warning(f"Unknown model {model}, using default pricing")
        return ModelPricing(input_cost_per_1k=0.01, output_cost_per_1k=0.03)

    def add_custom_pricing(self, model: str, pricing: ModelPricing) -> None:
        """Add custom pricing for a model.

        Args:
            model: Model name
            pricing: Pricing information
        """
        self.pricing[model] = pricing


class CostTrackerManager:
    """Manage cost tracking across scans."""

    def __init__(self, cost_limit: Optional[float] = None):
        """Initialize cost tracker.

        Args:
            cost_limit: Maximum cost limit (None for no limit)
        """
        self.cost_limit = cost_limit
        self.tracker = CostTracker()
        self.estimator = CostEstimator()
        self.cost_warning_threshold = cost_limit * 0.8 if cost_limit else 10.0
        self._warned = False

    def estimate_and_track(
        self, prompt: str, model: str, actual_output_tokens: Optional[int] = None
    ) -> CostEstimate:
        """Estimate and track cost for a request.

        Args:
            prompt: Input prompt
            model: Model name
            actual_output_tokens: Actual output tokens if known

        Returns:
            Cost estimate

        Raises:
            RuntimeError: If cost limit exceeded
        """
        estimate = self.estimator.estimate_cost(prompt, model)
        output_tokens = actual_output_tokens or estimate.estimated_output_tokens

        actual_pricing = self.estimator._get_pricing(model)
        actual_output_cost = (output_tokens / 1000) * actual_pricing.output_cost_per_1k
        total_actual_cost = estimate.input_cost + actual_output_cost

        self.tracker.total_input_tokens += estimate.input_tokens
        self.tracker.total_output_tokens += output_tokens
        self.tracker.total_cost += total_actual_cost
        self.tracker.call_count += 1

        if model not in self.tracker.model_costs:
            self.tracker.model_costs[model] = 0.0
        self.tracker.model_costs[model] += total_actual_cost

        if self.cost_limit and self.tracker.total_cost > self.cost_limit:
            raise RuntimeError(
                f"Cost limit ${self.cost_limit:.2f} exceeded. "
                f"Current total: ${self.tracker.total_cost:.2f}"
            )

        if not self._warned and self.tracker.total_cost > self.cost_warning_threshold:
            self._warned = True
            logger.warning(
                f"LLM cost warning: ${self.tracker.total_cost:.2f} spent "
                f"(threshold: ${self.cost_warning_threshold:.2f})"
            )

        return CostEstimate(
            input_tokens=estimate.input_tokens,
            estimated_output_tokens=output_tokens,
            input_cost=estimate.input_cost,
            estimated_output_cost=actual_output_cost,
            total_cost=total_actual_cost,
        )

    def get_total_cost(self) -> float:
        """Get total tracked cost.

        Returns:
            Total cost
        """
        return self.tracker.total_cost

    def get_statistics(self) -> Dict[str, Any]:
        """Get cost tracking statistics.

        Returns:
            Dictionary with statistics
        """
        return {
            "total_cost": self.tracker.total_cost,
            "total_input_tokens": self.tracker.total_input_tokens,
            "total_output_tokens": self.tracker.total_output_tokens,
            "call_count": self.tracker.call_count,
            "model_costs": self.tracker.model_costs,
            "currency": self.tracker.currency,
        }

    def reset(self) -> None:
        """Reset cost tracker."""
        self.tracker = CostTracker()
        self._warned = False


class PromptOptimizer:
    """Optimize prompts to reduce token count and cost."""

    @staticmethod
    def optimize(prompt: str, aggressive: bool = False) -> str:
        """Optimize prompt to reduce token count.

        Args:
            prompt: Original prompt
            aggressive: Enable aggressive optimization

        Returns:
            Optimized prompt
        """
        optimized = prompt

        if aggressive:
            optimized = PromptOptimizer._aggressive_optimize(optimized)
        else:
            optimized = PromptOptimizer._conservative_optimize(optimized)

        return optimized.strip()

    @staticmethod
    def _conservative_optimize(prompt: str) -> str:
        """Conservative prompt optimization.

        Args:
            prompt: Original prompt

        Returns:
            Optimized prompt
        """
        lines = prompt.split("\n")
        optimized_lines = []
        last_empty = False

        for line in lines:
            stripped = line.strip()

            if not stripped:
                if not last_empty:
                    optimized_lines.append("")
                last_empty = True
                continue

            last_empty = False

            if stripped.startswith("#"):
                continue

            optimized_lines.append(stripped)

        return "\n".join(optimized_lines)

    @staticmethod
    def _aggressive_optimize(prompt: str) -> str:
        """Aggressive prompt optimization.

        Args:
            prompt: Original prompt

        Returns:
            Optimized prompt
        """
        optimized = PromptOptimizer._conservative_optimize(prompt)

        optimized = re.sub(r"\s+", " ", optimized)
        optimized = re.sub(r"\s+([.,;:!?)])", r"\1", optimized)
        optimized = optimized.replace("  ", " ")

        return optimized

    @staticmethod
    def estimate_savings(original: str, optimized: str) -> Dict[str, int]:
        """Estimate token savings from optimization.

        Args:
            original: Original prompt
            optimized: Optimized prompt

        Returns:
            Dictionary with savings information
        """
        original_tokens = TokenCounter.estimate(original)
        optimized_tokens = TokenCounter.estimate(optimized)
        savings = original_tokens - optimized_tokens
        percentage = (savings / original_tokens * 100) if original_tokens > 0 else 0

        return {
            "original_tokens": original_tokens,
            "optimized_tokens": optimized_tokens,
            "tokens_saved": savings,
            "percentage_saved": int(percentage),
        }


class RecursiveCallDetector:
    """Detect potential recursive LLM call patterns."""

    RECURSION_PATTERNS = [
        r"generate.*using.*llm",
        r"call.*llm.*again",
        r"recursive.*generation",
        r"loop.*through.*responses",
        r"iterate.*with.*llm",
        r"chain.*llm.*calls",
    ]

    def __init__(self, enabled: bool = True):
        """Initialize recursive call detector.

        Args:
            enabled: Enable/disable detection
        """
        self.enabled = enabled
        self._call_stack: List[str] = []
        self._detected_patterns: List[str] = []

    def detect(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Detect potential recursive call patterns.

        Args:
            prompt: Input prompt
            context: Additional context (function name, call depth, etc.)

        Returns:
            True if recursive pattern detected
        """
        if not self.enabled:
            return False

        prompt_lower = prompt.lower()

        for pattern in self.RECURSION_PATTERNS:
            match = re.search(pattern, prompt_lower)
            if match:
                pattern_match = match.group()
                self._detected_patterns.append(pattern_match)
                logger.warning(f"Potential recursive LLM call pattern detected: {pattern_match}")
                return True

        call_depth = context.get("call_depth", 0) if context else 0
        if call_depth > 5:
            logger.warning(f"High LLM call depth detected: {call_depth} (potential recursion)")
            return True

        return False

        prompt_lower = prompt.lower()

        for pattern in self.RECURSION_PATTERNS:
            if re.search(pattern, prompt_lower):
                pattern_match = re.search(pattern, prompt_lower).group()
                self._detected_patterns.append(pattern_match)
                logger.warning(f"Potential recursive LLM call pattern detected: {pattern_match}")
                return True

        call_depth = context.get("call_depth", 0) if context else 0
        if call_depth > 5:
            logger.warning(f"High LLM call depth detected: {call_depth} (potential recursion)")
            return True

        return False

    def push_call(self, context: str) -> None:
        """Push a call onto the stack.

        Args:
            context: Call context description
        """
        self._call_stack.append(context)

        if len(self._call_stack) > 10:
            logger.warning(f"LLM call stack depth {len(self._call_stack)} exceeds safe limit")

    def pop_call(self) -> Optional[str]:
        """Pop a call from the stack.

        Returns:
            Popped context or None if empty
        """
        return self._call_stack.pop() if self._call_stack else None

    def get_detected_patterns(self) -> List[str]:
        """Get detected recursive patterns.

        Returns:
            List of detected patterns
        """
        return self._detected_patterns.copy()

    def reset(self) -> None:
        """Reset detector state."""
        self._call_stack.clear()
        self._detected_patterns.clear()
