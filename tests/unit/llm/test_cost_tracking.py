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

"""Tests for LLM cost estimation and tracking."""

import pytest
from acr.llm.cost_tracking import (
    ModelPricing,
    CostEstimate,
    CostTracker,
    TokenCounter,
    CostEstimator,
    CostTrackerManager,
    PromptOptimizer,
    RecursiveCallDetector,
)


class TestTokenCounter:
    def test_estimate_short_text(self):
        text = "Hello world"
        result = TokenCounter.estimate(text)
        assert result > 0
        assert result < 10

    def test_estimate_long_text(self):
        text = "This is a longer text " * 100
        result = TokenCounter.estimate(text)
        assert result > 100

    def test_estimate_empty_text(self):
        result = TokenCounter.estimate("")
        assert result == 0

    def test_estimate_with_model_claude(self):
        text = "Test text " * 100
        base = TokenCounter.estimate(text)
        claude = TokenCounter.estimate_with_model(text, "claude-3-5-sonnet-20241022")
        assert claude <= base

    def test_estimate_with_model_gpt4(self):
        text = "Test text " * 100
        base = TokenCounter.estimate(text)
        gpt4 = TokenCounter.estimate_with_model(text, "gpt-4")
        assert abs(gpt4 - base) < base * 0.1

    def test_estimate_with_model_gpt35(self):
        text = "Test text " * 100
        base = TokenCounter.estimate(text)
        gpt35 = TokenCounter.estimate_with_model(text, "gpt-3.5-turbo")
        assert gpt35 >= base


class TestCostEstimator:
    def test_estimate_cost_claude(self):
        estimator = CostEstimator()
        prompt = "Analyze this code for security vulnerabilities"
        estimate = estimator.estimate_cost(prompt, "claude-3-5-sonnet-20241022")

        assert estimate.input_tokens > 0
        assert estimate.estimated_output_tokens == 500
        assert estimate.input_cost > 0
        assert estimate.estimated_output_cost > 0
        assert estimate.total_cost > 0
        assert estimate.currency == "USD"

    def test_estimate_cost_gpt4(self):
        estimator = CostEstimator()
        prompt = "Explain this vulnerability"
        estimate = estimator.estimate_cost(prompt, "gpt-4")

        assert estimate.input_tokens > 0
        assert estimate.total_cost > 0
        assert estimate.estimated_output_cost > estimate.input_cost

    def test_estimate_cost_with_output_tokens(self):
        estimator = CostEstimator()
        prompt = "Test prompt"
        estimate = estimator.estimate_cost(prompt, "gpt-3.5-turbo", estimated_output_tokens=1000)

        assert estimate.estimated_output_tokens == 1000

    def test_estimate_cost_unknown_model(self):
        estimator = CostEstimator()
        prompt = "Test"
        estimate = estimator.estimate_cost(prompt, "unknown-model")

        assert estimate.total_cost > 0

    def test_add_custom_pricing(self):
        estimator = CostEstimator()
        custom_pricing = ModelPricing(input_cost_per_1k=0.001, output_cost_per_1k=0.002)
        estimator.add_custom_pricing("custom-model", custom_pricing)

        prompt = "Test prompt"
        estimate = estimator.estimate_cost(prompt, "custom-model")

        assert estimate.input_cost < 0.01
        assert estimate.estimated_output_cost < 0.02


class TestCostTrackerManager:
    def test_initial_state(self):
        manager = CostTrackerManager()
        stats = manager.get_statistics()

        assert stats["total_cost"] == 0.0
        assert stats["total_input_tokens"] == 0
        assert stats["total_output_tokens"] == 0
        assert stats["call_count"] == 0

    def test_track_single_call(self):
        manager = CostTrackerManager()
        prompt = "Test prompt for cost tracking"

        estimate = manager.estimate_and_track(prompt, "gpt-3.5-turbo", actual_output_tokens=100)

        assert estimate.input_tokens > 0
        assert manager.get_total_cost() > 0

    def test_track_multiple_calls(self):
        manager = CostTrackerManager()

        for i in range(3):
            prompt = f"Test prompt {i}"
            manager.estimate_and_track(prompt, "gpt-3.5-turbo", actual_output_tokens=100)

        stats = manager.get_statistics()
        assert stats["call_count"] == 3
        assert stats["total_cost"] > 0

    def test_cost_limit_exceeded(self):
        manager = CostTrackerManager(cost_limit=0.0001)
        prompt = "Test" * 1000

        with pytest.raises(RuntimeError) as exc_info:
            manager.estimate_and_track(prompt, "gpt-4", actual_output_tokens=100)

        assert "Cost limit" in str(exc_info.value)

    def test_cost_warning_threshold(self):
        manager = CostTrackerManager(cost_limit=0.01)
        prompt = "Test" * 100

        manager.estimate_and_track(prompt, "gpt-3.5-turbo", actual_output_tokens=1000)
        manager.estimate_and_track(prompt, "gpt-3.5-turbo", actual_output_tokens=1000)

        assert manager.get_total_cost() > 0

    def test_model_costs_tracking(self):
        manager = CostTrackerManager()
        prompt = "Test"

        manager.estimate_and_track(prompt, "gpt-3.5-turbo", actual_output_tokens=50)
        manager.estimate_and_track(prompt, "claude-3-haiku-20240307", actual_output_tokens=50)

        stats = manager.get_statistics()
        assert "gpt-3.5-turbo" in stats["model_costs"]
        assert "claude-3-haiku-20240307" in stats["model_costs"]

    def test_reset_tracker(self):
        manager = CostTrackerManager()
        prompt = "Test"

        manager.estimate_and_track(prompt, "gpt-3.5-turbo", actual_output_tokens=50)
        assert manager.get_total_cost() > 0

        manager.reset()
        stats = manager.get_statistics()
        assert stats["total_cost"] == 0.0
        assert stats["call_count"] == 0


class TestPromptOptimizer:
    def test_conervative_optimization(self):
        prompt = """
        # Comment that should be removed

        This is a test prompt
        Another line


        And another
        """
        optimized = PromptOptimizer.optimize(prompt, aggressive=False)

        assert "#" not in optimized
        assert "test prompt" in optimized
        assert optimized.count("\n\n") <= 1

    def test_aggressive_optimization(self):
        prompt = "This  is   a    test  with    extra   spaces"
        optimized = PromptOptimizer.optimize(prompt, aggressive=True)

        assert "  " not in optimized
        assert len(optimized) < len(prompt)

    def test_aggressive_optimization_punctuation(self):
        prompt = "Test text , with weird ; punctuation : !"
        optimized = PromptOptimizer.optimize(prompt, aggressive=True)

        assert " ," not in optimized
        assert " ;" not in optimized
        assert " :" not in optimized
        assert "," in optimized
        assert ";" in optimized

    def test_estimate_savings(self):
        original = "This is a long prompt " * 20
        optimized = PromptOptimizer.optimize(original, aggressive=True)

        savings = PromptOptimizer.estimate_savings(original, optimized)

        assert savings["original_tokens"] > 0
        assert savings["optimized_tokens"] > 0
        assert savings["tokens_saved"] >= 0
        assert 0 <= savings["percentage_saved"] <= 100

    def test_empty_prompt_optimization(self):
        optimized = PromptOptimizer.optimize("", aggressive=True)
        assert optimized == ""

    def test_no_savings_from_good_prompt(self):
        prompt = "Short prompt"
        optimized = PromptOptimizer.optimize(prompt, aggressive=True)

        savings = PromptOptimizer.estimate_savings(prompt, optimized)
        assert savings["tokens_saved"] >= 0


class TestRecursiveCallDetector:
    def test_detect_recursive_pattern(self):
        detector = RecursiveCallDetector(enabled=True)
        prompt = "Please generate a response using LLM and call LLM again"

        result = detector.detect(prompt)
        assert result is True

        patterns = detector.get_detected_patterns()
        assert len(patterns) > 0

    def test_no_recursive_pattern(self):
        detector = RecursiveCallDetector(enabled=True)
        prompt = "Analyze this code for security vulnerabilities"

        result = detector.detect(prompt)
        assert result is False

    def test_detector_disabled(self):
        detector = RecursiveCallDetector(enabled=False)
        prompt = "Generate using LLM and loop through responses"

        result = detector.detect(prompt)
        assert result is False

    def test_call_stack_depth(self):
        detector = RecursiveCallDetector(enabled=True)
        context = {"call_depth": 6}

        result = detector.detect("Test prompt", context)
        assert result is True

    def test_push_and_pop_calls(self):
        detector = RecursiveCallDetector()

        detector.push_call("function1")
        detector.push_call("function2")

        assert detector.pop_call() == "function2"
        assert detector.pop_call() == "function1"
        assert detector.pop_call() is None

    def test_call_stack_limit_warning(self, caplog):
        import logging

        caplog.set_level(logging.WARNING)
        detector = RecursiveCallDetector()

        for i in range(12):
            detector.push_call(f"call{i}")

        assert any("call stack depth" in record.message for record in caplog.records)

    def test_reset_detector(self):
        detector = RecursiveCallDetector()
        prompt = "Generate using LLM recursively"

        detector.detect(prompt)
        assert len(detector.get_detected_patterns()) > 0

        detector.reset()
        assert len(detector.get_detected_patterns()) == 0

    def test_all_recursion_patterns(self):
        detector = RecursiveCallDetector()

        patterns = [
            "generate a response using LLM",
            "call LLM again for better results",
            "perform recursive generation",
            "loop through all LLM responses",
            "iterate with LLM calls",
            "chain LLM calls together",
        ]

        for pattern in patterns:
            detector.reset()
            result = detector.detect(pattern)
            assert result is True, f"Pattern not detected: {pattern}"
