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

"""Configuration schema using Pydantic models."""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ProjectConfig(BaseModel):
    """Project-specific configuration."""

    name: str = Field(default="", description="Project name")
    root: str = Field(default=".", description="Project root directory")


class LanguageConfig(BaseModel):
    """Language-specific configuration."""

    enabled: bool = Field(default=True, description="Whether language is enabled")
    version: str = Field(default="", description="Language version")
    legacy_mode: bool = Field(
        default=False, description="Enable analysis of legacy code (Python < 3.8)"
    )


class PatternConfig(BaseModel):
    """Attack pattern configuration."""

    enabled: List[str] = Field(default_factory=list, description="Enabled pattern IDs")
    severity_threshold: str = Field(default="medium", description="Minimum severity to report")
    custom_patterns: str = Field(default="", description="Path to custom patterns directory")


class RedactionPatternConfig(BaseModel):
    """Custom redaction pattern configuration."""

    name: str = Field(description="Pattern name")
    pattern: str = Field(description="Regex pattern to match")
    description: str = Field(default="", description="Pattern description")


class RedactionConfig(BaseModel):
    """Sensitive data redaction configuration."""

    enabled: bool = Field(default=True, description="Enable sensitive data redaction")
    entropy_threshold: float = Field(
        default=4.5, description="Entropy threshold for detecting high-entropy strings (0-8)"
    )
    entropy_min_length: int = Field(
        default=20, description="Minimum length for entropy-based detection"
    )
    custom_patterns: List[RedactionPatternConfig] = Field(
        default_factory=list, description="Custom redaction patterns"
    )
    log_redactions: bool = Field(default=True, description="Log all redaction events")
    verify_redaction: bool = Field(
        default=True, description="Verify sensitive data is fully redacted before LLM calls"
    )


class LLMConfig(BaseModel):
    """LLM integration configuration."""

    enabled: bool = Field(default=False, description="Whether LLM integration is enabled")
    provider: str = Field(default="anthropic", description="LLM provider (anthropic, openai)")
    model: str = Field(default="claude-3-5-sonnet-20241022", description="LLM model")
    api_key_env: str = Field(
        default="ANTHROPIC_API_KEY", description="Environment variable for API key"
    )
    use_keyring: bool = Field(default=True, description="Use keyring for secure credential storage")
    keyring_name: str = Field(default="api_key", description="Credential name in keyring")
    max_tokens: int = Field(default=4096, description="Maximum tokens per request")
    cache_enabled: bool = Field(default=True, description="Enable LLM response caching")
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)


class AnalysisConfig(BaseModel):
    """Analysis configuration."""

    max_depth: int = Field(default=10, description="Maximum recursion depth")
    timeout: int = Field(default=300, description="Analysis timeout in seconds")
    parallel: bool = Field(default=False, description="Enable parallel processing")
    analyze_generated_code: bool = Field(
        default=False, description="Analyze generated code (default: exclude)"
    )


class ReportingConfig(BaseModel):
    """Reporting configuration."""

    formats: List[str] = Field(default_factory=lambda: ["markdown"], description="Output formats")
    output_dir: str = Field(default="./acr-reports", description="Output directory for reports")
    include_code_snippets: bool = Field(
        default=True, description="Include code snippets in reports"
    )
    max_snippet_lines: int = Field(default=10, description="Maximum lines per code snippet")


class ExclusionConfig(BaseModel):
    """File and directory exclusion configuration."""

    paths: List[str] = Field(
        default_factory=lambda: ["tests/", "venv/", ".venv/", "__pycache__/"],
        description="Paths to exclude",
    )
    files: List[str] = Field(
        default_factory=lambda: ["*.pyc", "*.pyo"],
        description="File patterns to exclude",
    )
    generated_code_patterns: List[str] = Field(
        default_factory=list,
        description="Custom regex patterns for generated code detection",
    )


class ACRConfig(BaseModel):
    """Main ACR configuration model."""

    project: ProjectConfig = Field(default_factory=ProjectConfig)
    languages: Dict[str, LanguageConfig] = Field(default_factory=dict)
    frameworks: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    patterns: PatternConfig = Field(default_factory=PatternConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    exclude: ExclusionConfig = Field(default_factory=ExclusionConfig)
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)
