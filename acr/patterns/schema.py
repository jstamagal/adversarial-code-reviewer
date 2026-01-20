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

"""Pattern schema using Pydantic models."""

from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field


class SeverityLevel:
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel:
    """Confidence levels for findings."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PatternLocation(BaseModel):
    """Code location in a pattern."""

    file: str = Field(description="File name or pattern")
    line: int = Field(description="Line number")
    column: Optional[int] = Field(default=None, description="Column number")
    function: Optional[str] = Field(default=None, description="Function name")
    class_name: Optional[str] = Field(default=None, description="Class name")


class PatternImpact(BaseModel):
    """Impact ratings for a pattern."""

    confidentiality: Optional[str] = Field(
        default=None, description="Confidentiality impact (high, medium, low, none)"
    )
    integrity: Optional[str] = Field(
        default=None, description="Integrity impact (high, medium, low, none)"
    )
    availability: Optional[str] = Field(
        default=None, description="Availability impact (high, medium, low, none)"
    )


class PatternRemediation(BaseModel):
    """Remediation information for a pattern."""

    description: str = Field(default="", description="Remediation description")
    code_before: Optional[str] = Field(default=None, description="Vulnerable code example")
    code_after: Optional[str] = Field(default=None, description="Fixed code example")


class Pattern(BaseModel):
    """Attack pattern model."""

    id: str = Field(description="Unique pattern identifier")
    name: str = Field(description="Pattern name")
    description: str = Field(description="Pattern description")
    severity: str = Field(description="Severity level")
    category: str = Field(description="Pattern category (e.g., injection, auth)")
    cwe_id: Optional[str] = Field(default=None, description="CWE identifier")
    owasp_id: Optional[str] = Field(default=None, description="OWASP Top 10 identifier")

    affected_languages: List[str] = Field(
        default_factory=list, description="Affected programming languages"
    )
    affected_frameworks: List[str] = Field(default_factory=list, description="Affected frameworks")

    templates: List[Dict[str, Any]] = Field(
        default_factory=list, description="Pattern templates for matching"
    )

    attack_vector: str = Field(description="Description of attack vector")
    example_payload: Optional[str] = Field(default=None, description="Example attack payload")

    remediation: PatternRemediation = Field(description="Remediation information")

    references: List[str] = Field(default_factory=list, description="Reference links")

    enabled: bool = Field(default=True, description="Whether pattern is enabled")

    version: Optional[str] = Field(default="1.0.0", description="Pattern version")
    author: Optional[str] = Field(default=None, description="Pattern author or maintainer")
    last_modified: Optional[str] = Field(default=None, description="Last modified date (ISO 8601)")
    tags: List[str] = Field(
        default_factory=list, description="Tags for categorization and searching"
    )

    relationships: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Pattern relationships: {'enables': [...], 'enabled_by': [...], 'related': [...]}",
    )

    dependencies: List[str] = Field(
        default_factory=list,
        description="Required language features or conditions for this pattern",
    )

    impact: Optional[PatternImpact] = Field(
        default=None, description="Impact ratings for confidentiality, integrity, availability"
    )
