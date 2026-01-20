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

"""Finding model."""

from typing import List, Optional

from pydantic import BaseModel, Field


class FindingLocation(BaseModel):
    """Location of a finding in code."""

    file: str = Field(description="File path")
    line: int = Field(description="Line number")
    column: Optional[int] = Field(default=None, description="Column number")
    function: Optional[str] = Field(default=None, description="Function name")
    class_name: Optional[str] = Field(default=None, description="Class name")


class FindingImpact(BaseModel):
    """Impact assessment of a finding."""

    confidentiality: str = Field(description="Confidentiality impact")
    integrity: str = Field(description="Integrity impact")
    availability: str = Field(description="Availability impact")


class FindingRemediation(BaseModel):
    """Remediation information for a finding."""

    description: str = Field(description="Remediation description")
    code_before: Optional[str] = Field(default=None, description="Vulnerable code example")
    code_after: Optional[str] = Field(default=None, description="Fixed code example")


class Finding(BaseModel):
    """Vulnerability finding model."""

    id: str = Field(description="Unique finding ID")
    title: str = Field(description="Finding title")

    severity: str = Field(description="Severity level")
    confidence: str = Field(description="Confidence level")
    category: str = Field(description="Vulnerability category")

    cwe_id: Optional[str] = Field(default=None, description="CWE identifier")
    owasp_id: Optional[str] = Field(default=None, description="OWASP Top 10 identifier")

    location: FindingLocation = Field(description="Code location")

    description: str = Field(description="Finding description")
    attack_vector: str = Field(description="Attack vector description")

    impact: FindingImpact = Field(description="Impact assessment")
    remediation: FindingRemediation = Field(description="Remediation information")

    references: List[str] = Field(default_factory=list, description="Reference links")
    related_findings: List[str] = Field(default_factory=list, description="Related finding IDs")
    related_patterns: List[str] = Field(default_factory=list, description="Related pattern IDs")

    state: str = Field(default="open", description="Finding state")

    created_at: str = Field(default_factory=lambda: "", description="Creation timestamp")
    updated_at: str = Field(default_factory=lambda: "", description="Last update timestamp")
