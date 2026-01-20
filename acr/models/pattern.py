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

"""Pattern model."""

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class Pattern(BaseModel):
    """Attack pattern model."""

    id: str = Field(description="Unique pattern identifier")
    name: str = Field(description="Pattern name")
    description: str = Field(description="Pattern description")

    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        description="Severity level"
    )
    category: str = Field(description="Pattern category")

    cwe_id: Optional[str] = Field(default=None, description="CWE identifier")
    owasp_id: Optional[str] = Field(default=None, description="OWASP Top 10 identifier")

    affected_languages: List[str] = Field(
        default_factory=list, description="Affected programming languages"
    )
    affected_frameworks: List[str] = Field(default_factory=list, description="Affected frameworks")

    templates: List[Dict[str, Any]] = Field(default_factory=list, description="Pattern templates")

    attack_vector: str = Field(description="Attack vector description")
    example_payload: Optional[str] = Field(default=None, description="Example payload")

    enabled: bool = Field(default=True, description="Whether pattern is enabled")
