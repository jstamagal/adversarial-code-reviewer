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

"""Finding annotation manager."""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

from acr.models.finding import Finding
from acr.utils.logger import get_logger

logger = get_logger(__name__)


class FindingAnnotation(BaseModel):
    """Annotation for a finding."""

    finding_id: str = Field(description="Unique finding ID")
    state: str = Field(
        description="Finding state: open, in-progress, fixed, won't-fix, false-positive"
    )
    notes: Optional[str] = Field(default=None, description="User notes about this finding")
    created_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat(),
        description="Annotation creation time",
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat(), description="Last update time"
    )
    updated_by: Optional[str] = Field(
        default=None, description="User who last updated the annotation"
    )


class AnnotationManager:
    """Manager for loading, saving, and applying finding annotations."""

    def __init__(self, state_path: Optional[Path] = None):
        """Initialize annotation manager.

        Args:
            state_path: Path to .acr-state.yaml file. If None, uses default search paths.
        """
        self.state_path = state_path
        self.annotations: Dict[str, FindingAnnotation] = {}
        self._load_annotations()

    def _load_annotations(self) -> None:
        """Load annotations from .acr-state.yaml file."""
        if self.state_path:
            if self.state_path.exists():
                self._load_from_path(self.state_path)
            return

        default_paths = [
            Path(".acr-state.yaml"),
            Path(".acr-state"),
            Path(".acr/state.yaml"),
        ]

        for path in default_paths:
            resolved_path = path.resolve()
            if resolved_path.exists():
                self.state_path = resolved_path
                self._load_from_path(resolved_path)
                logger.debug(f"Loaded annotations from {resolved_path}")
                return

        logger.debug("No annotation file found")

    def _load_from_path(self, path: Path) -> None:
        """Load annotations from specific path."""
        try:
            with open(path) as f:
                data = yaml.safe_load(f)

            if data and "annotations" in data:
                for ann_data in data["annotations"]:
                    try:
                        annotation = FindingAnnotation(**ann_data)
                        self.annotations[annotation.finding_id] = annotation
                    except Exception as e:
                        logger.warning(f"Failed to load annotation: {e}")

            logger.debug(f"Loaded {len(self.annotations)} annotations from {path}")
        except Exception as e:
            logger.error(f"Failed to load annotations from {path}: {e}")

    def save_annotations(self) -> None:
        """Save annotations to .acr-state.yaml file."""
        if not self.state_path:
            self.state_path = Path(".acr-state.yaml")

        try:
            data = {
                "version": "1.0",
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
                "annotations": [ann.model_dump() for ann in self.annotations.values()],
            }

            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_path, "w") as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)

            logger.debug(f"Saved {len(self.annotations)} annotations to {self.state_path}")
        except Exception as e:
            logger.error(f"Failed to save annotations to {self.state_path}: {e}")
            raise

    def get_annotation(self, finding_id: str) -> Optional[FindingAnnotation]:
        """Get annotation for a finding.

        Args:
            finding_id: Finding ID

        Returns:
            Annotation or None if not found
        """
        return self.annotations.get(finding_id)

    def set_annotation(
        self,
        finding_id: str,
        state: str,
        notes: Optional[str] = None,
        updated_by: Optional[str] = None,
    ) -> FindingAnnotation:
        """Set annotation for a finding.

        Args:
            finding_id: Finding ID
            state: Finding state (open, in-progress, fixed, won't-fix, false-positive)
            notes: Optional notes about the finding
            updated_by: Optional username of the updater

        Returns:
            The created or updated annotation

        Raises:
            ValueError: If state is invalid
        """
        valid_states = ["open", "in-progress", "fixed", "won't-fix", "false-positive"]
        if state not in valid_states:
            raise ValueError(f"Invalid state '{state}'. Must be one of: {valid_states}")

        now = datetime.utcnow().isoformat()

        if finding_id in self.annotations:
            annotation = self.annotations[finding_id]
            annotation.state = state
            annotation.updated_at = now
            annotation.updated_by = updated_by
            if notes is not None:
                annotation.notes = notes
        else:
            annotation = FindingAnnotation(
                finding_id=finding_id,
                state=state,
                notes=notes,
                created_at=now,
                updated_at=now,
                updated_by=updated_by,
            )
            self.annotations[finding_id] = annotation

        logger.debug(f"Set annotation for finding {finding_id} to state '{state}'")
        return annotation

    def mark_as_false_positive(
        self,
        finding_id: str,
        notes: Optional[str] = None,
        updated_by: Optional[str] = None,
    ) -> FindingAnnotation:
        """Mark a finding as false positive.

        Args:
            finding_id: Finding ID
            notes: Optional notes explaining why it's a false positive
            updated_by: Optional username of the updater

        Returns:
            The created or updated annotation
        """
        return self.set_annotation(
            finding_id=finding_id,
            state="false-positive",
            notes=notes,
            updated_by=updated_by,
        )

    def mark_as_accepted_risk(
        self,
        finding_id: str,
        notes: Optional[str] = None,
        updated_by: Optional[str] = None,
    ) -> FindingAnnotation:
        """Mark a finding as accepted risk (won't-fix).

        Args:
            finding_id: Finding ID
            notes: Optional notes explaining the risk acceptance
            updated_by: Optional username of the updater

        Returns:
            The created or updated annotation
        """
        return self.set_annotation(
            finding_id=finding_id,
            state="won't-fix",
            notes=notes,
            updated_by=updated_by,
        )

    def mark_as_in_progress(
        self,
        finding_id: str,
        notes: Optional[str] = None,
        updated_by: Optional[str] = None,
    ) -> FindingAnnotation:
        """Mark a finding as in-progress.

        Args:
            finding_id: Finding ID
            notes: Optional notes about the fix progress
            updated_by: Optional username of the updater

        Returns:
            The created or updated annotation
        """
        return self.set_annotation(
            finding_id=finding_id,
            state="in-progress",
            notes=notes,
            updated_by=updated_by,
        )

    def mark_as_open(
        self,
        finding_id: str,
        notes: Optional[str] = None,
        updated_by: Optional[str] = None,
    ) -> FindingAnnotation:
        """Mark a finding as open (reset state).

        Args:
            finding_id: Finding ID
            notes: Optional notes
            updated_by: Optional username of the updater

        Returns:
            The created or updated annotation
        """
        return self.set_annotation(
            finding_id=finding_id,
            state="open",
            notes=notes,
            updated_by=updated_by,
        )

    def remove_annotation(self, finding_id: str) -> bool:
        """Remove annotation for a finding.

        Args:
            finding_id: Finding ID

        Returns:
            True if annotation was removed, False if it didn't exist
        """
        if finding_id in self.annotations:
            del self.annotations[finding_id]
            logger.debug(f"Removed annotation for finding {finding_id}")
            return True
        return False

    def apply_annotations(self, findings: List[Finding]) -> List[Finding]:
        """Apply annotations to findings.

        Args:
            findings: List of findings to apply annotations to

        Returns:
            Findings with annotations applied (state and notes)
        """
        for finding in findings:
            annotation = self.get_annotation(finding.id)
            if annotation:
                finding.state = annotation.state
                logger.debug(f"Applied state '{annotation.state}' to finding {finding.id}")

        return findings

    def get_all_annotations(self) -> List[FindingAnnotation]:
        """Get all annotations.

        Returns:
            List of all annotations
        """
        return list(self.annotations.values())

    def get_annotations_by_state(self, state: str) -> List[FindingAnnotation]:
        """Get all annotations with a specific state.

        Args:
            state: Finding state

        Returns:
            List of annotations with the specified state
        """
        return [ann for ann in self.annotations.values() if ann.state == state]

    def get_statistics(self) -> Dict[str, int]:
        """Get annotation statistics.

        Returns:
            Dictionary with counts by state
        """
        stats = {
            "total": len(self.annotations),
            "open": 0,
            "in-progress": 0,
            "fixed": 0,
            "won't-fix": 0,
            "false-positive": 0,
        }

        for ann in self.annotations.values():
            if ann.state in stats:
                stats[ann.state] += 1

        return stats

    def reload(self) -> None:
        """Reload annotations from file."""
        self.annotations.clear()
        self._load_annotations()
        logger.debug("Reloaded annotations")
