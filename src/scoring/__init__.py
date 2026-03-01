"""
Scoring system for reverse engineering analysis.

Provides multi-dimensional scoring with:
  - Category accuracy (20 pts)
  - Mechanism accuracy (30 pts)
  - Artifact extraction (30 pts)
  - IOC accuracy (20 pts)
  + Bonuses and penalties
"""

from .score_v2 import (
    ArtifactSpec,
    IOCScorer,
    GroundTruthV2,
    MechanismScorer,
    CategoryScorer,
    ArtifactScorer,
    DimensionScorer,
    IOCSpec,
    print_score_report,
    score_v2,
)
from .ground_truth_v2 import GROUND_TRUTH_V2, get_ground_truth, list_targets

__all__ = [
    "score_v2",
    "print_score_report",
    "ArtifactSpec",
    "IOCSpec",
    "GroundTruthV2",
    "CategoryScorer",
    "MechanismScorer",
    "ArtifactScorer",
    "IOCScorer",
    "DimensionScorer",
    "GROUND_TRUTH_V2",
    "get_ground_truth",
    "list_targets",
]
