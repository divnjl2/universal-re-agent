"""
Multi-dimensional scoring system for reverse engineering analysis.

Replaces brittle keyword matching with:
  - Category accuracy (20 pts): exact/related/wrong
  - Mechanism accuracy (30 pts): exact/partial/wrong mechanism
  - Artifact extraction (30 pts): per-artifact scoring with type+value matching
  - IOC accuracy (20 pts): IP/port/URL/key extraction
  + Bonus for novel findings (+10%)
  - Penalty for false positives (-5 per major claim)

Returns structured score breakdown:
  {
    "total": 85,
    "dimensions": {"category": 20, "mechanism": 25, "artifacts": 30, "iocs": 10},
    "bonus": 5,
    "penalties": 0,
    "breakdown": {...},
    "summary": "..."
  }
"""

import json
import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict


@dataclass
class ArtifactSpec:
    """Ground truth artifact specification."""
    type: str  # "rc4_key", "string", "api_call", "constant", "function", "import"
    value: str  # exact expected value
    points: int = 15  # max points for this artifact
    aliases: List[str] = None  # alternative names/spellings
    required: bool = False  # whether this artifact must be found
    fuzzy: bool = False  # whether to allow fuzzy matching

    def __post_init__(self):
        if self.aliases is None:
            self.aliases = []


@dataclass
class IOCSpec:
    """Ground truth IOC specification."""
    type: str  # "ip", "port", "url", "key", "hash", "domain"
    value: str  # expected value
    points: int = 5
    required: bool = False


@dataclass
class GroundTruthV2:
    """Structured ground truth for a target."""
    category: str  # exact category string
    mechanism: str  # description for fuzzy matching
    mechanism_keywords: List[str]  # key terms that indicate correct mechanism
    artifacts: List[ArtifactSpec]
    iocs: List[IOCSpec]
    summary_keywords: Optional[List[str]] = None


# ──────────────────────────────────────────────────────────────────────────────
# SCORING DIMENSIONS
# ──────────────────────────────────────────────────────────────────────────────


class DimensionScorer:
    """Base class for scoring a dimension."""

    def score(
        self, target: str, analysis_json: Dict[str, Any], raw_text: str, ground_truth: GroundTruthV2
    ) -> Tuple[int, str]:
        """
        Args:
            target: target name
            analysis_json: parsed JSON from model (has category, mechanism, etc.)
            raw_text: raw text output from model
            ground_truth: structured ground truth spec

        Returns:
            (points_earned, explanation)
        """
        raise NotImplementedError


class CategoryScorer(DimensionScorer):
    """Score category accuracy (20 points)."""

    def score(
        self, target: str, analysis_json: Dict[str, Any], raw_text: str, ground_truth: GroundTruthV2
    ) -> Tuple[int, str]:
        model_category = (analysis_json.get("category") or "").lower().strip()
        expected = ground_truth.category.lower().strip()

        if model_category == expected:
            return 20, f"Exact match: {model_category}"

        # Check for related categories
        related_map = {
            "anti_analysis": ["evasion", "anti-analysis", "antidebug", "anti_debug"],
            "evasion": ["anti_analysis", "anti-analysis", "antidebug"],
            "malware_dropper": ["malware", "dropper", "payload_delivery"],
            "injection": ["process_injection", "process injection", "remote injection"],
            "obfuscation": ["vm_dispatch", "virtualization", "code obfuscation"],
        }

        related_cats = related_map.get(expected, [])
        if model_category in related_cats:
            return 10, f"Related category: {model_category} ≈ {expected}"

        # Partial match if substring
        if expected in model_category or model_category in expected:
            return 5, f"Partial match: {model_category} contains {expected}"

        return 0, f"Wrong category: {model_category} != {expected}"


class MechanismScorer(DimensionScorer):
    """Score mechanism accuracy (30 points) with fuzzy matching."""

    def __init__(self, similarity_threshold: float = 0.65):
        """
        Args:
            similarity_threshold: SequenceMatcher ratio threshold for "exact" match
        """
        self.threshold = similarity_threshold

    def _fuzzy_match(self, model_text: str, expected_text: str) -> float:
        """
        Compute fuzzy similarity between two mechanism descriptions.
        Uses SequenceMatcher ratio.
        """
        ratio = SequenceMatcher(None, model_text.lower(), expected_text.lower()).ratio()
        return ratio

    def _keyword_overlap_score(self, model_text: str, keywords: List[str]) -> float:
        """
        Score keyword overlap. Returns [0, 1] representing fraction of keywords found.
        """
        if not keywords:
            return 0.0
        model_lower = model_text.lower()
        found = sum(1 for kw in keywords if kw.lower() in model_lower)
        return found / len(keywords)

    def score(
        self, target: str, analysis_json: Dict[str, Any], raw_text: str, ground_truth: GroundTruthV2
    ) -> Tuple[int, str]:
        model_mechanism = (analysis_json.get("mechanism") or "").strip()
        if not model_mechanism:
            # Check if mechanism is in raw text at all
            if any(kw.lower() in raw_text.lower() for kw in ground_truth.mechanism_keywords):
                return 10, "Mechanism found in text but not in mechanism field"
            return 0, "No mechanism provided"

        # Fuzzy similarity on mechanism string
        similarity = self._fuzzy_match(model_mechanism, ground_truth.mechanism)

        # Keyword overlap on mechanism keywords
        kw_overlap = self._keyword_overlap_score(model_mechanism, ground_truth.mechanism_keywords)

        # Weighted score: 60% similarity + 40% keyword overlap
        fuzzy_score = 0.6 * similarity + 0.4 * kw_overlap

        if fuzzy_score >= self.threshold:
            return 30, f"Exact mechanism match (fuzzy={fuzzy_score:.2f})"

        if fuzzy_score >= 0.50:
            return 20, f"Partial mechanism match (fuzzy={fuzzy_score:.2f})"

        if fuzzy_score >= 0.35:
            return 10, f"Related mechanism (fuzzy={fuzzy_score:.2f}), keywords={ground_truth.mechanism_keywords}"

        if kw_overlap >= 0.5:
            # Good keywords but low string similarity
            return 15, f"Correct keywords ({kw_overlap:.0%}) but different wording"

        return 0, f"Wrong mechanism (fuzzy={fuzzy_score:.2f})"


class ArtifactScorer(DimensionScorer):
    """Score artifact extraction (30 points)."""

    def _find_artifact_in_text(
        self, artifact: ArtifactSpec, text: str, json_data: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Try to find an artifact in text or JSON.
        Returns (found, evidence_snippet)
        """
        text_lower = text.lower()
        value_lower = artifact.value.lower()

        # Exact match in text
        if value_lower in text_lower:
            # Find snippet for evidence
            idx = text_lower.find(value_lower)
            snippet = text[max(0, idx - 40) : min(len(text), idx + len(artifact.value) + 40)]
            return True, snippet

        # Check in JSON arrays
        json_str = json.dumps(json_data).lower()
        if value_lower in json_str:
            return True, f"Found in JSON: {artifact.value}"

        # Check aliases
        for alias in artifact.aliases:
            if alias.lower() in text_lower:
                return True, f"Found via alias: {alias}"

        # Fuzzy matching if enabled
        if artifact.fuzzy:
            for line in text.split("\n"):
                ratio = SequenceMatcher(None, line.lower(), value_lower).ratio()
                if ratio > 0.70:
                    return True, f"Found via fuzzy match: {line[:60]}"

        return False, ""

    def score(
        self, target: str, analysis_json: Dict[str, Any], raw_text: str, ground_truth: GroundTruthV2
    ) -> Tuple[int, str]:
        artifacts = ground_truth.artifacts
        if not artifacts:
            return 30, "No artifacts specified (full points)"

        points = 0
        found_artifacts = []
        missing_artifacts = []

        combined_text = raw_text + "\n" + json.dumps(analysis_json)

        for artifact in artifacts:
            found, evidence = self._find_artifact_in_text(artifact, combined_text, analysis_json)

            if found:
                points += artifact.points
                found_artifacts.append(f"{artifact.type}:{artifact.value}")
            else:
                if artifact.required:
                    missing_artifacts.append(f"{artifact.type}:{artifact.value} [REQUIRED]")
                else:
                    missing_artifacts.append(f"{artifact.type}:{artifact.value}")

        # Cap at 30
        points = min(points, 30)

        explanation = f"Found {len(found_artifacts)}/{len(artifacts)} artifacts (pts={points})"
        if found_artifacts:
            explanation += f"\n  Found: {found_artifacts[:3]}"
        if missing_artifacts:
            explanation += f"\n  Missed: {missing_artifacts[:3]}"

        return points, explanation


class IOCScorer(DimensionScorer):
    """Score IOC (IP/port/URL/key) extraction (20 points)."""

    IOC_PATTERNS = {
        "ip": r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
        "port": r"(?::\d{2,5}|port\s*=\s*(\d{2,5}))",
        "url": r"https?://[^\s]+",
        "key": r"[A-Fa-f0-9]{16,}",  # hex key of 16+ chars
        "hash": r"0x[A-Fa-f0-9]{6,8}",
    }

    def _find_ioc_in_text(self, ioc: IOCSpec, text: str) -> bool:
        """Try to find an IOC in text."""
        if ioc.type == "ip":
            pattern = self.IOC_PATTERNS["ip"]
            matches = re.findall(pattern, text)
            return ioc.value in matches

        if ioc.type == "port":
            # Look for exact port number
            return re.search(rf":\d*{ioc.value}\b|port\s*[:=]?\s*{ioc.value}\b", text, re.IGNORECASE)

        if ioc.type == "url":
            return ioc.value in text

        if ioc.type == "key":
            # Case-insensitive key match
            return ioc.value.lower() in text.lower()

        if ioc.type == "hash":
            return ioc.value.lower() in text.lower()

        return False

    def score(
        self, target: str, analysis_json: Dict[str, Any], raw_text: str, ground_truth: GroundTruthV2
    ) -> Tuple[int, str]:
        iocs = ground_truth.iocs
        if not iocs:
            return 20, "No IOCs specified (full points)"

        points_per_ioc = min(20 // len(iocs), 5)  # max 5 pts per IOC
        points = 0
        found_iocs = []

        combined_text = raw_text + "\n" + json.dumps(analysis_json)

        for ioc in iocs:
            if self._find_ioc_in_text(ioc, combined_text):
                points += ioc.points
                found_iocs.append(f"{ioc.type}:{ioc.value}")

        # Cap at 20
        points = min(points, 20)

        explanation = f"Found {len(found_iocs)}/{len(iocs)} IOCs (pts={points})"
        if found_iocs:
            explanation += f"\n  Found: {found_iocs}"

        return points, explanation


# ──────────────────────────────────────────────────────────────────────────────
# OVERALL SCORING
# ──────────────────────────────────────────────────────────────────────────────


def score_v2(
    target: str,
    analysis_json: Dict[str, Any],
    raw_text: str,
    ground_truth: GroundTruthV2,
    check_novel_findings: bool = True,
    check_false_positives: bool = True,
) -> Dict[str, Any]:
    """
    Score a reverse engineering analysis using multi-dimensional scoring.

    Args:
        target: target name (for reporting)
        analysis_json: parsed JSON from LLM (has category, mechanism, findings, etc.)
        raw_text: raw text output from LLM
        ground_truth: GroundTruthV2 spec for target
        check_novel_findings: if True, award +10% for novel findings not in ground truth
        check_false_positives: if True, penalize false positives (-5 each)

    Returns:
        {
            "total": 85,
            "max": 100,
            "percentage": 85,
            "dimensions": {
                "category": (points, explanation),
                "mechanism": (points, explanation),
                "artifacts": (points, explanation),
                "iocs": (points, explanation),
            },
            "bonus": {"novel_findings": 5, "total": 5},
            "penalties": {"false_positives": 0, "total": 0},
            "summary": "High confidence on category and mechanism; found 3/4 artifacts..."
        }
    """

    # Initialize scorers
    cat_scorer = CategoryScorer()
    mech_scorer = MechanismScorer(similarity_threshold=0.65)
    art_scorer = ArtifactScorer()
    ioc_scorer = IOCScorer()

    # Score each dimension
    cat_pts, cat_exp = cat_scorer.score(target, analysis_json, raw_text, ground_truth)
    mech_pts, mech_exp = mech_scorer.score(target, analysis_json, raw_text, ground_truth)
    art_pts, art_exp = art_scorer.score(target, analysis_json, raw_text, ground_truth)
    ioc_pts, ioc_exp = ioc_scorer.score(target, analysis_json, raw_text, ground_truth)

    dimensions_total = cat_pts + mech_pts + art_pts + ioc_pts

    # Bonuses
    bonus_pts = 0
    bonus_breakdown = {}

    if check_novel_findings:
        # Check for findings not mentioned in ground truth
        findings = analysis_json.get("findings", [])
        gt_keywords = set(
            ground_truth.mechanism_keywords
            + sum([art.aliases + [art.value] for art in ground_truth.artifacts], [])
        )
        novel_count = 0
        for finding in findings:
            finding_text = (finding.get("finding", "") + finding.get("evidence", "")).lower()
            if not any(kw.lower() in finding_text for kw in gt_keywords):
                novel_count += 1
        if novel_count > 0:
            bonus_pts += min(10, novel_count * 2)  # +2 per novel finding, max +10
            bonus_breakdown["novel_findings"] = min(10, novel_count * 2)

    bonus_breakdown["total"] = bonus_pts

    # Penalties
    penalty_pts = 0
    penalty_breakdown = {}

    if check_false_positives:
        # Check for confident claims about things NOT in ground truth
        findings = analysis_json.get("findings", [])
        gt_keywords = set(
            ground_truth.mechanism_keywords
            + sum([art.aliases + [art.value] for art in ground_truth.artifacts], [])
        )
        false_positives = 0
        for finding in findings:
            confidence = finding.get("confidence", 0.5)
            if confidence > 0.8:  # Only penalize high-confidence wrong findings
                finding_text = (finding.get("finding", "") + finding.get("evidence", "")).lower()
                # Check if it's something we didn't expect
                if not any(kw.lower() in finding_text for kw in gt_keywords):
                    # Could be a false positive, but only penalize if contradictory
                    if any(neg in finding_text for neg in ["not ", "no ", "without "]):
                        false_positives += 1

        if false_positives > 0:
            penalty_pts = min(15, false_positives * 5)
            penalty_breakdown["false_positives"] = penalty_pts

    penalty_breakdown["total"] = penalty_pts

    # Total score
    total = dimensions_total + bonus_pts - penalty_pts
    total = max(0, min(100, total))  # Clamp [0, 100]
    percentage = round((total / 100) * 100)

    # Build summary
    summary_parts = []
    if cat_pts == 20:
        summary_parts.append("[OK] Category exact")
    elif cat_pts >= 10:
        summary_parts.append("[~] Category related")
    else:
        summary_parts.append("[XX] Category wrong")

    if mech_pts >= 20:
        summary_parts.append("[OK] Mechanism strong")
    elif mech_pts >= 10:
        summary_parts.append("[~] Mechanism partial")
    else:
        summary_parts.append("[XX] Mechanism weak")

    art_found = art_pts // 5 if art_pts > 0 else 0  # Rough estimate
    summary_parts.append(f"Artifacts: {art_pts}/30pts")

    if bonus_pts > 0:
        summary_parts.append(f"+{bonus_pts} bonus")
    if penalty_pts > 0:
        summary_parts.append(f"-{penalty_pts} penalties")

    return {
        "target": target,
        "total": total,
        "max": 100,
        "percentage": percentage,
        "dimensions": {
            "category": {"points": cat_pts, "max": 20, "explanation": cat_exp},
            "mechanism": {"points": mech_pts, "max": 30, "explanation": mech_exp},
            "artifacts": {"points": art_pts, "max": 30, "explanation": art_exp},
            "iocs": {"points": ioc_pts, "max": 20, "explanation": ioc_exp},
        },
        "bonus": bonus_breakdown,
        "penalties": penalty_breakdown,
        "summary": " | ".join(summary_parts),
    }


def print_score_report(score_result: Dict[str, Any]) -> None:
    """Pretty-print a score_v2 result."""
    target = score_result["target"]
    total = score_result["total"]
    percentage = score_result["percentage"]

    print(f"\n{'='*70}")
    print(f"TARGET: {target}")
    print(f"{'='*70}")
    print(f"Total Score: {total}/100 ({percentage}%)")
    print(f"Summary: {score_result['summary']}")
    print()

    # Dimensions
    print("DIMENSIONS:")
    for dim_name, dim_data in score_result["dimensions"].items():
        pts = dim_data["points"]
        max_pts = dim_data["max"]
        exp = dim_data["explanation"]
        bar = "#" * (pts // (max_pts // 10)) + "-" * (10 - pts // (max_pts // 10))
        print(f"  [{bar}] {dim_name:12s} {pts:2d}/{max_pts:2d}")
        for line in exp.split("\n"):
            if line.strip():
                print(f"      {line}")

    # Bonuses
    if score_result["bonus"]["total"] > 0:
        print(f"\nBONUS: +{score_result['bonus']['total']}")
        for key, val in score_result["bonus"].items():
            if key != "total" and val > 0:
                print(f"  +{val}: {key}")

    # Penalties
    if score_result["penalties"]["total"] > 0:
        print(f"\nPENALTIES: -{score_result['penalties']['total']}")
        for key, val in score_result["penalties"].items():
            if key != "total" and val > 0:
                print(f"  -{val}: {key}")

    print()
