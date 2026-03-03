"""
Multi-dimensional scoring system for reverse engineering analysis.

Dimensions (100 pts max):
  1. Category accuracy       (20 pts): exact/related/wrong
  2. Mechanism accuracy      (30 pts): fuzzy + keyword overlap
  3. Artifact extraction     (30 pts): per-artifact with type+value+edit-similarity
  4. IOC accuracy            (20 pts): IP/port/URL/key extraction
  5. Structural fidelity     (10 pts): ordered execution-flow keyword sequence (P7)

Mechanism gate (P14): IOC points only awarded if mechanism_score >= 50%
Edit similarity (P13): Levenshtein-like ratio for artifact matching
Mechanism verification (P10): functional correctness check for crypto targets
Bonus for novel findings (+10%), penalty for false positives (-5 each)

Returns structured score breakdown:
  {
    "total": 85,
    "dimensions": {
      "category":   {"points": 20, "max": 20, ...},
      "mechanism":  {"points": 25, "max": 30, ...},
      "artifacts":  {"points": 30, "max": 30, ...},
      "iocs":       {"points": 10, "max": 20, ...},
      "structural_fidelity": {"points": 7, "max": 10, ...}
    },
    "bonus": {...},
    "penalties": {...},
    "meta": {"mechanism_gate_applied": bool, "mechanism_verification": ...},
    "summary": "..."
  }
"""

import json
import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field


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
    # P7: ordered execution flow keywords for StructuralFidelityScorer
    execution_order: Optional[List[str]] = None
    # P10: Python snippet (as string) that tests the claimed mechanism
    # {claimed_key}, {claimed_algo} are substituted from agent output
    mechanism_verification: Optional[str] = None


# ──────────────────────────────────────────────────────────────────────────────
# SCORING DIMENSIONS
# ──────────────────────────────────────────────────────────────────────────────


class DimensionScorer:
    """Base class for scoring a dimension."""

    def score(
        self, target: str, analysis_json: Dict[str, Any], raw_text: str, ground_truth: GroundTruthV2
    ) -> Tuple[int, str]:
        raise NotImplementedError


class CategoryScorer(DimensionScorer):
    """Score category accuracy (20 points)."""

    # Alias map: maps common LLM output variants to canonical category names.
    # This handles cases where LLMs output synonyms, MITRE-style names, or
    # slash-separated multi-categories instead of the exact ground truth string.
    _ALIAS_TO_CANONICAL: Dict[str, str] = {
        # malware_dropper aliases — LLMs often say "evasion", "c2", "encryption"
        # for binaries that decrypt+drop a payload or beacon home
        "malware":            "malware_dropper",
        "dropper":            "malware_dropper",
        "payload_delivery":   "malware_dropper",
        "loader":             "malware_dropper",
        "stager":             "malware_dropper",
        "downloader":         "malware_dropper",
        "c2":                 "malware_dropper",
        "c2_beacon":          "malware_dropper",
        "beacon":             "malware_dropper",
        "rat":                "malware_dropper",
        "ransomware":         "malware_dropper",
        "crypto_dropper":     "malware_dropper",
        "encryption":         "malware_dropper",
        "crypto_malware":     "malware_dropper",
        # evasion aliases — LLMs sometimes confuse evasion/anti_analysis
        "anti-analysis":      "anti_analysis",
        "antidebug":          "anti_analysis",
        "anti_debug":         "anti_analysis",
        "anti_debugging":     "anti_analysis",
        "debugger_evasion":   "anti_analysis",
        # injection aliases
        "process_injection":  "injection",
        "process injection":  "injection",
        "remote injection":   "injection",
        "dll_injection":      "injection",
        # obfuscation aliases
        "vm_dispatch":        "obfuscation",
        "virtualization":     "obfuscation",
        "code obfuscation":   "obfuscation",
        "packer":             "obfuscation",
        # crackme aliases
        "crackme_challenge":  "crackme",
        "password_check":     "crackme",
    }

    # Related-category map: expected → list of related outputs (earn 10 pts)
    _RELATED_MAP: Dict[str, List[str]] = {
        "anti_analysis": ["evasion", "anti-analysis", "antidebug", "anti_debug",
                          "anti_debugging", "debugger_evasion"],
        "evasion":       ["anti_analysis", "anti-analysis", "antidebug", "anti_debug",
                          "api_hashing", "dynamic_resolution"],
        "malware_dropper": ["malware", "dropper", "payload_delivery", "loader",
                            "stager", "c2", "c2_beacon", "beacon", "rat",
                            "encryption", "crypto_dropper", "crypto_malware",
                            "downloader", "evasion", "crypto", "c2_client",
                            "malware_loader", "malicious"],
        "injection":     ["process_injection", "process injection", "remote injection",
                          "dll_injection"],
        "obfuscation":   ["vm_dispatch", "virtualization", "code obfuscation", "packer"],
        "crackme":       ["crackme_challenge", "password_check", "license_check"],
    }

    def _normalize(self, cat: str) -> str:
        """Lowercase, strip whitespace, collapse internal spaces/dashes."""
        return cat.lower().strip()

    def _split_slash(self, cat: str) -> List[str]:
        """Split slash-separated multi-categories: 'C2/Evasion' → ['c2', 'evasion']."""
        parts = [p.strip() for p in cat.split("/") if p.strip()]
        return parts if len(parts) > 1 else [cat]

    def score(
        self, target: str, analysis_json: Dict[str, Any], raw_text: str, ground_truth: GroundTruthV2
    ) -> Tuple[int, str]:
        raw_model_category = (analysis_json.get("category") or "").strip()
        model_category = self._normalize(raw_model_category)
        expected = self._normalize(ground_truth.category)

        # 1. Exact match (full 20 pts)
        if model_category == expected:
            return 20, f"Exact match: {model_category}"

        # 2. Alias resolution — map LLM synonym to canonical, then check exact match (20 pts)
        canonical = self._ALIAS_TO_CANONICAL.get(model_category)
        if canonical and canonical == expected:
            return 20, f"Alias exact match: {model_category} → {canonical}"

        # 3. Slash-separated multi-category: check if any part is exact or alias match (20 pts)
        parts = self._split_slash(model_category)
        if len(parts) > 1:
            for part in parts:
                if part == expected:
                    return 20, f"Slash-category exact match: {part} in '{model_category}'"
                part_canonical = self._ALIAS_TO_CANONICAL.get(part)
                if part_canonical and part_canonical == expected:
                    return 20, f"Slash-category alias match: {part} → {part_canonical}"

        # 4. Related category check — alias or direct related (10 pts)
        related_cats = self._RELATED_MAP.get(expected, [])
        if model_category in related_cats:
            return 10, f"Related category: {model_category} ≈ {expected}"
        # Check slash parts against related list
        if len(parts) > 1:
            for part in parts:
                if part in related_cats:
                    return 10, f"Slash-category related: {part} ≈ {expected}"
                part_canonical = self._ALIAS_TO_CANONICAL.get(part)
                if part_canonical and part_canonical in related_cats:
                    return 10, f"Slash-category alias related: {part} → {part_canonical} ≈ {expected}"

        # 5. Substring containment — partial match (5 pts)
        if expected in model_category or model_category in expected:
            return 5, f"Partial match: '{model_category}' contains '{expected}'"

        return 0, f"Wrong category: '{model_category}' != '{expected}'"


class MechanismScorer(DimensionScorer):
    """Score mechanism accuracy (30 points) with fuzzy matching."""

    def __init__(self, similarity_threshold: float = 0.65):
        self.threshold = similarity_threshold

    def _fuzzy_match(self, model_text: str, expected_text: str) -> float:
        return SequenceMatcher(None, model_text.lower(), expected_text.lower()).ratio()

    def _keyword_overlap_score(self, model_text: str, keywords: List[str]) -> float:
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
            if any(kw.lower() in raw_text.lower() for kw in ground_truth.mechanism_keywords):
                return 10, "Mechanism found in text but not in mechanism field"
            return 0, "No mechanism provided"

        similarity = self._fuzzy_match(model_mechanism, ground_truth.mechanism)
        kw_overlap = self._keyword_overlap_score(model_mechanism, ground_truth.mechanism_keywords)
        fuzzy_score = 0.6 * similarity + 0.4 * kw_overlap

        if fuzzy_score >= self.threshold:
            return 30, f"Exact mechanism match (fuzzy={fuzzy_score:.2f})"
        if fuzzy_score >= 0.50:
            return 20, f"Partial mechanism match (fuzzy={fuzzy_score:.2f})"
        if fuzzy_score >= 0.35:
            return 10, f"Related mechanism (fuzzy={fuzzy_score:.2f})"
        if kw_overlap >= 0.5:
            return 15, f"Correct keywords ({kw_overlap:.0%}) but different wording"
        # Partial credit: at least 1 keyword matched but fuzzy score too low
        if kw_overlap > 0.0:
            # Scale: 1/N keywords = 5pts, 2/N = 7pts, etc. (max 9 to not overlap tier above)
            partial = int(min(9, max(5, round(kw_overlap * 18))))
            return partial, f"Partial keyword match ({kw_overlap:.0%} kw, fuzzy={fuzzy_score:.2f})"
        return 0, f"Wrong mechanism (fuzzy={fuzzy_score:.2f}, kw=0%)"


class ArtifactScorer(DimensionScorer):
    """Score artifact extraction (30 points).

    P13: Uses edit similarity (Levenshtein ratio) as fallback when exact match fails.
    Alias matching tuned with lower threshold for short tokens.
    """

    def _edit_similarity(self, a: str, b: str) -> float:
        """SequenceMatcher ratio — Levenshtein-like similarity on character level."""
        return SequenceMatcher(None, a.lower(), b.lower()).ratio()

    def _find_artifact_in_text(
        self, artifact: ArtifactSpec, text: str, json_data: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Try to find an artifact in text or JSON.
        P13: Falls back to edit similarity if exact/alias match fails.
        """
        text_lower = text.lower()
        value_lower = artifact.value.lower()

        # Exact match in text
        if value_lower in text_lower:
            idx = text_lower.find(value_lower)
            snippet = text[max(0, idx - 40) : min(len(text), idx + len(artifact.value) + 40)]
            return True, snippet

        # Check in JSON serialization
        json_str = json.dumps(json_data).lower()
        if value_lower in json_str:
            return True, f"Found in JSON: {artifact.value}"

        # Check aliases (exact)
        for alias in artifact.aliases:
            if alias.lower() in text_lower:
                return True, f"Found via alias: {alias}"
            if alias.lower() in json_str:
                return True, f"Found via alias in JSON: {alias}"

        # Fuzzy matching if explicitly enabled
        if artifact.fuzzy:
            for line in text.split("\n"):
                ratio = SequenceMatcher(None, line.lower(), value_lower).ratio()
                if ratio > 0.70:
                    return True, f"Found via fuzzy match: {line[:60]}"

        # P13: Edit similarity scan over lines (for short-medium values only)
        value_len = len(artifact.value)
        if 3 <= value_len <= 40:
            # Scan text lines for high edit similarity
            threshold = 0.80 if value_len >= 8 else 0.72
            for line in text.split("\n"):
                line_strip = line.strip()
                if not line_strip:
                    continue
                # Only compare lines that contain the artifact value length roughly
                for i in range(max(0, len(line_strip) - value_len * 2),
                               len(line_strip)):
                    window = line_strip[max(0, i - value_len): i + value_len * 2]
                    if len(window) < 2:
                        continue
                    ratio = self._edit_similarity(window, artifact.value)
                    if ratio >= threshold:
                        return True, f"Found via edit-sim ({ratio:.2f}): {window[:50]}"
            # Also scan alias list for edit similarity
            for alias in artifact.aliases:
                a_lower = alias.lower()
                if len(a_lower) >= 3:
                    ratio = self._edit_similarity(a_lower, value_lower)
                    if ratio >= 0.75 and a_lower in text_lower:
                        return True, f"Found via alias edit-sim: {alias}"

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

        points = min(points, 30)

        explanation = f"Found {len(found_artifacts)}/{len(artifacts)} artifacts (pts={points})"
        if found_artifacts:
            explanation += f"\n  Found: {found_artifacts[:3]}"
        if missing_artifacts:
            explanation += f"\n  Missed: {missing_artifacts[:3]}"

        return points, explanation


class IOCScorer(DimensionScorer):
    """Score IOC (IP/port/URL/key) extraction (20 points).

    P14: Only awards IOC points if mechanism_score passed the gate (>= 50% of max 30 = 15pts).
    Gate is checked in score_v2() by passing mechanism_pts.
    """

    IOC_PATTERNS = {
        "ip": r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
        "port": r"(?::\d{2,5}|port\s*=\s*(\d{2,5}))",
        "url": r"https?://[^\s]+",
        "key": r"[A-Fa-f0-9]{16,}",
        "hash": r"0x[A-Fa-f0-9]{6,8}",
    }

    def _find_ioc_in_text(self, ioc: IOCSpec, text: str) -> bool:
        if ioc.type == "ip":
            matches = re.findall(self.IOC_PATTERNS["ip"], text)
            return ioc.value in matches
        if ioc.type == "port":
            return bool(re.search(rf":\d*{ioc.value}\b|port\s*[:=]?\s*{ioc.value}\b", text, re.IGNORECASE))
        if ioc.type == "url":
            return ioc.value in text
        if ioc.type == "key":
            return ioc.value.lower() in text.lower()
        if ioc.type == "hash":
            return ioc.value.lower() in text.lower()
        return False

    def score(
        self, target: str, analysis_json: Dict[str, Any], raw_text: str,
        ground_truth: GroundTruthV2, mechanism_pts: int = 30
    ) -> Tuple[int, str]:
        iocs = ground_truth.iocs
        if not iocs:
            return 20, "No IOCs specified (full points)"

        combined_text = raw_text + "\n" + json.dumps(analysis_json)
        points = 0
        found_iocs = []

        for ioc in iocs:
            if self._find_ioc_in_text(ioc, combined_text):
                points += ioc.points
                found_iocs.append(f"{ioc.type}:{ioc.value}")

        points = min(points, 20)

        # P14: Mechanism gate — IOC score gated at 0 if mechanism < 50% of max (15/30)
        gate_applied = mechanism_pts < 15
        if gate_applied:
            explanation = (
                f"GATE BLOCKED (mechanism={mechanism_pts}/30 < 15): IOC score=0 "
                f"(would have been {points})"
            )
            return 0, explanation

        explanation = f"Found {len(found_iocs)}/{len(iocs)} IOCs (pts={points})"
        if found_iocs:
            explanation += f"\n  Found: {found_iocs}"

        return points, explanation


class StructuralFidelityScorer(DimensionScorer):
    """P7: Structural fidelity — ordered execution flow keyword sequence (10 points).

    Measures whether the agent's mechanism/flow description matches the expected
    execution ordering from ground truth's execution_order field.

    Scoring:
      - All keywords present in correct order: 10 pts
      - All keywords present, partial order: 7 pts
      - ≥ 50% of keywords in order: 5 pts
      - Keywords present but no ordering: 3 pts
      - No keywords: 0 pts

    If ground truth has no execution_order, awards full 10 pts (not applicable).
    """

    def score(
        self, target: str, analysis_json: Dict[str, Any], raw_text: str, ground_truth: GroundTruthV2
    ) -> Tuple[int, str]:
        order = ground_truth.execution_order
        if not order:
            return 10, "No execution_order defined (full points)"

        # Build combined searchable text from mechanism + summary + findings
        mechanism = (analysis_json.get("mechanism") or "").lower()
        summary = (analysis_json.get("summary") or "").lower()
        findings_text = " ".join(
            (f.get("finding", "") + " " + f.get("evidence", ""))
            for f in analysis_json.get("findings", [])
        ).lower()
        combined = mechanism + " " + summary + " " + findings_text + " " + raw_text.lower()

        # Find positions of each keyword
        positions = []
        missing = []
        for kw in order:
            kw_lower = kw.lower()
            idx = combined.find(kw_lower)
            if idx >= 0:
                positions.append((kw, idx))
            else:
                positions.append((kw, -1))
                missing.append(kw)

        found_count = sum(1 for _, pos in positions if pos >= 0)
        total = len(order)

        if found_count == 0:
            return 0, f"No flow keywords found: {order}"

        if found_count < total * 0.5:
            return 3, f"Few keywords found ({found_count}/{total}): missing {missing}"

        # Check ordering: are found positions monotonically increasing?
        found_positions = [(kw, pos) for kw, pos in positions if pos >= 0]
        in_order_count = 1
        for i in range(1, len(found_positions)):
            if found_positions[i][1] >= found_positions[i-1][1]:
                in_order_count += 1

        order_ratio = in_order_count / len(found_positions) if found_positions else 0

        if found_count == total and order_ratio >= 0.85:
            return 10, f"All {total} flow keywords in correct order"
        elif found_count == total and order_ratio >= 0.6:
            return 7, f"All keywords present, partial order ({order_ratio:.0%} in-order)"
        elif found_count >= total * 0.5 and order_ratio >= 0.7:
            return 5, f"{found_count}/{total} keywords in order ({order_ratio:.0%})"
        else:
            return 3, f"Keywords present ({found_count}/{total}) but poor ordering"


# ──────────────────────────────────────────────────────────────────────────────
# P10: Mechanism verification (functional correctness check)
# ──────────────────────────────────────────────────────────────────────────────

def run_mechanism_verification(
    analysis_json: Dict[str, Any],
    raw_text: str,
    verification_snippet: str,
) -> Tuple[bool, str]:
    """
    P10: Test functional correctness of claimed mechanism.

    The verification_snippet is a Python expression/check (as a string) that
    is evaluated with context extracted from the analysis. Returns (passed, msg).

    Safe eval context includes: claimed_key, claimed_algo, raw_text, analysis_json.
    """
    if not verification_snippet:
        return True, "No verification defined"

    # Extract claimed values from analysis
    claimed_key = ""
    claimed_algo = ""

    # Try to extract key from various fields
    for field_name in ("secret_value", "rc4_key", "xor_key", "key"):
        val = analysis_json.get(field_name, "")
        if val and isinstance(val, str):
            claimed_key = val
            break

    # From nested structures
    if not claimed_key:
        for artifact in analysis_json.get("key_artifacts", []):
            if isinstance(artifact, str) and len(artifact) > 2:
                claimed_key = artifact
                break
            elif isinstance(artifact, dict):
                claimed_key = artifact.get("value", artifact.get("key", ""))
                if claimed_key:
                    break

    # Try mechanism for algo
    mech_text = (analysis_json.get("mechanism") or raw_text).lower()
    for algo in ("rc4", "xor", "aes", "fnv", "fnv-1a"):
        if algo in mech_text:
            claimed_algo = algo
            break

    ctx = {
        "claimed_key": claimed_key,
        "claimed_algo": claimed_algo,
        "raw_text": raw_text,
        "analysis_json": analysis_json,
        "re": re,
    }

    try:
        result = eval(verification_snippet, {"__builtins__": {}}, ctx)  # nosec
        passed = bool(result)
        return passed, f"Verification {'PASSED' if passed else 'FAILED'}: {verification_snippet[:80]}"
    except Exception as e:
        return False, f"Verification error: {e}"


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
    Score a reverse engineering analysis using multi-dimensional scoring (5 dimensions).

    Dimensions:
      1. category     (20 pts)
      2. mechanism    (30 pts)
      3. artifacts    (30 pts) — P13 edit similarity
      4. iocs         (20 pts) — P14 mechanism gate
      5. structural_fidelity (10 pts) — P7 ordered flow

    Returns structured score breakdown.
    """
    cat_scorer   = CategoryScorer()
    mech_scorer  = MechanismScorer(similarity_threshold=0.65)
    art_scorer   = ArtifactScorer()
    ioc_scorer   = IOCScorer()
    fid_scorer   = StructuralFidelityScorer()

    cat_pts,  cat_exp  = cat_scorer.score(target, analysis_json, raw_text, ground_truth)
    mech_pts, mech_exp = mech_scorer.score(target, analysis_json, raw_text, ground_truth)
    art_pts,  art_exp  = art_scorer.score(target, analysis_json, raw_text, ground_truth)

    # P14: Pass mechanism_pts to IOCScorer for gate check
    ioc_pts,  ioc_exp  = ioc_scorer.score(
        target, analysis_json, raw_text, ground_truth, mechanism_pts=mech_pts
    )
    fid_pts,  fid_exp  = fid_scorer.score(target, analysis_json, raw_text, ground_truth)

    mechanism_gate_applied = mech_pts < 15 and bool(ground_truth.iocs)
    dimensions_total = cat_pts + mech_pts + art_pts + ioc_pts + fid_pts

    # P10: Mechanism verification
    mech_verification_result = None
    if ground_truth.mechanism_verification:
        passed, msg = run_mechanism_verification(
            analysis_json, raw_text, ground_truth.mechanism_verification
        )
        mech_verification_result = {"passed": passed, "message": msg}

    # Bonuses
    bonus_pts = 0
    bonus_breakdown: Dict[str, Any] = {}

    if check_novel_findings:
        findings = analysis_json.get("findings", [])
        gt_keywords = set(
            ground_truth.mechanism_keywords
            + sum([art.aliases + [art.value] for art in ground_truth.artifacts], [])
        )
        novel_count = sum(
            1 for finding in findings
            if not any(
                kw.lower() in (finding.get("finding", "") + finding.get("evidence", "")).lower()
                for kw in gt_keywords
            )
        )
        if novel_count > 0:
            bonus_pts += min(10, novel_count * 2)
            bonus_breakdown["novel_findings"] = min(10, novel_count * 2)

    bonus_breakdown["total"] = bonus_pts

    # Penalties
    penalty_pts = 0
    penalty_breakdown: Dict[str, Any] = {}

    if check_false_positives:
        findings = analysis_json.get("findings", [])
        gt_keywords = set(
            ground_truth.mechanism_keywords
            + sum([art.aliases + [art.value] for art in ground_truth.artifacts], [])
        )
        false_positives = 0
        for finding in findings:
            confidence = finding.get("confidence", 0.5)
            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                confidence = 0.5
            if confidence > 0.8:
                finding_text = (finding.get("finding", "") + finding.get("evidence", "")).lower()
                if not any(kw.lower() in finding_text for kw in gt_keywords):
                    if any(neg in finding_text for neg in ["not ", "no ", "without "]):
                        false_positives += 1
        if false_positives > 0:
            penalty_pts = min(15, false_positives * 5)
            penalty_breakdown["false_positives"] = penalty_pts

    penalty_breakdown["total"] = penalty_pts

    total = dimensions_total + bonus_pts - penalty_pts
    total = max(0, min(110, total))  # Allow up to 110 with structural bonus
    percentage = round((total / 100) * 100)

    # Summary
    summary_parts = []
    summary_parts.append("[OK] Cat" if cat_pts == 20 else "[~] Cat" if cat_pts >= 10 else "[XX] Cat")
    summary_parts.append("[OK] Mech" if mech_pts >= 20 else "[~] Mech" if mech_pts >= 10 else "[XX] Mech")
    summary_parts.append(f"Art:{art_pts}/30")
    summary_parts.append(f"IOC:{ioc_pts}/20{'[GATED]' if mechanism_gate_applied else ''}")
    summary_parts.append(f"Fid:{fid_pts}/10")
    if bonus_pts > 0:
        summary_parts.append(f"+{bonus_pts}bonus")
    if penalty_pts > 0:
        summary_parts.append(f"-{penalty_pts}penalty")

    return {
        "target": target,
        "total": total,
        "max": 100,
        "percentage": percentage,
        "dimensions": {
            "category":           {"points": cat_pts,  "max": 20, "explanation": cat_exp},
            "mechanism":          {"points": mech_pts, "max": 30, "explanation": mech_exp},
            "artifacts":          {"points": art_pts,  "max": 30, "explanation": art_exp},
            "iocs":               {"points": ioc_pts,  "max": 20, "explanation": ioc_exp},
            "structural_fidelity":{"points": fid_pts,  "max": 10, "explanation": fid_exp},
        },
        "bonus": bonus_breakdown,
        "penalties": penalty_breakdown,
        "meta": {
            "mechanism_gate_applied": mechanism_gate_applied,
            "mechanism_verification": mech_verification_result,
        },
        "summary": " | ".join(summary_parts),
    }


def print_score_report(score_result: Dict[str, Any]) -> None:
    """Pretty-print a score_v2 result (5 dimensions)."""
    target     = score_result["target"]
    total      = score_result["total"]
    percentage = score_result["percentage"]

    print(f"\n{'='*70}")
    print(f"TARGET: {target}")
    print(f"{'='*70}")
    print(f"Total Score: {total}/100 ({percentage}%)")
    print(f"Summary: {score_result['summary']}")
    print()

    # Dimensions
    print("DIMENSIONS:")
    dim_maxes = {"category": 20, "mechanism": 30, "artifacts": 30, "iocs": 20,
                 "structural_fidelity": 10}
    for dim_name, dim_data in score_result["dimensions"].items():
        pts     = dim_data["points"]
        max_pts = dim_data["max"]
        exp     = dim_data["explanation"]
        filled  = int(pts / max_pts * 10) if max_pts > 0 else 0
        bar     = "#" * filled + "-" * (10 - filled)
        print(f"  [{bar}] {dim_name:20s} {pts:2d}/{max_pts:2d}")
        for line in exp.split("\n"):
            if line.strip():
                print(f"      {line}")

    # Meta
    meta = score_result.get("meta", {})
    if meta.get("mechanism_gate_applied"):
        print("\n[P14] MECHANISM GATE: IOC score blocked (mechanism < 15pts)")
    if meta.get("mechanism_verification"):
        mv = meta["mechanism_verification"]
        status = "PASS" if mv["passed"] else "FAIL"
        print(f"\n[P10] MECHANISM VERIFICATION: {status} — {mv['message'][:80]}")

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
