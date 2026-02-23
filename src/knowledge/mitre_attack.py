"""
MITRE ATT&CK mapping for RE Agent.
Maps function categories and behavioural signals → ATT&CK TTPs.
Supports both static lookup and LLM-driven mapping via ModelRouter.
"""
from __future__ import annotations

from typing import Optional


# ---------------------------------------------------------------------------
# Static mapping: function_category → ATT&CK TTP list
# Each TTP is formatted as "TXXXX.YYY — Name" for human readability.
# ---------------------------------------------------------------------------

CATEGORY_TO_TTPS: dict[str, list[str]] = {
    "anti_debug": [
        "T1622 — Debugger Evasion",
        "T1497.001 — Virtualization/Sandbox Evasion: System Checks",
        "T1497.003 — Virtualization/Sandbox Evasion: Time Based Evasion",
    ],
    "crypto": [
        "T1027 — Obfuscated Files or Information",
        "T1573 — Encrypted Channel",
        "T1573.001 — Encrypted Channel: Symmetric Cryptography",
        "T1573.002 — Encrypted Channel: Asymmetric Cryptography",
    ],
    "network": [
        "T1071 — Application Layer Protocol",
        "T1071.001 — Application Layer Protocol: Web Protocols",
        "T1095 — Non-Application Layer Protocol",
        "T1571 — Non-Standard Port",
        "T1041 — Exfiltration Over C2 Channel",
    ],
    "file": [
        "T1005 — Data from Local System",
        "T1074.001 — Data Staged: Local Data Staging",
        "T1083 — File and Directory Discovery",
        "T1025 — Data from Removable Media",
        "T1560 — Archive Collected Data",
    ],
    "process": [
        "T1055 — Process Injection",
        "T1055.001 — Process Injection: Dynamic-link Library Injection",
        "T1055.002 — Process Injection: Portable Executable Injection",
        "T1134 — Access Token Manipulation",
        "T1106 — Native API",
        "T1059 — Command and Scripting Interpreter",
    ],
    "registry": [
        "T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys",
        "T1112 — Modify Registry",
        "T1012 — Query Registry",
    ],
    "obfuscation": [
        "T1027 — Obfuscated Files or Information",
        "T1027.002 — Obfuscated Files or Information: Software Packing",
        "T1027.005 — Obfuscated Files or Information: Indicator Removal from Tools",
        "T1140 — Deobfuscate/Decode Files or Information",
    ],
    "utility": [],
    "unknown": [],
}

# Additional keyword-to-TTP mappings for LLM-free signal scanning
KEYWORD_TTPS: dict[str, list[str]] = {
    "virtualalloc": ["T1055 — Process Injection"],
    "writeprocessmemory": ["T1055.002 — Process Injection: Portable Executable Injection"],
    "createremotethread": ["T1055 — Process Injection"],
    "rtldecompressbuffer": ["T1027.002 — Obfuscated Files or Information: Software Packing"],
    "isdebuggerpresent": ["T1622 — Debugger Evasion"],
    "ntqueryinformationprocess": ["T1622 — Debugger Evasion"],
    "rdtsc": ["T1497.003 — Virtualization/Sandbox Evasion: Time Based Evasion"],
    "wsaconnect": ["T1071.001 — Application Layer Protocol: Web Protocols"],
    "connect": ["T1095 — Non-Application Layer Protocol"],
    "send": ["T1041 — Exfiltration Over C2 Channel"],
    "recv": ["T1041 — Exfiltration Over C2 Channel"],
    "winhttp": ["T1071.001 — Application Layer Protocol: Web Protocols"],
    "regsetvalue": ["T1112 — Modify Registry"],
    "regcreatekey": ["T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys"],
    "cryptencrypt": ["T1573.001 — Encrypted Channel: Symmetric Cryptography"],
    "shellexecute": ["T1106 — Native API", "T1059 — Command and Scripting Interpreter"],
    "createprocess": ["T1059 — Command and Scripting Interpreter"],
    "loadlibrary": ["T1129 — Shared Modules"],
    "getprocaddress": ["T1129 — Shared Modules"],
    "setwindowshookex": ["T1056.001 — Input Capture: Keylogging"],
    "getasynckeystate": ["T1056.001 — Input Capture: Keylogging"],
    "bitblt": ["T1113 — Screen Capture"],
    "netsend": ["T1071 — Application Layer Protocol"],
}


class MitreAttackMapper:
    """
    Maps RE analysis findings → MITRE ATT&CK TTPs.

    Two modes:
    1. Static mapping via CATEGORY_TO_TTPS + KEYWORD_TTPS (always available).
    2. LLM-driven mapping via ModelRouter (richer context, optional).
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self._router: Optional[object] = None  # lazy ModelRouter

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def map_from_category(self, function_category: str) -> list[str]:
        """Return TTPs for a known function_category string."""
        return list(CATEGORY_TO_TTPS.get(function_category.lower(), []))

    def map_from_keywords(self, pseudocode: str) -> list[str]:
        """
        Scan decompiled pseudocode for API names and map to TTPs.
        Returns de-duplicated sorted TTP list.
        """
        lower = pseudocode.lower()
        found: set[str] = set()
        for keyword, ttps in KEYWORD_TTPS.items():
            if keyword in lower:
                found.update(ttps)
        return sorted(found)

    def map_from_findings(self, findings: list[dict]) -> list[str]:
        """
        Aggregate TTPs from a list of agent findings dicts.
        Looks at 'finding' text and any 'category' field.
        """
        found: set[str] = set()
        for f in findings:
            category = f.get("category", "")
            if category:
                found.update(self.map_from_category(category))
            text = (f.get("finding", "") + " " + f.get("evidence", "")).lower()
            for keyword, ttps in KEYWORD_TTPS.items():
                if keyword in text:
                    found.update(ttps)
        return sorted(found)

    def map_llm(
        self,
        pseudocode: str,
        function_name: str = "",
        existing_ttps: Optional[list[str]] = None,
    ) -> list[str]:
        """
        Use ModelRouter (Tier1) to augment TTP mapping with LLM reasoning.
        Falls back to keyword scan if router unavailable.
        """
        router = self._get_router()
        if router is None:
            return self.map_from_keywords(pseudocode)

        existing = existing_ttps or []
        prompt = f"""You are a MITRE ATT&CK expert.
Analyse this decompiled function and list the relevant ATT&CK TTPs.

Function name: {function_name or 'unknown'}
Already identified TTPs: {existing}

Pseudocode (first 1500 chars):
```c
{pseudocode[:1500]}
```

Return a JSON array of TTP strings in format "TXXXX — Name".
Only include TTPs with strong evidence. Return [] if none apply.
Example: ["T1055 — Process Injection", "T1622 — Debugger Evasion"]"""

        try:
            from ..models.router import TaskComplexity
            response = router.complete(
                prompt=prompt,
                system="You are a MITRE ATT&CK mapping assistant. Return JSON only.",
                complexity=TaskComplexity(score=0.2),
                max_tokens=512,
            )
            import json
            text = response.text.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            llm_ttps = json.loads(text.strip())
            if isinstance(llm_ttps, list):
                combined = set(existing) | set(llm_ttps)
                return sorted(combined)
        except Exception:
            pass
        # Fallback
        return self.map_from_keywords(pseudocode)

    def update_state_ttps(
        self,
        state: object,
        pseudocode: str = "",
        category: str = "",
        use_llm: bool = False,
        function_name: str = "",
    ) -> list[str]:
        """
        Convenience: compute TTPs and merge into state.mitre_ttps.
        Returns the full updated TTP list.
        """
        new_ttps: set[str] = set()

        if category:
            new_ttps.update(self.map_from_category(category))

        if pseudocode:
            new_ttps.update(self.map_from_keywords(pseudocode))

        if use_llm and pseudocode:
            new_ttps.update(
                self.map_llm(pseudocode, function_name, list(new_ttps))
            )

        if hasattr(state, "mitre_ttps"):
            existing: list[str] = state.mitre_ttps  # type: ignore[attr-defined]
            combined = sorted(set(existing) | new_ttps)
            state.mitre_ttps = combined  # type: ignore[attr-defined]
            return combined

        return sorted(new_ttps)

    # ------------------------------------------------------------------ #
    #  Internal                                                            #
    # ------------------------------------------------------------------ #

    def _get_router(self) -> Optional[object]:
        if self._router is not None:
            return self._router
        if not self.config:
            return None
        try:
            from ..models.router import ModelRouter
            self._router = ModelRouter(self.config)
            return self._router
        except Exception:
            return None
