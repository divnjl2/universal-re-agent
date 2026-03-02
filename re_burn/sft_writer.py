"""
RE Burn v1 — SFT / DPO Writer
Форматирует validated пары в LLaMA-Factory / axolotl формат.
v2:
- SFT: {instruction, input, output} — для fine-tuning RE specialist
- DPO: {instruction, chosen, rejected} — для preference learning
- Instruction использует features из binary dump (импорты, строки, XOR hits)
- write_sft_pairs() принимает пары из quality_gate и пишет JSONL
"""
import json, time
from pathlib import Path

RE_DIR   = Path(__file__).parent.parent
TRAINING = RE_DIR / "data" / "training"

INSTRUCTION_TEMPLATE = """\
Perform a complete reverse engineering analysis of the binary target '{target}'.

The binary has been disassembled and pre-processed. Use the provided features to:
1. Identify the binary category (crackme/malware_dropper/evasion/obfuscation/injector)
2. Describe the primary mechanism (algorithm + key details + execution flow)
3. Extract all key artifacts: crypto keys, passwords, constants, API names
4. Extract all IOCs: IP:port, embedded strings, crypto keys
5. Map MITRE ATT&CK TTPs

Produce final_report JSON with fields:
summary, category, mechanism, secret_value, key_artifacts, iocs, mitre_ttps, findings, confidence, analysis_quality.
Output raw JSON only."""


def _build_instruction(target: str) -> str:
    return INSTRUCTION_TEMPLATE.format(target=target)


def _build_input_features(target: str) -> str:
    """Load binary features from dump JSON for use as SFT input context."""
    dump_path = TRAINING / f"{target}_dump.json"
    if not dump_path.exists():
        return f"target: {target}"

    try:
        dump = json.loads(dump_path.read_text(encoding="utf-8"))
    except:
        return f"target: {target}"

    parts = []
    # Imports
    imports = dump.get("imports", [])[:30]
    if imports:
        imp_names = [f"{i.get('namespace','')}::{i.get('name','')}" for i in imports]
        parts.append(f"imports: {imp_names}")

    # Strings
    strings = dump.get("strings", [])[:20]
    if strings:
        parts.append(f"strings: {strings}")

    # XOR hits
    blobs = dump.get("data_bytes", [])
    xor_hits = [b for b in blobs if "xor_key" in b]
    if xor_hits:
        xor_info = [
            f"addr={b.get('address')} key={b.get('xor_key')} decoded={b.get('xor_decoded','')!r}"
            for b in xor_hits[:5]
        ]
        parts.append(f"xor_hits: {xor_info}")

    # Function count
    fns = dump.get("functions", [])
    user_fns = [f for f in fns if f.get("is_user")]
    parts.append(f"functions: {len(user_fns)} user-defined")

    return "\n".join(parts) if parts else f"target: {target}"


def write_sft_pairs(
    sft_pairs: list[dict],
    output_path: str,
    re_dir: str = None,   # API compat, unused
    write_dpo: bool = True,
) -> int:
    """
    Write SFT pairs to JSONL file (LLaMA-Factory alpaca format).
    Also writes DPO pairs if write_dpo=True.
    Returns number of SFT examples written.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    dpo_path = output_path.with_name(output_path.stem.replace("sft_", "dpo_") + ".jsonl")
    if "sft" not in output_path.name:
        dpo_path = output_path.with_suffix("").parent / f"dpo_{output_path.name}"

    written_sft = 0
    written_dpo = 0

    with open(output_path, "a", encoding="utf-8") as f_sft, \
         open(dpo_path, "a", encoding="utf-8") as f_dpo:

        for pair in sft_pairs:
            target = pair["target"]
            chosen  = pair["chosen"]
            rejected = pair.get("rejected", {})
            score   = pair.get("corrected_score", 0)
            delta   = pair.get("score_delta", 0)

            instruction = _build_instruction(target)
            input_ctx   = _build_input_features(target)

            # --- SFT record (alpaca format) ---
            sft_record = {
                "instruction": instruction,
                "input": input_ctx,
                "output": json.dumps(chosen, ensure_ascii=False),
                "metadata": {
                    "target": target,
                    "score_v2": score,
                    "score_delta": delta,
                    "correction_confidence": pair.get("correction_confidence", 0.7),
                    "wrong_claims": pair.get("wrong_claims", []),
                    "missing_items": pair.get("missing_items", []),
                    "timestamp": time.time(),
                    "source": "re_burn_v1",
                },
            }
            f_sft.write(json.dumps(sft_record, ensure_ascii=False) + "\n")
            written_sft += 1

            # --- DPO record (OpenAI format) ---
            if write_dpo and rejected:
                dpo_record = {
                    "instruction": instruction,
                    "input": input_ctx,
                    "chosen": json.dumps(chosen, ensure_ascii=False),
                    "rejected": json.dumps(rejected, ensure_ascii=False),
                    "chosen_score": score,
                    "rejected_score": pair.get("original_score", 0),
                    "score_delta": delta,
                    "target": target,
                    "correction_notes": pair.get("correction_notes", ""),
                    "timestamp": time.time(),
                    "source": "re_burn_v1",
                }
                f_dpo.write(json.dumps(dpo_record, ensure_ascii=False) + "\n")
                written_dpo += 1

    print(f"  [sft_writer] Written: {written_sft} SFT → {output_path.name}")
    if write_dpo:
        print(f"  [sft_writer] Written: {written_dpo} DPO → {dpo_path.name}")

    return written_sft
