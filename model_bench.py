#!/usr/bin/env python3
"""
Model Capability Mapping for Reverse Engineering Tasks

Phase 1: Micro-benchmarks testing 7 RE task types across 4-5 models
Phase 2: Correlation analysis with full binary benchmark

Invocation:
  python model_bench.py --phase micro [--output FILE]
  python model_bench.py --phase full --targets api_hash rc4_config vm_dispatch
  python model_bench.py --phase correlate --micro FILE --full FILE
"""

import json
import subprocess
import os
import tempfile
import sys
import io
from pathlib import Path
from typing import Tuple, Dict, Any, List
import argparse
import re
from datetime import datetime

# UTF-8 output fix for Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

BASE = Path(__file__).parent
LITELLM = "http://192.168.1.136:4000/v1/chat/completions"
API_KEY = "sk-nexus-litellm-2026"
TRAINING = BASE / "data" / "training"

# Models to test (ordered by preference)
MODELS = ["ag-gemini-flash", "coder-30b", "reasoning-14b", "cloud-sonnet", "worker-4b"]

# ============================================================================
# curl_llm: Direct LiteLLM inference (from do_re.py)
# ============================================================================

def curl_llm(model: str, system: str, user: str, max_tokens: int = 3000) -> Tuple[str, Dict]:
    """
    Call LiteLLM via curl (bypasses Windows proxy CIDR issues).

    Args:
        model: Model name (e.g., "coder-30b", "ag-gemini-flash")
        system: System prompt
        user: User message
        max_tokens: Max output tokens

    Returns:
        Tuple of (response_text, usage_dict)

    Raises:
        RuntimeError: On curl error or LiteLLM error
    """
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.1,
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tf:
        json.dump(payload, tf, ensure_ascii=False)
        tf_path = tf.name

    try:
        r = subprocess.run(
            [
                "curl", "-s", "-X", "POST", LITELLM,
                "-H", f"Authorization: Bearer {API_KEY}",
                "-H", "Content-Type: application/json",
                "--data-binary", f"@{tf_path}",
                "--max-time", "120",
            ],
            capture_output=True,
            text=True,
            timeout=130,
        )
    finally:
        os.unlink(tf_path)

    if r.returncode != 0:
        raise RuntimeError(f"curl rc={r.returncode}: {r.stderr[:200]}")

    data = json.loads(r.stdout)
    if "error" in data:
        raise RuntimeError(str(data["error"])[:200])

    return data["choices"][0]["message"]["content"].strip(), data.get("usage", {})


# ============================================================================
# Phase 1: Micro-Benchmark Tests
# ============================================================================

class MicroBenchmark:
    """Micro-benchmark for 7 RE task types."""

    SYSTEM_PROMPT = """You are an expert reverse engineer and cryptography analyst.
Answer questions directly with minimal explanation. Output only the essential information."""

    def __init__(self):
        self.results = {}

    def test_crypto_identification(self, model: str) -> Dict[str, Any]:
        """Task 2: Identify RC4 from pseudocode."""
        user_prompt = """
Analyze this pseudocode and identify the cryptographic algorithm:

for (int i = 0; i < 256; i++) S[i] = i;
int j = 0;
for (int i = 0; i < 256; i++) {
    j = (j + S[i] + key[i % keylen]) & 0xFF;
    uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
}
for (int n = 0; n < len; n++) {
    i = (i + 1) & 0xFF;
    j = (j + S[i]) & 0xFF;
    uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
    data[n] ^= S[(S[i] + S[j]) & 0xFF];
}

What cipher is this? Answer with cipher name only.
"""

        try:
            answer, usage = curl_llm(model, self.SYSTEM_PROMPT, user_prompt, max_tokens=100)

            # Check if answer contains RC4
            passed = "rc4" in answer.lower() or "arc4" in answer.lower() or "arcfour" in answer.lower()

            return {
                "test": "crypto_identification",
                "model": model,
                "passed": passed,
                "score": 100 if passed else 0,
                "answer": answer,
                "tokens_in": usage.get("prompt_tokens", 0),
                "tokens_out": usage.get("completion_tokens", 0),
            }
        except Exception as e:
            return {
                "test": "crypto_identification",
                "model": model,
                "passed": False,
                "score": 0,
                "error": str(e)[:100],
            }

    def test_data_decoding(self, model: str) -> Dict[str, Any]:
        """Task 3: Decrypt RC4-encrypted data."""
        user_prompt = """
Given:
- RC4 key: "NexusKey2026"
- Ciphertext (hex): 355B75E0CA952 4E2FB3CBD0ABA02BB053A4D51F9B836CF601F000000000000
                     5C17 38BA70FC7B1400000000000000000000000000000000000000000070 75
                     9ED2A7010EA3736B4A38F64A1819F3A4EDDDC5C9CE050F6CC405B DAD1000000000000000

Decrypt the first 32 bytes. What do the plaintext bytes contain?
Provide the decrypted content (IP address, strings, or hex values).
"""

        try:
            answer, usage = curl_llm(model, self.SYSTEM_PROMPT, user_prompt, max_tokens=200)

            # Check if answer contains relevant config strings
            relevant_strings = ["192.168", "nexus", "nrat", "config"]
            found_relevant = any(s in answer.lower() for s in relevant_strings)

            # Also check for exact plaintext
            correct = "192.168" in answer or "nerat" in answer.lower() or "nexusrat" in answer.lower()

            score = 100 if correct else (50 if found_relevant else 0)

            return {
                "test": "data_decoding",
                "model": model,
                "passed": score >= 50,
                "score": score,
                "answer": answer[:150],
                "tokens_in": usage.get("prompt_tokens", 0),
                "tokens_out": usage.get("completion_tokens", 0),
            }
        except Exception as e:
            return {
                "test": "data_decoding",
                "model": model,
                "passed": False,
                "score": 0,
                "error": str(e)[:100],
            }

    def test_hash_resolution(self, model: str) -> Dict[str, Any]:
        """Task 5: Identify Win32 API from hash constant."""
        user_prompt = """
A malware sample uses FNV-1a hash-based API resolution.
Found hash constant: 0x97BC257B
The code pattern shows: load kernel32.dll → iterate exports → compute FNV-1a hash → match against this constant.

Known FNV-1a hashes in kernel32.dll:
- VirtualAlloc: 0x97BC257B
- CreateRemoteThread: 0x481C6ABC
- WriteProcessMemory: 0xA4C5F2DE
- VirtualAllocEx: 0x12AB78FF

What Win32 API function does 0x97BC257B resolve to?
Answer with the exact function name.
"""

        try:
            answer, usage = curl_llm(model, self.SYSTEM_PROMPT, user_prompt, max_tokens=100)

            # Check if answer contains VirtualAlloc (either variant)
            correct = "virtualalloc" in answer.lower()

            return {
                "test": "hash_resolution",
                "model": model,
                "passed": correct,
                "score": 100 if correct else 0,
                "answer": answer,
                "tokens_in": usage.get("prompt_tokens", 0),
                "tokens_out": usage.get("completion_tokens", 0),
            }
        except Exception as e:
            return {
                "test": "hash_resolution",
                "model": model,
                "passed": False,
                "score": 0,
                "error": str(e)[:100],
            }

    def test_vm_trace(self, model: str) -> Dict[str, Any]:
        """Task 4: Trace custom VM bytecode execution."""
        user_prompt = """
VM opcode definitions:
  OP_PUSH=0x01, OP_POP=0x02, OP_ADD=0x03, OP_XOR=0x04
  OP_MOV=0x05, OP_MUL=0x06, OP_OUT=0x07, OP_HALT=0xFF

Bytecode (hex):
  05 00 41        # MOV r0, 0x41
  05 01 10        # MOV r1, 0x10
  04 00 AA        # XOR r0, 0xAA
  02 02           # POP r2
  06 01 03        # MUL r1, 0x03
  02 03           # POP r3
  03 02 03        # ADD r2, r3
  02 00           # POP r0
  07 00           # OUT r0
  FF              # HALT

Initial state: r[0-7] = 0, stack = empty, sp = -1

Trace execution step-by-step. What is the final output value (the result)?
Answer with a single hex value like 0x1B or 0x27.
"""

        try:
            answer, usage = curl_llm(model, self.SYSTEM_PROMPT, user_prompt, max_tokens=500)

            # Correct answer is 0x1B or 27 (decimal)
            # (0x41 ^ 0xAA) = 0xEB, (0x10 * 0x03) = 0x30, 0xEB + 0x30 = 0x11B = 0x1B (byte)
            correct = "0x1b" in answer.lower() or "0x1B" in answer or "27" in answer

            return {
                "test": "vm_trace",
                "model": model,
                "passed": correct,
                "score": 100 if correct else 0,
                "answer": answer[:200],
                "tokens_in": usage.get("prompt_tokens", 0),
                "tokens_out": usage.get("completion_tokens", 0),
            }
        except Exception as e:
            return {
                "test": "vm_trace",
                "model": model,
                "passed": False,
                "score": 0,
                "error": str(e)[:100],
            }

    def test_ioc_extraction(self, model: str) -> Dict[str, Any]:
        """Task 6: Extract indicators of compromise."""
        user_prompt = """
Analysis of a malware binary revealed:

RC4-decrypted configuration structure:
  c2_host: 192.168.99.1 (32-byte string field)
  c2_port: 4444 (uint16_t)
  sleep_ms: 30000 (uint32_t beacon interval)
  mutex_name: Global\\NexusRAT (32-byte string)

Additional findings:
  - Injection target: notepad.exe
  - HTTP User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
  - Embedded string constant: "CmdExec_2026_v1"

Extract all IOCs (indicators of compromise). For each, provide:
  - Type (IP_ADDRESS, PORT, MUTEX, PROCESS, USER_AGENT, STRING, etc.)
  - Value
  - Confidence (HIGH, MEDIUM, LOW)

List each IOC.
"""

        try:
            answer, usage = curl_llm(model, self.SYSTEM_PROMPT, user_prompt, max_tokens=300)

            # Count how many IOCs were correctly identified
            expected_iocs = ["192.168.99.1", "4444", "NexusRAT", "notepad.exe", "CmdExec_2026_v1"]
            found_count = sum(1 for ioc in expected_iocs if ioc in answer)

            # Scoring: >=4/5 = 100, >=3/5 = 75, >=2/5 = 50, <2/5 = 0
            if found_count >= 4:
                score = 100
            elif found_count >= 3:
                score = 75
            elif found_count >= 2:
                score = 50
            else:
                score = 0

            return {
                "test": "ioc_extraction",
                "model": model,
                "passed": found_count >= 3,
                "score": score,
                "found_count": found_count,
                "answer": answer[:200],
                "tokens_in": usage.get("prompt_tokens", 0),
                "tokens_out": usage.get("completion_tokens", 0),
            }
        except Exception as e:
            return {
                "test": "ioc_extraction",
                "model": model,
                "passed": False,
                "score": 0,
                "found_count": 0,
                "error": str(e)[:100],
            }

    def run_all_tests(self, models: List[str]) -> Dict[str, Any]:
        """Run all 5 micro-tests against all models."""
        tests = [
            self.test_crypto_identification,
            self.test_data_decoding,
            self.test_hash_resolution,
            self.test_vm_trace,
            self.test_ioc_extraction,
        ]

        all_results = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "phase": "micro",
            "models": models,
            "tests": {},
            "summary": {},
        }

        for test_func in tests:
            test_name = test_func.__name__.replace("test_", "")
            print(f"\nTest: {test_name}")
            all_results["tests"][test_name] = {}

            for model in models:
                print(f"  [{model}]", end=" ", flush=True)
                result = test_func(model)
                all_results["tests"][test_name][model] = result

                if result.get("passed"):
                    print(f"✓ {result.get('score', 0)}/100")
                else:
                    print(f"✗ {result.get('score', 0)}/100 {result.get('error', '')[:50]}")

        # Compute summary statistics
        for model in models:
            scores = []
            for test_name, test_results in all_results["tests"].items():
                if model in test_results:
                    scores.append(test_results[model].get("score", 0))

            if scores:
                all_results["summary"][model] = {
                    "avg_score": round(sum(scores) / len(scores), 1),
                    "pass_rate": round(sum(1 for s in scores if s >= 50) / len(scores), 2),
                    "total_tests": len(scores),
                }

        return all_results


# ============================================================================
# Phase 2: Full Binary Analysis (Uses existing do_re.py)
# ============================================================================

def run_full_benchmark(targets: List[str]):
    """Run full binary analysis (delegates to do_re.py)."""
    import subprocess

    cmd = ["python", str(BASE / "do_re.py"), "--targets"] + targets
    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, cwd=str(BASE))


# ============================================================================
# Phase 3: Correlation Analysis
# ============================================================================

def correlate_results(micro_file: Path, full_file: Path):
    """Analyze correlation between micro-tests and full binary results."""

    print("Phase 3: Correlation Analysis")
    print("=" * 60)

    with open(micro_file) as f:
        micro = json.load(f)

    with open(full_file) as f:
        full = json.load(f)

    # Create task type mapping
    task_mapping = {
        "basic_string_check": "pattern_recognition",
        "xor_crypto": "crypto_identification",
        "anti_debug": "pattern_recognition",
        "api_hash": "api_resolution",
        "rc4_config": "data_decoding",
        "evasion_combo": "pattern_recognition",
        "vm_dispatch": "vm_trace",
        "injector_stub": "pattern_recognition",
    }

    # Build per-task summary
    task_scores = {}
    for result in full:
        target = result.get("target")
        task_type = task_mapping.get(target, "unknown")
        score = result.get("score", 0)

        if task_type not in task_scores:
            task_scores[task_type] = []
        task_scores[task_type].append(score)

    print("\nFull Binary Results by Task Type:")
    print("-" * 60)
    for task_type, scores in sorted(task_scores.items()):
        avg = sum(scores) / len(scores) if scores else 0
        print(f"{task_type:25s}: {avg:5.1f}% (n={len(scores)})")

    print("\nMicro-Test Results by Task Type:")
    print("-" * 60)
    for test_name in micro.get("tests", {}):
        print(f"{test_name:25s}:")
        for model, result in micro["tests"][test_name].items():
            score = result.get("score", 0)
            print(f"  {model:20s}: {score:3d}/100")

    print("\nSummary by Model:")
    print("-" * 60)
    print(f"{'Model':<20} {'Micro Avg':<12} {'Full Avg':<12} {'Correlation':<12}")
    print("-" * 60)
    for model in micro.get("summary", {}):
        micro_avg = micro["summary"][model].get("avg_score", 0)

        # Try to extract full binary avg for this model
        full_avg = "N/A"
        full_avg_num = None
        for result in full:
            if result.get("model") == model:
                score = result.get("score", 0)
                if full_avg_num is None:
                    full_avg_num = []
                full_avg_num.append(score)

        if full_avg_num:
            full_avg = f"{sum(full_avg_num) / len(full_avg_num):.1f}%"

        corr = "N/A"
        if isinstance(full_avg, str) and "%" in full_avg:
            full_avg_val = float(full_avg.rstrip("%"))
            if full_avg_val >= micro_avg:
                corr = "pos"
            else:
                corr = "neg"

        print(f"{model:<20} {micro_avg:>8.1f}% {full_avg:>10} {corr:>10}")


# ============================================================================
# Main CLI
# ============================================================================

def main():
    ap = argparse.ArgumentParser(
        description="Model Capability Mapping for RE Tasks"
    )
    ap.add_argument(
        "--phase",
        choices=["micro", "full", "correlate"],
        default="micro",
        help="Benchmark phase to run",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=BASE / "results" / "model_micro_results.json",
        help="Output file for micro-benchmark results",
    )
    ap.add_argument(
        "--targets",
        nargs="+",
        help="Targets for full benchmark phase",
    )
    ap.add_argument(
        "--micro",
        type=Path,
        help="Micro-benchmark results file for correlation",
    )
    ap.add_argument(
        "--full",
        type=Path,
        help="Full benchmark results file for correlation",
    )
    ap.add_argument(
        "--models",
        nargs="+",
        default=MODELS,
        help="Models to benchmark",
    )

    args = ap.parse_args()

    if args.phase == "micro":
        print("Phase 1: Micro-Benchmark Tests")
        print("=" * 60)
        print(f"Models: {', '.join(args.models)}")
        print()

        bench = MicroBenchmark()
        results = bench.run_all_tests(args.models)

        # Ensure output directory exists
        args.output.parent.mkdir(parents=True, exist_ok=True)

        # Save results
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\nSaved: {args.output}")

        # Print summary
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        for model, summary in results.get("summary", {}).items():
            print(f"{model:20s}: {summary['avg_score']:5.1f}% avg, "
                  f"{summary['pass_rate']:.0%} pass rate")

    elif args.phase == "full":
        if not args.targets:
            print("Error: --targets required for full phase")
            sys.exit(1)
        run_full_benchmark(args.targets)

    elif args.phase == "correlate":
        if not args.micro or not args.full:
            print("Error: --micro and --full required for correlate phase")
            sys.exit(1)
        correlate_results(args.micro, args.full)


if __name__ == "__main__":
    main()
