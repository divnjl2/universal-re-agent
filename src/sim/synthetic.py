"""
Synthetic Binary Generator.
Generates source code with specific RE patterns (e.g. anti-debug, obfuscated strings,
simple crypto) and compiles them into binaries with ground truth data.
"""

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SyntheticTask:
    name: str
    source_code: str
    ground_truth: dict
    expected_ttp: list[str]
    binary_path: str = ""


class SyntheticBinaryGenerator:
    """Generates synthetic crackme/malware samples for agent training."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # Check if gcc is available
        self.has_gcc = self._check_compiler()

    def _check_compiler(self) -> bool:
        try:
            subprocess.run(["gcc", "--version"], capture_output=True, check=True)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            return False

    def generate_all(self) -> list[SyntheticTask]:
        """Generate all predefined synthetic tasks."""
        tasks = [
            self._gen_basic_string_check(),
            self._gen_xor_crypto(),
            self._gen_anti_debug(),
        ]
        
        compiled_tasks = []
        for task in tasks:
            # Always save source code and ground truth
            src_path = self.output_dir / f"{task.name}.c"
            src_path.write_text(task.source_code, encoding="utf-8")
            
            gt_path = self.output_dir / f"{task.name}.json"
            gt_path.write_text(json.dumps({
                "ground_truth": task.ground_truth,
                "expected_ttp": task.expected_ttp
            }, indent=2))
            
            if self.has_gcc:
                task = self._compile(task)
            
            compiled_tasks.append(task)
            
        return compiled_tasks

    def _compile(self, task: SyntheticTask) -> SyntheticTask:
        """Compile C source to executable."""
        src_path = self.output_dir / f"{task.name}.c"
        bin_path = self.output_dir / f"{task.name}.exe" if os.name == 'nt' else self.output_dir / task.name
        
        try:
            subprocess.run(["gcc", str(src_path), "-o", str(bin_path)], check=True, capture_output=True)
            task.binary_path = str(bin_path)
        except subprocess.CalledProcessError as e:
            print(f"Failed to compile {task.name}: {e.stderr.decode()}")
        
        return task

    def _gen_basic_string_check(self) -> SyntheticTask:
        src = """
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <password>\\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "AgenticRE2026") == 0) {
        printf("Access Granted!\\n");
        return 0;
    } else {
        printf("Access Denied.\\n");
        return 1;
    }
}
"""
        return SyntheticTask(
            name="basic_string_check",
            source_code=src,
            ground_truth={"password": "AgenticRE2026", "mechanism": "strcmp"},
            expected_ttp=[]
        )

    def _gen_xor_crypto(self) -> SyntheticTask:
        src = """
#include <stdio.h>
#include <string.h>

void decrypt_payload(unsigned char* data, int len) {
    unsigned char key = 0x5A;
    for(int i=0; i<len; i++) {
        data[i] ^= key;
    }
}

int main() {
    unsigned char payload[] = { 0x32, 0x3F, 0x3F, 0x2A, 0x3F, 0x31, 0x1A, 0x28, 0x35, 0x32 }; // "http://c2"
    decrypt_payload(payload, sizeof(payload));
    printf("Connecting to %s\\n", payload);
    return 0;
}
"""
        return SyntheticTask(
            name="xor_crypto",
            source_code=src,
            ground_truth={"key": "0x5A", "decrypted_string": "http://c2", "mechanism": "XOR decryption"},
            expected_ttp=["T1027 — Obfuscated Files or Information"]
        )

    def _gen_anti_debug(self) -> SyntheticTask:
        src = """
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
int check_debug() {
    return IsDebuggerPresent();
}
#else
// Linux stub
#include <unistd.h>
int check_debug() {
    return 0; 
}
#endif

int main() {
    if (check_debug()) {
        printf("Debugger detected! Exiting.\\n");
        return 1;
    }
    printf("Normal execution.\\n");
    return 0;
}
"""
        return SyntheticTask(
            name="anti_debug",
            source_code=src,
            ground_truth={"mechanism": "IsDebuggerPresent"},
            expected_ttp=["T1622 — Debugger Evasion"]
        )
