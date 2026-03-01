/*
 * tls_callback_trick.c — RE target: TLS callbacks with anti-debug and decryption
 *
 * Real-world relevance: Malware frequently uses TLS callbacks for early-stage
 * execution before main() is ever reached, making static analysis of main()
 * misleading. The actual interesting logic is entirely hidden in the callbacks.
 *
 * TLS Callback 0: Anti-debug checks (IsDebuggerPresent + NtGlobalFlag)
 * TLS Callback 1: XOR-decrypts a "config" string from .data section
 * TLS Callback 2: CRC32 integrity check on a fixed string (demo mismatch pattern)
 * main(): completely innocent — reads the buffer set by callbacks and prints it
 *
 * MITRE: T1055.012 — Process Injection: Process Hollowing (technique context)
 *        T1622     — Debugger Evasion
 *        T1497.001 — Virtualization/Sandbox Evasion: System Checks
 *
 * SAFE: "payload" is a benign config string. No external connections made.
 *       All decryption produces only the string "c2=10.20.30.40:9000;sleep=5000;id=TLS-DEMO-2026"
 */
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ── Forward declarations ─────────────────────────────────────────────────── */
void NTAPI tls_callback_0(PVOID hModule, DWORD dwReason, PVOID pContext);
void NTAPI tls_callback_1(PVOID hModule, DWORD dwReason, PVOID pContext);
void NTAPI tls_callback_2(PVOID hModule, DWORD dwReason, PVOID pContext);

/* ── TLS callback registration (MSVC x64) ────────────────────────────────── */
/*
 * The linker pragma /INCLUDE:_tls_used forces the TLS directory into the PE.
 * Each callback is placed in a named .CRT$XL? section — the loader collects
 * all pointers between .CRT$XLA and .CRT$XLZ and calls them in order.
 */
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:__tls_callback_0")
#pragma comment(linker, "/INCLUDE:__tls_callback_1")
#pragma comment(linker, "/INCLUDE:__tls_callback_2")

#pragma const_seg(".CRT$XLA")
extern const PIMAGE_TLS_CALLBACK __tls_callback_0 = tls_callback_0;
#pragma const_seg()

#pragma const_seg(".CRT$XLB")
extern const PIMAGE_TLS_CALLBACK __tls_callback_1 = tls_callback_1;
#pragma const_seg()

#pragma const_seg(".CRT$XLC")
extern const PIMAGE_TLS_CALLBACK __tls_callback_2 = tls_callback_2;
#pragma const_seg()

/* ── Encrypted payload in .data ───────────────────────────────────────────── */
/*
 * Plaintext:  "c2=10.20.30.40:9000;sleep=5000;id=TLS-DEMO-2026"
 * Key (8 bytes, cyclic): { 0x4E, 0x45, 0x58, 0x55, 0x53, 0x32, 0x30, 0x32 }
 *   i.e. "NEXUS202"
 * Encrypted[i] = plaintext[i] ^ key[i % 8]
 *
 * Python to regenerate:
 *   plain = b"c2=10.20.30.40:9000;sleep=5000;id=TLS-DEMO-2026"
 *   key   = [0x4E,0x45,0x58,0x55,0x53,0x32,0x30,0x32]
 *   enc   = [p ^ key[i%8] for i,p in enumerate(plain)]
 */
static unsigned char g_encrypted_config[] = {
    0x2D, 0x27, 0x75, 0x64, 0x7F, 0x02, 0x5F, 0x5F,  /* c2=10.20 */
    0x24, 0x25, 0x1B, 0x61, 0x7E, 0x07, 0x5E, 0x02,  /* .30.40:9 */
    0x5E, 0x73, 0x5B, 0x36, 0x21, 0x27, 0x6B, 0x77,  /* 000;slee */
    0x1F, 0x17, 0x18, 0x02, 0x02, 0x57, 0x02, 0x06,  /* p=5000;i */
    0x1A, 0x29, 0x68, 0x35, 0x1E, 0x57, 0x5E, 0x07,  /* d=TLS-DE */
    0x7D, 0x33, 0x1B, 0x75, 0x7E, 0x00, 0x5E, 0x00   /* MO-2026  */
};
#define CONFIG_LEN (sizeof(g_encrypted_config))

/* Decrypted buffer — filled by TLS callback 1 before main() runs */
static char g_config_plaintext[64] = { 0 };

/* Anti-debug result written by TLS callback 0 */
static volatile int g_analysis_env = 0;

/* CRC32 check result from TLS callback 2 */
static volatile int g_integrity_ok = 0;

/* ── XOR key ─────────────────────────────────────────────────────────────── */
static const unsigned char XOR_KEY[8] = {
    0x4E, 0x45, 0x58, 0x55, 0x53, 0x32, 0x30, 0x32   /* "NEXUS202" */
};

/* ── CRC32 table (standard polynomial 0xEDB88320) ────────────────────────── */
static uint32_t crc32_table[256];
static int      crc32_table_ready = 0;

static void crc32_init(void) {
    if (crc32_table_ready) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            if (c & 1) c = 0xEDB88320UL ^ (c >> 1);
            else        c >>= 1;
        }
        crc32_table[i] = c;
    }
    crc32_table_ready = 1;
}

static uint32_t crc32_compute(const unsigned char *data, size_t len) {
    crc32_init();
    uint32_t crc = 0xFFFFFFFFUL;
    for (size_t i = 0; i < len; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFUL;
}

/* ── TLS Callback 0: Anti-debug (T1622) ──────────────────────────────────── */
/*
 * Checks two independent debugger presence indicators:
 *   1. Win32 API IsDebuggerPresent()  — reads PEB.BeingDebugged (offset 0x02)
 *   2. PEB.NtGlobalFlag (x64 offset 0xBC) — set to 0x70 by debugger:
 *        FLG_HEAP_ENABLE_TAIL_CHECK   (0x10)
 *        FLG_HEAP_ENABLE_FREE_CHECK   (0x20)
 *        FLG_HEAP_VALIDATE_PARAMETERS (0x40)
 *
 * MITRE T1622: Debugger Evasion
 */
void NTAPI tls_callback_0(PVOID hModule, DWORD dwReason, PVOID pContext) {
    (void)hModule; (void)pContext;

    if (dwReason != DLL_PROCESS_ATTACH) return;

    /* Check 1: standard BeingDebugged flag */
    if (IsDebuggerPresent()) {
        g_analysis_env |= 0x01;
    }

    /* Check 2: NtGlobalFlag via direct PEB read (x64 GS-segment walk)
     * PEB address = __readgsqword(0x60) [GS:0x60 on x64]
     * NtGlobalFlag lives at PEB+0xBC
     * T1497.001: System Checks — PEB inspection
     */
#ifdef _WIN64
    {
        BYTE  *peb            = (BYTE *)__readgsqword(0x60);
        ULONG  nt_global_flag = *(ULONG *)(peb + 0xBC);
        /* Debugger sets bits 0x70: tail/free/validate heap flags */
        if ((nt_global_flag & 0x70) != 0) {
            g_analysis_env |= 0x02;
        }
    }
#endif

    printf("[TLS-0] Anti-debug check: env_flags=0x%02X  %s\n",
           g_analysis_env,
           (g_analysis_env ? "ANALYSIS ENVIRONMENT DETECTED" : "clean"));
}

/* ── TLS Callback 1: XOR decrypt config (T1055.012 concept) ─────────────── */
/*
 * Decrypts g_encrypted_config in-place-equivalent into g_config_plaintext.
 * Key: "NEXUS202" cyclic XOR.
 * Simulates a stage-0 stub that decrypts its second-stage config before
 * the PE loader hands control to main().
 *
 * MITRE T1055.012: Process Hollowing — technique context (decryption of config
 * is analogous to the stage that reconstructs a hollowed image).
 */
void NTAPI tls_callback_1(PVOID hModule, DWORD dwReason, PVOID pContext) {
    (void)hModule; (void)pContext;

    if (dwReason != DLL_PROCESS_ATTACH) return;

    size_t len = CONFIG_LEN < sizeof(g_config_plaintext) - 1
                 ? CONFIG_LEN
                 : sizeof(g_config_plaintext) - 1;

    for (size_t i = 0; i < len; i++) {
        g_config_plaintext[i] = (char)(g_encrypted_config[i] ^ XOR_KEY[i % 8]);
    }
    g_config_plaintext[len] = '\0';

    printf("[TLS-1] Config decrypted (%zu bytes): %s\n", len, g_config_plaintext);
}

/* ── TLS Callback 2: CRC32 integrity check ───────────────────────────────── */
/*
 * Computes CRC32("NEXUS2026") and compares against a hardcoded constant.
 * In real malware this pattern verifies that the binary has not been patched.
 * Here the expected hash is intentionally wrong (0x12345678) — the mismatch
 * is part of the training pattern for the RE agent to recognize.
 *
 * Actual CRC32("NEXUS2026") ≈ 0x3B8CB3B4  (varies by polynomial — demo only).
 */
#define INTEGRITY_STRING     "NEXUS2026"
#define INTEGRITY_EXPECTED   0x12345678UL   /* intentionally wrong — demo mismatch */

void NTAPI tls_callback_2(PVOID hModule, DWORD dwReason, PVOID pContext) {
    (void)hModule; (void)pContext;

    if (dwReason != DLL_PROCESS_ATTACH) return;

    const unsigned char *data = (const unsigned char *)INTEGRITY_STRING;
    size_t               len  = strlen(INTEGRITY_STRING);
    uint32_t             crc  = crc32_compute(data, len);

    g_integrity_ok = (crc == INTEGRITY_EXPECTED) ? 1 : 0;

    printf("[TLS-2] CRC32(\"%s\") = 0x%08X  expected=0x%08X  match=%s\n",
           INTEGRITY_STRING, crc, INTEGRITY_EXPECTED,
           g_integrity_ok ? "YES" : "NO (demo mismatch — expected)");
}

/* ── main(): decoy — looks completely innocent ───────────────────────────── */
/*
 * By the time execution reaches main(), all three TLS callbacks have already
 * run. The config buffer is populated, anti-debug check is done, CRC verified.
 * main() merely reads the results and prints them — a classic decoy pattern
 * designed to mislead analysts who skip straight to main() in IDA/Ghidra.
 */
int main(void) {
    printf("=== TLS Callback Trick Demo ===\n");

    /* Read config that was "magically" populated (actually by TLS-1) */
    if (g_config_plaintext[0] != '\0') {
        printf("[main] Config loaded: %s\n", g_config_plaintext);
    } else {
        printf("[main] Config not available.\n");
    }

    /* Print anti-debug status (set by TLS-0) */
    if (g_analysis_env) {
        printf("[main] Warning: analysis environment flags = 0x%02X\n", g_analysis_env);
    } else {
        printf("[main] Environment clean.\n");
    }

    /* Print integrity status (set by TLS-2) */
    printf("[main] Integrity check: %s\n",
           g_integrity_ok ? "passed" : "failed (expected in demo)");

    printf("[main] Done.\n");
    return 0;
}
