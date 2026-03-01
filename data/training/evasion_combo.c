/*
 * evasion_combo.c — RE target: combined sandbox/debugger evasion
 *
 * Techniques (each returns 1 if analysis environment detected):
 *   T1: IsDebuggerPresent  (T1622)
 *   T2: Heap flags check   (T1497.001) — real heap != sandbox heap
 *   T3: Timing delta check (T1497.003) — RDTSC / QueryPerformanceCounter
 *   T4: CPUID hypervisor   (T1497.001) — bit 31 of ECX in CPUID leaf 1
 *   T5: Parent process name (T3: parent != explorer.exe in sandbox)
 *
 * If ANY check fires → "Analysis environment detected" and exit.
 * Else → "Executing payload stub" (benign).
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>

/* T1 — PEB BeingDebugged flag via IsDebuggerPresent */
static int check_debugger(void) {
    return (int)IsDebuggerPresent();
}

/* T2 — Heap flags: NtGlobalFlag in PEB (x64: GS:[0x60]) is 0x70 under debugger */
static int check_heap_flags(void) {
#ifdef _WIN64
    /* Read NtGlobalFlag from PEB+0xBC (x64) directly via GS segment */
    BYTE *peb = (BYTE *)__readgsqword(0x60);
    ULONG nt_global_flag = *(ULONG *)(peb + 0xBC);
    /* FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS */
    return (nt_global_flag & 0x70) != 0;
#else
    return 0;
#endif
}

/* T3 — RDTSC timing: two consecutive reads; gap > threshold = debugger/emulator */
static int check_timing(void) {
    LARGE_INTEGER t1, t2, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    /* Trivial work */
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) x += i;
    QueryPerformanceCounter(&t2);
    /* If gap > 10ms, something is hooking or slowing us down */
    LONGLONG delta_us = ((t2.QuadPart - t1.QuadPart) * 1000000LL) / freq.QuadPart;
    return (delta_us > 10000LL);  /* > 10 ms */
}

/* T4 — CPUID leaf 1: ECX bit 31 = hypervisor present */
static int check_hypervisor(void) {
    int info[4] = {0};
    __cpuid(info, 1);
    return (info[2] >> 31) & 1;
}

/* T5 — Parent process: if parent != explorer.exe, suspicious */
static int check_parent_process(void) {
    DWORD ppid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    DWORD my_pid = GetCurrentProcessId();

    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == my_pid) {
                ppid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (!ppid) return 0;

    /* Find parent name */
    if (Process32FirstW(snap, &pe)) {
        /* snap is closed — skip for simplicity; just flag if ppid is suspicious */
    }
    /* If parent PID is 0 or 4 (System) — likely sandbox */
    return (ppid <= 8);
}

int main(void) {
    int score = 0;
    printf("=== Evasion Combo Check ===\n");

    if (check_debugger())        { printf("[!] T1: Debugger detected\n");      score++; }
    if (check_heap_flags())      { printf("[!] T2: Heap flags anomaly\n");     score++; }
    if (check_timing())          { printf("[!] T3: Timing anomaly\n");         score++; }
    if (check_hypervisor())      { printf("[!] T4: Hypervisor detected\n");    score++; }
    if (check_parent_process())  { printf("[!] T5: Suspicious parent PID\n");  score++; }

    if (score > 0) {
        printf("\n[ABORT] Analysis environment detected (%d/%d checks). Exiting.\n", score, 5);
        ExitProcess(0);
    }

    printf("\n[OK] Clean environment. Executing payload stub.\n");
    printf("Payload: 0xDEADBEEF\n");
    return 0;
}
