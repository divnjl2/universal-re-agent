/*
 * syscall_direct.c — RE target: direct syscall stubs + SSN obfuscation
 *
 * Real-world relevance: Malware bypasses EDR/AV hooks in ntdll.dll by invoking
 * NT system calls directly via hand-crafted stubs. The stub bytes are stored
 * as a data array, copied to RWX memory, and called through a function pointer.
 * This leaves no visible call to NtAllocateVirtualMemory in the IAT.
 *
 * Techniques demonstrated:
 *   1. SSN (System Service Number) obfuscation via XOR
 *   2. Shellcode-style stub copy to RWX VirtualAlloc region
 *   3. Type-punned function pointer call (no IAT entry for NT syscalls)
 *   4. FNV-1a hash of target process name (no plaintext "svchost.exe" string)
 *   5. Simulated injection target identification (NEVER opens any process)
 *
 * MITRE: T1055.001 — Process Injection: Dynamic-link Library Injection (context)
 *        T1106     — Native API
 *        T1622     — Debugger Evasion
 *
 * SAFE: Allocates and immediately frees 4096 bytes in OWN process only.
 *       No external process is opened, written to, or modified in any way.
 *       The "injection target" hash is computed and printed but never used.
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ── NT type definitions (subset — avoids needing DDK/WDK headers) ────────── */
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

/*
 * NtAllocateVirtualMemory signature:
 *   NTSTATUS NtAllocateVirtualMemory(
 *       HANDLE    ProcessHandle,
 *       PVOID    *BaseAddress,
 *       ULONG_PTR ZeroBits,
 *       PSIZE_T   RegionSize,
 *       ULONG     AllocationType,
 *       ULONG     Protect
 *   );
 */
typedef NTSTATUS(NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE    ProcessHandle,
    PVOID    *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

/*
 * NtFreeVirtualMemory signature:
 *   NTSTATUS NtFreeVirtualMemory(
 *       HANDLE  ProcessHandle,
 *       PVOID  *BaseAddress,
 *       PSIZE_T RegionSize,
 *       ULONG   FreeType
 *   );
 */
typedef NTSTATUS(NTAPI *NtFreeVirtualMemory_t)(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType
);

/* ── SSN obfuscation ─────────────────────────────────────────────────────── */
/*
 * System Service Numbers for Windows 10 x64 (build 19041):
 *   NtAllocateVirtualMemory = 0x0018
 *   NtFreeVirtualMemory     = 0x001E
 *
 * Stored as XOR-obfuscated constants — a static scan sees only 0x1337/0x1321,
 * not the actual SSNs. Reversal requires recognizing the XOR pattern.
 *
 * T1106: Native API — direct syscall bypasses ntdll hook layer
 */
#define SSN_ALLOC_OBFUSCATED  0x1337UL   /* 0x1337 ^ 0x132F = 0x0018 */
#define SSN_FREE_OBFUSCATED   0x1321UL   /* 0x1321 ^ 0x132F = 0x001E */
#define SSN_XOR_KEY           0x132FUL

static DWORD deobfuscate_ssn(DWORD obfuscated) {
    return obfuscated ^ SSN_XOR_KEY;
}

/* ── Syscall stub templates ───────────────────────────────────────────────── */
/*
 * x64 NT syscall calling convention:
 *   MOV EAX, <SSN>     — load system service number
 *   MOV R10, RCX       — syscall uses R10 instead of RCX for first arg
 *   SYSCALL            — transfer to kernel
 *   RET
 *
 * Byte encoding:
 *   B8 xx 00 00 00  = MOV EAX, imm32 (SSN in low byte, zeros in upper 3)
 *   4C 8B D1        = MOV R10, RCX
 *   0F 05           = SYSCALL
 *   C3              = RET
 *
 * The SSN byte at offset 1 is patched at runtime from the deobfuscated value.
 */
#define STUB_SIZE 11

/* Template with placeholder SSN byte (0x00 at offset 1 — patched at runtime) */
static const BYTE stub_template[] = {
    0xB8, 0x00, 0x00, 0x00, 0x00,  /* MOV EAX, 0x00000000  <- SSN patched at [1] */
    0x4C, 0x8B, 0xD1,               /* MOV R10, RCX                                */
    0x0F, 0x05,                     /* SYSCALL                                      */
    0xC3                            /* RET                                          */
};

/* Assembled NtAllocateVirtualMemory stub (SSN = 0x18 on Win10 19041) */
static const BYTE nt_alloc_stub_ref[] = {
    0xB8, 0x18, 0x00, 0x00, 0x00,  /* MOV EAX, 0x18 */
    0x4C, 0x8B, 0xD1,               /* MOV R10, RCX  */
    0x0F, 0x05,                     /* SYSCALL       */
    0xC3                            /* RET           */
};

/* Assembled NtFreeVirtualMemory stub (SSN = 0x1E on Win10 19041) */
static const BYTE nt_free_stub_ref[] = {
    0xB8, 0x1E, 0x00, 0x00, 0x00,  /* MOV EAX, 0x1E */
    0x4C, 0x8B, 0xD1,               /* MOV R10, RCX  */
    0x0F, 0x05,                     /* SYSCALL       */
    0xC3                            /* RET           */
};

/* ── FNV-1a hash (32-bit) ────────────────────────────────────────────────── */
/*
 * FNV-1a is the standard algorithm used by malware for API hashing.
 * Here we hash the target process name "svchost.exe" to demonstrate
 * the technique without embedding the plaintext string.
 *
 * FNV offset basis: 0x811C9DC5
 * FNV prime:        0x01000193
 *
 * fnv1a("svchost.exe") — computed at runtime, printed, but never used
 * to open any process.
 *
 * MITRE T1106: Native API — FNV hashing hides target process identity
 */
#define FNV_OFFSET_BASIS  0x811C9DC5UL
#define FNV_PRIME         0x01000193UL

static uint32_t fnv1a_hash(const char *str) {
    uint32_t hash = FNV_OFFSET_BASIS;
    while (*str) {
        hash ^= (uint8_t)(*str++);
        hash *= FNV_PRIME;
    }
    return hash;
}

/*
 * Target process name assembled on the stack — no plaintext in the binary.
 * "svchost.exe" = 11 chars + null
 * T1497.001: System Checks — process name obfuscation
 */
static void build_target_name(char *buf, int bufsize) {
    /* "svchost.exe\0" assembled char-by-char */
    if (bufsize < 12) return;
    buf[ 0] = 's'; buf[ 1] = 'v'; buf[ 2] = 'c';
    buf[ 3] = 'h'; buf[ 4] = 'o'; buf[ 5] = 's';
    buf[ 6] = 't'; buf[ 7] = '.'; buf[ 8] = 'e';
    buf[ 9] = 'x'; buf[10] = 'e'; buf[11] = '\0';
}

/* ── Build and install a syscall stub into RWX memory ───────────────────── */
/*
 * Copies the template into RWX-allocated memory, patches the SSN byte,
 * returns the executable address as a function pointer.
 */
static LPVOID alloc_rwx_stub(DWORD ssn, LPVOID *out_rwx_region) {
    /* Allocate one page of RWX memory */
    LPVOID rwx = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (!rwx) return NULL;

    /* Copy template and patch SSN at byte offset 1 */
    memcpy(rwx, stub_template, STUB_SIZE);
    ((BYTE *)rwx)[1] = (BYTE)(ssn & 0xFF);   /* Low byte of SSN */

    *out_rwx_region = rwx;
    return rwx;
}

/* ── main ─────────────────────────────────────────────────────────────────── */
int main(void) {
    printf("=== Direct Syscall Demo ===\n");

    /* Step 1: SSN deobfuscation demo */
    DWORD ssn_alloc = deobfuscate_ssn(SSN_ALLOC_OBFUSCATED);
    DWORD ssn_free  = deobfuscate_ssn(SSN_FREE_OBFUSCATED);
    printf("[ssn] NtAllocateVirtualMemory: obfuscated=0x%04X xor_key=0x%04X -> SSN=0x%04X\n",
           SSN_ALLOC_OBFUSCATED, SSN_XOR_KEY, ssn_alloc);
    printf("[ssn] NtFreeVirtualMemory:     obfuscated=0x%04X xor_key=0x%04X -> SSN=0x%04X\n",
           SSN_FREE_OBFUSCATED, SSN_XOR_KEY, ssn_free);

    /* Step 2: FNV-1a hash of target process name (identification only — no open) */
    char target_name[16] = { 0 };
    build_target_name(target_name, sizeof(target_name));
    uint32_t target_hash = fnv1a_hash(target_name);
    printf("[fnv] target process hash: 0x%08X  (fnv1a of \"%s\")\n",
           target_hash, target_name);
    printf("[fnv] NOTE: process is NOT opened — hash is identification only\n");

    /* Step 3: Show reference stub bytes */
    printf("[stub] NtAllocateVirtualMemory stub (SSN=0x%02X): ", ssn_alloc);
    for (int i = 0; i < STUB_SIZE; i++) printf("%02X ", nt_alloc_stub_ref[i]);
    printf("\n");
    printf("[stub] NtFreeVirtualMemory stub     (SSN=0x%02X): ", ssn_free);
    for (int i = 0; i < STUB_SIZE; i++) printf("%02X ", nt_free_stub_ref[i]);
    printf("\n");

    /* Step 4: Build live NtAllocateVirtualMemory stub in RWX memory */
    LPVOID rwx_alloc_region = NULL;
    LPVOID alloc_stub_ptr   = alloc_rwx_stub(ssn_alloc, &rwx_alloc_region);
    if (!alloc_stub_ptr) {
        printf("[error] VirtualAlloc for alloc stub failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[rwx] NtAllocateVirtualMemory stub installed at %p\n", alloc_stub_ptr);

    /* Step 5: Build live NtFreeVirtualMemory stub in separate RWX page */
    LPVOID rwx_free_region = NULL;
    LPVOID free_stub_ptr   = alloc_rwx_stub(ssn_free, &rwx_free_region);
    if (!free_stub_ptr) {
        printf("[error] VirtualAlloc for free stub failed: %lu\n", GetLastError());
        VirtualFree(rwx_alloc_region, 0, MEM_RELEASE);
        return 1;
    }
    printf("[rwx] NtFreeVirtualMemory stub     installed at %p\n", free_stub_ptr);

    /* Step 6: Call NtAllocateVirtualMemory via stub to allocate 4096 bytes
     *         in OWN process (GetCurrentProcess() = -1 handle) */
    NtAllocateVirtualMemory_t pNtAllocVm = (NtAllocateVirtualMemory_t)alloc_stub_ptr;

    PVOID   base_addr   = NULL;
    SIZE_T  region_size = 4096;

    printf("[alloc] Calling NtAllocateVirtualMemory in own process...\n");
    NTSTATUS status = pNtAllocVm(
        GetCurrentProcess(),    /* -1 = own process handle */
        &base_addr,             /* output: allocated address */
        0,                      /* ZeroBits */
        &region_size,           /* RegionSize (in/out) */
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        printf("[alloc] NtAllocateVirtualMemory failed: NTSTATUS=0x%08X\n", (DWORD)status);
        printf("[alloc] NOTE: SSN 0x%02X may differ on this OS build — demo continues\n", ssn_alloc);
        /* Fall back to Win32 to prove benign intent */
        base_addr   = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        region_size = 4096;
        if (base_addr) {
            printf("[alloc] Fallback VirtualAlloc succeeded: %p\n", base_addr);
        }
    } else {
        printf("[alloc] Allocated %zu bytes at %p (own process only)\n",
               region_size, base_addr);
    }

    /* Step 7: Write benign marker into the allocation */
    if (base_addr) {
        static const BYTE MARKER[] = {
            0x4E, 0x45, 0x58, 0x55, 0x53,  /* "NEXUS" */
            0x44, 0x45, 0x4D, 0x4F, 0x00   /* "DEMO\0" */
        };
        memcpy(base_addr, MARKER, sizeof(MARKER));
        printf("[alloc] Wrote NEXUS marker to allocated region.\n");
    }

    /* Step 8: Free via NtFreeVirtualMemory stub */
    if (base_addr) {
        NtFreeVirtualMemory_t pNtFreeVm = (NtFreeVirtualMemory_t)free_stub_ptr;

        SIZE_T free_size = 0;  /* 0 = free entire region when MEM_RELEASE */
        printf("[free]  Calling NtFreeVirtualMemory...\n");
        NTSTATUS free_status = pNtFreeVm(
            GetCurrentProcess(),
            &base_addr,
            &free_size,
            MEM_RELEASE
        );

        if (!NT_SUCCESS(free_status)) {
            printf("[free]  NtFreeVirtualMemory failed: 0x%08X — using VirtualFree\n",
                   (DWORD)free_status);
            VirtualFree(base_addr, 0, MEM_RELEASE);
        } else {
            printf("[free]  Memory freed successfully via direct syscall.\n");
        }
    }

    /* Step 9: Release RWX stub regions */
    VirtualFree(rwx_alloc_region, 0, MEM_RELEASE);
    VirtualFree(rwx_free_region,  0, MEM_RELEASE);
    printf("[rwx]  Stub regions released.\n");

    printf("[main] Done. Simulated injection target hash: 0x%08X (never used)\n",
           target_hash);
    return 0;
}
