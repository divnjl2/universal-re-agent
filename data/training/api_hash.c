/*
 * api_hash.c — RE target: dynamic API resolution via FNV-1a hash
 *
 * Real-world relevance: shellcode and packers walk the export table
 * and match function names by hash to avoid explicit import table entries.
 * Static analysis sees no useful imports; dynamic trace exposes the calls.
 *
 * Technique: PEB->Ldr walk + FNV-1a 32-bit hash matching
 */
#include <windows.h>
#include <stdio.h>

#define FNV_PRIME  0x01000193
#define FNV_BASIS  0x811C9DC5

/* Pre-computed FNV-1a hashes of target API names:
 *   "VirtualAlloc"    -> 0x97BC257B
 *   "GetSystemInfo"   -> 0x4A70F71C
 *   "GetTickCount"    -> 0x4A738CFF
 *   "ExitProcess"     -> 0xCA2D3EB1
 */
#define HASH_VIRTUALALLOC   0x97BC257B
#define HASH_GETSYSTEMINFO  0x4A70F71C
#define HASH_GETTICKCOUNT   0x4A738CFF
#define HASH_EXITPROCESS    0xCA2D3EB1

typedef LPVOID (WINAPI *fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef VOID   (WINAPI *fnGetSystemInfo)(LPSYSTEM_INFO);
typedef DWORD  (WINAPI *fnGetTickCount)(VOID);
typedef VOID   (WINAPI *fnExitProcess)(UINT);

static DWORD fnv1a(const char *s) {
    DWORD h = FNV_BASIS;
    while (*s) { h ^= (unsigned char)*s++; h *= FNV_PRIME; }
    return h;
}

/* Walk kernel32 export directory and match by hash */
static FARPROC resolve(HMODULE mod, DWORD target) {
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);

    DWORD *names  = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ords   = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs  = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if (fnv1a(name) == target)
            return (FARPROC)(base + funcs[ords[i]]);
    }
    return NULL;
}

int main(void) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");

    fnVirtualAlloc   pVA  = (fnVirtualAlloc)  resolve(k32, HASH_VIRTUALALLOC);
    fnGetSystemInfo  pGSI = (fnGetSystemInfo) resolve(k32, HASH_GETSYSTEMINFO);
    fnGetTickCount   pGTC = (fnGetTickCount)  resolve(k32, HASH_GETTICKCOUNT);

    if (!pVA || !pGSI || !pGTC) {
        printf("hash resolution failed\n");
        return 1;
    }

    SYSTEM_INFO si;
    pGSI(&si);
    DWORD tick = pGTC();

    /* Allocate a buffer and stamp it with system info */
    BYTE *buf = (BYTE *)pVA(NULL, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buf) {
        buf[0] = (BYTE)(si.dwNumberOfProcessors);
        buf[1] = (BYTE)(tick & 0xFF);
        buf[2] = 0xDE; buf[3] = 0xAD;  /* marker */
        VirtualFree(buf, 0, MEM_RELEASE);
    }

    printf("processors=%u  tick=%u  resolved=%d/%d\n",
           si.dwNumberOfProcessors, tick,
           (pVA ? 1 : 0) + (pGSI ? 1 : 0) + (pGTC ? 1 : 0), 3);
    return 0;
}
