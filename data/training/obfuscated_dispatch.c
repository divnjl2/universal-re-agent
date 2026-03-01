/*
 * obfuscated_dispatch.c — RE target: encrypted function pointer table
 *                         + stack-assembled strings + indirect calls
 *
 * Real-world relevance: Malware hides its action dispatch table by XOR-encoding
 * all function pointers. Command strings never appear in the string table — they
 * are assembled character-by-character on the stack at runtime. Both techniques
 * defeat naive static string search and IAT-based detection.
 *
 * Structure:
 *   - 8 benign action functions (do_beacon … do_noop) that only printf their name
 *   - enc_table[i] = ((uintptr_t)real_func ^ 0xCAFEF00D) ^ (uintptr_t)i
 *   - Decryption on dispatch: func = (enc_table[i] ^ 0xCAFEF00D) ^ (uintptr_t)i
 *   - All command strings assembled char-by-char on the stack
 *   - Opaque predicates (dead branches that static analysis must evaluate)
 *   - main() calls dispatch(0), dispatch(7), dispatch(3), dispatch(1)
 *
 * MITRE: T1027.009 — Obfuscated Files or Info: Embedded Payloads
 *        T1055     — Process Injection (concept only — no actual injection)
 *
 * SAFE: All action functions merely printf a description. Nothing is executed.
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ── XOR encryption constant for the function pointer table ─────────────── */
#define FP_XOR_MASK  ((uintptr_t)0xCAFEF00DUL)

/* ── Action function type ─────────────────────────────────────────────────── */
typedef void (*action_fn)(void);

/* ── Encrypted table (filled at runtime in init_table) ───────────────────── */
static uintptr_t enc_table[8];

/* ── Action functions — completely benign ────────────────────────────────── */

/* Index 0 */
static void do_beacon(void) {
    /* Stack-assembled string: "beacon" */
    char cmd[8];
    cmd[0] = 'b'; cmd[1] = 'e'; cmd[2] = 'a';
    cmd[3] = 'c'; cmd[4] = 'o'; cmd[5] = 'n'; cmd[6] = '\0';
    printf("[ACTION] %s: would execute here (DEMO)\n", cmd);
}

/* Index 1 */
static void do_sleep(void) {
    /* Stack-assembled string: "sleep" */
    char cmd[8];
    cmd[0] = 's'; cmd[1] = 'l'; cmd[2] = 'e';
    cmd[3] = 'e'; cmd[4] = 'p'; cmd[5] = '\0';
    printf("[ACTION] %s: would execute here (DEMO)\n", cmd);
}

/* Index 2 */
static void do_exfil(void) {
    /* Stack-assembled string: "exfil" */
    char cmd[8];
    cmd[0] = 'e'; cmd[1] = 'x'; cmd[2] = 'f';
    cmd[3] = 'i'; cmd[4] = 'l'; cmd[5] = '\0';
    printf("[ACTION] %s: would execute here (DEMO)\n", cmd);
}

/* Index 3 */
static void do_persist(void) {
    /* Stack-assembled string: "persist" */
    char cmd[10];
    cmd[0] = 'p'; cmd[1] = 'e'; cmd[2] = 'r';
    cmd[3] = 's'; cmd[4] = 'i'; cmd[5] = 's';
    cmd[6] = 't'; cmd[7] = '\0';
    printf("[ACTION] %s: would execute here (DEMO)\n", cmd);
}

/* Index 4 */
static void do_elevate(void) {
    /* Stack-assembled string: "elevate" */
    char cmd[10];
    cmd[0] = 'e'; cmd[1] = 'l'; cmd[2] = 'e';
    cmd[3] = 'v'; cmd[4] = 'a'; cmd[5] = 't';
    cmd[6] = 'e'; cmd[7] = '\0';
    printf("[ACTION] %s: would execute here (DEMO)\n", cmd);
}

/* Index 5 */
static void do_shell(void) {
    /* Stack-assembled string: "shell" */
    char cmd[8];
    cmd[0] = 's'; cmd[1] = 'h'; cmd[2] = 'e';
    cmd[3] = 'l'; cmd[4] = 'l'; cmd[5] = '\0';
    printf("[ACTION] %s: would execute here (DEMO)\n", cmd);
}

/* Index 6 */
static void do_cleanup(void) {
    /* Stack-assembled string: "cleanup" */
    char cmd[10];
    cmd[0] = 'c'; cmd[1] = 'l'; cmd[2] = 'e';
    cmd[3] = 'a'; cmd[4] = 'n'; cmd[5] = 'u';
    cmd[6] = 'p'; cmd[7] = '\0';
    printf("[ACTION] %s: would execute here (DEMO)\n", cmd);
}

/* Index 7 */
static void do_noop(void) {
    /* Stack-assembled string: "noop" */
    char cmd[8];
    cmd[0] = 'n'; cmd[1] = 'o'; cmd[2] = 'o';
    cmd[3] = 'p'; cmd[4] = '\0';
    printf("[ACTION] %s: would execute here (DEMO)\n", cmd);
}

/* ── Unencrypted function pointer array (only used during init) ──────────── */
static const action_fn PLAIN_TABLE[8] = {
    do_beacon,   /* 0 */
    do_sleep,    /* 1 */
    do_exfil,    /* 2 */
    do_persist,  /* 3 */
    do_elevate,  /* 4 */
    do_shell,    /* 5 */
    do_cleanup,  /* 6 */
    do_noop,     /* 7 */
};

/* ── Encrypt the function pointer table ──────────────────────────────────── */
/*
 * enc_table[i] = ((uintptr_t)PLAIN_TABLE[i] ^ FP_XOR_MASK) ^ (uintptr_t)i
 *
 * The double-XOR with i makes each slot use a different effective key,
 * preventing a simple "XOR all entries with 0xCAFEF00D" attack.
 */
static void init_table(void) {
    for (int i = 0; i < 8; i++) {
        uintptr_t fp = (uintptr_t)PLAIN_TABLE[i];
        enc_table[i] = (fp ^ FP_XOR_MASK) ^ (uintptr_t)i;
    }
}

/* ── Dispatch: decrypt and call function at index ────────────────────────── */
/*
 * Reverses the encryption: XOR with FP_XOR_MASK, then XOR with index.
 * Casts the result to action_fn and calls it.
 *
 * For a static analyst:
 *   - enc_table contains values like 0xCAFEF00D ^ <ptr> ^ <idx>
 *   - The call target is not visible until runtime decryption
 *   - Indirect call: call rax — no static API reference
 */
static void dispatch(int index) {
    if (index < 0 || index >= 8) {
        printf("[dispatch] index %d out of range\n", index);
        return;
    }

    /* Opaque predicate 1: x < 0 && x > 0x7FFFFFFF is always false */
    int x = (int)GetTickCount();
    if (x < 0 && x > 0x7FFFFFFF) {
        printf("ERROR: impossible branch\n");  /* dead code */
        ExitProcess(0xDEAD);
    }

    /* Opaque predicate 2: constant math — result always equals 0 */
    volatile int magic = (17 * 13) - 221;   /* 221 - 221 = 0 */
    if (magic != 0) {
        printf("ERROR: math is broken\n");   /* dead code */
        ExitProcess(0xBEEF);
    }

    /* Opaque predicate 3: pointer comparison that can never be true */
    void *stack_ptr = &index;
    void *null_ptr  = NULL;
    if (stack_ptr == null_ptr) {
        printf("ERROR: stack_ptr is null\n"); /* dead code */
        ExitProcess(0xBAD0);
    }

    /* Decrypt and call */
    uintptr_t enc  = enc_table[index];
    uintptr_t decr = (enc ^ FP_XOR_MASK) ^ (uintptr_t)index;
    action_fn  fn  = (action_fn)decr;

    /* Opaque predicate 4: GetTickCount always >= 0 as unsigned, cast to int
     * on any real system this will be >= 0 for the first 24.8 days of uptime */
    unsigned int ticks = GetTickCount();
    if (ticks > 0xFFFFFFFFU) {
        printf("ERROR: tick overflow\n");  /* dead code — ticks IS unsigned */
        return;
    }

    printf("[dispatch] index=%d  enc=0x%p  calling -> ", index, (void *)enc);
    fn();
}

/* ── main ─────────────────────────────────────────────────────────────────── */
/*
 * Sequence: beacon(0) -> noop(7) -> persist(3) -> sleep(1)
 * Mirrors a typical C2 pattern: first beacon, then no-op keepalive,
 * then persistence, then sleep.
 *
 * Opaque predicate 5 (in main): time comparison that always passes.
 */
int main(void) {
    printf("=== Obfuscated Dispatch Demo ===\n");

    /* Build the encrypted table */
    init_table();
    printf("[main] Encrypted function pointer table initialized.\n");
    printf("[main] Table[0]=0x%p  Table[7]=0x%p  (XOR-masked)\n",
           (void *)enc_table[0], (void *)enc_table[7]);

    /* Opaque predicate 5: sizeof is a compile-time constant — always 8 on x64 */
    if (sizeof(uintptr_t) == 0) {
        printf("ERROR: impossible sizeof\n");  /* dead code */
        return 1;
    }

    /* Dispatch sequence */
    printf("[main] Dispatching sequence: beacon -> noop -> persist -> sleep\n");
    dispatch(0);   /* do_beacon  */
    dispatch(7);   /* do_noop    */
    dispatch(3);   /* do_persist */
    dispatch(1);   /* do_sleep   */

    printf("[main] Dispatch sequence complete.\n");
    return 0;
}
