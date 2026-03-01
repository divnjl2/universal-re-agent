/*
 * vm_dispatch.c — RE target: custom bytecode VM with obfuscated computation
 *
 * Real-world relevance: VMs hide real logic behind a custom instruction set.
 * Static analysis sees a dispatcher loop — dynamic trace reveals the computation.
 *
 * VM has 8 opcodes (OP_PUSH, OP_POP, OP_ADD, OP_XOR, OP_MOV, OP_JNZ, OP_CALL, OP_HALT)
 * The bytecode computes: result = (A XOR 0xAA) + (B * 3) where A=0x41, B=0x10
 * Expected result: (0x41 ^ 0xAA) + (0x10 * 3) = 0xEB + 0x30 = 0x11B -> 0x1B (low byte)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define VM_STACK_SIZE 64
#define VM_REG_COUNT  8

/* Opcodes */
#define OP_PUSH  0x01  /* PUSH imm8 */
#define OP_POP   0x02  /* POP  reg */
#define OP_ADD   0x03  /* ADD  reg, reg -> push result */
#define OP_XOR   0x04  /* XOR  reg, imm8 -> push result */
#define OP_MOV   0x05  /* MOV  reg, imm8 */
#define OP_MUL   0x06  /* MUL  reg, imm8 -> push result */
#define OP_OUT   0x07  /* OUT  reg (print) */
#define OP_HALT  0xFF  /* HALT */

typedef struct {
    uint8_t  stack[VM_STACK_SIZE];
    int      sp;         /* stack pointer */
    uint8_t  reg[VM_REG_COUNT];
    uint8_t *ip;         /* instruction pointer */
    int      running;
} VMState;

static void vm_push(VMState *vm, uint8_t v) {
    if (vm->sp < VM_STACK_SIZE - 1) vm->stack[++vm->sp] = v;
}

static uint8_t vm_pop(VMState *vm) {
    if (vm->sp >= 0) return vm->stack[vm->sp--];
    return 0;
}

static void vm_step(VMState *vm) {
    uint8_t op = *vm->ip++;
    switch (op) {
        case OP_PUSH: {
            uint8_t imm = *vm->ip++;
            vm_push(vm, imm);
            break;
        }
        case OP_POP: {
            uint8_t reg = *vm->ip++;
            vm->reg[reg % VM_REG_COUNT] = vm_pop(vm);
            break;
        }
        case OP_ADD: {
            uint8_t ra = *vm->ip++;
            uint8_t rb = *vm->ip++;
            vm_push(vm, vm->reg[ra % VM_REG_COUNT] + vm->reg[rb % VM_REG_COUNT]);
            break;
        }
        case OP_XOR: {
            uint8_t reg = *vm->ip++;
            uint8_t imm = *vm->ip++;
            vm_push(vm, vm->reg[reg % VM_REG_COUNT] ^ imm);
            break;
        }
        case OP_MOV: {
            uint8_t reg = *vm->ip++;
            uint8_t imm = *vm->ip++;
            vm->reg[reg % VM_REG_COUNT] = imm;
            break;
        }
        case OP_MUL: {
            uint8_t reg = *vm->ip++;
            uint8_t imm = *vm->ip++;
            vm_push(vm, vm->reg[reg % VM_REG_COUNT] * imm);
            break;
        }
        case OP_OUT: {
            uint8_t reg = *vm->ip++;
            printf("VM OUT r%u = 0x%02X (%u)\n",
                   reg % VM_REG_COUNT,
                   vm->reg[reg % VM_REG_COUNT],
                   vm->reg[reg % VM_REG_COUNT]);
            break;
        }
        case OP_HALT:
            vm->running = 0;
            break;
        default:
            fprintf(stderr, "VM: unknown opcode 0x%02X\n", op);
            vm->running = 0;
    }
}

/*
 * Bytecode program:
 *   MOV r0, 0x41        ; r0 = A = 0x41
 *   MOV r1, 0x10        ; r1 = B = 0x10
 *   XOR r0, 0xAA        ; push (r0 ^ 0xAA) = 0xEB
 *   POP r2              ; r2 = 0xEB
 *   MUL r1, 0x03        ; push (r1 * 3) = 0x30
 *   POP r3              ; r3 = 0x30
 *   ADD r2, r3          ; push (r2 + r3) = 0x11B -> 0x1B (uint8)
 *   POP r0              ; r0 = result
 *   OUT r0              ; print r0
 *   HALT
 */
static const uint8_t BYTECODE[] = {
    OP_MOV, 0, 0x41,
    OP_MOV, 1, 0x10,
    OP_XOR, 0, 0xAA,
    OP_POP, 2,
    OP_MUL, 1, 0x03,
    OP_POP, 3,
    OP_ADD, 2, 3,
    OP_POP, 0,
    OP_OUT, 0,
    OP_HALT
};

int main(void) {
    VMState vm;
    memset(&vm, 0, sizeof(vm));
    vm.sp      = -1;
    vm.ip      = (uint8_t *)BYTECODE;
    vm.running = 1;

    printf("VM starting. Bytecode size: %zu bytes\n", sizeof(BYTECODE));
    int steps = 0;
    while (vm.running && steps < 1000) {
        vm_step(&vm);
        steps++;
    }
    printf("VM halted after %d steps.\n", steps);
    return 0;
}
