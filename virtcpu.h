#ifndef VIRTCPU_H
#define VIRTCPU_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/**
 * Memory-safe CPU architecture with tagged pointers and permission enforcement.
 *
 * This architecture implements a RISC-V inspired CPU with built-in memory safety features:
 * - Tagged pointers: 8 bits of tag in upper bits of 64-bit pointers
 * - Tag memory: one tag byte per 8-byte aligned memory region
 * - Memory permissions: read/write/execute at page granularity
 * - W^X enforcement: no simultaneous W and X permission
 */

#define NUM_REGISTERS 32                                      // x0-x31, with x0 hardwired to zero
#define WORD_SIZE_BYTES 8                                     // 64-bit architecture
#define PAGE_SIZE_BYTES 4096                                  // 4K pages
#define MEM_SIZE_BYTES (1 * 1024 * 1024)                      // 1MiB simulation
#define TAG_MEM_SIZE_BYTES (MEM_SIZE_BYTES / WORD_SIZE_BYTES) // 1 tag per 8 bytes
#define NUM_PAGES (MEM_SIZE_BYTES / PAGE_SIZE_BYTES)

#define TAG_SHIFT 56                       // tag is in bits 63:56
#define TAG_MASK 0xFFULL                   // 8-bit tag mask
#define ADDRESS_MASK 0x00FFFFFFFFFFFFFFULL // 56-bit address mask
#define TAG_DEFAULT 0x00                   // default tag (untagged)

#define INSTR_SIZE_BYTES 4               // 32-bit instructions
#define INSTR_ALIGN_BYTES 4              // 4-byte alignment
#define DATA_ALIGN_BYTES WORD_SIZE_BYTES // 8-byte alignment for data

#define PERM_NONE 0         // no permissions
#define PERM_READ (1 << 0)  // read permission
#define PERM_WRITE (1 << 1) // write permission
#define PERM_EXEC (1 << 2)  // execute permission

typedef enum {
    OP_NOP = 0,
    OP_ADD,
    OP_SUB,
    OP_LI,
    OP_ADDI,
    OP_LOAD,
    OP_LOADTAG,
    OP_STORE,
    OP_STORETAG,
    OP_JUMP,
    OP_JUMPR,
    OP_BEQ,
    OP_BNE,
    OP_GETTAG,
    OP_SETTAG,
    OP_HALT
} OpCode;

typedef enum {
    FAULT_NONE = -1,
    FAULT_INSTR_ADDR_MISALIGNED,
    FAULT_INSTR_ACCESS,
    FAULT_ILLEGAL_INSTRUCTION,
    FAULT_BREAKPOINT,
    FAULT_LOAD_ADDR_MISALIGNED,
    FAULT_LOAD_ACCESS,
    FAULT_STORE_ADDR_MISALIGNED,
    FAULT_STORE_ACCESS,
    FAULT_TAG_CHECK_LOAD,
    FAULT_TAG_CHECK_STORE,
    FAULT_W_X_VIOLATION
} FaultType;

typedef struct {
    uint64_t pc;
    uint64_t registers[NUM_REGISTERS];
    uint64_t mepc;    // exception program counter
    FaultType mcause; // exception cause
    uint64_t mtval;   // exception value
} CPUState;

typedef struct {
    uint8_t *data;                  // main memory
    uint8_t *tags;                  // tag memory
    uint8_t permissions[NUM_PAGES]; // page permissions
} MemorySystem;

typedef struct {
    OpCode opcode;
    uint8_t rd;    // destination register
    uint8_t rs1;   // source register 1
    uint8_t rs2;   // source register 2
    int64_t imm;   // immediate value
    uint64_t addr; // instruction address
} DecodedInstruction;

// Initialization
void cpu_init(CPUState *cpu);
void cpu_reset(CPUState *cpu);
void mem_init(MemorySystem *mem);
void mem_destroy(MemorySystem *mem);

// Memory configuration
bool mem_set_page_permissions(MemorySystem *mem, uint32_t page_index, uint8_t perms);
bool mem_load_program(MemorySystem *mem, const uint8_t *program, uint64_t start_addr, uint32_t size_bytes);

// Tag operations
uint8_t get_pointer_tag(uint64_t tagged_addr);
uint64_t get_pointer_address(uint64_t tagged_addr);
uint64_t create_tagged_pointer(uint64_t address, uint8_t tag);
uint8_t mem_get_tag(const MemorySystem *mem, uint64_t address);
void mem_set_tag(MemorySystem *mem, uint64_t address, uint8_t tag);

// Core CPU cycle
FaultType cpu_fetch(CPUState *cpu, MemorySystem *mem, uint32_t *instruction_word);
void cpu_decode(uint32_t instruction_word, uint64_t instr_addr, DecodedInstruction *decoded);
FaultType cpu_execute(CPUState *cpu, MemorySystem *mem, const DecodedInstruction *decoded);
FaultType cpu_step(CPUState *cpu, MemorySystem *mem);
FaultType cpu_run(CPUState *cpu, MemorySystem *mem, uint64_t max_instructions);

// Memory access
FaultType mem_read_word(const MemorySystem *mem, uint64_t address, uint64_t ptr_tag, uint64_t *value);
FaultType mem_write_word(MemorySystem *mem, uint64_t address, uint64_t ptr_tag, uint64_t value);
FaultType mem_read_word_tagged(const MemorySystem *mem, uint64_t address, uint64_t ptr_tag, uint64_t *value, uint8_t *tag);
FaultType mem_write_word_tagged(MemorySystem *mem, uint64_t address, uint64_t ptr_tag, uint64_t value, uint8_t tag);

// Debugging
const char* fault_type_to_string(FaultType fault);
void cpu_dump_state(const CPUState *cpu, FILE *stream);
void mem_dump_page_permissions(const MemorySystem *mem, FILE *stream);
void mem_dump_region(const MemorySystem *mem, uint64_t start, uint64_t size, FILE *stream);
FaultType mem_debug_read_word(const MemorySystem *mem, uint64_t address, uint64_t *value);

// Validation
FaultType validate_memory_access(const MemorySystem *mem, uint64_t address, uint8_t ptr_tag, bool isWrite, bool isExec, uint64_t *fault_addr);
static inline bool is_fault(FaultType result) {
    return result != FAULT_NONE;
}

#endif // VIRTCPU_H
