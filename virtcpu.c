#include "virtcpu.h"

/**
 * Implementation of memory-safe CPU with tagged pointers.
 */

uint8_t get_pointer_tag(uint64_t tagged_addr) {
    return (tagged_addr >> TAG_SHIFT) & (uint8_t)TAG_MASK;
}

uint64_t get_pointer_address(uint64_t tagged_addr) {
    return tagged_addr & ADDRESS_MASK;
}

uint64_t create_tagged_pointer(uint64_t address, uint8_t tag) {
    return (address & ADDRESS_MASK) | ((uint64_t)tag << TAG_SHIFT);
}

uint8_t mem_get_tag(const MemorySystem *mem, uint64_t address) {
    assert(mem != NULL);
    if (address >= MEM_SIZE_BYTES || (address % DATA_ALIGN_BYTES != 0)) {
        return TAG_DEFAULT;
    }
    uint64_t tag_index = address / DATA_ALIGN_BYTES;
    return mem->tags[tag_index];
}

void mem_set_tag(MemorySystem *mem, uint64_t address, uint8_t tag) {
    assert(mem != NULL);
    if (address >= MEM_SIZE_BYTES || (address % DATA_ALIGN_BYTES != 0)) {
        return;
    }
    uint64_t tag_index = address / DATA_ALIGN_BYTES;
    mem->tags[tag_index] = tag;
}

FaultType validate_memory_access(const MemorySystem *mem, uint64_t address,
                                uint8_t ptr_tag, bool isWrite, bool isExec,
                                uint64_t *fault_addr) {
    assert(mem != NULL && fault_addr != NULL);

    // Bounds check
    if (address >= MEM_SIZE_BYTES) {
        *fault_addr = address;
        if (isExec) return FAULT_INSTR_ACCESS;
        return isWrite ? FAULT_STORE_ACCESS : FAULT_LOAD_ACCESS;
    }

    // Alignment check
    uint32_t alignment = isExec ? INSTR_ALIGN_BYTES : DATA_ALIGN_BYTES;
    if (address % alignment != 0) {
        *fault_addr = address;
        if (isExec) return FAULT_INSTR_ADDR_MISALIGNED;
        return isWrite ? FAULT_STORE_ADDR_MISALIGNED : FAULT_LOAD_ADDR_MISALIGNED;
    }

    // Permission and W^X check
    uint32_t page_index = address / PAGE_SIZE_BYTES;
    uint8_t page_perms = mem->permissions[page_index];
    bool is_writable = (page_perms & PERM_WRITE) != 0;
    bool is_executable = (page_perms & PERM_EXEC) != 0;

    // W^X violation check
    if (is_writable && is_executable) {
        *fault_addr = address;
        return FAULT_W_X_VIOLATION;
    }

    // Permission check
    uint8_t required_perm = isExec ? PERM_EXEC : (isWrite ? PERM_WRITE : PERM_READ);
    if ((page_perms & required_perm) == 0) {
        *fault_addr = address;
        if (isExec) return FAULT_INSTR_ACCESS;
        return isWrite ? FAULT_STORE_ACCESS : FAULT_LOAD_ACCESS;
    }

    // Tag check (only for data access, not instruction fetch)
    if (!isExec) {
        uint8_t memory_tag = mem_get_tag(mem, address);
        if (memory_tag != TAG_DEFAULT && ptr_tag != memory_tag) {
            *fault_addr = address;
            return isWrite ? FAULT_TAG_CHECK_STORE : FAULT_TAG_CHECK_LOAD;
        }
    }

    return FAULT_NONE;
}

FaultType mem_read_word(
    const MemorySystem *mem,
    uint64_t address,
    uint64_t ptr_tag,
    uint64_t *value
) {
    assert(mem != NULL && value != NULL);

    uint64_t fault_addr;
    FaultType fault = validate_memory_access(
        mem, address, get_pointer_tag(ptr_tag), false, false, &fault_addr
    );

    if (is_fault(fault)) {
        return fault;
    }

    // Read the full 64-bit value without truncation
    memcpy(value, &mem->data[address], WORD_SIZE_BYTES);

    // Optionally, could verify tag here for control flow integrity
    // For example: if (is_control_flow_ptr(*value) && !verify_cf_target(*value)) return FAULT_CF_INTEGRITY;

    return FAULT_NONE;
}

FaultType mem_write_word(
    MemorySystem *mem,
    uint64_t address,
    uint64_t ptr_tag,
    uint64_t value
) {
    assert(mem != NULL);

    uint8_t tag = get_pointer_tag(ptr_tag);
    uint64_t fault_addr;
    FaultType fault = validate_memory_access(
        mem, address, tag, true, false, &fault_addr
    );

    if (is_fault(fault)) {
        return fault;
    }

    // Store the full 64-bit value including high bits - don't truncate!
    memcpy(&mem->data[address], &value, WORD_SIZE_BYTES);

    // Propagate the tag from the pointer to the memory location
    mem_set_tag(mem, address, tag);

    return FAULT_NONE;
}

FaultType mem_read_word_tagged(
    const MemorySystem *mem,
    uint64_t address,
    uint64_t ptr_tag,
    uint64_t *value,
    uint8_t *tag
) {
    assert(mem != NULL && value != NULL && tag != NULL);

    uint64_t fault_addr;
    FaultType fault = validate_memory_access(
        mem, address, get_pointer_tag(ptr_tag), false, false, &fault_addr
    );

    if (is_fault(fault)) {
        return fault;
    }

    memcpy(value, &mem->data[address], WORD_SIZE_BYTES);
    *tag = mem_get_tag(mem, address);

    return FAULT_NONE;
}

FaultType mem_write_word_tagged(MemorySystem *mem, uint64_t address, uint64_t ptr_tag,
                               uint64_t value, uint8_t tag) {
    assert(mem != NULL);

    uint64_t fault_addr;
    FaultType fault = validate_memory_access(
        mem, address, get_pointer_tag(ptr_tag), true, false, &fault_addr
    );

    if (is_fault(fault)) {
        return fault;
    }

    // Store the address part of the value
    uint64_t addr_value = get_pointer_address(value);
    memcpy(&mem->data[address], &addr_value, WORD_SIZE_BYTES);

    // Set tag explicitly (overriding the default propagation)
    mem_set_tag(mem, address, tag);

    return FAULT_NONE;
}

void cpu_init(CPUState *cpu) {
    assert(cpu != NULL);
    cpu_reset(cpu);
}

void cpu_reset(CPUState *cpu) {
    assert(cpu != NULL);
    cpu->pc = 0;
    memset(cpu->registers, 0, sizeof(cpu->registers));
    cpu->mepc = 0;
    cpu->mcause = FAULT_NONE;
    cpu->mtval = 0;
}

void mem_init(MemorySystem *mem) {
    assert(mem != NULL);

    mem->data = (uint8_t *)calloc(MEM_SIZE_BYTES, 1);
    if (!mem->data) {
        perror("Failed to allocate main memory");
        exit(EXIT_FAILURE);
    }

    mem->tags = (uint8_t *)calloc(TAG_MEM_SIZE_BYTES, 1);
    if (!mem->tags) {
        perror("Failed to allocate tag memory");
        free(mem->data);
        exit(EXIT_FAILURE);
    }

    // Initialize all tags to default (0)
    memset(mem->tags, TAG_DEFAULT, TAG_MEM_SIZE_BYTES);

    // Initialize all permissions to none
    memset(mem->permissions, PERM_NONE, NUM_PAGES);
}

void mem_destroy(MemorySystem *mem) {
    if (mem) {
        free(mem->data);
        free(mem->tags);
        mem->data = NULL;
        mem->tags = NULL;
    }
}

bool mem_set_page_permissions(MemorySystem *mem, uint32_t page_index, uint8_t perms) {
    assert(mem != NULL);

    if (page_index >= NUM_PAGES) {
        fprintf(stderr, "Error: Invalid page index %u\n", page_index);
        return false;
    }

    // Warning for W^X pages
    if ((perms & PERM_WRITE) && (perms & PERM_EXEC)) {
        fprintf(stderr, "Warning: Setting W^X permissions on page %u\n", page_index);
    }

    mem->permissions[page_index] = perms;
    return true;
}

bool mem_load_program(MemorySystem *mem, const uint8_t *program, uint64_t start_addr, uint32_t size_bytes) {
    assert(mem != NULL && program != NULL);

    if (start_addr >= MEM_SIZE_BYTES ||
        size_bytes > MEM_SIZE_BYTES ||
        start_addr > MEM_SIZE_BYTES - size_bytes) {
        fprintf(stderr, "Error: Program load out of bounds\n");
        return false;
    }

    memcpy(&mem->data[start_addr], program, size_bytes);
    return true;
}

FaultType cpu_fetch(CPUState *cpu, MemorySystem *mem, uint32_t *instruction_word) {
    assert(cpu != NULL && mem != NULL && instruction_word != NULL);

    uint64_t fault_addr;
    FaultType fault = validate_memory_access(
        mem, cpu->pc, 0, false, true, &fault_addr
    );

    if (is_fault(fault)) {
        cpu->mepc = cpu->pc;
        cpu->mcause = fault;
        cpu->mtval = fault_addr;
        return fault;
    }

    // Fetch the instruction
    memcpy(instruction_word, &mem->data[cpu->pc], INSTR_SIZE_BYTES);

    // Update PC
    cpu->pc += INSTR_SIZE_BYTES;

    return FAULT_NONE;
}

void cpu_decode(uint32_t instruction_word, uint64_t instr_addr, DecodedInstruction *decoded) {
    assert(decoded != NULL);

    // Simple instruction format:
    // [31:24] opcode, [23:19] rd, [18:14] rs1, [13:9] rs2, [8:0] immediate/unused

    decoded->opcode = (OpCode)((instruction_word >> 24) & 0xFF);
    decoded->rd = (instruction_word >> 19) & 0x1F;
    decoded->rs1 = (instruction_word >> 14) & 0x1F;
    decoded->rs2 = (instruction_word >> 9) & 0x1F;
    decoded->imm = (int16_t)((instruction_word & 0x1FF) << 7) >> 7; // sign extend 9-bit immediate
    decoded->addr = instr_addr;
}

FaultType cpu_execute(CPUState *cpu, MemorySystem *mem, const DecodedInstruction *decoded) {
    assert(cpu != NULL && mem != NULL && decoded != NULL);

    // Ensure x0 is always 0
    cpu->registers[0] = 0;

    uint64_t val_rs1 = cpu->registers[decoded->rs1];
    uint64_t val_rs2 = cpu->registers[decoded->rs2];
    uint64_t result = 0;
    bool writeback = false;
    FaultType fault = FAULT_NONE;

    switch (decoded->opcode) {
        case OP_NOP:
            // No operation
            break;

        case OP_ADD:
            // Add two registers (result is untagged)
            result = get_pointer_address(val_rs1) + get_pointer_address(val_rs2);
            writeback = true;
            break;

        case OP_SUB:
            // Subtract two registers (result is untagged)
            result = get_pointer_address(val_rs1) - get_pointer_address(val_rs2);
            writeback = true;
            break;

        case OP_LI:
            // Load immediate value into register (clears tag)
            result = (uint64_t)(decoded->imm & 0x1FF); // Immediate is 9 bits
            writeback = true;
            break;

        case OP_ADDI:
            // Add immediate to register value (clears tag)
            result = get_pointer_address(val_rs1) + (int64_t)decoded->imm;
            writeback = true;
            break;

        case OP_LOAD:
            // Load from memory, clear tag
            fault = mem_read_word(mem, get_pointer_address(val_rs1) + decoded->imm,
                                val_rs1, &result);
            writeback = !is_fault(fault);
            break;

        case OP_LOADTAG:
            // Load from memory, preserve tag
            {
                uint8_t tag;
                fault = mem_read_word_tagged(mem, get_pointer_address(val_rs1) + decoded->imm,
                                          val_rs1, &result, &tag);
                if (!is_fault(fault)) {
                    result = create_tagged_pointer(result, tag);
                    writeback = true;
                }
            }
            break;

        case OP_STORE:
            // Store to memory
            fault = mem_write_word(mem, get_pointer_address(val_rs1) + decoded->imm,
                                 val_rs1, val_rs2);
            break;

        case OP_STORETAG:
            // Store to memory with explicit tag
            {
                uint8_t tag = decoded->imm & 0xFF;
                fault = mem_write_word_tagged(mem, get_pointer_address(val_rs1),
                                            val_rs1, val_rs2, tag);
            }
            break;

        case OP_JUMP:
            // Jump to address + offset
            cpu->pc = decoded->addr + decoded->imm;
            break;

        case OP_JUMPR:
            // Jump to register + offset
            cpu->pc = get_pointer_address(val_rs1) + decoded->imm;
            break;

        case OP_BEQ:
            // Branch if equal
            if (val_rs1 == val_rs2) {
                cpu->pc = decoded->addr + decoded->imm;
            }
            break;

        case OP_BNE:
            // Branch if not equal
            if (val_rs1 != val_rs2) {
                cpu->pc = decoded->addr + decoded->imm;
            }
            break;

        case OP_GETTAG:
            // Get tag from register
            result = get_pointer_tag(val_rs1);
            writeback = true;
            break;

        case OP_SETTAG:
            // Set tag on register
            result = create_tagged_pointer(get_pointer_address(val_rs1),
                                         decoded->imm & 0xFF);
            writeback = true;
            break;

        case OP_HALT:
            // Halt execution
            fault = FAULT_BREAKPOINT;
            break;

        default:
            fault = FAULT_ILLEGAL_INSTRUCTION;
            cpu->mtval = decoded->opcode;
            break;
    }

    if (is_fault(fault)) {
        cpu->mepc = decoded->addr;
        cpu->mcause = fault;
        return fault;
    }

    if (writeback && decoded->rd != 0) {
        cpu->registers[decoded->rd] = result;
    }

    return FAULT_NONE;
}

FaultType cpu_step(CPUState *cpu, MemorySystem *mem) {
    uint32_t instruction;
    FaultType fault = cpu_fetch(cpu, mem, &instruction);
    if (is_fault(fault)) {
        return fault;
    }

    DecodedInstruction decoded;
    cpu_decode(instruction, cpu->pc - INSTR_SIZE_BYTES, &decoded);

    return cpu_execute(cpu, mem, &decoded);
}

FaultType cpu_run(CPUState *cpu, MemorySystem *mem, uint64_t max_instructions) {
    uint64_t count = 0;
    FaultType fault = FAULT_NONE;

    while (count < max_instructions) {
        fault = cpu_step(cpu, mem);
        count++;

        if (is_fault(fault)) {
            break;
        }
    }

    return fault;
}

const char* fault_type_to_string(FaultType fault) {
    switch(fault) {
        case FAULT_NONE: return "no fault";
        case FAULT_INSTR_ADDR_MISALIGNED: return "instruction address misaligned";
        case FAULT_INSTR_ACCESS: return "instruction access violation";
        case FAULT_ILLEGAL_INSTRUCTION: return "illegal instruction";
        case FAULT_BREAKPOINT: return "breakpoint";
        case FAULT_LOAD_ADDR_MISALIGNED: return "load address misaligned";
        case FAULT_LOAD_ACCESS: return "load access violation";
        case FAULT_STORE_ADDR_MISALIGNED: return "store address misaligned";
        case FAULT_STORE_ACCESS: return "store access violation";
        case FAULT_TAG_CHECK_LOAD: return "tag check fault (load)";
        case FAULT_TAG_CHECK_STORE: return "tag check fault (store)";
        case FAULT_W_X_VIOLATION: return "W^X violation";
        default: return "unknown";
    }
}

void cpu_dump_state(const CPUState *cpu, FILE *stream) {
    fprintf(stream, "=== CPU state\n");
    fprintf(stream, "PC: 0x%016llx\n", (unsigned long long)cpu->pc);

    for (int i = 0; i < NUM_REGISTERS; i++) {
        uint64_t reg = cpu->registers[i];
        uint8_t tag = get_pointer_tag(reg);
        uint64_t addr = get_pointer_address(reg);

        fprintf(stream, "x%02d: 0x%016llx [addr: 0x%014llx, tag: 0x%02x]\n",
                i, (unsigned long long)reg, (unsigned long long)addr, tag);
    }

    fprintf(stream, "Fault Status: ");
    if (cpu->mcause == FAULT_NONE) {
        fprintf(stream, "None\n");
    } else {
        fprintf(stream, "%s\n", fault_type_to_string(cpu->mcause));
        fprintf(stream, "MEPC: 0x%016llx\n", (unsigned long long)cpu->mepc);
        fprintf(stream, "MTVAL: 0x%016llx\n", (unsigned long long)cpu->mtval);
    }

    fprintf(stream, "===\n");
}

void mem_dump_page_permissions(const MemorySystem *mem, FILE *stream) {
    fprintf(stream, "=== Memory page permissions\n");

    for (uint32_t i = 0; i < NUM_PAGES; i++) {
        uint8_t perms = mem->permissions[i];
        if (perms != PERM_NONE) {
            fprintf(stream, "Page %3u (0x%08x - 0x%08x): ",
                    i, i * PAGE_SIZE_BYTES, (i + 1) * PAGE_SIZE_BYTES - 1);

            fprintf(stream, "R:%d W:%d X:%d",
                    (perms & PERM_READ) ? 1 : 0,
                    (perms & PERM_WRITE) ? 1 : 0,
                    (perms & PERM_EXEC) ? 1 : 0);

            if ((perms & PERM_WRITE) && (perms & PERM_EXEC)) {
                fprintf(stream, " (W^X warning!)");
            }

            fprintf(stream, "\n");
        }
    }

    fprintf(stream, "===\n");
}

void mem_dump_region(const MemorySystem *mem, uint64_t start, uint64_t size, FILE *stream) {
    fprintf(stream, "=== Memory dump [0x%016llx - 0x%016llx]\n",
            (unsigned long long)start, (unsigned long long)(start + size - 1));

    uint64_t end = start + size;
    if (end > MEM_SIZE_BYTES) end = MEM_SIZE_BYTES;

    for (uint64_t addr = start; addr < end; addr += WORD_SIZE_BYTES) {
        uint64_t value;
        FaultType result = mem_debug_read_word(mem, addr, &value);

        if (is_fault(result)) {
            fprintf(stream, "0x%016llx: <access fault: %s>\n",
                   (unsigned long long)addr, fault_type_to_string(result));
        } else {
            uint8_t tag = mem_get_tag(mem, addr);
            fprintf(stream, "0x%016llx: 0x%016llx [tag: 0x%02x]\n",
                   (unsigned long long)addr, (unsigned long long)value, tag);
        }
    }

    fprintf(stream, "===\n");
}

FaultType mem_debug_read_word(const MemorySystem *mem, uint64_t address, uint64_t *value) {
    assert(mem != NULL && value != NULL);

    if (address >= MEM_SIZE_BYTES) {
        return FAULT_LOAD_ACCESS;
    }

    if (address % WORD_SIZE_BYTES != 0) {
        return FAULT_LOAD_ADDR_MISALIGNED;
    }

    memcpy(value, &mem->data[address], WORD_SIZE_BYTES);
    return FAULT_NONE;
}
