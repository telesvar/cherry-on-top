#include "virtcpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

/**
 * Security testing of the CPU architecture.
 *
 * This file contains tests that verify the memory safety features of the CPU
 * and attempts to breach the security mechanisms through various attacks.
 */

// Global CPU and memory state for tests
CPUState cpu_state;
MemorySystem memory;

uint32_t create_instruction(OpCode op, uint8_t rd, uint8_t rs1, uint8_t rs2, int16_t imm) {
    uint32_t instr = 0;
    instr |= ((uint32_t)op << 24);
    instr |= ((uint32_t)(rd & 0x1F) << 19);
    instr |= ((uint32_t)(rs1 & 0x1F) << 14);
    instr |= ((uint32_t)(rs2 & 0x1F) << 9);
    instr |= ((uint32_t)(imm & 0x1FF));
    return instr;
}

void load_test_program(MemorySystem *mem, const uint32_t *program, uint32_t num_instructions, uint64_t start_addr) {
    mem_load_program(mem, (const uint8_t*)program, start_addr, num_instructions * INSTR_SIZE_BYTES);
}

// Helper function to build up a large address value through multiple ADDI instructions
// Returns the next index to use in the program array
int build_address(uint32_t *program, int idx, uint8_t reg, uint64_t target_addr) {
    // First, load 0 into the register
    program[idx++] = create_instruction(OP_LI, reg, 0, 0, 0);

    // Build up the address in chunks (max 0x1FF per addition due to immediate field size)
    uint64_t current = 0;
    while (current < target_addr) {
        // Calculate how much to add (up to 0x1FF per step)
        uint16_t increment = (target_addr - current > 0x1FF) ? 0x1FF : (target_addr - current);
        program[idx++] = create_instruction(OP_ADDI, reg, reg, 0, increment);
        current += increment;
    }

    return idx;
}

// Fixed macro that handles HALT instructions properly
#define RUN_TEST(test_func, expect_fault_val, expected_fault_val) do { \
    printf("\n=== Running test: %s\n", #test_func); \
    cpu_state.mcause = FAULT_NONE; \
    test_func(); \
    if (expect_fault_val && cpu_state.mcause == expected_fault_val) { \
        printf("TEST PASSED: got expected fault: %s\n", fault_type_to_string(expected_fault_val)); \
    } else if (!expect_fault_val && (cpu_state.mcause == FAULT_NONE || cpu_state.mcause == FAULT_BREAKPOINT)) { \
        printf("TEST PASSED: normal execution (ended with %s)\n", fault_type_to_string(cpu_state.mcause)); \
    } else if (expect_fault_val) { \
        printf("TEST FAILED: expected fault %s but got %s\n", \
               fault_type_to_string(expected_fault_val), \
               fault_type_to_string(cpu_state.mcause)); \
    } else { \
        printf("TEST FAILED: expected normal execution but got %s\n", \
               fault_type_to_string(cpu_state.mcause)); \
    } \
    printf("===\n"); \
} while(0)

void test_basic_computation() {
    // Initialize CPU and memory
    cpu_init(&cpu_state);
    mem_init(&memory);

    // Set up memory permissions (code at 0x1000, data at 0x2000)
    mem_set_page_permissions(&memory, 1, PERM_READ | PERM_EXEC);  // code page
    mem_set_page_permissions(&memory, 2, PERM_READ | PERM_WRITE); // data page

    // Create a simple program: add x1 = 5, x2 = 10, x3 = x1 + x2
    uint32_t program[] = {
        // li x1, 5 (Load immediate)
        create_instruction(OP_LI, 1, 0, 0, 5),

        // li x2, 10 (Load immediate)
        create_instruction(OP_LI, 2, 0, 0, 10),

        // add x3, x1, x2
        create_instruction(OP_ADD, 3, 1, 2, 0),

        // halt
        create_instruction(OP_HALT, 0, 0, 0, 0)
    };

    // Load program at 0x1000
    load_test_program(&memory, program, 4, 0x1000);

    // Set PC to start of program
    cpu_state.pc = 0x1000;

    // Run the program
    FaultType result = cpu_run(&cpu_state, &memory, 10);

    // Check results
    assert(cpu_state.registers[1] == 5);
    assert(cpu_state.registers[2] == 10);
    assert(cpu_state.registers[3] == 15);
    assert(result == FAULT_BREAKPOINT); // we should have hit HALT

    // Clean up
    mem_destroy(&memory);
}

void test_memory_operations() {
    // Initialize CPU and memory
    cpu_init(&cpu_state);
    mem_init(&memory);

    // Set up memory permissions
    mem_set_page_permissions(&memory, 0, PERM_READ | PERM_WRITE); // data at 0x0-0xFFF
    mem_set_page_permissions(&memory, 1, PERM_READ | PERM_EXEC);  // code at 0x1000

    // Create a simple program using a small address that fits in immediate field
    uint32_t program[] = {
        // li x1, 0x100 (small address in page 0)
        create_instruction(OP_LI, 1, 0, 0, 0x100),

        // li x2, 42
        create_instruction(OP_LI, 2, 0, 0, 42),

        // sd x2, 0(x1)
        create_instruction(OP_STORE, 0, 1, 2, 0),

        // li x3, 0
        create_instruction(OP_LI, 3, 0, 0, 0),

        // ld x3, 0(x1)
        create_instruction(OP_LOAD, 3, 1, 0, 0),

        // halt
        create_instruction(OP_HALT, 0, 0, 0, 0)
    };

    // Load program at 0x1000
    load_test_program(&memory, program, 6, 0x1000);

    // Set PC to start of program
    cpu_state.pc = 0x1000;

    // Run the program
    FaultType result = cpu_run(&cpu_state, &memory, 10);

    // Check results -- use address part for comparison
    assert(get_pointer_address(cpu_state.registers[3]) == 42);

    // Check memory at 0x100
    uint64_t value;
    mem_debug_read_word(&memory, 0x100, &value);
    assert(value == 42);

    // Clean up
    mem_destroy(&memory);
}

void test_permission_violation() {
    // Initialize CPU and memory
    cpu_init(&cpu_state);
    mem_init(&memory);

    // Set up memory permissions
    mem_set_page_permissions(&memory, 1, PERM_READ | PERM_EXEC); // code at 0x1000
    // Page 0 has NO WRITE permission
    mem_set_page_permissions(&memory, 0, PERM_READ);

    // Create a simple program that tries to write to a read-only page
    uint32_t program[] = {
        // li x1, 0x100 (address in read-only page 0)
        create_instruction(OP_LI, 1, 0, 0, 0x100),

        // li x2, 42
        create_instruction(OP_LI, 2, 0, 0, 42),

        // sd x2, 0(x1) -- this should fail with FAULT_STORE_ACCESS
        create_instruction(OP_STORE, 0, 1, 2, 0),

        // halt (should not reach this)
        create_instruction(OP_HALT, 0, 0, 0, 0)
    };

    // Load program at 0x1000
    load_test_program(&memory, program, 4, 0x1000);

    // Set PC to start of program
    cpu_state.pc = 0x1000;

    // Run the program - should fault on the store
    FaultType result = cpu_run(&cpu_state, &memory, 10);

    // Verify fault
    assert(result == FAULT_STORE_ACCESS);

    // Clean up
    mem_destroy(&memory);
}

void test_wx_violation() {
    // Initialize CPU and memory
    cpu_init(&cpu_state);
    mem_init(&memory);

    // Set up memory permissions -- explicitly set W^X on page 0
    mem_set_page_permissions(&memory, 0, PERM_READ | PERM_WRITE | PERM_EXEC); // W^X violation at 0x0
    mem_set_page_permissions(&memory, 1, PERM_READ | PERM_EXEC);              // code at 0x1000

    // Simple direct program
    uint32_t program[] = {
        // li x1, 0x100 (address in page 0 with W^X)
        create_instruction(OP_LI, 1, 0, 0, 0x100),

        // li x2, 42
        create_instruction(OP_LI, 2, 0, 0, 42),

        // sd x2, 0(x1) -- should fail with W^X violation
        create_instruction(OP_STORE, 0, 1, 2, 0),

        // halt
        create_instruction(OP_HALT, 0, 0, 0, 0)
    };

    // Load program at 0x1000
    load_test_program(&memory, program, 4, 0x1000);

    // Set PC to start of program
    cpu_state.pc = 0x1000;

    // Run the program directly
    FaultType result = cpu_run(&cpu_state, &memory, 10);

    // Verify fault
    assert(result == FAULT_W_X_VIOLATION);

    // Clean up
    mem_destroy(&memory);
}

void test_tag_mismatch() {
    // Initialize CPU and memory
    cpu_init(&cpu_state);
    mem_init(&memory);

    // Set up memory permissions
    mem_set_page_permissions(&memory, 0, PERM_READ | PERM_WRITE); // data at 0x0-0xFFF
    mem_set_page_permissions(&memory, 1, PERM_READ | PERM_EXEC);  // code at 0x1000

    // Create a simple program
    uint32_t program[] = {
        // li x1, 0x100 (address in page 0)
        create_instruction(OP_LI, 1, 0, 0, 0x100),

        // li x2, 99
        create_instruction(OP_LI, 2, 0, 0, 99),

        // sd x2, 0(x1) -- store with default tag
        create_instruction(OP_STORE, 0, 1, 2, 0),

        // halt
        create_instruction(OP_HALT, 0, 0, 0, 0)
    };

    // Load program at 0x1000
    load_test_program(&memory, program, 4, 0x1000);

    // Set PC to start of program
    cpu_state.pc = 0x1000;

    // Run the first part to set up memory
    FaultType result = cpu_run(&cpu_state, &memory, 10);

    // Make sure the first part ran successfully
    assert(result == FAULT_BREAKPOINT);

    // Manually set the tag to 0x42 (simulating privileged operation)
    mem_set_tag(&memory, 0x100, 0x42);

    // Now create a second program that tries to load with wrong tag
    uint32_t program2[] = {
        // li x1, 0x100 (address in page 0)
        create_instruction(OP_LI, 1, 0, 0, 0x100),

        // ld x3, 0(x1) -- this should fail due to tag mismatch
        create_instruction(OP_LOAD, 3, 1, 0, 0),

        // halt (should not reach this)
        create_instruction(OP_HALT, 0, 0, 0, 0)
    };

    // Load second program
    load_test_program(&memory, program2, 3, 0x1000);

    // Reset PC
    cpu_state.pc = 0x1000;

    // Run second program - should fault on the load
    result = cpu_run(&cpu_state, &memory, 10);

    // Verify fault
    assert(result == FAULT_TAG_CHECK_LOAD);

    // Clean up
    mem_destroy(&memory);
}

void test_alignment_fault() {
    // Initialize CPU and memory
    cpu_init(&cpu_state);
    mem_init(&memory);

    // Set up memory permissions
    mem_set_page_permissions(&memory, 0, PERM_READ | PERM_WRITE); // data at 0x0-0xFFF
    mem_set_page_permissions(&memory, 1, PERM_READ | PERM_EXEC);  // code at 0x1000

    // Create a simple program with misaligned access
    uint32_t program[] = {
        // li x1, 0x104 (misaligned for 8-byte access)
        create_instruction(OP_LI, 1, 0, 0, 0x104),

        // li x2, 42
        create_instruction(OP_LI, 2, 0, 0, 42),

        // sd x2, 0(x1) -- should fault on misalignment
        create_instruction(OP_STORE, 0, 1, 2, 0),

        // halt
        create_instruction(OP_HALT, 0, 0, 0, 0)
    };

    // Load program at 0x1000
    load_test_program(&memory, program, 4, 0x1000);

    // Set PC to start of program
    cpu_state.pc = 0x1000;

    // Run the program
    FaultType result = cpu_run(&cpu_state, &memory, 10);

    // Verify fault
    assert(result == FAULT_STORE_ADDR_MISALIGNED);

    // Clean up
    mem_destroy(&memory);
}

void test_tag_laundering_attack() {
    // This test attempts to bypass security by:
    // 1. Loading from protected memory (which strips tags)
    // 2. Storing back with a different tag

    cpu_init(&cpu_state);
    mem_init(&memory);

    // Set up memory permissions
    mem_set_page_permissions(&memory, 0, PERM_READ | PERM_WRITE); // data at 0x100
    mem_set_page_permissions(&memory, 1, PERM_READ | PERM_EXEC);  // code at 0x1000

    // Prepare protected memory with a value and a special tag
    uint64_t secret_data = 0xDEADBEEFULL;
    memcpy(&memory.data[0x100], &secret_data, 8);
    mem_set_tag(&memory, 0x100, 0x42); // protected with tag 0x42

    // Create the attack program
    uint32_t program[] = {
        // li x1, 0x100
        create_instruction(OP_LI, 1, 0, 0, 0x100),

        // Try to set correct tag to read protected memory
        create_instruction(OP_SETTAG, 1, 1, 0, 0x42),

        // ld x2, 0(x1) -- load from protected memory with correct tag
        create_instruction(OP_LOAD, 2, 1, 0, 0),

        // Change pointer tag to non-matching
        create_instruction(OP_SETTAG, 1, 1, 0, 0x00),

        // sd x2, 0(x1) -- try to store back with different tag
        create_instruction(OP_STORE, 0, 1, 2, 0),

        // halt
        create_instruction(OP_HALT, 0, 0, 0, 0)
    };

    // Load program at 0x1000
    load_test_program(&memory, program, 6, 0x1000);

    // Set PC to start of program
    cpu_state.pc = 0x1000;

    // Run the program
    FaultType result = cpu_run(&cpu_state, &memory, 10);

    // Verify that the attack should be detected
    // (in our model, we should get a tag check fault on store)
    assert(result == FAULT_TAG_CHECK_STORE);

    // Also check that the memory tag is still 0x42
    assert(mem_get_tag(&memory, 0x100) == 0x42);

    // Clean up
    mem_destroy(&memory);
}

void test_execute_data_attack() {
    // This test attempts to execute code from a data page

    cpu_init(&cpu_state);
    mem_init(&memory);

    // Set up memory permissions
    mem_set_page_permissions(&memory, 0, PERM_READ | PERM_WRITE); // data at 0x0-0xFFF (no EXEC)
    mem_set_page_permissions(&memory, 1, PERM_READ | PERM_EXEC);  // code at 0x1000

    // Create a simple program that tries to jump to a data page
    uint32_t program[] = {
        // li x1, 0x100 (address in data page)
        create_instruction(OP_LI, 1, 0, 0, 0x100),

        // Jump to data page
        create_instruction(OP_JUMPR, 0, 1, 0, 0),

        // halt (should not reach this)
        create_instruction(OP_HALT, 0, 0, 0, 0)
    };

    // Load program at 0x1000
    load_test_program(&memory, program, 3, 0x1000);

    // Also put some "code" in the data page
    uint32_t data_memory[] = {
        create_instruction(OP_LI, 2, 0, 0, 99),
        create_instruction(OP_HALT, 0, 0, 0, 0)
    };
    load_test_program(&memory, data_memory, 2, 0x100);

    // Set PC to start of program
    cpu_state.pc = 0x1000;

    // Run the program
    FaultType result = cpu_run(&cpu_state, &memory, 10);

    // Verify that the execution is caught
    assert(result == FAULT_INSTR_ACCESS);

    // Clean up
    mem_destroy(&memory);
}

void test_control_flow_hijack() {
    printf("\nNOTE: This test demonstrates a security vulnerability in our architecture:\n");
    printf("When storing pointers in memory, only the address portion (low 56 bits) is preserved.\n");
    printf("This allows attackers to manipulate stored addresses and hijack control flow.\n\n");

    cpu_init(&cpu_state);
    mem_init(&memory);

    // Set up memory permissions for all relevant pages
    mem_set_page_permissions(&memory, 0, PERM_READ | PERM_WRITE | PERM_EXEC); // make page 0 executable too
    mem_set_page_permissions(&memory, 1, PERM_READ | PERM_EXEC);              // code at 0x1000

    // Create the malicious code at address 0x40 (where the jump will go)
    uint32_t evil_code[] = {
        create_instruction(OP_LI, 5, 0, 0, 0xFF),   // x5 = 0xFF
        create_instruction(OP_HALT, 0, 0, 0, 0)     // halt
    };

    // Load the malicious code at address 0x40
    load_test_program(&memory, evil_code, 2, 0x40);

    // Create the safe code at address 0x28 (the intended target)
    uint32_t safe_code[] = {
        create_instruction(OP_LI, 5, 0, 0, 1),      // x5 = 1
        create_instruction(OP_HALT, 0, 0, 0, 0)     // halt
    };

    // Load the safe code at address 0x28
    load_test_program(&memory, safe_code, 2, 0x28);

    // Create the main program
    uint32_t program[] = {
        // li x1, 0x100 - Address to store return addr
        create_instruction(OP_LI, 1, 0, 0, 0x100),

        // Set up safe address (0x28)
        create_instruction(OP_LI, 2, 0, 0, 0x28),   // just the offset (0x28)

        // Store safe return addr
        create_instruction(OP_STORE, 0, 1, 2, 0),

        // Set up malicious address (0x40)
        create_instruction(OP_LI, 3, 0, 0, 0x40),   // just the offset (0x40)

        // Overwrite return addr (simulated buffer overflow)
        create_instruction(OP_STORE, 0, 1, 3, 0),

        // Load and jump to return addr
        create_instruction(OP_LOAD, 4, 1, 0, 0),
        create_instruction(OP_JUMPR, 0, 4, 0, 0)    // jump will go to 0x40
    };

    // Load program at 0x1000
    load_test_program(&memory, program, sizeof(program)/sizeof(program[0]), 0x1000);

    // Print out the program's instructions at key points for verification
    printf("Safe code at 0x28: 0x%08x\n", *(uint32_t*)&memory.data[0x28]);
    printf("Evil code at 0x40: 0x%08x\n", *(uint32_t*)&memory.data[0x40]);

    // Set PC to start of program
    cpu_state.pc = 0x1000;

    // Run the program
    FaultType result = cpu_run(&cpu_state, &memory, 20);

    // Print the final state
    printf("Final register x5 = 0x%llx\n", cpu_state.registers[5]);
    printf("Final PC = 0x%llx\n", cpu_state.pc);
    printf("Result = %s\n", fault_type_to_string(result));

    // In this architecture, the control flow hijack succeeds because:
    // 1. We only store the address part when writing pointers to memory
    // 2. We don't maintain pointer integrity across memory operations
    // 3. There's no control flow integrity validation

    // The attack successfully sets x5 to 0xFF by hijacking control flow
    assert(cpu_state.registers[5] == 0xFF);
    assert(result == FAULT_BREAKPOINT);

    // Clean up
    mem_destroy(&memory);

    printf("\nPotential mitigations that would prevent this attack:\n");
    printf("1. Store full pointer values (address + tag) in memory\n");
    printf("2. Implement control flow integrity checking\n");
    printf("3. Add return address signing or pointer authentication\n");
}

int main() {
    // Basic functionality tests
    RUN_TEST(test_basic_computation, false, FAULT_NONE);
    RUN_TEST(test_memory_operations, false, FAULT_NONE);

    // Security mitigations tests
    RUN_TEST(test_permission_violation, true, FAULT_STORE_ACCESS);
    RUN_TEST(test_wx_violation, true, FAULT_W_X_VIOLATION);
    RUN_TEST(test_tag_mismatch, true, FAULT_TAG_CHECK_LOAD);
    RUN_TEST(test_alignment_fault, true, FAULT_STORE_ADDR_MISALIGNED);

    // Attack tests
    RUN_TEST(test_tag_laundering_attack, true, FAULT_TAG_CHECK_STORE);
    RUN_TEST(test_execute_data_attack, true, FAULT_INSTR_ACCESS);
    RUN_TEST(test_control_flow_hijack, false, FAULT_NONE);

    printf("The CPU architecture provides strong memory safety guarantees through:\n");
    printf("1. Memory permissions (R/W/X) at page granularity\n");
    printf("2. W^X enforcement to prevent code injection\n");
    printf("3. Tagged pointers to prevent unauthorized memory access\n");
    printf("4. Alignment requirements to ensure proper memory access\n\n");

    printf("However, the architecture has limitations:\n");
    printf("1. Pointer integrity is not maintained across memory operations\n");
    printf("2. No control flow integrity protection\n");
    printf("3. Currently vulnerable to control flow hijacking attacks\n\n");

    printf("These limitations demonstrate real-world security challenges and\n");
    printf("highlight areas for future improvements in CPU security design.\n");

    return 0;
}
