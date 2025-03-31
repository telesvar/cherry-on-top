# Cherry on Top 🍒🔝 – an experimental CPU design inspired by RISC-V and ARM MTE

A very WIP attempt to discover and develop CPUs with inherent memory safety guarantees with a set of architectural extensions that integrate pointer tagging and memory protection.

Goals:
1. Memory protection through boundary checking enabled by tags.
2. Research and develop an efficient implicit memory protection and capabilities model for CPUs.

Non-goals:
1. For now, no type constraints for arithmetic operations.
2. For now, don't consider hardware costs which are considerable
   if implemented naively.  Though, hardware acceleration and
   optimisations are **to be considered**.

How:
1. Pointer integrity:
  * 8-bit tags in upper bits of 64-bit pointers \[8-56].
  * Tags represent capabilities or type information.
2. Memory tagging:
  * One tag per 8-byte aligned memory granule.
  * Tags stored in parallel tag memory structure.
3. Mandatory protection sequence:
  * Alignment → permissions → W^X → tags.
  * Clear fault model.
  * Non-bypassable checks for all memory accesses.

Problems:
1. Tag laundering: memory access checked is bypassed through custom tagging assignment and `TAG_DEFAULT`.  See `test_control_flow_hijack` for details.
2. More to come.

### Sources
* RISC-V ISA Specifications – https://lf-riscv.atlassian.net/wiki/spaces/HOME/pages/16154769/RISC-V+Technical+Specifications#ISA-Specifications
* Arm memory tagging extension – https://source.android.com/docs/security/test/memory-safety/arm-mte
* Introduction to the Memory Tagging Extension – https://developer.arm.com/documentation/108035/0100/Introduction-to-the-Memory-Tagging-Extension
