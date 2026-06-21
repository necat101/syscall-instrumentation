#!/usr/bin/env python3
"""
syscall_instrumentation_demo.py

Python simulation of syscall instrumentation concepts from:
https://www.humprog.org/~stephen/blog/2026/06/15/

Demonstrates the key ideas without requiring compilation.
"""

import time
import sys

def print_header(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70 + "\n")

def test_1_syscall_overhead_simulation():
    """Simulate syscall overhead comparison"""
    print_header("Test 1: Syscall Overhead Simulation")
    
    iterations = 1_000_000
    
    # Simulate direct syscall (baseline)
    start = time.perf_counter_ns()
    for _ in range(iterations):
        pass  # Simulating direct syscall overhead
    direct_time = time.perf_counter_ns() - start
    
    # Simulate libc wrapper (small overhead)
    start = time.perf_counter_ns()
    for _ in range(iterations):
        x = 1 + 1  # Simulating libc wrapper overhead
    libc_time = time.perf_counter_ns() - start
    
    # Simulate vDSO (no kernel transition)
    start = time.perf_counter_ns()
    for _ in range(iterations):
        y = 2 + 2  # Simulating vDSO (userspace only)
    vdso_time = time.perf_counter_ns() - start
    
    print(f"Running {iterations:,} iterations...\n")
    print(f"Direct syscall simulation:  {direct_time:>12,} ns total")
    print(f"libc wrapper simulation:    {libc_time:>12,} ns total")
    print(f"vDSO simulation:            {vdso_time:>12,} ns total")
    print()
    print("In real measurements:")
    print("  - Direct syscall: ~100-200 ns")
    print("  - libc wrapper:   ~100-250 ns (minimal overhead)")
    print("  - vDSO:           ~10-20 ns (no context switch!)")
    print("  - vDSO is 10-20x faster than syscall")

def test_2_instruction_encoding():
    """Demonstrate instruction encoding challenge"""
    print_header("Test 2: Instruction Encoding Challenge")
    
    print("The core problem: syscall is 2 bytes, jumps are 5+ bytes")
    print()
    print("x86-64 instruction encodings:")
    print("  syscall:              0f 05                    (2 bytes)")
    print("  ud2 (illegal):         0f 0b                    (2 bytes)")
    print("  call *%rax:            ff d0                    (2 bytes)")
    print("  jmp rel32:             e9 XX XX XX XX           (5 bytes)")
    print("  call rel32:            e8 XX XX XX XX           (5 bytes)")
    print("  call *disp32(%rip):    ff 15 XX XX XX XX        (6 bytes)")
    print()
    print("Problem: Can't replace 2 bytes with 5 bytes!")
    print("Solution approaches:")
    print("  1. Use another 2-byte instruction (ud2, call *%rax)")
    print("  2. Instruction punning: reuse next 3 bytes as displacement")
    print("  3. Relocate entire function (expensive)")

def test_3_zpoline_simulation():
    """Simulate zpoline approach"""
    print_header("Test 3: zpoline Concept")
    
    print("zpoline: Replace 'syscall' with 'call *%rax'")
    print()
    print("How it works:")
    print("  Before:  [0f 05]  syscall")
    print("           [%rax = 1]  (sys_write)")
    print()
    print("  After:   [ff d0]  call *%rax")
    print("           [%rax = 1]  → calls address 0x1")
    print()
    print("Setup required:")
    print("  - Map executable code at addresses 0x0 - 0x200")
    print("  - Each address corresponds to a syscall number")
    print("  - Handler at each address does the actual syscall")
    print()
    
    # Simulate the mapping
    syscall_numbers = {
        0: "read", 1: "write", 2: "open", 3: "close",
        60: "exit", 57: "fork", 59: "execve"
    }
    
    print("Example mapping:")
    for num, name in list(syscall_numbers.items())[:5]:
        print(f"  Address 0x{num:02x}: handler for sys_{name}()")
    print("  ...")
    
    print()
    print("Trade-offs:")
    print("  ✓ No signal handling (fast)")
    print("  ✓ Works for any 2-byte site")
    print("  ✗ Breaks NULL pointer protection")
    print("  ✗ Requires privileges to map low memory")
    print("  ✗ Need MPK or validation for safety")

def test_4_instruction_punning():
    """Demonstrate instruction punning"""
    print_header("Test 4: Instruction Punning (E9Patch approach)")
    
    print("Idea: Use bytes AFTER syscall as jump displacement")
    print()
    print("Example:")
    print("  Original code at 0x401000:")
    print("    0x401000: 0f 05          syscall")
    print("    0x401002: 48 89 c7       mov %rax, %rdi")
    print("    0x401005: e8 XX XX XX XX call somewhere")
    print()
    print("  Patched code:")
    print("    0x401000: e9 48 89 c7 00  jmp 0x401000 + 5 + 0x00c78948")
    print("                    ^^^^^^^^^")
    print("                    These bytes are REUSED from next instruction!")
    print()
    print("  Target: 0x401000 + 5 + 0x00c78948 = 0x408e4a?  (example)")
    print()
    
    # Simulate finding a free spot
    import random
    random.seed(42)  # Deterministic for demo
    
    print("In practice:")
    print("  - Displacement is 32-bit signed (±2GB range)")
    print("  - We need to find unused memory in that range")
    print("  - Place trampoline code there")
    print("  - Trampoline does instrumentation, then original syscall")
    print()
    
    # Simulate success rate
    attempts = 1000
    successes = 0
    for _ in range(attempts):
        # Simulate random displacement from punned bytes
        disp = random.randint(-0x80000000, 0x7fffffff)
        # Simulate checking if address is free (simplified)
        # In reality, would check /proc/self/maps
        if abs(disp) < 0x40000000:  # Within 1GB, more likely to be free
            successes += 1
    
    print(f"Simulated success rate: {successes}/{attempts} ({100*successes/attempts:.1f}%)")
    print("  (Actual rate depends on binary layout and ASLR)")
    print()
    print("E9Patch improvements:")
    print("  - Multiple punning strategies (different instruction forms)")
    print("  - 'Neighbor eviction' for difficult cases")
    print("  - Virtual memory tricks to share physical pages")

def test_5_memory_indirect():
    """Demonstrate memory-indirect approach from article"""
    print_header("Test 5: Memory-Indirect Calls (Article's Approach)")
    
    print("Article explores: call *disp32(%rip) and lcall *disp32(%rax)")
    print()
    print("Memory-indirect call:")
    print("  ff 15 XX XX XX XX    call *0xXXXXXXXX(%rip)")
    print("  ")
    print("  CPU does:")
    print("    1. Calculate address: %rip + displacement")
    print("    2. Load 8 bytes from that address")
    print("    3. Jump to that address")
    print()
    print("For instrumentation:")
    print("  - We control the displacement (via punned bytes)")
    print("  - We place our handler address at that memory location")
    print("  - CPU loads it and jumps to our handler")
    print()
    
    print("Far call variant (lcall):")
    print("  ff 1d XX XX XX XX    lcall *0xXXXXXXXX(%rip)")
    print("  Loads 6 bytes: 2-byte segment selector + 4-byte offset")
    print("  Can use repeating bytes: 0x1f1f1f1f1f1f")
    print("  → Always decodes to same address regardless of alignment!")
    print()
    
    print("Article's conclusion:")
    print("  - Clever, but limited practical benefit")
    print("  - More complex than zpoline or E9Patch")
    print("  - Still needs low memory mapping for %rax variant")
    print("  - Author implemented prototype but didn't pursue further")

def test_6_hn_discussion_summary():
    """Summarize HN discussion points"""
    print_header("Test 6: HN Discussion Summary")
    
    print("Core Debate: Direct syscalls vs libc/vDSO mediation")
    print()
    print("Team 'Direct Syscalls Are Good' (Linux model):")
    print("  • Full kernel API access without libc dependency")
    print("  • Flexibility for containers, static binaries, alternative libcs")
    print("  • Can write tools in assembly without libc bloat")
    print("  • Decoupling is architecturally clean")
    print()
    print("Team 'Mediated Syscalls Are Good' (OpenBSD/Windows model):")
    print("  • Easy to intercept/hook all syscalls in one place")
    print("  • Better for security instrumentation")
    print("  • Simplifies ABI compatibility")
    print("  • LD_PRELOAD 'just works'")
    print()
    print("Practical Alternatives Mentioned:")
    print("  • seccomp-bpf: Filter syscalls in kernel")
    print("  • seccomp user notification: Handle in userspace")
    print("  • eBPF tracepoints: Monitor without stopping process")
    print("  • ftrace: Kernel function tracing")
    print("  • io_uring: Batch syscalls to reduce overhead")
    print()
    print("Consensus: Different tools for different jobs")
    print("  - For security: seccomp, eBPF")
    print("  - For debugging: ptrace, LD_PRELOAD")
    print("  - For performance: vDSO, io_uring, direct syscalls")
    print("  - For instrumentation: Depends on requirements!")

def main():
    print("=" * 70)
    print("SYSCALL INSTRUMENTATION CONCEPTS DEMO")
    print("Based on: https://www.humprog.org/~stephen/blog/2026/06/15/")
    print("HN Discussion: https://news.ycombinator.com/item?id=48566824")
    print("=" * 70)
    
    test_1_syscall_overhead_simulation()
    test_2_instruction_encoding()
    test_3_zpoline_simulation()
    test_4_instruction_punning()
    test_5_memory_indirect()
    test_6_hn_discussion_summary()
    
    print_header("Summary")
    print("Key takeaways:")
    print("  1. Syscall instrumentation is hard because syscalls are 2 bytes")
    print("  2. Multiple clever approaches exist with different trade-offs")
    print("  3. No perfect solution - depends on requirements")
    print("  4. For most use cases, existing tools (eBPF, seccomp) are better")
    print("  5. Direct syscall vs mediated is an architectural trade-off")
    print()
    print("The article's exploration of memory-indirect far calls is")
    print("intellectually interesting but practically limited.")
    print("Existing solutions (zpoline, E9Patch) are more mature.")
    print()
    print("Demo complete!")

if __name__ == "__main__":
    main()
