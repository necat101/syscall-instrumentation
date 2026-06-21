# Syscall Instrumentation Experiments

Experiments with system call instrumentation on Linux/x86-64 based on Stephen Kell's research and HN discussion #48566824.

## Overview

This project explores techniques for intercepting and instrumenting system calls on Linux/x86-64, focusing on the challenges posed by the 2-byte `syscall` instruction (0f 05) vs 5+ byte jump instructions.

**Based on:**
- Blog: https://www.humprog.org/~stephen/blog/2026/06/15/
- HN Discussion: https://news.ycombinator.com/item?id=48566824
- libsystrap: https://github.com/stephenrkell/libsystrap

## Key Concepts

### The Core Problem
```
syscall instruction:  0f 05  (2 bytes)
Near jump:            e9 XX XX XX XX  (5 bytes)
Near call:            e8 XX XX XX XX  (5 bytes)
```

You can't replace a 2-byte syscall with a 5-byte jump without overwriting the next 3 bytes of code!

### Solutions Explored

#### 1. **Instruction Punning** (Liteinst, E9Patch)
Reuse bytes from the *next* instruction as part of the jump offset:
```
Before: 0f 05 48 89 c7    (syscall; mov %rax,%rdi)
After:  e9 48 89 c7 XX    (jmp +0xc78948)
```
The bytes `48 89 c7` become the displacement. If they point to free memory, we can place a trampoline there.

**Pros:** Works in many cases, no signals
**Cons:** Statistical (may fail), needs lots of virtual address space

#### 2. **zpoline**
Replace syscall with `call *%rax` (ff d0):
- `%rax` contains syscall number (e.g., 1 for write, 60 for exit)
- Calls address 0x1, 0x3c, etc. (very low memory)
- Map handler code at those low addresses

**Pros:** Always works for 2-byte sites, very fast
**Cons:** 
- Requires mapping page 0 (needs privileges, breaks NULL protection)
- Needs MPK or validation to catch real NULL derefs
- Unpredictable if `%rax` is large

#### 3. **Signal-based (libsystrap)**
Replace syscall with `ud2` (0f 0b):
- Generates SIGILL
- Handler does the syscall and returns

**Pros:** Always works, simple
**Cons:** Double trap overhead, complex signal handling

#### 4. **Memory-Indirect Calls (Article's Exploration)**
Use `call *disp32(%rip)` or `lcall *disp32(%rax)`:
```
ff 15 XX XX XX XX  call *disp32(%rip)
ff 98 XX XX XX XX  lcall *disp32(%rax)  ; far call via LDT
```

**Article's conclusion:** Limited utility, complex, not better than existing approaches.

## HN Discussion Highlights

### Direct Syscalls vs libc/vDSO

**Arguments FOR direct syscalls (Linux model):**
- "Amazing idea" - full kernel API access without libc
- Flexibility, decoupled from userspace
- Can write utilities in pure assembly
- Containers work across different libc versions
- No forced C FFI

**Arguments AGAINST:**
- "Terrible idea" - robs ability to intercept in userspace
- Makes instrumentation harder
- libc becomes security boundary without kernel protection
- Windows/BSD model (via ntdll/libc) is cleaner for interception

### Interception Methods Discussed

1. **LD_PRELOAD**
   - Only works for libc calls
   - Can't intercept direct syscalls
   - vDSO is injected by kernel, but ld.so manages it

2. **seccomp + user notification**
   - Kernel-supported, secure
   - Higher overhead but flexible
   - Good for sandboxing

3. **eBPF tracepoints**
   - Very flexible, kernel-level
   - Requires privileges
   - Production monitoring standard

4. **ftrace**
   - Built-in, low overhead
   - Kernel-side only

5. **ptrace**
   - Standard but ~1000x overhead
   - Stops target process

### Performance Considerations

From the discussion:
- Syscall overhead matters for high-frequency operations
- Solutions exist for latency-sensitive workloads:
  - **io_uring**: Batch syscalls, async I/O
  - **DPDK**: Kernel bypass for networking
  - **futex**: Efficient userspace synchronization
  - **vDSO**: Avoid kernel transition entirely

## Building and Running

```bash
# Compile
gcc -O2 -o syscall_instrumentation syscall_instrumentation.c -ldl

# Run
./syscall_instrumentation

# Or run Python demo (no compilation needed)
python3 demo.py
```

## Expected Output

The program demonstrates:

1. **Syscall Overhead Comparison**
   - Direct syscall vs libc wrapper vs vDSO
   - Typical results: vDSO ~10-100x faster than syscall

2. **Instruction Encoding**
   - Shows actual bytes of syscall instruction
   - Demonstrates the 2-byte vs 5-byte problem

3. **Conceptual Demonstrations**
   - How zpoline would work
   - How instruction punning works
   - Memory-indirect call approaches

4. **Method Comparison**
   - Trade-offs of different interception techniques
   - When to use each approach

## Files

- `syscall_instrumentation.c` - Main test program (requires compilation)
- `demo.py` - Python simulation (runs anywhere)
- `Makefile` - Build configuration
- `README.md` - This file

## Key Takeaways from Article

Stephen Kell's exploration of memory-indirect far calls via LDT:

**What was tried:**
- Using `lcall *(%rax)` with LDT entries
- Memory-indirect calls: `call *disp32(%rip)`, `call *disp32(%rax)`, `lcall *disp32(%rax)`
- Idea: Fill memory with repeating byte patterns that decode to the same handler address

**Why it didn't work well:**
1. `%rax`-relative: Need to fill 512 consecutive bytes with valid addresses (impossible for 8-byte near addresses, possible for 6-byte far addresses with repeating bytes)
2. Still needs low memory mapping (though not page 0)
3. Limited to ~50% of patch sites (negative displacements don't work)
4. Complex to implement correctly
5. No clear advantage over zpoline or E9Patch

**Interesting findings:**
- Far calls can use repeating-byte addresses (e.g., 0x1f1f:0x1f1f1f1f)
- Can share physical pages via virtual memory tricks
- LDT manipulation is possible but adds complexity

## Further Reading

- **libsystrap**: https://github.com/stephenrkell/libsystrap
- **zpoline paper**: https://www.usenix.org/system/files/atc20-yamamoto.pdf
- **E9Patch**: https://github.com/GJDuck/e9patch
- **Liteinst**: https://dl.acm.org/doi/10.1145/3062341.3062344
- **Original blog post**: https://www.humprog.org/~stephen/blog/2026/06/15/

## License

MIT - Educational purposes
