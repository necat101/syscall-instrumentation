/*
 * syscall_instrumentation.c
 * 
 * Experiments with syscall instrumentation on Linux/x86-64
 * Based on: https://www.humprog.org/~stephen/blog/2026/06/15/
 * HN Discussion: https://news.ycombinator.com/item?id=48566824
 * 
 * This program demonstrates:
 * 1. Direct syscalls vs libc wrappers vs vDSO
 * 2. Syscall overhead measurement
 * 3. Basic instrumentation concepts
 * 4. Comparison of interception approaches
 * 
 * Key concepts from the article:
 * - System calls are 2 bytes (0f 05) but jumps are 5+ bytes
 * - Instruction punning: using next instruction bytes as jump offset
 * - zpoline: call *%rax where rax = syscall number (maps handler at low addresses)
 * - Memory-indirect calls for instrumentation
 * 
 * HN Discussion points addressed:
 * - Direct syscalls vs libc/vDSO trade-offs
 * - Syscall overhead in practice
 * - Alternatives: seccomp, bpf, ftrace
 * - Security implications
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/mman.h>

// Direct syscall using inline assembly
static inline long direct_syscall0(long n) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long direct_syscall1(long n, long a1) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long direct_syscall3(long n, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

// Timing helper
static inline long long get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

// Test 1: Direct syscall vs libc wrapper overhead
void test_syscall_overhead() {
    const int iterations = 1000000;
    long long start, end;
    long long direct_time, libc_time, vdso_time;
    
    printf("=== Test 1: Syscall Overhead Comparison ===\n");
    printf("Running %d iterations of getpid()...\n\n", iterations);
    
    // Test 1a: Direct syscall
    start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        direct_syscall0(SYS_getpid);
    }
    end = get_time_ns();
    direct_time = end - start;
    
    // Test 1b: libc wrapper
    start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        getpid();
    }
    end = get_time_ns();
    libc_time = end - start;
    
    // Test 1c: vDSO (gettimeofday is often in vDSO)
    struct timeval tv;
    start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        gettimeofday(&tv, NULL);
    }
    end = get_time_ns();
    vdso_time = end - start;
    
    printf("Direct syscall:  %lld ns total, %.2f ns/call\n", 
           direct_time, (double)direct_time / iterations);
    printf("libc getpid():   %lld ns total, %.2f ns/call\n", 
           libc_time, (double)libc_time / iterations);
    printf("vDSO gettimeofday: %lld ns total, %.2f ns/call\n", 
           vdso_time, (double)vdso_time / iterations);
    printf("\nOverhead:\n");
    printf("  libc wrapper: %.2f%% overhead vs direct\n", 
           ((double)libc_time / direct_time - 1) * 100);
    printf("  vDSO vs syscall: %.2fx faster (no kernel transition)\n", 
           (double)direct_time / vdso_time);
    printf("\n");
}

// Test 2: Demonstrate the 2-byte syscall instruction
void test_syscall_encoding() {
    printf("=== Test 2: Syscall Instruction Encoding ===\n");
    printf("The syscall instruction is 2 bytes: 0x0f 0x05\n");
    printf("This is the challenge for instrumentation - jumps are 5+ bytes\n\n");
    
    // Show actual bytes of a syscall
    unsigned char *code = (unsigned char*)direct_syscall0;
    
    printf("Direct syscall function bytes (first 16):\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", code[i]);
        if ((i + 1) % 8 == 0) printf(" ");
    }
    printf("\n");
    
    // Find the syscall instruction (0f 05)
    for (int i = 0; i < 15; i++) {
        if (code[i] == 0x0f && code[i+1] == 0x05) {
            printf("Found syscall instruction at offset %d: 0f 05\n", i);
            printf("Next bytes: %02x %02x %02x %02x\n", 
                   code[i+2], code[i+3], code[i+4], code[i+5]);
            break;
        }
    }
    printf("\n");
}

// Test 3: Simulate zpoline-style instrumentation concept
void test_zpoline_concept() {
    printf("=== Test 3: zpoline Concept Simulation ===\n");
    printf("zpoline replaces 'syscall' (0f 05) with 'call *%%rax' (ff d0)\n");
    printf("Since %%rax = syscall number (small int), it calls low address\n");
    printf("Handler must be mapped at addresses 0-512\n\n");
    
    printf("Concept demonstration:\n");
    printf("  Original:  0f 05          syscall\n");
    printf("  Patched:   ff d0          call *%%rax\n");
    printf("  If %%rax=1 (write): calls address 0x1\n");
    printf("  If %%rax=60 (exit): calls address 0x3c\n\n");
    
    printf("Trade-offs (from HN discussion):\n");
    printf("  + No signal handling overhead (unlike libsystrap's ud2 approach)\n");
    printf("  + Works for 2-byte patch sites\n");
    printf("  - Requires mapping low memory (needs privileges on Linux)\n");
    printf("  - Breaks NULL pointer protection\n");
    printf("  - Needs MPK or validation to catch NULL derefs\n");
    printf("  - Unpredictable if %%rax is large\n\n");
}

// Test 4: Memory-indirect call simulation
void test_memory_indirect_concept() {
    printf("=== Test 4: Memory-Indirect Call Instrumentation ===\n");
    printf("Article explores: ff 1d XX XX XX XX  (call *disp32(%%rip))\n");
    printf("                  ff 98 XX XX XX XX  (lcall *disp32(%%rax))\n\n");
    
    printf("Idea: Use bytes after syscall as displacement\n");
    printf("  syscall at 0x401000: 0f 05 48 89 c7 ...\n");
    printf("  Patch to:            ff 15 48 89 c7 ... (call *0xc78948(%%rip))\n");
    printf("  The '48 89 c7' bytes become part of the jump target!\n\n");
    
    printf("This is 'instruction punning' - reusing instruction bytes\n");
    printf("as data (displacement) for the patch.\n\n");
    
    printf("Challenges:\n");
    printf("  - Displacement is only 32-bit (±2GB range)\n");
    printf("  - Must find free memory within range\n");
    printf("  - Different patch sites need different displacements\n");
    printf("  - Article's conclusion: Limited utility, complex to implement\n\n");
}

// Test 5: Compare interception methods (from HN discussion)
void test_interception_methods() {
    printf("=== Test 5: Syscall Interception Methods Comparison ===\n");
    printf("(Based on HN discussion points)\n\n");
    
    printf("1. Direct Patching (libsystrap, E9Patch, zpoline):\n");
    printf("   Pros: Low overhead, transparent to application\n");
    printf("   Cons: Complex, fragile, security concerns\n");
    printf("   Use case: Performance-critical instrumentation\n\n");
    
    printf("2. LD_PRELOAD (libc interposition):\n");
    printf("   Pros: Simple, portable, no kernel changes\n");
    printf("   Cons: Only works for libc calls, not direct syscalls\n");
    printf("   Use case: Debugging, testing, simple interposition\n\n");
    
    printf("3. seccomp + user notification:\n");
    printf("   Pros: Kernel-supported, secure, flexible\n");
    printf("   Cons: Higher overhead, requires setup\n");
    printf("   Use case: Sandboxing, syscall filtering\n\n");
    
    printf("4. eBPF tracepoints / kprobes:\n");
    printf("   Pros: Very flexible, kernel-level visibility\n");
    printf("   Cons: Requires privileges, complex to write\n");
    printf("   Use case: Production monitoring, profiling\n\n");
    
    printf("5. ptrace:\n");
    printf("   Pros: Standard, works everywhere\n");
    printf("   Cons: Very high overhead (~1000x), stops target\n");
    printf("   Use case: Debuggers (gdb, strace)\n\n");
    
    printf("6. ftrace:\n");
    printf("   Pros: Built into kernel, low overhead\n");
    printf("   Cons: Kernel-side only, limited filtering\n");
    printf("   Use case: Kernel debugging, performance analysis\n\n");
}

// Test 6: Demonstrate vDSO vs real syscall
void test_vdso_detection() {
    printf("=== Test 6: vDSO Detection ===\n");
    
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[256];
        printf("Memory mappings containing 'vdso':\n");
        while (fgets(line, sizeof(line), maps)) {
            if (strstr(line, "vdso") || strstr(line, "vsyscall")) {
                printf("  %s", line);
            }
        }
        fclose(maps);
    }
    
    printf("\nvDSO functions (no syscall, userspace only):\n");
    printf("  - gettimeofday\n");
    printf("  - clock_gettime (some clocks)\n");
    printf("  - getcpu\n");
    printf("  - time\n\n");
    
    printf("These avoid the expensive kernel transition.\n");
    printf("HN discussion: vDSO is a middle ground between\n");
    printf("direct syscalls and full libc wrappers.\n\n");
}

// Test 7: Actual instrumentation demo
static long (*real_write)(int, const void *, size_t) = NULL;

long instrumented_write(int fd, const void *buf, size_t count) {
    static int call_count = 0;
    call_count++;
    
    if (call_count <= 3) {
        fprintf(stderr, "[INSTRUMENTED] write(fd=%d, count=%zu) call #%d\n", 
                fd, count, call_count);
    }
    
    if (!real_write) {
        real_write = dlsym(RTLD_NEXT, "write");
    }
    return real_write(fd, buf, count);
}

void test_instrumentation_demo() {
    printf("=== Test 7: Instrumentation Demo ===\n");
    printf("Simulating what LD_PRELOAD or patched syscall would do:\n\n");
    
    instrumented_write(STDOUT_FILENO, "Hello from instrumented write!\n", 30);
    instrumented_write(STDOUT_FILENO, "This call was intercepted\n", 26);
    
    printf("\nIn real instrumentation:\n");
    printf("  - libsystrap: patches syscall to ud2, handles in SIGILL\n");
    printf("  - zpoline: patches to 'call *%%rax', jumps to low memory handler\n");
    printf("  - E9Patch: uses instruction punning with trampolines\n");
    printf("  - This demo: simple function interposition\n\n");
}

int main() {
    printf("=================================================================\n");
    printf("Syscall Instrumentation Experiments - Linux/x86-64\n");
    printf("Based on Stephen Kell's blog and HN discussion #48566824\n");
    printf("=================================================================\n\n");
    
    test_syscall_overhead();
    test_syscall_encoding();
    test_zpoline_concept();
    test_memory_indirect_concept();
    test_interception_methods();
    test_vdso_detection();
    test_instrumentation_demo();
    
    printf("=================================================================\n");
    printf("Summary - Key Takeaways from Article & HN Discussion:\n");
    printf("=================================================================\n\n");
    
    printf("1. Direct syscalls vs libc:\n");
    printf("   - Linux allows direct syscalls (ABI stable)\n");
    printf("   - Trade-off: Flexibility vs interceptability\n");
    printf("   - HN debate: Some call it 'terrible', others 'amazing'\n\n");
    
    printf("2. Instrumentation challenges:\n");
    printf("   - Syscall is 2 bytes, jumps are 5+ bytes\n");
    printf("   - Instruction punning reuses next bytes as offset\n");
    printf("   - Each approach has trade-offs (memory, security, complexity)\n\n");
    
    printf("3. Article's conclusion:\n");
    printf("   - Memory-indirect lcall approach has limited utility\n");
    printf("   - Complex to implement correctly\n");
    printf("   - Existing solutions (zpoline, E9Patch) are more practical\n\n");
    
    printf("4. Practical alternatives (from HN):\n");
    printf("   - For most use cases: seccomp, eBPF, ftrace\n");
    printf("   - For debugging: ptrace, LD_PRELOAD\n");
    printf("   - For performance: vDSO, io_uring, direct syscalls\n\n");
    
    printf("Test completed successfully!\n");
    
    return 0;
}
