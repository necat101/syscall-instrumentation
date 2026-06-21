/*
 * syscall_instrumentation_v2.c
 * 
 * FIXED VERSION - Addresses all feedback from code review
 * 
 * Fixes applied:
 * 1. Use strlen() instead of hardcoded lengths
 * 2. Changed long to ssize_t for write() functions
 * 3. Added dlsym() error checking
 * 4. Added fflush(stdout) for proper output ordering
 * 5. Renamed to "Manual instrumentation simulation"
 * 6. Fixed benchmark to compare same syscalls
 * 7. Use ratio instead of percentage
 * 8. Added noinline, used attributes
 * 9. Fixed buffer overrun in code scanning
 * 10. More accurate title/comments
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
// Marked noinline+used to ensure it exists for inspection
__attribute__((noinline, used))
static long direct_syscall0(long n) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n)
        : "rcx", "r11", "memory"
    );
    return ret;
}

__attribute__((noinline, used))
static long direct_syscall1(long n, long a1) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1)
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

// Test 1: Fixed - compare apples to apples
void test_syscall_overhead() {
    const int iterations = 1000000;
    const int warmup = 10000;
    long long start, end;
    long long direct_time, libc_time;
    volatile struct timeval tv; // volatile to prevent optimization
    
    printf("=== Test 1: Syscall Overhead Comparison (FIXED) ===\n");
    printf("Running %d iterations of gettimeofday()...\n", iterations);
    printf("Comparing: raw syscall vs libc wrapper (same operation)\n\n");
    
    // Warmup
    for (int i = 0; i < warmup; i++) {
        syscall(SYS_gettimeofday, (struct timeval*)&tv, NULL);
        gettimeofday((struct timeval*)&tv, NULL);
    }
    
    // Test 1a: Direct syscall
    start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        syscall(SYS_gettimeofday, (struct timeval*)&tv, NULL);
    }
    end = get_time_ns();
    direct_time = end - start;
    
    // Test 1b: libc wrapper (which uses vDSO when available)
    start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        gettimeofday((struct timeval*)&tv, NULL);
    }
    end = get_time_ns();
    libc_time = end - start;
    
    printf("Direct syscall:  %lld ns total, %.2f ns/call\n", 
           direct_time, (double)direct_time / iterations);
    printf("libc wrapper:    %lld ns total, %.2f ns/call\n", 
           libc_time, (double)libc_time / iterations);
    printf("\n");
    printf("  libc/direct ratio: %.3fx\n", (double)libc_time / direct_time);
    if (libc_time < direct_time) {
        printf("  → libc is faster (likely using vDSO, no kernel transition)\n");
    } else {
        printf("  → direct syscall is faster (libc overhead)\n");
    }
    printf("\n");
}

// Test 2: Fixed buffer overrun and added bounds checking
void test_syscall_encoding() {
    printf("=== Test 2: Syscall Instruction Encoding ===\n");
    printf("The syscall instruction is 2 bytes: 0x0f 0x05\n\n");
    
    unsigned char *code = (unsigned char*)direct_syscall0;
    const size_t scan_len = 32; // Safe bound
    
    printf("Direct syscall function bytes (first %zu):\n", scan_len);
    for (size_t i = 0; i < scan_len; i++) {
        printf("%02x ", code[i]);
        if ((i + 1) % 8 == 0) printf(" ");
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
    
    // Find the syscall instruction with proper bounds checking
    int found = 0;
    for (size_t i = 0; i < scan_len - 1; i++) {
        if (code[i] == 0x0f && code[i+1] == 0x05) {
            printf("Found syscall instruction at offset %zu: 0f 05\n", i);
            if (i + 5 < scan_len) {
                printf("Next bytes: %02x %02x %02x %02x\n", 
                       code[i+2], code[i+3], code[i+4], code[i+5]);
            }
            found = 1;
            break;
        }
    }
    if (!found) {
        printf("Syscall instruction not found in first %zu bytes\n", scan_len);
        printf("(Function may be too small or compiler optimized differently)\n");
    }
    printf("\n");
}

// Test 7: FIXED VERSION with proper types and error handling
static ssize_t (*real_write)(int, const void *, size_t) = NULL;

ssize_t instrumented_write(int fd, const void *buf, size_t count) {
    static int call_count = 0;
    call_count++;
    
    if (call_count <= 3) {
        // Use write() directly to avoid recursion if this were a real hook
        // fprintf() calls write() internally!
        char msg[128];
        int len = snprintf(msg, sizeof(msg), 
                          "[INSTRUMENTED] write(fd=%d, count=%zu) call #%d\n", 
                          fd, count, call_count);
        // In a real implementation, we'd use the real write here
        // For demo, we just print to stderr via direct syscall to avoid recursion
        syscall(SYS_write, STDERR_FILENO, msg, len);
    }
    
    // Initialize real_write with error checking
    if (!real_write) {
        dlerror(); // Clear any existing error
        real_write = dlsym(RTLD_NEXT, "write");
        char *err = dlerror();
        if (err) {
            // Can't use fprintf here in real hook - would recurse!
            // Use direct syscall to report error
            const char *err_msg = "dlsym(write) failed\n";
            syscall(SYS_write, STDERR_FILENO, err_msg, strlen(err_msg));
            _exit(1);
        }
    }
    return real_write(fd, buf, count);
}

void test_instrumentation_demo() {
    printf("=== Test 7: Manual Instrumentation Simulation (FIXED) ===\n");
    printf("Note: This is a SIMULATION - not actual interception\n");
    printf("Real LD_PRELOAD would override write() globally\n\n");
    
    // FIX: Use strlen() instead of hardcoded values
    // FIX: Add fflush() to ensure proper ordering
    fflush(stdout);
    
    const char *msg1 = "Hello from instrumented write!\n";
    instrumented_write(STDOUT_FILENO, msg1, strlen(msg1));
    
    const char *msg2 = "This call was intercepted\n";
    instrumented_write(STDOUT_FILENO, msg2, strlen(msg2));
    
    printf("\nIn a real LD_PRELOAD implementation:\n");
    printf("  - Function would be named 'write' (not instrumented_write)\n");
    printf("  - Would be compiled as shared library\n");
    printf("  - LD_PRELOAD would interpose it before libc\n");
    printf("  - Must avoid recursion (fprintf → write → fprintf...)\n");
    printf("  - Use direct syscalls or recursion guards\n\n");
}

int main() {
    printf("=================================================================\n");
    printf("Syscall Instrumentation Concepts - FIXED VERSION\n");
    printf("Addresses code review feedback\n");
    printf("=================================================================\n\n");
    
    test_syscall_overhead();
    test_syscall_encoding();
    test_instrumentation_demo();
    
    printf("=================================================================\n");
    printf("All fixes applied successfully!\n");
    printf("=================================================================\n");
    
    return 0;
}
