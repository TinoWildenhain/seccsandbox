#include "sandbox.h"
#include <stdint.h>  // Add this line for uint32_t

#define ALLOW_SYSCALL(name) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

int setup_seccomp(struct sandbox_config *config) {
    // Determine the default action based on configuration
    uint32_t default_action;
    switch (config->seccomp_mode) {
        case SECCOMP_MODE_LOG:
            default_action = SECCOMP_RET_LOG;
            break;
        case SECCOMP_MODE_ERRNO:
            default_action = SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA);
            break;
        case SECCOMP_MODE_KILL:
        default:
            default_action = SECCOMP_RET_KILL_PROCESS;
            break;
    }

    struct sock_filter filter[] = {
        // Load architecture
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),

        // Check architecture (x86_64)
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),

        // Load syscall number
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

        // Special handling for clone3 - return ENOSYS to force fallback to clone()
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_clone3, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),

        // Program execution
        ALLOW_SYSCALL(execve),           // Execute a new program

        // File I/O operations
        ALLOW_SYSCALL(read),             // Read from file descriptor
        ALLOW_SYSCALL(write),            // Write to file descriptor
        ALLOW_SYSCALL(open),             // Open file (legacy)
        ALLOW_SYSCALL(openat),           // Open file relative to directory fd
        ALLOW_SYSCALL(close),            // Close file descriptor

        // File metadata operations
        ALLOW_SYSCALL(stat),             // Get file status (legacy)
        ALLOW_SYSCALL(fstat),            // Get file status by fd
        ALLOW_SYSCALL(lstat),            // Get file status, don't follow symlinks
        ALLOW_SYSCALL(newfstatat),       // Get file status relative to directory fd
        ALLOW_SYSCALL(statx),            // Get extended file status (modern)
        ALLOW_SYSCALL(statfs),           // Get filesystem statistics
        ALLOW_SYSCALL(fstatfs),          // Get filesystem statistics by fd
        ALLOW_SYSCALL(access),           // Check file permissions (legacy)
        ALLOW_SYSCALL(faccessat),        // Check file permissions relative to directory fd

        // Advanced I/O and file optimization
        ALLOW_SYSCALL(pread64),          // Read from file at offset
        ALLOW_SYSCALL(pwrite64),         // Write to file at offset
        ALLOW_SYSCALL(fadvise64),        // File access pattern advice

        // File positioning and control
        ALLOW_SYSCALL(lseek),            // Change file position
        ALLOW_SYSCALL(fcntl),            // File control operations
        ALLOW_SYSCALL(ioctl),            // Device control operations

        // Memory management
        ALLOW_SYSCALL(mmap),             // Map memory
        ALLOW_SYSCALL(mprotect),         // Change memory protection
        ALLOW_SYSCALL(munmap),           // Unmap memory
        ALLOW_SYSCALL(brk),              // Change heap size
        ALLOW_SYSCALL(madvise),          // Give advice about memory usage
        ALLOW_SYSCALL(mremap),           // Remap memory
        ALLOW_SYSCALL(msync),            // Synchronize memory with storage
        ALLOW_SYSCALL(mlock),            // Lock memory pages
        ALLOW_SYSCALL(munlock),          // Unlock memory pages

        // Signal handling
        ALLOW_SYSCALL(rt_sigaction),     // Set signal handler
        ALLOW_SYSCALL(rt_sigprocmask),   // Change signal mask
        ALLOW_SYSCALL(rt_sigreturn),     // Return from signal handler
        ALLOW_SYSCALL(sigaltstack),      // Set alternate signal stack
        ALLOW_SYSCALL(kill),             // Send signal to process

        // Pipe operations
        ALLOW_SYSCALL(pipe),             // Create pipe (legacy)
        ALLOW_SYSCALL(pipe2),            // Create pipe with flags

        // File descriptor duplication
        ALLOW_SYSCALL(dup),              // Duplicate file descriptor
        ALLOW_SYSCALL(dup2),             // Duplicate to specific fd number
        ALLOW_SYSCALL(dup3),             // Duplicate with flags

        // Process identification
        ALLOW_SYSCALL(getpid),           // Get process ID
        ALLOW_SYSCALL(getppid),          // Get parent process ID
        ALLOW_SYSCALL(gettid),           // Get thread ID

        // User/group identification
        ALLOW_SYSCALL(getuid),           // Get real user ID
        ALLOW_SYSCALL(getgid),           // Get real group ID
        ALLOW_SYSCALL(geteuid),          // Get effective user ID
        ALLOW_SYSCALL(getegid),          // Get effective group ID
        ALLOW_SYSCALL(setfsuid),         // Set filesystem user ID
        ALLOW_SYSCALL(setfsgid),         // Set filesystem group ID

        // Directory operations
        ALLOW_SYSCALL(getcwd),           // Get current working directory
        ALLOW_SYSCALL(chdir),            // Change working directory
        ALLOW_SYSCALL(fchdir),           // Change working directory by fd
        ALLOW_SYSCALL(readlink),         // Read symbolic link (legacy)
        ALLOW_SYSCALL(readlinkat),       // Read symbolic link relative to directory fd
        ALLOW_SYSCALL(getdents64),       // Read directory entries

        // Process termination
        ALLOW_SYSCALL(exit),             // Terminate process
        ALLOW_SYSCALL(exit_group),       // Terminate all threads in process

        // Process synchronization
        ALLOW_SYSCALL(wait4),            // Wait for process to change state
        ALLOW_SYSCALL(waitid),           // Wait for process with more options

        // System information
        ALLOW_SYSCALL(uname),            // Get system information
        ALLOW_SYSCALL(times),            // Get process times
        ALLOW_SYSCALL(sched_getaffinity), // Get CPU affinity mask - SAFE TO ADD

        // Resource limits
        ALLOW_SYSCALL(getrlimit),        // Get resource limits
        ALLOW_SYSCALL(prlimit64),        // Get/set resource limits
        ALLOW_SYSCALL(getrusage),        // Get resource usage

        // Process groups
        ALLOW_SYSCALL(sched_getaffinity), // Get CPU affinity mask - SAFE TO ADD
        ALLOW_SYSCALL(getpgrp),          // Get process group ID
        ALLOW_SYSCALL(setsid),           // Create new session
        ALLOW_SYSCALL(setpgid),          // Set process group ID

        // Time operations
        ALLOW_SYSCALL(clock_gettime),    // Get time from clock
        ALLOW_SYSCALL(clock_getres),     // Get clock resolution

        // Architecture-specific operations
        ALLOW_SYSCALL(arch_prctl),       // Set architecture-specific thread state

        // Threading and synchronization
        ALLOW_SYSCALL(futex),            // Fast userspace mutex
        ALLOW_SYSCALL(set_tid_address),  // Set thread ID address
        ALLOW_SYSCALL(set_robust_list),  // Set robust futex list
        ALLOW_SYSCALL(clone),            // Create child process/thread
        ALLOW_SYSCALL(fork),             // Create child process
        ALLOW_SYSCALL(vfork),            // Create child process (optimized)

        // Process control
        ALLOW_SYSCALL(prctl),            // Process control operations

        // Advanced I/O
        ALLOW_SYSCALL(pread64),          // Read from file at offset
        ALLOW_SYSCALL(pwrite64),         // Write to file at offset

        // Kernel features
        ALLOW_SYSCALL(rseq),             // Restartable sequences
        ALLOW_SYSCALL(getrandom),        // Get random bytes from kernel

        // Event handling and I/O multiplexing
        ALLOW_SYSCALL(poll),             // Wait for events on file descriptors
        ALLOW_SYSCALL(select),           // Wait for events (legacy)
        ALLOW_SYSCALL(pselect6),         // Wait for events with signal mask
        ALLOW_SYSCALL(epoll_create1),    // Create epoll instance
        ALLOW_SYSCALL(epoll_ctl),        // Control epoll instance
        ALLOW_SYSCALL(epoll_wait),       // Wait for epoll events

        // File operations
        ALLOW_SYSCALL(fchmod),           // Change file permissions by fd
        ALLOW_SYSCALL(fchown),           // Change file ownership by fd
        ALLOW_SYSCALL(ftruncate),        // Truncate file by fd
        ALLOW_SYSCALL(fsync),            // Synchronize file data
        ALLOW_SYSCALL(fdatasync),        // Synchronize file data (no metadata)
        ALLOW_SYSCALL(unlink),           // Remove/delete files
        ALLOW_SYSCALL(rename),           // Rename/move files (legacy)
        ALLOW_SYSCALL(renameat),         // Rename relative to directory fd
        ALLOW_SYSCALL(renameat2),        // Rename with additional flags

        // Memory management and NUMA policy
        ALLOW_SYSCALL(mmap),             // Map memory
        ALLOW_SYSCALL(mprotect),         // Change memory protection
        ALLOW_SYSCALL(munmap),           // Unmap memory
        ALLOW_SYSCALL(brk),              // Change heap size
        ALLOW_SYSCALL(madvise),          // Give advice about memory usage
        ALLOW_SYSCALL(mbind),            // Set NUMA memory policy - for performance
        ALLOW_SYSCALL(mremap),           // Remap memory
        ALLOW_SYSCALL(msync),            // Synchronize memory with storage
        ALLOW_SYSCALL(mlock),            // Lock memory pages
        ALLOW_SYSCALL(munlock),          // Unlock memory pages

        // NUMA memory policy syscalls
        ALLOW_SYSCALL(mbind),            // Set NUMA memory policy
        ALLOW_SYSCALL(get_mempolicy),    // Get NUMA memory policy
        ALLOW_SYSCALL(set_mempolicy),    // Set default NUMA memory policy
        ALLOW_SYSCALL(migrate_pages),    // Migrate pages between NUMA nodes (optional)


        // Default action based on configuration
        BPF_STMT(BPF_RET+BPF_K, default_action),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        if (errno == EINVAL) {
            printf("Warning: Seccomp filtering not supported, skipping syscall restrictions\n");
            return 0;
        }
        perror("prctl(PR_SET_SECCOMP)");
        return -1;
    }

    const char *mode_str = config->seccomp_mode == SECCOMP_MODE_KILL ? "kill" :
                          config->seccomp_mode == SECCOMP_MODE_LOG ? "log" : "errno";
    printf("Seccomp syscall filtering applied successfully (mode: %s)\n", mode_str);
    return 0;
}
