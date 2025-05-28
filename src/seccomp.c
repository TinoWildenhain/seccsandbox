#include "sandbox.h"

#define ALLOW_SYSCALL(name) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

int setup_seccomp(void) {
    struct sock_filter filter[] = {
        // Load architecture
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),

        // Check architecture (x86_64)
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

        // Load syscall number
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

        // Allow essential syscalls
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(openat),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(lstat),
        ALLOW_SYSCALL(lseek),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(mprotect),
        ALLOW_SYSCALL(munmap),
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(rt_sigaction),
        ALLOW_SYSCALL(rt_sigprocmask),
        ALLOW_SYSCALL(rt_sigreturn),
        ALLOW_SYSCALL(ioctl),
        ALLOW_SYSCALL(access),
        ALLOW_SYSCALL(pipe),
        ALLOW_SYSCALL(dup),
        ALLOW_SYSCALL(dup2),
        ALLOW_SYSCALL(getpid),
        ALLOW_SYSCALL(getuid),
        ALLOW_SYSCALL(getgid),
        ALLOW_SYSCALL(geteuid),
        ALLOW_SYSCALL(getegid),
        ALLOW_SYSCALL(fcntl),
        ALLOW_SYSCALL(getcwd),
        ALLOW_SYSCALL(chdir),
        ALLOW_SYSCALL(readlink),
        ALLOW_SYSCALL(execve),
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(wait4),
        ALLOW_SYSCALL(kill),
        ALLOW_SYSCALL(uname),
        ALLOW_SYSCALL(getrlimit),
        ALLOW_SYSCALL(getrusage),
        ALLOW_SYSCALL(times),
        ALLOW_SYSCALL(getpgrp),
        ALLOW_SYSCALL(getppid),
        ALLOW_SYSCALL(setsid),
        ALLOW_SYSCALL(setpgid),
        ALLOW_SYSCALL(clock_gettime),
        ALLOW_SYSCALL(arch_prctl),
        ALLOW_SYSCALL(futex),
        ALLOW_SYSCALL(set_tid_address),
        ALLOW_SYSCALL(set_robust_list),
        ALLOW_SYSCALL(rseq),
        ALLOW_SYSCALL(madvise),
        ALLOW_SYSCALL(clone),
        ALLOW_SYSCALL(fork),
        ALLOW_SYSCALL(vfork),
        ALLOW_SYSCALL(sigaltstack),
        ALLOW_SYSCALL(getrandom),

        // Default: kill process
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return -1;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        perror("prctl(PR_SET_SECCOMP)");
        return -1;
    }

    return 0;
}
