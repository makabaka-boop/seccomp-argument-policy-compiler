/*
 * probe.c -- minimal fixed, side-effect-free seccomp verification probe.
 *
 *   probe <prog.filter> <arch:x86_64|aarch64> [foreign.filter]
 *
 * Design
 * ------
 * The PARENT never installs any filter.  For every fixed test case it forks
 * a fresh, isolated child.  The child installs the filter and performs
 * exactly ONE syscall, then reports the outcome through its wait status:
 *
 *   - normal exit:  exit code == errno produced (0 == success/ALLOW)
 *   - killed by SIGSYS (31): the filter returned SECCOMP_RET_KILL_PROCESS
 *
 * Thus the post-install child needs only the installing prctl(2), the single
 * test syscall and exit_group(2) -- all of which the probe policy explicitly
 * allows.  No fork/pipe/futex bookkeeping ever runs inside a filter.
 *
 * If [foreign.filter] is given, one extra child attempts to install it and
 * is expected to be killed by the architecture gate (foreign AUDIT_ARCH).
 *
 * Side effects:
 *   - close() cases are always answered ERRNO by the policy, so the kernel
 *     never actually closes a descriptor;
 *   - dup2() cases that ALLOW use invalid descriptors -> -EBADF only;
 *   - madvise() cases are always answered before the kernel acts (advice
 *     values never take effect);
 *   - getpid() is inherently side-effect free.
 *
 * Build for the target (must match <arch>):
 *   x86_64 : x86_64-linux-gnu-gcc -O2 -Wall -static -o probe probe.c
 *   native : cc -O2 -Wall -o probe probe.c
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SIGSYS
#define SIGSYS 31
#endif

struct nrset {
    long getpid, close_nr, dup2, madvise, unknown_nr,
         exit_group, prctl_nr, seccomp_nr, write_nr;
    unsigned x32_bit;
    const char *name;
};

#if defined(__x86_64__)
static const struct nrset NRS = {
    39, 3, 33, 28, 400, 231, 157, 317, 1, 0x40000000U, "x86_64"
};
#define TARGET_ARCH "x86_64"
#elif defined(__aarch64__)
static const struct nrset NRS = {
    172, 57, 23, 233, 400, 94, 167, 383, 64, 0, "aarch64"
};
#define TARGET_ARCH "aarch64"
#else
#error "unsupported host (need x86-64 or aarch64)"
#endif

/* raw 3-argument syscall: never touches errno in libc */
#if defined(__x86_64__)
static long raw3(long nr, long a, long b, long c) {
    long ret;
    register long r10 __asm__("r10") = c;
    __asm__ volatile ("syscall" : "=a"(ret)
        : "a"(nr), "D"(a), "S"(b), "d"(r10)
        : "rcx","r11","memory","cc");
    return ret;
}
#elif defined(__aarch64__)
static long raw3(long nr, long a, long b, long c) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile ("svc 0" : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2) : "memory","cc");
    return x0;
}
#endif

/* raw 6-argument syscall (used by smoke mode) */
#if defined(__x86_64__)
static long raw6(long nr, long a1, long a2, long a3,
                 long a4, long a5, long a6) {
    long ret;
    register long r10r __asm__("r10") = a4;
    register long r8r  __asm__("r8")  = a5;
    register long r9r  __asm__("r9")  = a6;
    __asm__ volatile ("syscall" : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(r10r),
          "r"(r8r), "r"(r9r)
        : "rcx","r11","memory","cc");
    return ret;
}
#elif defined(__aarch64__)
static long raw6(long nr, long a1, long a2, long a3,
                 long a4, long a5, long a6) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    register long x5 __asm__("x5") = a6;
    __asm__ volatile ("svc 0" : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory","cc");
    return x0;
}
#endif

static unsigned char *read_file(const char *path, size_t *len) {
    int f = open(path, O_RDONLY);
    if (f < 0) return NULL;
    struct stat st;
    if (fstat(f, &st) < 0 || st.st_size <= 0 || st.st_size % 8) { close(f); return NULL; }
    unsigned char *buf = malloc((size_t)st.st_size);
    if (!buf) { close(f); return NULL; }
    ssize_t off = 0, r;
    while (off < st.st_size && (r = read(f, buf + off, (size_t)st.st_size - off)) > 0)
        off += r;
    close(f);
    if (off != st.st_size) { free(buf); return NULL; }
    *len = (size_t)st.st_size;
    return buf;
}

/* result of a child observed by the parent */
enum outcome { O_EXIT, O_KILL, O_OTHER };
struct obs { enum outcome kind; int code; };

static struct obs run_child_install(const unsigned char *filter, size_t flen,
                                    long nr, long a, long b, long c) {
    pid_t pid = fork();
    if (pid < 0) return (struct obs){O_OTHER, -1};
    if (pid == 0) {
        /* child: filter installed HERE; the parent stays unfiltered */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) _exit(200);
        struct sock_fprog sf = {
            .len = (unsigned short)(flen / 8),
            .filter = (struct sock_filter *)filter,
        };
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sf) < 0)
            _exit(201);                 /* e.g. rejected install call */
        long r = raw3(nr, a, b, c);
        int e = r < 0 ? (int)-r : 0;    /* kernel negates errno */
        raw3(NRS.exit_group, e & 0xff, 0, 0);
        _exit(202);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st))
        return (struct obs){O_KILL, WTERMSIG(st)};
    if (WIFEXITED(st))
        return (struct obs){O_EXIT, WEXITSTATUS(st)};
    return (struct obs){O_OTHER, st};
}

static struct obs run_child_install6(const unsigned char *filter, size_t flen,
                                     long nr, const long a[6]) {
    pid_t pid = fork();
    if (pid < 0) return (struct obs){O_OTHER, -1};
    if (pid == 0) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) _exit(200);
        struct sock_fprog sf = {
            .len = (unsigned short)(flen / 8),
            .filter = (struct sock_filter *)filter,
        };
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sf) < 0)
            _exit(201);
        long r = raw6(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        int e = r < 0 ? (int)-r : 0;
        raw3(NRS.exit_group, e & 0xff, 0, 0);
        _exit(202);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st))
        return (struct obs){O_KILL, WTERMSIG(st)};
    if (WIFEXITED(st))
        return (struct obs){O_EXIT, WEXITSTATUS(st)};
    return (struct obs){O_OTHER, st};
}

struct case_t {
    const char *tag;
    long nr, a1, a2, a3;
};

#define U64(x) ((long)(unsigned long long)(x))

int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[2], TARGET_ARCH) != 0) {
        fprintf(stderr, "usage: %s prog.filter %s [foreign.filter]\n"
                        "(this binary is built for %s)\n",
                argv[0], TARGET_ARCH, TARGET_ARCH);
        return 2;
    }
    size_t flen;
    unsigned char *filter = read_file(argv[1], &flen);
    if (!filter) { perror("read filter"); return 2; }

    /* smoke mode: install an arbitrary filter and issue exactly one call.
     * Usage: probe <f> <arch> smoke <nr> a1..a6
     * Exercises the kernel BPF verifier's acceptance of the program (e.g.
     * one containing long-jump trampolines) and reports that call. */
    if (argc == 11 && !strcmp(argv[3], "smoke")) {
        long nr = strtol(argv[4], NULL, 0);
        long a[6];
        for (int i = 0; i < 6; i++)
            a[i] = strtol(argv[5 + i], NULL, 0);
        struct obs o = run_child_install6(filter, flen, nr, a);
        if (o.kind == O_EXIT)
            printf("SMOKE EXIT errno=%d\n", o.code);
        else if (o.kind == O_KILL)
            printf("SMOKE KILL signal=%d\n", o.code);
        else
            printf("SMOKE ABNORMAL 0x%x\n", o.code);
        return 0;
    }

    unsigned char *foreign = NULL; size_t flen2 = 0;
    if (argc == 4) {
        foreign = read_file(argv[3], &flen2);
        if (!foreign) { perror("read foreign filter"); return 2; }
    }

    /* The tag set matches policies/probe*.json in order. Expected outcomes
     * are decided out-of-band by tools/check_kernel.py against the same
     * independent evaluator used in the differential oracle, so the probe
     * never hard-codes what its own filter should answer. */
    const struct case_t cases[] = {
        {"getpid",            NRS.getpid,  0,0,0},
        {"close_999999",      NRS.close_nr,999999,0,0},
        {"close_42_1000",     NRS.close_nr,42,1000,0},
        {"close_42_5000",     NRS.close_nr,42,5000,0},
        {"close_42_999",      NRS.close_nr,42,999,0},
        {"close_42_5001",     NRS.close_nr,42,5001,0},
        {"close_42_0",        NRS.close_nr,42,0,0},
        {"close_42_50",       NRS.close_nr,42,50,0},
        {"dup2_77_88",        NRS.dup2,77,88,0},
        {"dup2_10_20",        NRS.dup2,10,20,0},
        {"dup2_99_99",        NRS.dup2,99,99,0},
        {"dup2_100_0",        NRS.dup2,100,0,0},
        {"madv_0",            NRS.madvise,0,0,0},
        {"madv_4",            NRS.madvise,0,0,4},
        {"madv_5",            NRS.madvise,0,0,5},
        {"madv_9",            NRS.madvise,0,0,9},
        {"madv_10",           NRS.madvise,0,0,10},
        {"madv_2p32_2",       NRS.madvise,0,0,U64(4294967298ULL)},
        {"madv_2p32_9",       NRS.madvise,0,0,U64(4294967305ULL)},
        {"unknown",           NRS.unknown_nr,0,0,0},
        {"x32tagged",
         (long)(NRS.getpid | NRS.x32_bit), 0,0,0},
    };
    const int ncases = (int)(sizeof(cases)/sizeof(cases[0]));

    int infra = 0, ran = 0;
    printf("== kernel probe filter=%s arch=%s ==\n", argv[1], NRS.name);
    for (int i = 0; i < ncases; i++) {
        const struct case_t *t = &cases[i];
        if (!NRS.x32_bit && strstr(t->tag, "x32")) {
            printf("CASE %-16s SKIP no-x32-arch\n", t->tag);
            continue;
        }
        struct obs o = run_child_install(filter, flen,
                                         t->nr, t->a1, t->a2, t->a3);
        ran++;
        if (o.kind == O_EXIT)
            printf("CASE %-16s EXIT errno=%d\n", t->tag, o.code);
        else if (o.kind == O_KILL)
            printf("CASE %-16s KILL signal=%d\n", t->tag, o.code);
        else {
            printf("CASE %-16s ABNORMAL 0x%x\n", t->tag, o.code);
            infra++;
        }
    }

    if (foreign) {
        pid_t pid = fork();
        if (pid == 0) {
            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) _exit(200);
            struct sock_fprog sf = {
                .len = (unsigned short)(flen2 / 8),
                .filter = (struct sock_filter *)foreign,
            };
            if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sf) < 0)
                _exit(201);
            raw3(NRS.exit_group, 0, 0, 0);
            _exit(202);
        }
        int st = 0; waitpid(pid, &st, 0);
        ran++;
        if (WIFSIGNALED(st))
            printf("CASE foreign-arch      KILL signal=%d\n", WTERMSIG(st));
        else if (WIFEXITED(st) && WEXITSTATUS(st) == 201)
            printf("CASE foreign-arch      REFUSED install=201\n");
        else
            printf("CASE foreign-arch      ABNORMAL 0x%x\n", st), infra++;
    }

    printf("ran=%d infra_failures=%d\n", ran, infra);
    return infra ? 1 : 0;
}
