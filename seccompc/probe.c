/*
 * probe.c — minimal seccomp-bpf probe (no libseccomp), Linux x86-64.
 *
 * Usage: probe FILTER PROBES RESULTS
 *
 * The parent process stays unfiltered.  It forks exactly one child; the
 * child installs FILTER (raw array of struct sock_filter) on itself with
 * PR_SET_NO_NEW_PRIVS + PR_SET_SECCOMP, then invokes every probe case
 * from PROBES (fixed, side-effect-free syscalls only: cases expected to
 * be ALLOWed use argument-free syscalls such as getpid; cases expected
 * to be denied are never executed by the kernel).  Each result
 * {ret, errno} is written to a pipe on fd 3 — the policy under test must
 * therefore explicitly allow write(2) to fd 3 and exit_group(2), which
 * the child needs to report results and terminate.  The parent collects
 * the raw result records into RESULTS.
 *
 * If SECCOMPC_INIT is set to "1" in the environment, the probe runs as a
 * VM init: it reads /filter.bpf and /probes.bin, hex-encodes the results
 * to /dev/console between marker lines, then powers the machine off.
 * (Used by vm_test.sh to verify the filter inside an x86-64 guest.)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/reboot.h>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif
#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

#define RESULT_FD 3            /* pipe endpoint the policy must allow write(2) to */
#define MAX_INSNS 4096
#define CHILD_TIMEOUT_MS 10000

struct probe_case {            /* 56 bytes, must match the plan generator */
    uint32_t nr;
    uint32_t pad;
    uint64_t args[6];
};

struct probe_result {          /* 16 bytes */
    int64_t ret;
    int32_t err;
    int32_t pad;
};

static void *read_file(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    long n;
    void *buf;

    if (!f) { perror(path); exit(1); }
    if (fseek(f, 0, SEEK_END) < 0) { perror("fseek"); exit(1); }
    n = ftell(f);
    if (n < 0) { perror("ftell"); exit(1); }
    if (fseek(f, 0, SEEK_SET) < 0) { perror("fseek"); exit(1); }
    buf = malloc(n > 0 ? (size_t)n : 1);
    if (!buf) { perror("malloc"); exit(1); }
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        perror("fread");
        exit(1);
    }
    fclose(f);
    *len_out = (size_t)n;
    return buf;
}

/* Run all probe cases with the filter installed in this (child) process.
 * Never returns. */
static void run_child(int pipe_wr, const void *fbuf, size_t flen,
                      const void *pbuf, size_t ncases)
{
    struct sock_fprog prog;
    const struct probe_case *cases = pbuf;
    size_t i;

    close(STDIN_FILENO);
    if (pipe_wr != RESULT_FD) {
        if (dup2(pipe_wr, RESULT_FD) < 0) { perror("dup2"); _exit(2); }
        close(pipe_wr);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        _exit(2);
    }
    prog.len = (unsigned short)(flen / 8);
    prog.filter = (struct sock_filter *)fbuf;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        perror("prctl(PR_SET_SECCOMP)");
        _exit(2);
    }
    /* The filter is active now.  Only syscalls the policy explicitly
     * allows may be used from here on: the probe syscalls themselves,
     * write(2) to RESULT_FD and exit_group(2). */
    for (i = 0; i < ncases; i++) {
        struct probe_result r;

        errno = 0;
        r.ret = syscall((long)cases[i].nr,
                        (long)cases[i].args[0], (long)cases[i].args[1],
                        (long)cases[i].args[2], (long)cases[i].args[3],
                        (long)cases[i].args[4], (long)cases[i].args[5]);
        r.err = errno;
        r.pad = 0;
        (void)syscall(SYS_write, RESULT_FD, &r, sizeof r);
    }
    syscall(SYS_exit_group, 0);
    /* Policy bug: exit_group was denied.  Spin until the parent times
     * out and kills us. */
    for (;;)
        syscall(SYS_exit_group, 0);
}

int main(int argc, char **argv)
{
    const char *filter_path, *probes_path, *results_path;
    size_t flen, plen, ncases, cap, len, nres;
    void *fbuf, *pbuf;
    uint8_t *buf;
    int pfd[2], status, timed_out;
    pid_t pid;
    FILE *o;
    int init_mode = (getpid() == 1) ||
                    (getenv("SECCOMPC_INIT") != NULL &&
                     !strcmp(getenv("SECCOMPC_INIT"), "1"));

    if (init_mode) {
        filter_path = "/filter.bpf";
        probes_path = "/probes.bin";
        results_path = "/dev/console";   /* hex-encoded, see below */
    } else {
        if (argc != 4) {
            fprintf(stderr, "usage: %s FILTER PROBES RESULTS\n", argv[0]);
            return 64;
        }
        filter_path = argv[1];
        probes_path = argv[2];
        results_path = argv[3];
    }

    fbuf = read_file(filter_path, &flen);
    pbuf = read_file(probes_path, &plen);
    if (flen == 0 || flen % 8 || flen / 8 > MAX_INSNS) {
        fprintf(stderr, "probe: bad filter size %zu\n", flen);
        return 65;
    }
    if (plen == 0 || plen % sizeof(struct probe_case)) {
        fprintf(stderr, "probe: bad probes size %zu\n", plen);
        return 65;
    }
    ncases = plen / sizeof(struct probe_case);

    if (pipe(pfd) < 0) { perror("pipe"); return 1; }
    pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid == 0) {
        /* isolated child: the filter is installed here and only here */
        close(pfd[0]);
        run_child(pfd[1], fbuf, flen, pbuf, ncases);
    }

    /* parent: stays unfiltered, collects results */
    close(pfd[1]);
    cap = 1 << 16;
    len = 0;
    buf = malloc(cap);
    if (!buf) { perror("malloc"); return 1; }
    timed_out = 0;
    for (;;) {
        struct pollfd p = { .fd = pfd[0], .events = POLLIN, .revents = 0 };
        int pr = poll(&p, 1, CHILD_TIMEOUT_MS);
        ssize_t r;

        if (pr < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }
        if (pr == 0) {
            timed_out = 1;
            kill(pid, SIGKILL);
            break;
        }
        if (len + 65536 > cap) {
            uint8_t *nb;
            cap *= 2;
            nb = realloc(buf, cap);
            if (!nb) { perror("realloc"); free(buf); return 1; }
            buf = nb;
        }
        r = read(pfd[0], buf + len, cap - len);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            perror("read");
            break;
        }
        if (r == 0)
            break;
        len += (size_t)r;
    }
    status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;

    if (init_mode) {
        /* hex-encode results to the serial console, then power off */
        static const char hexd[] = "0123456789abcdef";
        size_t i;
        o = fopen(results_path, "w");
        if (o) {
            fprintf(o, "\n@@RESULTS-BEGIN@@\n");
            for (i = 0; i < len; i++) {
                fputc(hexd[buf[i] >> 4], o);
                fputc(hexd[buf[i] & 15], o);
                if (i % 64 == 63)
                    fputc('\n', o);
            }
            fprintf(o, "\n@@RESULTS-END@@\n");
            fprintf(o, "probe: child status 0x%x, %zu records\n",
                    status, len / sizeof(struct probe_result));
            fclose(o);
        }
        sync();
        reboot(LINUX_REBOOT_CMD_POWER_OFF);
        for (;;)
            pause();
    }

    o = fopen(results_path, "wb");
    if (!o) { perror(results_path); return 1; }
    if (len && fwrite(buf, 1, len, o) != len) { perror("fwrite"); return 1; }
    fclose(o);

    nres = len / sizeof(struct probe_result);
    if (len % sizeof(struct probe_result))
        fprintf(stderr, "probe: warning: %zu trailing partial bytes\n",
                len % sizeof(struct probe_result));

    /* show that the parent itself never got a filter */
    {
        FILE *st = fopen("/proc/self/status", "r");
        char line[256];
        if (st) {
            while (fgets(line, sizeof line, st))
                if (!strncmp(line, "Seccomp:", 8)) {
                    printf("probe: parent %s", line);
                    break;
                }
            fclose(st);
        }
    }

    if (timed_out) {
        printf("probe: child timed out (filter likely blocks "
               "write/exit_group), %zu records\n", nres);
        return 2;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("probe: child exited normally, %zu records\n", nres);
        return 0;
    }
    if (WIFEXITED(status))
        printf("probe: child exited with status %d, %zu records\n",
               WEXITSTATUS(status), nres);
    else if (WIFSIGNALED(status))
        printf("probe: child killed by signal %d, %zu records\n",
               WTERMSIG(status), nres);
    return 2;
}
