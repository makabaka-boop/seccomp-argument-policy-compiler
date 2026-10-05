#!/usr/bin/env python3
"""check_kernel.py -- compare REAL kernel seccomp results to the oracle.

Runs probe/probe (which installs the compiled filter in one isolated child
per case), parses its machine-readable output, and checks every observed
decision against the independent evaluator -- the same oracle used by the
interpreter differential tests. This proves the emitted cBPF means what it
says when actually loaded by the kernel, not just by our interpreter.

Observation mapping (seccomp_data args the probe passes):
  EXIT errno=e   <=> policy decision ALLOW and kernel returned -e
                     (probe chooses only calls whose natural errno is known),
                     or policy decision ERRNO(e);
  KILL signal    <=> policy decision KILL.
"""

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import evaluator

# probe case tag -> (x86_64 nr, [args])  (must match probe.c table)
CASES = [
    ("getpid", 39, [0, 0, 0]),
    ("close_999999", 3, [999999, 0, 0]),
    ("close_42_1000", 3, [42, 1000, 0]),
    ("close_42_5000", 3, [42, 5000, 0]),
    ("close_42_999", 3, [42, 999, 0]),
    ("close_42_5001", 3, [42, 5001, 0]),
    ("close_42_0", 3, [42, 0, 0]),
    ("close_42_50", 3, [42, 50, 0]),
    ("dup2_77_88", 33, [77, 88, 0]),
    ("dup2_10_20", 33, [10, 20, 0]),
    ("dup2_99_99", 33, [99, 99, 0]),
    ("dup2_100_0", 33, [100, 0, 0]),
    ("madv_0", 28, [0, 0, 0]),
    ("madv_4", 28, [0, 0, 4]),
    ("madv_5", 28, [0, 0, 5]),
    ("madv_9", 28, [0, 0, 9]),
    ("madv_10", 28, [0, 0, 10]),
    ("madv_2p32_2", 28, [0, 0, 4294967298]),
    ("madv_2p32_9", 28, [0, 0, 4294967305]),
    ("unknown", 400, [0, 0, 0]),
    ("x32tagged", 39 | 0x40000000, [0, 0, 0]),
]

# nr remap applied by tools/mk_aarch64.py (keep in sync)
NR_AARCH64 = {39: 172, 3: 57, 33: 23, 28: 233, 400: 999}

# natural kernel errno for the probe's ALLOWed, deliberately-failing calls
# (x86-64 and aarch64 agree on these; getpid ALLOW succeeds -> errno 0)
NATURAL_ERRNO = {
    "getpid": 0,
    "dup2_10_20": 9, "dup2_99_99": 9,
}


def expected(tag, nr, args, arch):
    pol_path = os.path.join(HERE, "..", "policies",
                            "probe.json" if arch == "x86_64"
                            else "probe_aarch64.json")
    oracle = evaluator.load(pol_path)
    audit = evaluator.ARCH_AUDIT[arch]
    return evaluator.evaluate(oracle, {
        "nr": nr & 0xFFFFFFFF, "arch": audit,
        "args": args + [0] * (6 - len(args))})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("probe_bin")
    ap.add_argument("filter")
    ap.add_argument("arch", choices=("x86_64", "aarch64"))
    ap.add_argument("--foreign", help="foreign-arch filter for gate check")
    ap.add_argument("--longjump",
                    help="trampoline-heavy filter to install (verifier+smoke)")
    args = ap.parse_args()

    cmd = [args.probe_bin, args.filter, args.arch]
    if args.foreign:
        cmd.append(args.foreign)
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = p.stdout
    sys.stdout.write(out)
    if p.returncode not in (0, 1):
        print("probe infra error rc=%d\n%s" % (p.returncode, p.stderr))
        return 2

    observed = {}
    for line in out.splitlines():
        m = re.match(r"CASE (\S+)\s+(EXIT errno=(\d+)|KILL signal=(\d+)|"
                     r"SKIP.*|REFUSED.*|ABNORMAL.*)", line)
        if m:
            tag, whole = m.group(1), m.group(2)
            if whole.startswith("EXIT"):
                observed[tag] = ("exit", int(m.group(3)))
            elif whole.startswith("KILL"):
                observed[tag] = ("kill", int(m.group(4)))
            elif whole.startswith("SKIP"):
                observed[tag] = ("skip", 0)
            else:
                observed[tag] = ("other", whole)

    fails = 0
    checked = 0
    for tag, nr_x86, xargs in CASES:
        nr = nr_x86
        if args.arch == "aarch64":
            if nr_x86 == (39 | 0x40000000):
                nr = NR_AARCH64[39]    # x32 case skipped on aarch64 anyway
            else:
                nr = NR_AARCH64.get(nr_x86, nr_x86)
        exp = expected(tag, nr, xargs, args.arch)
        obs = observed.get(tag)
        if obs is None:
            print("MISSING CASE %s" % tag); fails += 1; continue
        if obs[0] == "skip":
            continue
        checked += 1
        ok = False
        detail = ""
        if exp[0] == "kill":
            ok = obs[0] == "kill" and obs[1] in (31, 9)
            detail = "want KILL got %s" % (obs,)
        elif exp[0] == "errno":
            ok = obs[0] == "exit" and obs[1] == exp[1]
            detail = "want ERRNO(%d) got %s" % (exp[1], obs)
        else:  # allow: kernel result must match the natural no-side-effect one
            want_e = NATURAL_ERRNO.get(tag, 0)
            ok = obs[0] == "exit" and obs[1] == want_e
            detail = "want ALLOW(errno=%d) got %s" % (want_e, obs)
        print("%-16s %s %s" % (tag, "PASS" if ok else "FAIL",
                               "" if ok else detail))
        if not ok:
            fails += 1

    # foreign-arch gate
    if args.foreign and "foreign-arch" in observed:
        o = observed["foreign-arch"]
        ok = o[0] == "kill" or o[0] == "other"
        if o[0] == "other" and "REFUSED" not in str(o[1]):
            ok = False
        print("%-16s %s" % ("foreign-arch", "PASS" if ok else "FAIL %s" % o))
        checked += 1
        if not ok:
            fails += 1

    # long-jump filter: the kernel verifier must accept the trampoline-heavy
    # program and it must decide correctly (oracle decides expectation).
    if args.longjump:
        lj_nr = 172 if args.arch == "aarch64" else 39
        base = 1 << 32
        lj_pol = os.path.join(HERE, "..", "policies",
                              "longjump_aarch64.json"
                              if args.arch == "aarch64" else "longjump.json")
        oracle_lj = evaluator.load(lj_pol)
        # slot values: last range per slot (i=24..29) midpoint & outside
        good = [0] * 6
        for i in range(30):
            good[i % 6] = base + 1000 + i + 3
        bad = [0] * 6
        audit = evaluator.ARCH_AUDIT[args.arch]
        for tag, vec in (("longjump-match", good), ("longjump-miss", bad)):
            exp = evaluator.evaluate(oracle_lj, {"nr": lj_nr, "arch": audit,
                                                 "args": vec})
            sp = subprocess.run(
                [args.probe_bin, args.longjump, args.arch, "smoke",
                 str(lj_nr)] + [str(v) for v in vec],
                capture_output=True, text=True)
            line = sp.stdout.strip()
            got = None
            mm = re.search(r"EXIT errno=(\d+)", line)
            if mm:
                got = ("errno", int(mm.group(1)))
                if exp == ("allow",) and got[1] == 0:
                    got = ("allow",)
            elif "KILL" in line:
                got = ("kill",)
            ok = got == exp or (exp[0] == "allow" and got and got[0] == "allow")
            print("%-16s %s (kernel=%s oracle=%s)"
                  % (tag, "PASS" if ok else "FAIL", line, exp))
            checked += 1
            if not ok:
                fails += 1

    print("kernel-verified cases=%d failures=%d => %s"
          % (checked, fails, "PASS" if fails == 0 else "FAIL"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
