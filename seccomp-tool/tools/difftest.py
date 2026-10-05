#!/usr/bin/env python3
"""Differential test oracle: independent evaluator  vs  cBPF interpreter.

Compiles policies with the tool compiler, runs many synthetic seccomp_data
inputs through BOTH the independent reference evaluator and an independent
cBPF interpreter over the *raw emitted filter*, and requires identical
decisions. Also checks structural invariants: legal opcodes, bounded loads,
u8 jump ranges, termination, and that no comparison ever truncates to 32
bits (every 64-bit compare touches both words).
"""

import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import bpf as B
import interp
import evaluator
from compiler import compile_policy, pack_filter, PolicyError

X86 = evaluator.ARCH_AUDIT["x86_64"]
AA = evaluator.ARCH_AUDIT["aarch64"]


def dec_action(k):
    if k == B.SECCOMP_RET_ALLOW:
        return ("allow",)
    if k == B.SECCOMP_RET_KILL_PROCESS:
        return ("kill",)
    if (k & 0xFFFF0000) == B.SECCOMP_RET_ERRNO:
        return ("errno", k & 0xFFFF)
    return ("weird", k)


def enc_action(a):
    if a[0] == "allow":
        return B.SECCOMP_RET_ALLOW
    if a[0] == "kill":
        return B.SECCOMP_RET_KILL_PROCESS
    return B.SECCOMP_RET_ERRNO | a[1]


# ---------------------------------------------------------------------------
# Fixed, hand-designed probes (incl. boundary semantics)
# ---------------------------------------------------------------------------
BIG = 1 << 32


def fixed_cases():
    """(arch, nr, args, description)"""
    out = []
    z = [0] * 6

    def a(nr, args, why, arch=X86):
        out.append((arch, nr, (args + [0] * 6)[:6], why))

    # architecture gate
    a(39, z, "getpid x86 allowed", X86)
    a(39, z, "getpid under WRONG arch aarch64 => kill", AA)
    # x32 bit
    a(39 | 0x40000000, z, "x32-tagged getpid must kill", X86)
    a(0x40000003, z, "x32 close must kill", X86)
    a(0x3FFFFFFF, z, "max native nr (default errno)", X86)

    # close rules
    a(3, [999999, 0], "close 999999 -> errno92 (first-match, before interval)")
    a(3, [42, 1000], "close fd42 arg1=1000 in [1000,5000] -> errno99")
    a(3, [42, 5000], "close arg1=5000 closed upper bound -> errno99")
    a(3, [42, 999], "close arg1=999 just below interval -> errno78")
    a(3, [42, 5001], "close arg1=5001 just above interval -> errno78")
    a(3, [42, 50], "close arg1=50 excluded by NOT(eq 50) -> falls default")
    a(3, [42, 0], "close arg1=0 <100 and !=50 -> errno78")
    a(3, [10, BIG + 50], "close arg1 crosses 2^32: not <100 -> default")
    a(3, [10, BIG - 1], "close arg1=2^32-1 -> default")
    a(3, [0, BIG * 5 + 1234], "high u64 value 5*2^32+1234 -> default")

    # dup2 rules (and, allow shadowing)
    a(33, [77, 88], "dup2 77,88 AND -> errno77")
    a(33, [77, 89], "dup2 AND fails -> allowed? no: lt rule then default")
    a(33, [10, 20], "dup2 both <100 -> allow (later rule)")
    a(33, [99, 99], "dup2 99,99 eq boundary (<100) -> allow")
    a(33, [100, 0], "dup2 100 not <100 -> default errno5")

    # madvise with nested NOT/OR and 2^32-spanning interval
    a(28, [0, 0, 0], "madvise arg2=0 in [0,4] -> errno88")
    a(28, [0, 0, 4], "madvise arg2=4 closed upper -> errno88")
    a(28, [0, 0, 5], "madvise arg2=5: not in range; nested: !(gt8 or !(le9))=66")
    a(28, [0, 0, 9], "madvise arg2=9 satisfies le9 under double neg -> 66")
    a(28, [0, 0, 10], "madvise arg2=10 -> default errno5")
    a(28, [0, 0, BIG + 9], "madvise arg2=2^32+9 -> default (no 32-bit trunc)")
    a(28, [0, 0, BIG + 2], "madvise 2^32+2 -> default; truncating would hit 88")

    # unknown syscalls / default
    a(400, z, "unknown nr -> default errno5")
    a(999, z, "unknown nr -> default errno5")
    # backtracking syscalls explicitly allowed
    a(231, z, "exit_group allowed")
    a(60, z, "exit allowed")
    a(157, z, "prctl allowed")
    a(317, z, "seccomp install allowed")
    a(1, z, "write allowed")
    return out


# ---------------------------------------------------------------------------
# Random policy synthesis (stays inside compiler-supported limits)
# ---------------------------------------------------------------------------
LEAF_TMPL = [
    ("eq", "v"), ("ne", "v"), ("lt", "v"), ("le", "v"),
    ("gt", "v"), ("ge", "v"), ("range", "lo", "hi"),
]


def rnd_value(rng, biased):
    pool = [0, 1, 4, 5, 8, 9, 10, 99, 100, 255, 1000, 5000,
            BIG - 1, BIG, BIG + 1, BIG + 2, BIG + 9,
            BIG * 3 + 1, MASK64 if False else (1 << 64) - 1]
    if biased and rng.random() < 0.75:
        return rng.choice(pool)
    return rng.randrange(1 << 64)


def rnd_leaf(rng, depth):
    arg = rng.randrange(6)
    kind = rng.choice(LEAF_TMPL)
    if kind[0] == "range":
        lo = rnd_value(rng, True)
        width = rng.choice([0, 1, 10, BIG, BIG * 4])
        hi = min((1 << 64) - 1, lo + width)
        return {"arg": {"arg": arg, "op": "range",
                        "min": str(lo), "max": str(hi)}}
    return {"arg": {"arg": arg, "op": kind[0],
                    "value": str(rnd_value(rng, True))}}


LEAF_BUDGET = [30]


def rnd_cond(rng, depth=0):
    if depth >= 3 or rng.random() < 0.55:
        if LEAF_BUDGET[0] <= 0:
            return None
        LEAF_BUDGET[0] -= 1
        return rnd_leaf(rng, depth)
    kind = rng.choice(["and", "or", "not"])
    if kind == "not":
        c = rnd_cond(rng, depth + 1)
        return {"not": c} if c is not None else None
    n = rng.randrange(2, 4)
    kids = []
    for _ in range(n):
        c = rnd_cond(rng, depth + 1)
        if c is not None:
            kids.append(c)
    return {kind: kids} if kids else None


def rnd_action(rng):
    return rng.choice(["allow", "kill", {"errno": str(rng.randrange(1, 4096))}])


def rnd_policy(rng, n_rules=None):
    LEAF_BUDGET[0] = 30
    arch = rng.choice(["x86_64", "x86_64", "aarch64"])
    n_rules = n_rules or rng.randrange(1, 8)
    nrs = rng.sample(range(0, 500), n_rules)
    rules = []
    for nr in nrs:
        r = {"syscall": nr, "action": rnd_action(rng)}
        if rng.random() < 0.7:
            c = rnd_cond(rng)
            if c is not None:
                r["when"] = c
        rules.append(r)
    return {"arch": arch, "default": rnd_action(rng), "rules": rules}


def rnd_data(rng, pol):
    arch_nr = evaluator.ARCH_AUDIT[pol["arch"]]
    # 85% correct arch, 15% foreign arch
    arch = arch_nr if rng.random() < 0.85 else rng.choice(
        [v for v in evaluator.ARCH_AUDIT.values() if v != arch_nr])
    # bias nr towards policy syscalls and boundary values
    if rng.random() < 0.6 and pol["rules"]:
        nr = rng.choice(pol["rules"])["syscall"]
        if pol["arch"] == "x86_64" and rng.random() < 0.1:
            nr |= 0x40000000
    else:
        nr = rng.choice([rng.randrange(0, 600), 0, 0x3FFFFFFF,
                         0x40000003, BIG - 1, BIG])
    args = [rnd_value(rng, True) for _ in range(6)]
    return nr, arch, args


# ---------------------------------------------------------------------------
# structural checks on emitted filters
# ---------------------------------------------------------------------------
def check_structure(insns, raw_doc):
    assert insns[-1].code == B.RET_K
    n = len(insns)
    saw_all_words = {a: [False, False] for a in range(6)}
    for i, ins in enumerate(insns):
        if ins.code == B.LD_ABS_W:
            assert ins.k + 4 <= 64, "load past seccomp_data"
            for a in range(6):
                if ins.k == B.OFF_ARGS + 8 * a:
                    saw_all_words[a][0] = True
                if ins.k == B.OFF_ARGS + 8 * a + 4:
                    saw_all_words[a][1] = True
        if ins.code in (B.JMP_JEQ_K, B.JMP_JGT_K, B.JMP_JGE_K):
            assert ins.jt <= 255 and ins.jf <= 255, "u8 jump violated"
            assert 0 <= i + 1 + ins.jt < n
            assert 0 <= i + 1 + ins.jf < n
        if ins.code == B.JMP_JA:
            assert 0 <= i + 1 + ins.k < n
    # every argument compared anywhere must use BOTH 32-bit words
    used = set()

    def walk(node):
        if node is None:
            return
        if not isinstance(node, dict):
            raise AssertionError("condition node not an object: %r" % (node,))
        keys = list(node.keys())
        if len(keys) != 1:
            raise AssertionError("condition node has %d keys: %r"
                                 % (len(keys), keys))
        key = keys[0]
        body = node[key]
        if key == "arg":
            used.add(int(body["arg"]))
        elif key == "not":
            walk(body)
        else:
            for child in body:
                walk(child)

    for rule in raw_doc.get("rules", []):
        walk(rule.get("when"))
    for a in used:
        assert saw_all_words[a] == [True, True], (
            "arg %d comparison truncated to 32 bits (missing word load)" % a)


# ---------------------------------------------------------------------------
def run_case(prog, oracle_pol, nr, arch, args):
    data = interp.pack_seccomp_data(nr, arch, args)
    bpf_ret = interp.run(prog, data)
    bpf_act = dec_action(bpf_ret)
    ref_act = evaluator.evaluate(oracle_pol, {"nr": nr, "arch": arch,
                                              "args": args})
    return bpf_act, ref_act


def main():
    failures = 0
    checked = 0

    # ---- A) shipped probe policy against hand cases ----
    pol_path = os.path.join(HERE, "..", "policies", "probe.json")
    text = open(pol_path).read()
    pol_struct, insns, _ = compile_policy(text)
    blob = pack_filter(insns)
    prog = interp.load_program(blob)
    check_structure(insns, json.loads(text))
    oracle = evaluator.load(text, is_text=True)
    for arch, nr, args, why in fixed_cases():
        b, r = run_case(prog, oracle, nr, arch, args)
        checked += 1
        if b != r:
            failures += 1
            print("MISMATCH fixed[%s]\n  interp=%s reference=%s" % (why, b, r))
    print("fixed cases: checked=%d" % checked)

    # ---- B) long-jump policy, incl. trampoline semantics ----
    text2 = open(os.path.join(HERE, "..", "policies", "longjump.json")).read()
    p2, i2, tramp = compile_policy(text2)
    assert tramp > 0, "test policy no longer forces long jumps"
    check_structure(i2, json.loads(text2))
    prog2 = interp.load_program(pack_filter(i2))
    orc2 = evaluator.load(text2, is_text=True)
    base = BIG
    # OR of 30 closed ranges: put each slot in the MIDDLE of the last range
    # touching that slot (ranges on a slot are disjoint and ascending).
    args = [0] * 6
    for i in range(30):
        args[i % 6] = base + 1000 + i + 3
    b, r = run_case(prog2, orc2, 39, X86, args)
    checked += 1
    if b != r or b != ("errno", 123):
        failures += 1
        print("MISMATCH longjump allmatch b=%s r=%s" % (b, r))
    # boundary: last range per slot, closed upper value
    args_hi = [0] * 6
    for i in range(30):
        args_hi[i % 6] = base + 1000 + i + 7
    b, r = run_case(prog2, orc2, 39, X86, args_hi)
    checked += 1
    if b != r or b != ("errno", 123):
        failures += 1
        print("MISMATCH longjump upper b=%s r=%s" % (b, r))
    # one below every range minimum => OR false => shadowed ALLOW rule
    args2 = [0] * 6
    b, r = run_case(prog2, orc2, 39, X86, args2)
    checked += 1
    if b != r or b != ("allow",):
        failures += 1
        print("MISMATCH longjump break b=%s r=%s" % (b, r))
    # just above the last range per slot => false as well
    args3 = [0] * 6
    for i in range(24, 30):
        args3[i % 6] = base + 1000 + i + 8
    b, r = run_case(prog2, orc2, 39, X86, args3)
    checked += 1
    if b != r or b != ("allow",):
        failures += 1
        print("MISMATCH longjump above b=%s r=%s" % (b, r))
    # arch mismatch still kills even on a long program
    b, r = run_case(prog2, orc2, 39, AA, args)
    checked += 1
    if b != r or b != ("kill",):
        failures += 1
        print("MISMATCH longjump arch b=%s r=%s" % (b, r))

    # ---- C) random policy fuzz ----
    rng = random.Random(20261005)
    N_POL = 1500
    N_DATA = 200
    max_insns_seen = 0
    for pi in range(N_POL):
        doc = rnd_policy(rng)
        text = json.dumps(doc)
        try:
            pol_struct, insns, _ = compile_policy(text)
        except PolicyError as e:
            # only acceptable if validation genuinely rejected input
            continue
        max_insns_seen = max(max_insns_seen, len(insns))
        check_structure(insns, doc)
        prog = interp.load_program(pack_filter(insns))
        oracle = evaluator.load(text, is_text=True)
        for _ in range(N_DATA):
            nr, arch, args = rnd_data(rng, doc)
            b, r = run_case(prog, oracle, nr, arch, args)
            checked += 1
            if b != r:
                failures += 1
                print("MISMATCH fuzz pol#%d nr=%#x arch=%#x args=%s\n"
                      "  policy=%s\n  interp=%s reference=%s"
                      % (pi, nr, arch, args, text[:300], b, r))
                if failures > 10:
                    break
        if failures > 10:
            break

    print("random policies=%d, total comparisons=%d, max insns=%d"
          % (N_POL, checked, max_insns_seen))

    # ---- D) parser-level safety checks ----
    def must_fail(t, needle):
        try:
            compile_policy(t)
        except PolicyError as e:
            assert needle in str(e), (needle, str(e))
            return
        raise AssertionError("should have failed: %s" % needle)

    must_fail(json.dumps({"arch": "x86_64", "default": "kill",
                          "rules": [{"syscall": 0x40000001,
                                     "action": "allow"}]}), "x32")
    must_fail(json.dumps({"arch": "mips", "default": "kill", "rules": []}),
              "arch")
    must_fail(json.dumps({"arch": "x86_64", "default": "kill",
                          "rules": [{"syscall": 1, "action": "allow",
                                     "when": {"arg": {"arg": 0, "op": "eq",
                                                      "value": "-1"}}}]}),
              "decimal")
    must_fail(json.dumps({"arch": "x86_64", "default": "kill",
                          "rules": [{"syscall": 1, "action": "allow",
                                     "when": {"arg": {"arg": 9, "op": "eq",
                                                      "value": "1"}}}]}),
              "0..5")
    # >30 leaf comparisons rejected
    leaves = [{"arg": {"arg": i % 6, "op": "eq", "value": str(i)}}
              for i in range(31)]
    must_fail(json.dumps({"arch": "x86_64", "default": "kill",
                          "rules": [{"syscall": 1, "action": "allow",
                                     "when": {"and": leaves}}]}),
              "30")
    print("parser safety: ok")

    if failures:
        print("FAIL: %d mismatches" % failures)
        return 1
    print("ALL DIFFERENTIAL CHECKS PASSED (%d decisions)" % checked)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
