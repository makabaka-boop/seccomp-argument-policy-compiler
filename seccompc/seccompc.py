#!/usr/bin/env python3
"""
seccompc — seccomp policy compiler for Linux x86-64 (no libseccomp).

Compiles a JSON policy into a classic-BPF seccomp filter plus a human
readable instruction listing and a rule->instruction source map.

Policy schema
-------------
{
  "default": {"action": "errno", "errno": 13},        # optional; this is the built-in default
  "rules": [
    {
      "name": "optional label",
      "syscall": 39,                                   # x86-64 syscall number (JSON number)
      "condition": { ... },                            # optional; absence matches any args
      "action": {"action": "allow"}                    # or {"action": "errno", "errno": 42}
    }
  ]
}

condition := {"eq":       {"arg": 0..5, "value": "<decimal u64 string>"}}
           | {"in_range": {"arg": 0..5, "lo": "<dec>", "hi": "<dec>"}}   # closed interval
           | {"and": [condition, ...]}
           | {"or":  [condition, ...]}
           | {"not":  condition}

Semantics: rules are tried in order; the first rule whose syscall number
matches and whose condition holds decides (ALLOW or ERRNO).  If no rule
matches, the default action applies (deny).  At most 30 comparison
conditions (eq/in_range leaves) per rule.

Guarantees of the generated filter:
  * checks seccomp_data.arch == AUDIT_ARCH_X86_64 first, kills otherwise;
  * kills any syscall number carrying the x32 bit (0x40000000);
  * compares arguments as full unsigned 64-bit values (hi/lo word pairs),
    never truncated to 32 bits;
  * never dereferences pointers: classic seccomp BPF can only read
    seccomp_data, so pointer arguments are compared as values only;
  * conditional jumps that exceed the 8-bit classic-BPF range are
    rewritten through 32-bit JA trampolines;
  * every execution path ends at a legal return instruction (statically
    verified before the filter is written out).

Subcommands:
  compile   policy -> filter.bpf + listing.txt + map.json
  selftest  cross-check the policy evaluator against the cBPF interpreter
            on synthesized seccomp_data (incl. arch-mismatch / x32 cases)
  genplan   emit probes.bin + expect.json for the C probe
  check     compare probe results against expect.json
  test      compile + selftest + genplan + run probe + check
"""

import argparse
import itertools
import json
import os
import random
import struct
import subprocess
import sys

# ---------------------------------------------------------------- constants

AUDIT_ARCH_X86_64 = 0xC000003E
X32_SYSCALL_BIT = 0x40000000
U64_MAX = 0xFFFFFFFFFFFFFFFF

RET_KILL_PROCESS = 0x80000000
RET_ERRNO = 0x00050000
RET_ALLOW = 0x7FFF0000
ERRNO_MAX = 4095

# classic BPF encodings (see linux/filter.h)
BPF_LD, BPF_LDX, BPF_ST, BPF_STX = 0x00, 0x01, 0x02, 0x03
BPF_ALU, BPF_JMP, BPF_RET, BPF_MISC = 0x04, 0x05, 0x06, 0x07
BPF_W, BPF_H, BPF_B = 0x00, 0x08, 0x10
BPF_IMM, BPF_ABS, BPF_IND, BPF_MEM, BPF_LEN, BPF_MSH = 0x00, 0x20, 0x40, 0x60, 0x80, 0xA0
BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV = 0x00, 0x10, 0x20, 0x30
BPF_OR, BPF_AND, BPF_LSH, BPF_RSH = 0x40, 0x50, 0x60, 0x70
BPF_NEG, BPF_MOD, BPF_XOR = 0x80, 0x90, 0xA0
BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET = 0x00, 0x10, 0x20, 0x30, 0x40
BPF_K, BPF_X = 0x00, 0x08

LD_W_ABS = BPF_LD | BPF_W | BPF_ABS        # 0x20
ALU_AND_K = BPF_ALU | BPF_AND | BPF_K      # 0x54
JA = BPF_JMP | BPF_JA                      # 0x05
JEQ_K = BPF_JMP | BPF_JEQ | BPF_K          # 0x15
JGT_K = BPF_JMP | BPF_JGT | BPF_K          # 0x25
JGE_K = BPF_JMP | BPF_JGE | BPF_K          # 0x35
RET_K = BPF_RET | BPF_K                    # 0x16

# struct seccomp_data layout
OFF_NR = 0
OFF_ARCH = 4
OFF_IP = 8
OFF_ARGS = 16
SECCOMP_DATA_LEN = 64

BPF_MAXINSNS = 4096
MAX_COND_LEAVES_PER_RULE = 30
MAX_COND_DEPTH = 64
MAX_PROBE_CASES = 300

DEFAULT_ACTION = {"action": "errno", "errno": 13}  # EACCES

# Syscalls the real probe may execute when a case is expected to be ALLOWed
# (all argument-free, always succeeding, no side effects):
#   24 sched_yield, 39 getpid, 102 getuid, 104 getgid,
#   107 geteuid, 108 getegid, 110 getppid, 186 gettid
SAFE_EXEC_SYSCALLS = frozenset({24, 39, 102, 104, 107, 108, 110, 186})
# Extra numbers allowed in the probe plan only when the expected action is
# ERRNO, because the kernel then never executes the syscall: write(1),
# exit(60), exit_group(231) (harness syscalls) and two invalid numbers
# (harmless -ENOSYS even if a buggy filter let them through).
SAFE_DENIED_SYSCALLS = SAFE_EXEC_SYSCALLS | {1, 60, 231, 999, 3900}


class PolicyError(Exception):
    pass


class CompileError(Exception):
    pass


class BPFError(Exception):
    pass


# ------------------------------------------------------------- policy model

def parse_u64(s, what):
    if not isinstance(s, str) or not s or any(c not in "0123456789" for c in s):
        raise PolicyError(f"{what}: expected a decimal string, got {s!r}")
    v = int(s, 10)
    if v > U64_MAX:
        raise PolicyError(f"{what}: {s!r} exceeds the unsigned 64-bit range")
    return v


def parse_arg_index(v, what):
    if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= 5:
        raise PolicyError(f"{what}: arg index must be an integer in 0..5, got {v!r}")
    return v


def parse_condition(node, depth, leaves):
    """JSON condition -> nested tuple tree; leaves[0] counts comparisons."""
    if depth > MAX_COND_DEPTH:
        raise PolicyError("condition nesting too deep")
    if not isinstance(node, dict) or len(node) != 1:
        raise PolicyError(f"condition must be a single-key object, got {node!r}")
    op, body = next(iter(node.items()))
    if op == "eq":
        if not isinstance(body, dict):
            raise PolicyError("eq: object with 'arg' and 'value' required")
        arg = parse_arg_index(body.get("arg"), "eq")
        val = parse_u64(body.get("value"), "eq value")
        leaves[0] += 1
        return ("eq", arg, val)
    if op == "in_range":
        if not isinstance(body, dict):
            raise PolicyError("in_range: object with 'arg', 'lo', 'hi' required")
        arg = parse_arg_index(body.get("arg"), "in_range")
        lo = parse_u64(body.get("lo"), "in_range lo")
        hi = parse_u64(body.get("hi"), "in_range hi")
        if lo > hi:
            raise PolicyError(f"in_range: lo ({lo}) > hi ({hi})")
        leaves[0] += 1
        return ("range", arg, lo, hi)
    if op in ("and", "or"):
        if not isinstance(body, list) or not body:
            raise PolicyError(f"{op}: non-empty list of conditions required")
        return (op, [parse_condition(c, depth + 1, leaves) for c in body])
    if op == "not":
        return ("not", parse_condition(body, depth + 1, leaves))
    raise PolicyError(f"unknown condition operator {op!r}")


def parse_action(obj, what):
    if not isinstance(obj, dict):
        raise PolicyError(f"{what}: action object required")
    a = obj.get("action")
    if a == "allow":
        return ("allow",)
    if a == "errno":
        e = obj.get("errno")
        if not isinstance(e, int) or isinstance(e, bool) or not 1 <= e <= ERRNO_MAX:
            raise PolicyError(f"{what}: errno must be an integer in 1..{ERRNO_MAX}")
        return ("errno", e)
    raise PolicyError(f"{what}: unknown action {a!r} (want 'allow' or 'errno')")


class Rule:
    def __init__(self, index, name, nr, cond, action):
        self.index = index
        self.name = name
        self.nr = nr
        self.cond = cond
        self.action = action


class Policy:
    def __init__(self, default, rules):
        self.default = default
        self.rules = rules


def parse_policy(obj):
    if not isinstance(obj, dict):
        raise PolicyError("top-level JSON object required")
    default = parse_action(obj.get("default", DEFAULT_ACTION), "default")
    raw_rules = obj.get("rules")
    if not isinstance(raw_rules, list):
        raise PolicyError("'rules': list required")
    rules = []
    for i, r in enumerate(raw_rules):
        if not isinstance(r, dict):
            raise PolicyError(f"rule {i}: object required")
        nr = r.get("syscall")
        if not isinstance(nr, int) or isinstance(nr, bool) or not 0 <= nr < X32_SYSCALL_BIT:
            raise PolicyError(
                f"rule {i}: syscall must be an integer in [0, 2^30) "
                f"without the x32 bit, got {nr!r}")
        cond = None
        if "condition" in r:
            leaves = [0]
            try:
                cond = parse_condition(r["condition"], 0, leaves)
            except PolicyError as e:
                raise PolicyError(f"rule {i}: {e}") from e
            if leaves[0] > MAX_COND_LEAVES_PER_RULE:
                raise PolicyError(
                    f"rule {i}: {leaves[0]} comparison conditions exceed "
                    f"the limit of {MAX_COND_LEAVES_PER_RULE}")
        action = parse_action(r.get("action"), f"rule {i}")
        rules.append(Rule(i, r.get("name", f"rule-{i}"), nr, cond, action))
    return Policy(default, rules)


def load_policy(path):
    with open(path) as f:
        return parse_policy(json.load(f))


def encode_action(action):
    if action[0] == "allow":
        return RET_ALLOW
    return RET_ERRNO | action[1]


def action_text(k):
    if k == RET_ALLOW:
        return "ALLOW"
    if k == RET_KILL_PROCESS:
        return "KILL_PROCESS"
    if (k & 0xFFFF0000) == RET_ERRNO:
        return f"ERRNO({k & 0xFFFF})"
    return f"0x{k:08x}"


# ------------------------------------------------------- policy evaluator
# Independent reference semantics: what the JSON policy *means*.  The cBPF
# interpreter below must agree with this on every synthesized input.

def eval_condition(cond, args):
    op = cond[0]
    if op == "eq":
        return args[cond[1]] == cond[2]
    if op == "range":
        return cond[2] <= args[cond[1]] <= cond[3]
    if op == "and":
        return all(eval_condition(c, args) for c in cond[1])
    if op == "or":
        return any(eval_condition(c, args) for c in cond[1])
    if op == "not":
        return not eval_condition(cond[1], args)
    raise AssertionError(op)


def evaluate(policy, nr, arch, args):
    """Return the seccomp return value the policy mandates."""
    if arch != AUDIT_ARCH_X86_64:
        return RET_KILL_PROCESS
    if nr & X32_SYSCALL_BIT:
        return RET_KILL_PROCESS
    for rule in policy.rules:
        if rule.nr == nr and (rule.cond is None or eval_condition(rule.cond, args)):
            return encode_action(rule.action)
    return encode_action(policy.default)


# ---------------------------------------------------------------- compiler

class Label:
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name


class Insn:
    """A classic-BPF instruction with symbolic jump targets (Label|None)."""
    __slots__ = ("code", "k", "jt", "jf", "comment", "rule")

    def __init__(self, code, k=0, jt=None, jf=None, comment="", rule=-1):
        self.code = code
        self.k = k
        self.jt = jt
        self.jf = jf
        self.comment = comment
        self.rule = rule


class Compiled:
    def __init__(self, insns, metas, n_expanded, label_pos, labels):
        self.insns = insns            # list of (code, jt, jf, k), fully resolved
        self.metas = metas            # parallel list of Insn (comment/rule)
        self.n_expanded = n_expanded  # conditional jumps rewritten via JA
        self.label_pos = label_pos    # id(Label) -> insn index
        self.labels = labels          # named labels for the map


class Compiler:
    def __init__(self):
        self.items = []               # Insn | Label
        self.nlabels = 0

    def label(self, name):
        self.nlabels += 1
        return Label(f"{name}{self.nlabels}")

    def place(self, lbl):
        self.items.append(lbl)

    def emit(self, code, k=0, comment="", rule=-1):
        self.items.append(Insn(code, k=k, comment=comment, rule=rule))

    def emit_jcc(self, code, k, jt, jf, comment="", rule=-1):
        self.items.append(Insn(code, k=k, jt=jt, jf=jf, comment=comment, rule=rule))

    # -- condition tree -> cBPF; control leaves via labels lt (true) / lf (false)
    def gen_condition(self, cond, lt, lf, rule):
        op = cond[0]
        if op == "eq":
            _, arg, v = cond
            off = OFF_ARGS + 8 * arg
            hi, lo = (v >> 32) & 0xFFFFFFFF, v & 0xFFFFFFFF
            # full 64-bit compare: high word first, then low word
            self.emit(LD_W_ABS, off + 4, f"arg{arg}.hi", rule)
            self.emit_jcc(JEQ_K, hi, None, lf, f"arg{arg}.hi == 0x{hi:08x}?", rule)
            self.emit(LD_W_ABS, off, f"arg{arg}.lo", rule)
            self.emit_jcc(JEQ_K, lo, lt, lf, f"arg{arg}.lo == 0x{lo:08x}?", rule)
            return
        if op == "range":
            _, arg, lo_v, hi_v = cond
            off = OFF_ARGS + 8 * arg
            lh, ll = (lo_v >> 32) & 0xFFFFFFFF, lo_v & 0xFFFFFFFF
            hh, hl = (hi_v >> 32) & 0xFFFFFFFF, hi_v & 0xFFFFFFFF
            l_up = self.label("upper")
            # x >= lo  <=>  xh > lh || (xh == lh && xl >= ll)
            self.emit(LD_W_ABS, off + 4, f"arg{arg}.hi", rule)
            self.emit_jcc(JGT_K, lh, l_up, None, f"arg{arg}.hi > lo.hi?", rule)
            self.emit_jcc(JEQ_K, lh, None, lf, f"arg{arg}.hi == lo.hi?", rule)
            self.emit(LD_W_ABS, off, f"arg{arg}.lo", rule)
            self.emit_jcc(JGE_K, ll, l_up, lf, f"arg{arg}.lo >= lo.lo?", rule)
            # x <= hi  <=>  xh < hh || (xh == hh && xl <= hl)
            self.place(l_up)
            self.emit(LD_W_ABS, off + 4, f"arg{arg}.hi", rule)
            self.emit_jcc(JGT_K, hh, lf, None, f"arg{arg}.hi > hi.hi?", rule)
            self.emit_jcc(JEQ_K, hh, None, lt, f"arg{arg}.hi == hi.hi?", rule)
            self.emit(LD_W_ABS, off, f"arg{arg}.lo", rule)
            self.emit_jcc(JGT_K, hl, lf, lt, f"arg{arg}.lo > hi.lo?", rule)
            return
        if op == "and":
            children = cond[1]
            for c in children[:-1]:
                mid = self.label("and")
                self.gen_condition(c, mid, lf, rule)
                self.place(mid)
            self.gen_condition(children[-1], lt, lf, rule)
            return
        if op == "or":
            children = cond[1]
            for c in children[:-1]:
                mid = self.label("or")
                self.gen_condition(c, lt, mid, rule)
                self.place(mid)
            self.gen_condition(children[-1], lt, lf, rule)
            return
        if op == "not":
            self.gen_condition(cond[1], lf, lt, rule)  # swap continuations
            return
        raise AssertionError(op)


def _layout(items):
    pos = {}
    insns = []
    for it in items:
        if isinstance(it, Label):
            pos[id(it)] = len(insns)
        else:
            insns.append(it)
    return insns, pos


def _resolve(items):
    """Fixpoint: rewrite conditional jumps whose target is further than the
    8-bit jt/jf range (255) through a 32-bit JA trampoline:

        jcc k, jt=T, jf=F            (T far, F near)
    becomes
        jcc k, jt=+0 (-> next), jf=F
        ja  T
    and symmetrically; if both are far, two trampolines are emitted.
    """
    expanded = 0
    items = list(items)
    for _ in range(10000):
        insns, pos = _layout(items)
        bad = None
        for i, ins in enumerate(insns):
            if (ins.code & 0x07) != BPF_JMP or ins.code == JA:
                continue
            jto = pos[id(ins.jt)] - (i + 1) if ins.jt is not None else 0
            jfo = pos[id(ins.jf)] - (i + 1) if ins.jf is not None else 0
            if jto < 0 or jfo < 0:
                raise CompileError(f"backward conditional jump at insn {i}")
            if jto > 255 or jfo > 255:
                bad = (ins, jto > 255, jfo > 255)
                break
        if bad is None:
            return items, expanded
        ins, t_far, f_far = bad
        meta = dict(comment=ins.comment, rule=ins.rule)
        # A near target may be None (fall through to the next insn).  Once a
        # trampoline is inserted between the jcc and that next insn, the
        # fall-through would land on the trampoline, so give it an explicit
        # label placed after the trampoline instead.
        if t_far and f_far:
            l1, l2 = Label("trampT"), Label("trampF")
            new = [Insn(ins.code, k=ins.k, jt=l1, jf=l2, **meta),
                   l1, Insn(JA, jt=ins.jt, comment="trampoline -> T", rule=ins.rule),
                   l2, Insn(JA, jt=ins.jf, comment="trampoline -> F", rule=ins.rule)]
        elif t_far:
            l1 = Label("trampT")
            if ins.jf is None:
                ln = Label("fall")
                new = [Insn(ins.code, k=ins.k, jt=l1, jf=ln, **meta),
                       l1, Insn(JA, jt=ins.jt, comment="trampoline -> T", rule=ins.rule),
                       ln]
            else:
                new = [Insn(ins.code, k=ins.k, jt=l1, jf=ins.jf, **meta),
                       l1, Insn(JA, jt=ins.jt, comment="trampoline -> T", rule=ins.rule)]
        else:
            l1 = Label("trampF")
            if ins.jt is None:
                ln = Label("fall")
                new = [Insn(ins.code, k=ins.k, jt=ln, jf=l1, **meta),
                       l1, Insn(JA, jt=ins.jf, comment="trampoline -> F", rule=ins.rule),
                       ln]
            else:
                new = [Insn(ins.code, k=ins.k, jt=ins.jt, jf=l1, **meta),
                       l1, Insn(JA, jt=ins.jf, comment="trampoline -> F", rule=ins.rule)]
        # replace the offending instruction object in the item stream
        for idx, it in enumerate(items):
            if it is ins:
                items[idx:idx + 1] = new
                break
        expanded += 1
    raise CompileError("conditional-jump resolution did not converge")


def _finalize(items):
    insns, pos = _layout(items)
    final = []
    for i, ins in enumerate(insns):
        if ins.code == JA:
            off = pos[id(ins.jt)] - (i + 1)
            if not 0 <= off <= 0xFFFFFFFF:
                raise CompileError(f"JA out of range at insn {i}")
            final.append((ins.code, 0, 0, off))
        elif (ins.code & 0x07) == BPF_JMP:
            jto = pos[id(ins.jt)] - (i + 1) if ins.jt is not None else 0
            jfo = pos[id(ins.jf)] - (i + 1) if ins.jf is not None else 0
            if not (0 <= jto <= 255 and 0 <= jfo <= 255):
                raise CompileError(f"unresolved long jump at insn {i}")
            final.append((ins.code, jto, jfo, ins.k))
        else:
            final.append((ins.code, 0, 0, ins.k))
    return final, insns, pos


def compile_policy(policy):
    c = Compiler()
    l_kill = c.label("kill")
    l_default = c.label("default")

    # Prologue: architecture check, then x32-bit rejection.
    c.emit(LD_W_ABS, OFF_ARCH, "load arch")
    c.emit_jcc(JEQ_K, AUDIT_ARCH_X86_64, None, l_kill,
               "arch == AUDIT_ARCH_X86_64?")
    c.emit(LD_W_ABS, OFF_NR, "load nr")
    c.emit(ALU_AND_K, X32_SYSCALL_BIT, "nr & __X32_SYSCALL_BIT")
    c.emit_jcc(JEQ_K, 0, None, l_kill, "x32 bit clear?")

    rule_labels = []
    for i, rule in enumerate(policy.rules):
        l_start = c.label(f"rule{i}")
        l_action = c.label(f"rule{i}_action")
        l_next = c.label(f"rule{i}_next")
        c.place(l_start)
        c.emit(LD_W_ABS, OFF_NR, "load nr", i)
        c.emit_jcc(JEQ_K, rule.nr, None, l_next, f"nr == {rule.nr}?", i)
        if rule.cond is not None:
            c.gen_condition(rule.cond, l_action, l_next, i)
        c.place(l_action)
        c.emit(RET_K, encode_action(rule.action),
               f"rule {i} ({rule.name}): {action_text(encode_action(rule.action))}", i)
        c.place(l_next)
        rule_labels.append((l_start, l_action, l_next))

    c.place(l_default)
    c.emit(RET_K, encode_action(policy.default), "default action", -2)
    c.place(l_kill)
    c.emit(RET_K, RET_KILL_PROCESS, "kill (arch/x32 mismatch)", -3)

    items, n_expanded = _resolve(c.items)
    insns, metas, pos = _finalize(items)
    if len(insns) > BPF_MAXINSNS:
        raise CompileError(f"filter has {len(insns)} instructions > {BPF_MAXINSNS}")
    labels = {
        "default": pos[id(l_default)],
        "kill": pos[id(l_kill)],
        "rules": [(pos[id(s)], pos[id(a)], pos[id(n)]) for s, a, n in rule_labels],
    }
    return Compiled(insns, metas, n_expanded, pos, labels)


# -------------------------------------------------- static filter verifier
# Mirrors the kernel's classic-BPF checks plus seccomp-specific rules:
# every path must end at a legal return instruction.

def _valid_ret(k):
    if k in (RET_ALLOW, RET_KILL_PROCESS):
        return True
    return (k & 0xFFFF0000) == RET_ERRNO and 1 <= (k & 0xFFFF) <= ERRNO_MAX


def verify_static(insns):
    n = len(insns)
    if not 1 <= n <= BPF_MAXINSNS:
        raise BPFError(f"filter length {n} out of range 1..{BPF_MAXINSNS}")
    for i, (code, jt, jf, k) in enumerate(insns):
        cls = code & 0x07
        if cls == BPF_LD and (code & 0xE0) == BPF_ABS:
            width = {BPF_W: 4, BPF_H: 2, BPF_B: 1}.get(code & 0x18)
            if width is None or k + width > SECCOMP_DATA_LEN:
                raise BPFError(f"insn {i}: load outside seccomp_data")
        if cls == BPF_JMP:
            if (code & 0xF0) == BPF_JA:
                if i + 1 + k >= n:
                    raise BPFError(f"insn {i}: JA target out of bounds")
            else:
                if not (0 <= jt <= 255 and 0 <= jf <= 255):
                    raise BPFError(f"insn {i}: conditional offset exceeds 8 bits")
                if i + 1 + jt >= n or i + 1 + jf >= n:
                    raise BPFError(f"insn {i}: jump target out of bounds")
        if cls == BPF_RET and not (code & 0x08) and not _valid_ret(k):
            raise BPFError(f"insn {i}: illegal seccomp return value 0x{k:08x}")
    if insns[-1][0] != RET_K:
        raise BPFError("last instruction is not a return")
    seen = [False] * n
    stack = [0]
    while stack:
        i = stack.pop()
        if seen[i]:
            continue
        seen[i] = True
        code, jt, jf, k = insns[i]
        cls = code & 0x07
        if cls == BPF_RET:
            continue
        if cls == BPF_JMP and (code & 0xF0) == BPF_JA:
            stack.append(i + 1 + k)
        elif cls == BPF_JMP:
            stack.append(i + 1 + jt)
            stack.append(i + 1 + jf)
        else:
            if i + 1 >= n:
                raise BPFError(f"insn {i}: falls off the end of the filter")
            stack.append(i + 1)
    if not all(seen):
        raise BPFError("unreachable instructions present")


# ------------------------------------------------------- cBPF interpreter
# Executes the *emitted filter file* against a synthesized seccomp_data,
# so the exact bytes handed to the kernel are what gets cross-checked.

def interp(insns, data):
    A = 0
    X = 0
    M = [0] * 16
    pc = 0
    n = len(insns)
    for _ in range(1000000):
        if not 0 <= pc < n:
            raise BPFError(f"pc out of bounds: {pc}")
        code, jt, jf, k = insns[pc]
        cls = code & 0x07
        npc = pc + 1
        if cls == BPF_LD:
            size = code & 0x18
            mode = code & 0xE0
            if mode == BPF_IMM:
                A = k
            elif mode == BPF_ABS:
                width = {BPF_W: 4, BPF_H: 2, BPF_B: 1}[size]
                if k + width > len(data):
                    raise BPFError("load outside seccomp_data")
                A = int.from_bytes(data[k:k + width], "little")
            elif mode == BPF_MEM:
                A = M[k & 15]
            elif mode == BPF_LEN:
                A = len(data)
            else:
                raise BPFError(f"unsupported LD mode 0x{mode:x}")
        elif cls == BPF_LDX:
            mode = code & 0xE0
            if mode == BPF_IMM:
                X = k
            elif mode == BPF_MEM:
                X = M[k & 15]
            elif mode == BPF_LEN:
                X = len(data)
            else:
                raise BPFError(f"unsupported LDX mode 0x{mode:x}")
        elif cls == BPF_ST:
            M[k & 15] = A
        elif cls == BPF_STX:
            M[k & 15] = X
        elif cls == BPF_ALU:
            op = code & 0xF0
            src = X if (code & 0x08) else k
            if op == BPF_ADD:
                A = (A + src) & 0xFFFFFFFF
            elif op == BPF_SUB:
                A = (A - src) & 0xFFFFFFFF
            elif op == BPF_MUL:
                A = (A * src) & 0xFFFFFFFF
            elif op == BPF_DIV:
                if src == 0:
                    return 0
                A = (A // src) & 0xFFFFFFFF
            elif op == BPF_OR:
                A |= src
            elif op == BPF_AND:
                A &= src
            elif op == BPF_LSH:
                A = (A << src) & 0xFFFFFFFF
            elif op == BPF_RSH:
                A = (A >> src) & 0xFFFFFFFF
            elif op == BPF_NEG:
                A = (-A) & 0xFFFFFFFF
            elif op == BPF_MOD:
                if src == 0:
                    return 0
                A %= src
            elif op == BPF_XOR:
                A ^= src
            else:
                raise BPFError(f"unsupported ALU op 0x{op:x}")
        elif cls == BPF_JMP:
            op = code & 0xF0
            src = X if (code & 0x08) else k
            if op == BPF_JA:
                npc = pc + 1 + k
            elif op == BPF_JEQ:
                npc = pc + 1 + (jt if A == src else jf)
            elif op == BPF_JGT:
                npc = pc + 1 + (jt if A > src else jf)
            elif op == BPF_JGE:
                npc = pc + 1 + (jt if A >= src else jf)
            elif op == BPF_JSET:
                npc = pc + 1 + (jt if (A & src) else jf)
            else:
                raise BPFError(f"unsupported JMP op 0x{op:x}")
        elif cls == BPF_RET:
            return A if (code & 0x08) else k
        elif cls == BPF_MISC:
            if code == 0x07:      # TAX
                X = A
            elif code == 0x87:    # TXA
                A = X
            else:
                raise BPFError(f"unsupported MISC 0x{code:x}")
        else:
            raise BPFError(f"unsupported class 0x{cls:x}")
        pc = npc
    raise BPFError("step limit exceeded")


# ------------------------------------------------------------ filter codec

def encode_filter(insns):
    return b"".join(struct.pack("<HBBI", code, jt, jf, k)
                    for (code, jt, jf, k) in insns)


def decode_filter(data):
    if len(data) % 8:
        raise BPFError("filter file size is not a multiple of 8")
    return [struct.unpack_from("<HBBI", data, off)
            for off in range(0, len(data), 8)]


# ------------------------------------------------------ test case synthesis

def _interesting_u64():
    return [0, 1, 2, 3, 15, 16, 255, 256, 4095, 4096,
            2**31 - 1, 2**31, 2**32 - 1, 2**32, 2**32 + 1,
            2**63 - 1, 2**63, 2**64 - 2, 2**64 - 1]


def _leaf_boundaries(cond, out):
    op = cond[0]
    if op == "eq":
        _, a, v = cond
        s = out.setdefault(a, set())
        for x in (v, v - 1, v + 1, v & 0xFFFFFFFF, v >> 32,
                  (v & 0xFFFFFFFF) | (1 << 32)):
            if 0 <= x <= U64_MAX:
                s.add(x)
    elif op == "range":
        _, a, lo, hi = cond
        s = out.setdefault(a, set())
        mid = (lo + hi) // 2
        for x in (lo - 1, lo, lo + 1, mid, hi - 1, hi, hi + 1,
                  lo & 0xFFFFFFFF, hi & 0xFFFFFFFF,
                  2**32 - 1, 2**32, 2**32 + 1):
            if 0 <= x <= U64_MAX:
                s.add(x)
    elif op in ("and", "or"):
        for c in cond[1]:
            _leaf_boundaries(c, out)
    elif op == "not":
        _leaf_boundaries(cond[1], out)


def synthesize_cases(policy, seed=1234):
    """Synthesize (nr, arch, args) tuples exercising every rule boundary."""
    rng = random.Random(seed)
    cases = []
    seen = set()

    def add(nr, args, arch=AUDIT_ARCH_X86_64):
        key = (nr, arch, tuple(args))
        if key not in seen:
            seen.add(key)
            cases.append(key)

    pool_nrs = sorted({r.nr for r in policy.rules} | {999, 3900})
    for rule in policy.rules:
        if rule.cond is None:
            add(rule.nr, [0] * 6)
            add(rule.nr, [U64_MAX] * 6)
            continue
        bnd = {}
        _leaf_boundaries(rule.cond, bnd)
        # one boundary value at a time, other args zero
        for a, vals in bnd.items():
            for v in sorted(vals):
                args = [0] * 6
                args[a] = v
                add(rule.nr, args)
        # full cross product for two-argument rules (capped)
        args_used = sorted(bnd)
        if 2 == len(args_used):
            lists = [sorted(bnd[a])[:12] for a in args_used]
            for combo in itertools.product(*lists):
                args = [0] * 6
                for a, v in zip(args_used, combo):
                    args[a] = v
                add(rule.nr, args)
        # random combinations drawn from the boundary pool
        for _ in range(40):
            args = [0] * 6
            for a in args_used:
                args[a] = rng.choice(sorted(bnd[a]))
            add(rule.nr, args)
    # global random cases
    interesting = _interesting_u64()
    for _ in range(300):
        nr = rng.choice(pool_nrs)
        args = [rng.choice(interesting) if rng.random() < 0.5
                else rng.getrandbits(64) for _ in range(6)]
        add(nr, args)
    # arch-mismatch and x32 variants (software cross-check only)
    for nr, arch, args in list(cases[:40]):
        for bad_arch in (0, 0x40000003, 0xC00000B7):
            add(nr, list(args), arch=bad_arch)
        add(nr | X32_SYSCALL_BIT, list(args))
    return cases


# ------------------------------------------------------------ output files

def render_listing(comp, policy_path):
    lines = [
        f"# classic-BPF seccomp filter compiled from {policy_path}",
        f"# {len(comp.insns)} instructions, "
        f"{comp.n_expanded} long-jump fixups; all paths verified to end at RET",
        "# seccomp_data: nr@0 arch@4 ip@8 args[i]@16+8i (lo word first)",
    ]
    for i, ((code, jt, jf, k), meta) in enumerate(zip(comp.insns, comp.metas)):
        if code == LD_W_ABS:
            text = f"ld  w, [{k}]"
        elif code == ALU_AND_K:
            text = f"and #0x{k:08x}"
        elif code == JA:
            text = f"ja  -> {i + 1 + k}"
        elif code in (JEQ_K, JGT_K, JGE_K):
            op = {JEQ_K: "jeq", JGT_K: "jgt", JGE_K: "jge"}[code]
            text = f"{op} 0x{k:08x}, jt -> {i + 1 + jt}, jf -> {i + 1 + jf}"
        elif code == RET_K:
            text = f"ret {action_text(k)}"
        else:
            text = f"code=0x{code:02x} jt={jt} jf={jf} k={k}"
        tag = f" [rule {meta.rule}]" if meta.rule >= 0 else ""
        comment = f"  ; {meta.comment}{tag}" if meta.comment else ""
        lines.append(f"{i:4d}: {text:<44}{comment}")
    return "\n".join(lines) + "\n"


def render_map(comp, policy, policy_path):
    rules = []
    starts = [s for s, _, _ in comp.labels["rules"]]
    ends = starts[1:] + [comp.labels["default"]]
    for rule, (start, action_pos, _), end in zip(
            policy.rules, comp.labels["rules"], ends):
        rules.append({
            "index": rule.index,
            "name": rule.name,
            "syscall": rule.nr,
            "action": action_text(encode_action(rule.action)),
            "insns": [start, end],
            "action_insn": action_pos,
        })
    return {
        "policy": policy_path,
        "insn_count": len(comp.insns),
        "expanded_conditional_jumps": comp.n_expanded,
        "default_insn": comp.labels["default"],
        "kill_insn": comp.labels["kill"],
        "rules": rules,
        "insn_rule": [m.rule for m in comp.metas],
    }


def write_outputs(comp, policy, policy_path, outdir):
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "filter.bpf"), "wb") as f:
        f.write(encode_filter(comp.insns))
    with open(os.path.join(outdir, "listing.txt"), "w") as f:
        f.write(render_listing(comp, policy_path))
    with open(os.path.join(outdir, "map.json"), "w") as f:
        json.dump(render_map(comp, policy, policy_path), f, indent=2)


# ------------------------------------------------------------------ stages

def run_selftest(policy, filter_bytes, seed):
    insns = decode_filter(filter_bytes)
    verify_static(insns)
    cases = synthesize_cases(policy, seed)
    mismatches = []
    for nr, arch, args in cases:
        data = struct.pack("<IIQ6Q", nr, arch, 0, *args)
        want = evaluate(policy, nr, arch, args)
        got = interp(insns, data)
        if want != got:
            mismatches.append((nr, arch, args, want, got))
    return cases, mismatches


def build_plan(policy, cases):
    """Select synthesized cases that are safe to execute for real."""
    plan = []
    for nr, arch, args in cases:
        if arch != AUDIT_ARCH_X86_64 or (nr & X32_SYSCALL_BIT):
            continue                      # cannot fabricate arch/x32 for real
        ret = evaluate(policy, nr, arch, args)
        if ret == RET_ALLOW:
            if nr not in SAFE_EXEC_SYSCALLS:
                continue                  # would really execute: must be harmless
            expect = {"kind": "allow"}
        elif (ret & 0xFFFF0000) == RET_ERRNO:
            if nr not in SAFE_DENIED_SYSCALLS:
                continue
            expect = {"kind": "errno", "errno": ret & 0xFFFF}
        else:
            continue                      # KILL: never probed for real
        plan.append((nr, args, expect))
        if len(plan) >= MAX_PROBE_CASES:
            break
    return plan


def write_plan(plan, probes_path, expect_path):
    with open(probes_path, "wb") as f:
        for nr, args, _ in plan:
            f.write(struct.pack("<II6Q", nr, 0, *args))
    expect = {"cases": [
        {"nr": nr, "args": list(args), "expect": exp} for nr, args, exp in plan]}
    with open(expect_path, "w") as f:
        json.dump(expect, f, indent=2)


def check_results(expect, results_bytes):
    cases = expect["cases"]
    if len(results_bytes) % 16:
        return False, [f"results size {len(results_bytes)} is not a multiple of 16"]
    n = len(results_bytes) // 16
    if n != len(cases):
        return False, [f"expected {len(cases)} result records, got {n} "
                       f"(child died early or write/exit_group was denied)"]
    lines = []
    bad = 0
    for i, (case, off) in enumerate(zip(cases, range(0, len(results_bytes), 16))):
        ret, err, _pad = struct.unpack_from("<qii", results_bytes, off)
        exp = case["expect"]
        if exp["kind"] == "allow":
            ok = ret != -1
            want = "ALLOW (syscall executes, ret != -1)"
        else:
            ok = ret == -1 and err == exp["errno"]
            want = f"ERRNO({exp['errno']})"
        if not ok:
            bad += 1
            if bad <= 20:
                lines.append(
                    f"case {i}: nr={case['nr']} args="
                    f"{[hex(a) for a in case['args']]} want {want}, "
                    f"got ret={ret} errno={err}")
    if bad:
        lines.append(f"{bad}/{len(cases)} cases FAILED")
        return False, lines
    return True, [f"{len(cases)}/{len(cases)} kernel results match expectations"]


# ----------------------------------------------------------------- commands

def cmd_compile(args):
    policy = load_policy(args.policy)
    comp = compile_policy(policy)
    verify_static(comp.insns)
    write_outputs(comp, policy, args.policy, args.outdir)
    print(f"compile: {len(comp.insns)} insns, {comp.n_expanded} long-jump "
          f"fixups, {len(policy.rules)} rules -> {args.outdir}/"
          f"{{filter.bpf,listing.txt,map.json}}")
    return 0


def cmd_selftest(args):
    policy = load_policy(args.policy)
    if args.filter:
        with open(args.filter, "rb") as f:
            filter_bytes = f.read()
    else:
        filter_bytes = encode_filter(compile_policy(policy).insns)
    cases, mismatches = run_selftest(policy, filter_bytes, args.seed)
    if mismatches:
        for nr, arch, args, want, got in mismatches[:10]:
            print(f"MISMATCH nr={nr} arch=0x{arch:08x} "
                  f"args={[hex(a) for a in args]} "
                  f"want {action_text(want)} got {action_text(got)}")
        print(f"selftest: {len(mismatches)}/{len(cases)} mismatches")
        return 1
    print(f"selftest: evaluator == cBPF interpreter on all "
          f"{len(cases)} synthesized seccomp_data cases")
    return 0


def cmd_genplan(args):
    policy = load_policy(args.policy)
    cases = synthesize_cases(policy, args.seed)
    plan = build_plan(policy, cases)
    write_plan(plan, args.probes, args.expect)
    n_allow = sum(1 for _, _, e in plan if e["kind"] == "allow")
    print(f"genplan: {len(plan)} probe cases "
          f"({n_allow} allow, {len(plan) - n_allow} errno) "
          f"-> {args.probes}, {args.expect}")
    return 0


def cmd_check(args):
    with open(args.expect) as f:
        expect = json.load(f)
    with open(args.results, "rb") as f:
        results = f.read()
    ok, lines = check_results(expect, results)
    for line in lines:
        print(line)
    return 0 if ok else 1


def cmd_test(args):
    outdir = args.outdir or os.path.join(
        "out", os.path.splitext(os.path.basename(args.policy))[0])
    policy = load_policy(args.policy)

    comp = compile_policy(policy)
    verify_static(comp.insns)
    write_outputs(comp, policy, args.policy, outdir)
    print(f"compile: {len(comp.insns)} insns, {comp.n_expanded} long-jump "
          f"fixups, {len(policy.rules)} rules")

    filter_path = os.path.join(outdir, "filter.bpf")
    with open(filter_path, "rb") as f:
        filter_bytes = f.read()
    cases, mismatches = run_selftest(policy, filter_bytes, args.seed)
    if mismatches:
        print(f"selftest: FAILED ({len(mismatches)}/{len(cases)} mismatches)")
        return 1
    print(f"selftest: {len(cases)} synthesized cases, "
          f"evaluator == interpreter on all")

    plan = build_plan(policy, cases)
    probes_path = os.path.join(outdir, "probes.bin")
    expect_path = os.path.join(outdir, "expect.json")
    results_path = os.path.join(outdir, "results.bin")
    write_plan(plan, probes_path, expect_path)
    n_allow = sum(1 for _, _, e in plan if e["kind"] == "allow")
    print(f"genplan: {len(plan)} probe cases ({n_allow} allow, "
          f"{len(plan) - n_allow} errno)")

    proc = subprocess.run(
        [args.probe, filter_path, probes_path, results_path],
        capture_output=True, text=True, timeout=180)
    for line in (proc.stdout + proc.stderr).splitlines():
        print(f"  {line}")
    probe_ok = proc.returncode == 0

    with open(expect_path) as f:
        expect = json.load(f)
    results = b""
    if os.path.exists(results_path):
        with open(results_path, "rb") as f:
            results = f.read()
    check_ok, lines = check_results(expect, results)
    for line in lines:
        print(f"check: {line}")

    ok = probe_ok and check_ok
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


def main(argv):
    ap = argparse.ArgumentParser(prog="seccompc", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("compile", help="compile policy to filter + listing + map")
    p.add_argument("policy")
    p.add_argument("--outdir", required=True)

    p = sub.add_parser("selftest", help="cross-check evaluator vs cBPF interpreter")
    p.add_argument("policy")
    p.add_argument("--filter", help="filter file (default: compile in-memory)")
    p.add_argument("--seed", type=int, default=1234)

    p = sub.add_parser("genplan", help="write probe plan + expectations")
    p.add_argument("policy")
    p.add_argument("--probes", required=True)
    p.add_argument("--expect", required=True)
    p.add_argument("--seed", type=int, default=1234)

    p = sub.add_parser("check", help="compare probe results with expectations")
    p.add_argument("--results", required=True)
    p.add_argument("--expect", required=True)

    p = sub.add_parser("test", help="compile + selftest + genplan + probe + check")
    p.add_argument("policy")
    p.add_argument("--probe", default="./probe")
    p.add_argument("--outdir")
    p.add_argument("--seed", type=int, default=1234)

    args = ap.parse_args(argv)
    try:
        handler = {"compile": cmd_compile, "selftest": cmd_selftest,
                   "genplan": cmd_genplan, "check": cmd_check,
                   "test": cmd_test}[args.cmd]
        return handler(args)
    except (PolicyError, CompileError, BPFError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
