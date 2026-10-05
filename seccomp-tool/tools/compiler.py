"""seccomp policy -> classic BPF filter compiler.

Policy JSON schema
------------------
{
  "arch": "x86_64",                      # or "aarch64" (host self-test aid)
  "default": "allow" | "kill" | {"errno": "5"},
  "rules": [
    {"syscall": <nr int>,
     "action": "allow" | "kill" | {"errno": "77"},
     "when": <condition>}                # optional; missing => always matches
  ]
}

Conditions (constants are DECIMAL STRINGS, interpreted as unsigned 64-bit):
  {"arg": 0..5, "op": "eq"|"ne"|"gt"|"ge"|"lt"|"le", "value": "123"}
  {"arg": 0..5, "op": "range", "min": "1", "max": "4294967300"}  # closed
  {"and": [c, ...]} {"or": [c, ...]} {"not": c}

Rules are evaluated in order; first match wins. Every emitted path ends in
a legal RET (ALLOW / ERRNO(n) / KILL_PROCESS). No libseccomp involved.
"""

import json
import struct

from bpf import (Insn, LD_ABS_W, JMP_JA, JMP_JEQ_K, JMP_JGT_K, JMP_JGE_K,
                 RET_K, OFF_NR, OFF_ARCH, OFF_ARGS, SECCOMP_RET_KILL_PROCESS,
                 SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, MAX_FILTER_INSNS,
                 MAX_SHORT_JUMP)

ARCHES = {
    "x86_64": {"audit": 0xC000003E, "x32_bit": 0x40000000, "nr_max": 0x3FFFFFFF},
    "aarch64": {"audit": 0xC00000B7, "x32_bit": None, "nr_max": 0x3FFFFFFF},
}

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

LEAF_OPS = {"eq", "ne", "gt", "ge", "lt", "le", "range"}
MAX_CONDITIONS_PER_RULE = 30


class PolicyError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Labeled IR
# ---------------------------------------------------------------------------
class Label:
    __slots__ = ("name", "index")

    def __init__(self, name):
        self.name = name
        self.index = None

    def __repr__(self):
        return "<%s>" % self.name


class _Marker:
    __slots__ = ("label",)

    def __init__(self, label):
        self.label = label


class Builder:
    def __init__(self):
        self.elems = []
        self._serial = 0

    def fresh(self, prefix):
        self._serial += 1
        return Label("%s%d" % (prefix, self._serial))

    def mark(self, label):
        self.elems.append(_Marker(label))

    def emit(self, code, k=0, jt=None, jf=None, note=None):
        """Emit a conditional branch; jt/jf may be Label or None.

        None is encoded as a marker placed immediately after the branch so
        later trampoline insertion keeps fall-through semantics.
        """
        ins = Insn(code, k=k, note=note)
        fall = self.fresh("L")
        if jt is None:
            jt = fall
        if jf is None:
            jf = fall
        ins._jt_label = jt
        ins._jf_label = jf
        self.elems.append(ins)
        self.mark(fall)
        return ins

    def ja(self, target, note=None):
        ins = Insn(JMP_JA, k=0, note=note)
        ins._target = target
        self.elems.append(ins)
        return ins

    def plain(self, insn):
        self.elems.append(insn)
        return insn


# ---------------------------------------------------------------------------
# Policy parsing / validation
# ---------------------------------------------------------------------------
def _parse_decimal_u64(raw, where):
    if not isinstance(raw, str):
        raise PolicyError("%s: constant must be a decimal string, got %r"
                          % (where, raw))
    s = raw.strip()
    if not s or not s.isdigit():
        raise PolicyError("%s: not a non-negative decimal string: %r"
                          % (where, raw))
    v = int(s, 10)
    if v > MASK64:
        raise PolicyError("%s: value exceeds uint64: %s" % (where, raw))
    return v


def parse_action(obj, where):
    if obj == "allow":
        return ("A",)
    if obj == "kill":
        return ("K",)
    if isinstance(obj, dict) and set(obj) == {"errno"}:
        n = _parse_decimal_u64(obj["errno"], where + ".errno")
        if not (1 <= n <= 4095):
            raise PolicyError("%s: errno must be in 1..4095" % where)
        return ("E", n)
    raise PolicyError("%s: bad action %r" % (where, obj))


def _validate_cond(node, rule_idx, path, counter):
    """Return a normalized condition tree; count leaf comparisons."""
    if not isinstance(node, dict) or len(node) != 1:
        raise PolicyError("rule %d %s: condition must be {op: ...}, got %r"
                          % (rule_idx, path, node))
    kind, body = next(iter(node.items()))
    if kind in ("and", "or"):
        if not isinstance(body, list) or not body:
            raise PolicyError("rule %d %s: %s needs a non-empty list"
                              % (rule_idx, path, kind))
        children = [_validate_cond(c, rule_idx, "%s.%s[%d]" % (path, kind, i),
                                   counter)
                    for i, c in enumerate(body)]
        return (kind, children)
    if kind == "not":
        return ("not", _validate_cond(body, rule_idx, path + ".not", counter))
    if kind == "arg":
        if not isinstance(body, dict):
            raise PolicyError("rule %d %s: arg leaf must be object"
                              % (rule_idx, path))
        idx = body.get("arg")
        op = body.get("op")
        if not isinstance(idx, int) or not 0 <= idx <= 5:
            raise PolicyError("rule %d %s: arg must be 0..5" % (rule_idx, path))
        if op not in LEAF_OPS:
            raise PolicyError("rule %d %s: unknown op %r" % (rule_idx, path, op))
        if op == "range":
            lo = _parse_decimal_u64(body["min"],
                                    "%s rule %d" % (path, rule_idx))
            hi = _parse_decimal_u64(body["max"],
                                    "%s rule %d" % (path, rule_idx))
            if lo > hi:
                raise PolicyError("rule %d %s: range min > max"
                                  % (rule_idx, path))
            counter[0] += 1
            return ("range", idx, lo, hi)
        val = _parse_decimal_u64(body["value"],
                                 "%s rule %d" % (path, rule_idx))
        counter[0] += 1
        return (op, idx, val)
    raise PolicyError("rule %d %s: unknown condition kind %r"
                      % (rule_idx, path, kind))


def parse_policy(text):
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise PolicyError("invalid JSON: %s" % e)
    if not isinstance(doc, dict):
        raise PolicyError("top level must be an object")
    arch_name = doc.get("arch", "x86_64")
    if arch_name not in ARCHES:
        raise PolicyError("unsupported arch %r (want x86_64/aarch64)"
                          % arch_name)
    arch = ARCHES[arch_name]
    default = parse_action(doc.get("default", "kill"), "default")

    rules = []
    for i, r in enumerate(doc.get("rules", [])):
        if not isinstance(r, dict):
            raise PolicyError("rule %d: must be object" % i)
        nr = r.get("syscall")
        if not isinstance(nr, int) or not 0 <= nr <= arch["nr_max"] \
                or (arch["x32_bit"] and nr & arch["x32_bit"]):
            raise PolicyError(
                "rule %d: syscall must be a valid native 64-bit number "
                "(x32 bit 0x40000000 rejected at compile time)" % i)
        action = parse_action(r["action"], "rule %d.action" % i)
        counter = [0]
        cond = (None if "when" not in r
                else _validate_cond(r["when"], i, "when", counter))
        if counter[0] > MAX_CONDITIONS_PER_RULE:
            raise PolicyError(
                "rule %d: %d comparisons exceeds limit of %d"
                % (i, counter[0], MAX_CONDITIONS_PER_RULE))
        rules.append({"nr": nr, "action": action, "cond": cond,
                      "ncond": counter[0]})
    return {"arch_name": arch_name, "arch": arch,
            "default": default, "rules": rules}


# ---------------------------------------------------------------------------
# Condition code generation (full unsigned 64-bit semantics)
# ---------------------------------------------------------------------------
def _gen_leaf(b, node, ltrue, lfalse, rule_idx, path):
    op = node[0]
    arg_idx = node[1]
    base = OFF_ARGS + 8 * arg_idx
    n = ("cmp", rule_idx, path)

    if op == "range":
        # closed interval  lo <= x <= hi, as a direct conjunction without
        # re-entrant leaf expansion (which would share fall markers).
        ge_lo = ("ge", arg_idx, node[2])
        le_hi = ("le", arg_idx, node[3])
        second = b.fresh("range2")
        _emit_single_cmp(b, ge_lo, second, lfalse, rule_idx, path + ".ge")
        b.mark(second)
        _emit_single_cmp(b, le_hi, ltrue, lfalse, rule_idx, path + ".le")
        return

    _emit_single_cmp(b, node, ltrue, lfalse, rule_idx, path)


def _emit_single_cmp(b, node, ltrue, lfalse, rule_idx, path):
    op = node[0]
    arg_idx = node[1]
    base = OFF_ARGS + 8 * arg_idx
    n = ("cmp", rule_idx, path)
    v = node[2]
    hi = (v >> 32) & MASK32
    lo = v & MASK32

    low_ok = b.fresh("low")    # high word equal => compare low word
    mid = b.fresh("himid")     # first high test not taken => distinguish < vs =

    if op == "eq":
        b.plain(Insn(LD_ABS_W, k=base + 4, note=n))
        b.emit(JMP_JEQ_K, k=hi, jt=low_ok, jf=lfalse)
    elif op == "ne":
        b.plain(Insn(LD_ABS_W, k=base + 4, note=n))
        b.emit(JMP_JEQ_K, k=hi, jt=low_ok, jf=ltrue)
    else:
        # Three-way split of the unsigned high word needs two conditional
        # jumps: first separates one extreme, JEQ separates equal from the
        # other extreme, and only the equal-half case reaches the low test.
        b.plain(Insn(LD_ABS_W, k=base + 4, note=n))
        if op == "gt":
            # hi > vhi -> true ; otherwise hi <= vhi
            b.emit(JMP_JGT_K, k=hi, jt=ltrue, jf=mid)
            b.mark(mid)
            b.emit(JMP_JEQ_K, k=hi, jt=low_ok, jf=lfalse)
        elif op == "le":
            # hi > vhi -> false ; otherwise hi <= vhi
            b.emit(JMP_JGT_K, k=hi, jt=lfalse, jf=mid)
            b.mark(mid)
            b.emit(JMP_JEQ_K, k=hi, jt=low_ok, jf=ltrue)
        elif op == "ge":
            # hi >= vhi : equal -> low, greater -> true
            b.emit(JMP_JGE_K, k=hi, jt=mid, jf=lfalse)
            b.mark(mid)
            b.emit(JMP_JEQ_K, k=hi, jt=low_ok, jf=ltrue)
        elif op == "lt":
            # hi >= vhi : equal -> low, greater -> false
            b.emit(JMP_JGE_K, k=hi, jt=mid, jf=ltrue)
            b.mark(mid)
            b.emit(JMP_JEQ_K, k=hi, jt=low_ok, jf=lfalse)
        else:
            raise AssertionError(op)

    b.mark(low_ok)
    b.plain(Insn(LD_ABS_W, k=base, note=n))
    if op == "eq":
        b.emit(JMP_JEQ_K, k=lo, jt=ltrue, jf=lfalse)
    elif op == "ne":
        b.emit(JMP_JEQ_K, k=lo, jt=lfalse, jf=ltrue)
    elif op == "gt":
        b.emit(JMP_JGT_K, k=lo, jt=ltrue, jf=lfalse)
    elif op == "le":
        b.emit(JMP_JGT_K, k=lo, jt=lfalse, jf=ltrue)
    elif op == "ge":
        b.emit(JMP_JGE_K, k=lo, jt=ltrue, jf=lfalse)
    elif op == "lt":
        b.emit(JMP_JGE_K, k=lo, jt=lfalse, jf=ltrue)


def gen_cond(b, node, ltrue, lfalse, rule_idx, path):
    kind = node[0]
    if kind == "and":
        children = node[1]
        if not children:
            b.ja(ltrue)
            return
        if len(children) == 1:
            gen_cond(b, children[0], ltrue, lfalse, rule_idx, path + "[0]")
            return
        rest = b.fresh("and")
        gen_cond(b, children[0], rest, lfalse, rule_idx, path + "[0]")
        b.mark(rest)
        gen_cond(b, ("and", children[1:]), ltrue, lfalse, rule_idx,
                 path + ".tail")
    elif kind == "or":
        children = node[1]
        if not children:
            b.ja(lfalse)
            return
        if len(children) == 1:
            gen_cond(b, children[0], ltrue, lfalse, rule_idx, path + "[0]")
            return
        rest = b.fresh("or")
        gen_cond(b, children[0], ltrue, rest, rule_idx, path + "[0]")
        b.mark(rest)
        gen_cond(b, ("or", children[1:]), ltrue, lfalse, rule_idx,
                 path + ".tail")
    elif kind == "not":
        gen_cond(b, node[1], lfalse, ltrue, rule_idx, path + ".not")
    else:
        _gen_leaf(b, node, ltrue, lfalse, rule_idx, path)


# ---------------------------------------------------------------------------
# Whole filter
# ---------------------------------------------------------------------------
def action_ret(action):
    if action[0] == "A":
        return SECCOMP_RET_ALLOW
    if action[0] == "K":
        return SECCOMP_RET_KILL_PROCESS
    return SECCOMP_RET_ERRNO | (action[1] & 0xFFFF)


def action_name(action):
    if action[0] == "A":
        return "ALLOW"
    if action[0] == "K":
        return "KILL_PROCESS"
    return "ERRNO(%d)" % action[1]


def build_ir(policy):
    b = Builder()
    arch = policy["arch"]

    # 1) architecture gate: mismatch => KILL_PROCESS
    kill_lbl = b.fresh("kill")
    b.plain(Insn(LD_ABS_W, k=OFF_ARCH, note=("arch",)))
    b.emit(JMP_JEQ_K, k=arch["audit"], jf=kill_lbl,
           note=("arch",))

    # 2) reject the x32 ABI syscall bit (never treat 0x400000xx as native)
    if arch["x32_bit"]:
        b.plain(Insn(LD_ABS_W, k=OFF_NR, note=("x32",)))
        b.emit(JMP_JGT_K, k=arch["x32_bit"] - 1, jt=kill_lbl,
               note=("x32",))

    # 3) ordered dispatch interleaved with rule bodies.  A non-matching or
    #    condition-failing rule falls straight through to the next test, so
    #    all control flow is strictly forward (cBPF has no backwards jumps
    #    from a clean seccomp program layout).
    action_labels = {}

    def lbl_for(action):
        if action not in action_labels:
            action_labels[action] = b.fresh("act")
        return action_labels[action]

    default_lbl = b.fresh("default")
    n_rules = len(policy["rules"])

    for i, rule in enumerate(policy["rules"]):
        fail = (b.fresh("rule%d_fail" % i) if i < n_rules - 1
                else default_lbl)
        if arch["x32_bit"] is None or i > 0:
            b.plain(Insn(LD_ABS_W, k=OFF_NR, note=("dispatch", i)))
        body = b.fresh("rule%d_body" % i)
        b.emit(JMP_JEQ_K, k=rule["nr"], jt=body, jf=fail,
               note=("dispatch", i))
        b.mark(body)
        target = lbl_for(rule["action"])
        if rule["cond"] is not None:
            gen_cond(b, rule["cond"], target, fail, i, "when")
        else:
            b.ja(target)
        if i < n_rules - 1:
            b.mark(fail)

    # last rule's fail label IS default_lbl; nothing more needed

    # 4) terminal block: default, one RET per distinct action, KILL
    b.mark(default_lbl)
    b.plain(Insn(RET_K, k=action_ret(policy["default"]),
                 note=("ret", action_name(policy["default"]))))
    for action, lbl in action_labels.items():
        b.mark(lbl)
        b.plain(Insn(RET_K, k=action_ret(action),
                     note=("ret", action_name(action))))
    b.mark(kill_lbl)
    b.plain(Insn(RET_K, k=SECCOMP_RET_KILL_PROCESS,
                 note=("ret", "KILL_PROCESS")))
    return b


# ---------------------------------------------------------------------------
# Relaxation: expand forward branches that exceed the u8 jump range
# ---------------------------------------------------------------------------
def resolve(b):
    """Flatten IR -> (insns, label->index)."""
    insns, positions = [], {}
    for el in b.elems:
        if isinstance(el, _Marker):
            positions[id(el.label)] = len(insns)
        else:
            insns.append(el)
    return insns, positions


def relax(b):
    rounds = 0
    n_trampolines = 0
    while True:
        rounds += 1
        insns, pos = resolve(b)
        fix = None
        for idx, ins in enumerate(insns):
            if ins.code == JMP_JA:
                if id(ins._target) not in pos:
                    raise PolicyError(
                        "internal: JA target %s unplaced at %d (note=%r)"
                        % (ins._target.name, idx, ins.note))
                tgt = pos[id(ins._target)]
                if tgt < idx + 1:
                    raise PolicyError("internal: backward JA at %d" % idx)
                continue
            if ins._jt_label is None:
                continue
            for side, lbl in (("jt", ins._jt_label), ("jf", ins._jf_label)):
                if id(lbl) not in pos:
                    raise PolicyError(
                        "internal: branch label %s unplaced at %d (note=%r)"
                        % (lbl.name, idx, ins.note))
                dist = pos[id(lbl)] - (idx + 1)
                if dist < 0:
                    raise PolicyError("internal: backward branch at %d" % idx)
                if dist > MAX_SHORT_JUMP:
                    fix = (idx, side)
                    break
            if fix:
                break
        if fix is None:
            return insns, pos, n_trampolines

        idx, side = fix
        ins = insns[idx]
        # element in b.elems corresponding to ins, insert trampolines after it
        epos = b.elems.index(ins)

        # Determine which sides are far; insert one JA trampoline per far side.
        far = []
        for s, lbl in (("jt", ins._jt_label), ("jf", ins._jf_label)):
            if pos[id(lbl)] - (idx + 1) > MAX_SHORT_JUMP:
                far.append((s, lbl))
        inserts = []
        for s, lbl in far:
            t = b.fresh("tramp")
            ja = Insn(JMP_JA, k=0, note=("tramp",))
            ja._target = lbl
            inserts.append((t, ja))
            if s == "jt":
                ins._jt_label = t
            else:
                ins._jf_label = t
            n_trampolines += 1
        # splice in right after the branch (markers shift down -> fallthrough
        # semantics are preserved because fall targets are marker-based)
        for off, (t, ja) in enumerate(inserts):
            b.elems.insert(epos + 1 + 2 * off, _Marker(t))
            b.elems.insert(epos + 2 + 2 * off, ja)


def finalize_offsets(insns, pos):
    for idx, ins in enumerate(insns):
        if ins.code == JMP_JA:
            ins.k = pos[id(ins._target)] - (idx + 1)
        elif ins._jt_label is not None:
            jt = pos[id(ins._jt_label)] - (idx + 1)
            jf = pos[id(ins._jf_label)] - (idx + 1)
            if not (0 <= jt <= MAX_SHORT_JUMP and 0 <= jf <= MAX_SHORT_JUMP):
                raise PolicyError("internal: branch out of range after fixup")
            ins.jt, ins.jf = jt, jf
        # sanity: nothing dangling
    return insns


# ---------------------------------------------------------------------------
# Verification of every legal path
# ---------------------------------------------------------------------------
def verify(insns):
    if not insns:
        raise PolicyError("empty filter")
    if len(insns) > MAX_FILTER_INSNS:
        raise PolicyError("filter too large: %d > %d"
                          % (len(insns), MAX_FILTER_INSNS))
    n = len(insns)
    # Reachability graph: every reachable insn must terminate in RET; jumps
    # must stay in bounds and land on a real instruction.
    seen = [False] * n
    stack = [0]
    while stack:
        i = stack.pop()
        if i >= n or seen[i]:
            continue
        seen[i] = True
        c = insns[i].code
        if c == RET_K:
            continue
        if c == JMP_JA:
            stack.append(i + 1 + insns[i].k)
            continue
        if c in (JMP_JEQ_K, JMP_JGT_K, JMP_JGE_K):
            stack.append(i + 1 + insns[i].jt)
            stack.append(i + 1 + insns[i].jf)
            continue
        if c == LD_ABS_W:
            stack.append(i + 1)
            continue
        raise PolicyError("internal: unexpected opcode 0x%02x at %d" % (c, i))
    for i, s in enumerate(seen):
        if not s:
            raise PolicyError("internal: unreachable insn at %d" % i)
    if insns[-1].code != RET_K:
        raise PolicyError("internal: filter does not end in RET")
    for i, ins in enumerate(insns):
        c = ins.code
        if c == JMP_JA:
            for t in (i + 1 + ins.k,):
                if not (0 <= t < n):
                    raise PolicyError("jump out of bounds at %d" % i)
        elif c in (JMP_JEQ_K, JMP_JGT_K, JMP_JGE_K):
            for d in (ins.jt, ins.jf):
                t = i + 1 + d
                if not (0 <= t < n):
                    raise PolicyError("jump out of bounds at %d" % i)
                if insns[t].note and insns[t].note[0] == "tramp":
                    if insns[t].code != JMP_JA:
                        raise PolicyError("bad trampoline at %d" % t)


# ---------------------------------------------------------------------------
# Public compile entry point
# ---------------------------------------------------------------------------
def compile_policy(text):
    policy = parse_policy(text)
    b = build_ir(policy)
    insns, pos, n_tramp = relax(b)
    finalize_offsets(insns, pos)
    verify(insns)
    return policy, insns, n_tramp


def pack_filter(insns):
    return b"".join(i.packed() for i in insns)
