"""Independent reference evaluator for seccomp JSON policies.

This deliberately does NOT import compiler code-generation; it parses the
JSON policy with a small independent reader and computes decisions straight
from the source semantics. It is the oracle the generated cBPF is checked
against.

seccomp_data is a tuple/dict:
  {"nr": int, "arch": int, "args": [u64 x6], "ip": int}

Result is one of:
  ("allow",)  ("errno", n)  ("kill",)
Architecture mismatch and the x32 syscall bit always yield KILL first.
"""

import json

MASK64 = (1 << 64) - 1

ARCH_AUDIT = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
X32_BIT = 0x40000000


def _u64(s, where):
    if not isinstance(s, str) or not s.isdigit():
        raise ValueError("%s: decimal string required, got %r" % (where, s))
    v = int(s, 10)
    if v > MASK64:
        raise ValueError("%s: > uint64" % where)
    return v


def load(path_or_text, is_text=False):
    doc = json.loads(path_or_text) if is_text else json.load(
        open(path_or_text, "r", encoding="utf-8"))
    arch = doc.get("arch", "x86_64")
    if arch not in ARCH_AUDIT:
        raise ValueError("bad arch")

    def act(a):
        if a == "allow":
            return ("allow",)
        if a == "kill":
            return ("kill",)
        n = _u64(a["errno"], "errno")
        if not 1 <= n <= 4095:
            raise ValueError("errno range")
        return ("errno", n)

    rules = []
    for r in doc.get("rules", []):
        rules.append((int(r["syscall"]), act(r["action"]),
                      None if "when" not in r else r["when"]))
    return {"arch": arch, "default": act(doc.get("default", "kill")),
            "rules": rules}


def _eval_cond(node, args):
    """Independent tree walk, unsigned 64-bit arithmetic throughout."""
    kind, body = next(iter(node.items()))
    if kind == "and":
        return all(_eval_cond(c, args) for c in body)
    if kind == "or":
        return any(_eval_cond(c, args) for c in body)
    if kind == "not":
        return not _eval_cond(body, args)
    if kind == "arg":
        x = args[int(body["arg"])] & MASK64
        op = body["op"]
        if op == "range":
            return _u64(body["min"], "min") <= x <= _u64(body["max"], "max")
        v = _u64(body["value"], "value")
        return {
            "eq": lambda: x == v,
            "ne": lambda: x != v,
            "gt": lambda: x > v,
            "ge": lambda: x >= v,
            "lt": lambda: x < v,
            "le": lambda: x <= v,
        }[op]()
    raise ValueError("unknown node %r" % node)

def evaluate(policy, data):
    # Gate 1: exact architecture audit number.
    if data["arch"] != ARCH_AUDIT[policy["arch"]]:
        return ("kill",)
    nr = data["nr"] & 0xFFFFFFFF
    # Gate 2 (x86_64): x32 ABI bit set => kill, never dispatched natively.
    if policy["arch"] == "x86_64" and nr & X32_BIT:
        return ("kill",)
    # Gate 3: first matching rule in declared order.
    for sysnr, action, cond in policy["rules"]:
        if nr != sysnr:
            continue
        if cond is None or _eval_cond(cond, data["args"]):
            return action
    return policy["default"]
