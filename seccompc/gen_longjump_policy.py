#!/usr/bin/env python3
"""Generate policies/longjump.json.

A single rule with an OR of 30 range conditions compiles to ~300
instructions, so the conditional jumps from the early alternatives to
the rule's action (and to the next rule) exceed the 8-bit (255 insn)
classic-BPF range and must be rewritten through 32-bit JA trampolines.
"""
import json
import os

ranges_allow = [
    {"in_range": {"arg": 0, "lo": str(10 * (i + 1)), "hi": str(10 * (i + 1) + 1)}}
    for i in range(30)
]  # [10,11] [20,21] ... [300,301]

ranges_errno = [
    {"in_range": {"arg": 0, "lo": str(500 + 10 * i), "hi": str(500 + 10 * i + 1)}}
    for i in range(30)
]  # [500,501] [510,511] ... [790,791]

policy = {
    "default": {"action": "errno", "errno": 13},
    "rules": [
        {"name": "probe-write-result", "syscall": 1,
         "condition": {"eq": {"arg": 0, "value": "3"}},
         "action": {"action": "allow"}},
        {"name": "probe-exit", "syscall": 231,
         "action": {"action": "allow"}},
        {"name": "getpid-or-of-30-ranges", "syscall": 39,
         "condition": {"or": ranges_allow},
         "action": {"action": "allow"}},
        {"name": "getuid-or-of-30-ranges-errno", "syscall": 102,
         "condition": {"or": ranges_errno},
         "action": {"action": "errno", "errno": 78}},
        {"name": "getgid-deep-and-across-args", "syscall": 104,
         "condition": {"and": [
             {"in_range": {"arg": 0, "lo": "1000", "hi": "2000"}},
             {"eq": {"arg": 1, "value": "4294967296"}},
             {"in_range": {"arg": 2, "lo": "0",
                           "hi": "18446744073709551615"}},
             {"not": {"eq": {"arg": 3, "value": "7"}}},
             {"eq": {"arg": 4, "value": "8"}},
             {"in_range": {"arg": 5, "lo": "9", "hi": "10"}}]},
         "action": {"action": "errno", "errno": 77}},
    ],
}

out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "policies", "longjump.json")
with open(out, "w") as f:
    json.dump(policy, f, indent=2)
    f.write("\n")
print(f"wrote {out}")
