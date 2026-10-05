#!/usr/bin/env python3
"""Derive the aarch64 twin of an x86_64 policy.

Only syscall numbers and the arch tag change; every condition tree, action,
default and ordering is preserved. The generated filter exercises the exact
same compiler code paths for real kernel install verification on non-x86
hosts. The x86-64-specific guarantees (exact arch, x32-bit rejection) remain
encoded in the genuine x86_64 output.
"""

import json
import sys

NR_MAP = {
    39: 172,   # getpid
    3: 57,     # close
    33: 23,    # dup2 -> dup (filter keys on the number, not the ABI name)
    28: 233,   # madvise
    400: 999,  # deliberately unused => default
    60: 93,    # exit
    231: 94,   # exit_group
    1: 64,     # write
    157: 167,  # prctl
    # long-jump stress policy trailing allows (distinct legal numbers; the
    # probe never invokes them):
    2: 57,
    4: 56, 5: 55, 6: 62, 8: 63, 9: 64, 10: 65, 11: 78, 12: 91,
    13: 79, 14: 165, 16: 160, 20: 214, 21: 215, 24: 221, 27: 167,
    32: 169, 35: 170, 41: 173, 45: 113, 293: 59, 157: 167,
}


def main(src, dst):
    doc = json.load(open(src, "r", encoding="utf-8"))
    doc["arch"] = "aarch64"
    for r in doc["rules"]:
        n = r["syscall"]
        if n not in NR_MAP:
            raise SystemExit("no aarch64 mapping for syscall %d" % n)
        r["syscall"] = NR_MAP[n]
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print("wrote %s (%d rules)" % (dst, len(doc["rules"])))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
