#!/usr/bin/env bash
# End-to-end test on a native x86-64 host: build the probe, compile all
# policies, cross-check evaluator vs cBPF interpreter, then load each
# filter in an isolated child process and compare real kernel results.
set -euo pipefail
cd "$(dirname "$0")"

CC="${CC:-cc}"
"$CC" -O2 -Wall -Wextra -o probe probe.c

python3 gen_longjump_policy.py

fail=0
for p in policies/range64.json policies/nested_not.json \
         policies/shadow.json policies/longjump.json; do
    name="$(basename "$p" .json)"
    echo "=== $name ==="
    if ! python3 seccompc.py test "$p" --probe ./probe --outdir "out/$name"; then
        fail=1
    fi
done

# the longjump policy must actually have exercised the >255 jump rewriting
python3 - <<'EOF'
import json
m = json.load(open("out/longjump/map.json"))
n = m["expanded_conditional_jumps"]
assert n > 0, "longjump policy compiled without long-jump fixups"
print(f"longjump policy: {n} conditional jumps rewritten through JA trampolines")
EOF

if [ "$fail" -ne 0 ]; then
    echo "TESTS FAILED"
    exit 1
fi
echo "ALL POLICY TESTS PASSED"
