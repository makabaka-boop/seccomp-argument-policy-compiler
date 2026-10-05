# seccomp policy compiler + minimal C probe

A small, self-contained toolkit that compiles a JSON syscall policy into a
loadable **classic BPF (cBPF)** seccomp filter — without libseccomp — then
proves the filter correct three different ways.

```
tools/
  seccompcc        JSON policy -> .filter (raw sock_filter[]),
                                  .list (annotated disasm + provenance map),
                                  .stats (JSON summary)
  bpf.py           cBPF opcode / seccomp_data model
  compiler.py      policy parser + 64-bit codegen + long-jump relaxation
  evaluator.py     INDEPENDENT reference evaluator (policy oracle)
  interp.py        INDEPENDENT classic-BPF interpreter (runs the raw filter)
  difftest.py      evaluator  vs  interpreter over synthetic seccomp_data
  check_kernel.py  evaluator  vs  the REAL kernel, via the C probe
  mk_aarch64.py    host-verification twin (arch number remap)
policies/
  probe.json       x86-64 probe policy
  longjump.json    policy engineered to exceed the u8 jump range
probe/
  probe.c          fixed, side-effect-free kernel probe
Makefile
```

## Policy format

```jsonc
{
  "arch": "x86_64",                 // mandatory exact-arch gate
  "default": {"errno": "5"},        // allow | kill | {"errno":"N"}
  "rules": [
    { "syscall": 3, "action": {"errno": "92"},
      "when": {"arg": {"arg": 0, "op": "eq", "value": "999999"}} }
  ]
}
```

* Rules are matched **in order; the first match wins**; no match ⇒ `default`
  (default-deny oriented).
* Conditions, **constants are decimal strings** parsed as unsigned 64-bit:
  * leaves: `{arg:0..5, op:eq|ne|lt|le|gt|ge, value:"..."}`
  * closed interval: `{arg:0..5, op:"range", min:"...", max:"..."}`
  * booleans: `{"and":[…]}`, `{"or":[…]}`, `{"not": …}` (arbitrarily nested)
* At most **30 leaf comparisons per rule** (rejected at compile time).
* Actions: `"allow"`, `"kill"`, or `{"errno":"1..4095"}`.

## What the generated filter guarantees

* **Exact architecture gate**: loads `seccomp_data.arch`, compares against
  `AUDIT_ARCH_X86_64` (`0xc000003e`); any mismatch runs `RET KILL_PROCESS`.
* **x32 ABI rejection**: after the arch gate, any syscall number with the
  `0x40000000` bit set runs `RET KILL_PROCESS` — x32 numbers are never
  dispatched as native. Setting that bit in a policy is also a compile error.
* **Full unsigned 64-bit comparisons**: each leaf loads and tests **both**
  32-bit words of the argument (`args[i].hi`, `args[i].lo`) with a proper
  three-way unsigned split of the high word. Nothing is truncated to 32 bits.
* **Values, not pointed-to memory**: comparisons use the argument registers
  from `seccomp_data` only; the filter never dereferences a pointer.
* **All paths terminate in a legal `RET`** (`ALLOW` / `ERRNO(n)` /
  `KILL_PROCESS`). The compiler builds a reachability graph, bounds-checks
  every jump, requires the last instruction to be `RET`, and rejects programs
  over the 4096-instruction classic limit.
* **Long jumps**: conditional jump offsets are 8 bits. When a branch target
  lies >255 instructions away the compiler inserts a `JA` trampoline and
  re-resolves until every `jt/jf` fits. `policies/longjump.json` forces this
  (27 trampolines / 414 insns on x86-64).

## Build & test

```sh
make            # native probe + all filters + full verification
make test       # differential stage + real-kernel stage
make x86_64     # needs x86_64-linux-gnu-gcc; produces out/probe-x86_64
```

On an x86-64 machine the kernel stage loads the genuine x86-64 filter and
uses the aarch64 build only as the foreign-arch kill case. On other hosts it
instead runs the arch-remapped twin for semantics and loads the x86-64 filter
to confirm the arch gate kills in the real kernel; the x86-64 byte-level
correctness itself is covered by the architecture-independent differential
stage (the emitted cBPF is identical logic either way).

### Verification pipeline

1. **Differential** (`difftest.py`, ~300k decisions): independently evaluates
   the JSON policy and independently interprets the emitted raw filter over
   random + boundary synthetic `seccomp_data` (both 64-bit words, foreign
   arch, x32 bit, `2^32±` boundaries, nested NOT/AND/OR, first-match
   shadowing). It also structurally asserts: bounded loads only, every
   compared argument touches both words, and every conditional offset ≤255.
2. **Real kernel** (`check_kernel.py` + `probe.c`): the parent **never**
   installs a filter; it forks one isolated child per case, the child sets
   `PR_SET_NO_NEW_PRIVS` and installs the filter via `prctl`, performs one
   fixed side-effect-free syscall, and reports through its wait status
   (`exit(errno)` or `SIGSYS`). Observed kernel results are checked against
   the same independent evaluator. The probe policy explicitly allows only
   the install/exit bookkeeping calls.
3. **Long-jump acceptance**: the 400+ insn trampoline filter is actually
   installed (kernel BPF verifier) via the probe's `smoke` mode and checked
   at `2^32+` interval boundaries.

## Outputs

For `out/probe_x86_64` the compiler writes:

* `out/probe_x86_64.filter` — raw `struct sock_filter[]`, 8 bytes/insn
  (`u16 code; u8 jt; u8 jf; u32 k`, little endian); mmap/`prctl` ready.
* `out/probe_x86_64.list` — per-instruction disassembly with provenance
  comments (`arch gate`, `reject x32`, `rule N comparison <path>`,
  `LONG-JUMP TRAMPOLINE`, `ACTION …`) and a rule→instruction index map.
* `out/probe_x86_64.stats` — instruction count, trampoline count, rule table.

This project targets **policy-compilation correctness**; it is deliberately
not a general sandbox launcher.
