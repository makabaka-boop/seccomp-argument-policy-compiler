#!/usr/bin/env python3
"""
vm_test.py — run the probe-based verification inside an x86-64 qemu guest.

This harness exists because the development host is aarch64: the compiled
filters target AUDIT_ARCH_X86_64, so the real-kernel probe must run under
an x86-64 kernel.  It cross-compiles probe.c into a static x86-64 binary
(with zig cc), packs it into a tiny initramfs as /init together with the
filter and the probe plan, boots qemu-system-x86_64 (TCG), and reads the
hex-encoded results back from the serial console.

Required tools (override with env vars):
  ZIG      path to zig                 (default: /tmp/x86/zig/zig)
  QEMU     qemu-system-x86_64 binary   (default: /tmp/x86/rootfs/usr/bin/qemu-system-x86_64)
  VMLINUZ  x86-64 kernel image         (default: /tmp/x86/vmlinuz)
  QEMU_LIB LD_LIBRARY_PATH for qemu    (default: /tmp/x86/rootfs/usr/lib/x86_64-linux-gnu)
  QEMU_FIRMWARE  qemu -L firmware dir  (default: /tmp/x86/rootfs/usr/share/qemu)

Usage: python3 vm_test.py [policy.json ...]
"""

import os
import re
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import seccompc

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(HERE, "out", "vm")

ZIG = os.environ.get("ZIG", "/tmp/x86/zig/zig")
QEMU = os.environ.get("QEMU", "/tmp/x86/rootfs/usr/bin/qemu-system-x86_64")
VMLINUZ = os.environ.get("VMLINUZ", "/tmp/x86/vmlinuz")
QEMU_LIB = os.environ.get(
    "QEMU_LIB", "/tmp/x86/rootfs/usr/lib/aarch64-linux-gnu:"
                "/tmp/x86/rootfs/lib/aarch64-linux-gnu")
QEMU_FIRMWARE = os.environ.get(
    "QEMU_FIRMWARE", "/tmp/x86/rootfs/usr/share/qemu")

POLICIES = ["range64", "nested_not", "shadow", "longjump"]
QEMU_TIMEOUT = 240


def build_probe():
    out = os.path.join(BUILD, "probe.x86_64")
    if os.path.exists(out) and os.path.getmtime(out) > os.path.getmtime(
            os.path.join(HERE, "probe.c")):
        return out
    os.makedirs(BUILD, exist_ok=True)
    subprocess.run(
        [ZIG, "cc", "-target", "x86_64-linux-musl", "-static", "-O2",
         "-o", out, os.path.join(HERE, "probe.c")], check=True)
    return out


def cpio_newc(entries):
    """Build a newc-format cpio archive from (name, mode, data, dev) tuples."""
    out = b""
    ino = 1

    def rec(name, mode, data, rdev=(0, 0)):
        nonlocal out, ino
        hdr = b"070701"
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0,
                  rdev[0], rdev[1], len(name) + 1, 0]
        ino += 1
        rec_b = hdr + b"".join(f"{f & 0xFFFFFFFF:08x}".encode() for f in fields)
        rec_b += name.encode() + b"\0"
        rec_b += b"\0" * ((4 - len(rec_b) % 4) % 4)
        rec_b += data
        rec_b += b"\0" * ((4 - len(rec_b) % 4) % 4)
        return rec_b

    for name, mode, data, rdev in entries:
        out += rec(name, mode, data, rdev)
    out += rec("TRAILER!!!", 0, b"")
    out += b"\0" * ((512 - len(out) % 512) % 512)
    return out


def build_initramfs(path, probe_bin, filter_b, probes_b):
    with open(probe_bin, "rb") as f:
        probe = f.read()
    entries = [
        ("init", 0o100755, probe, (0, 0)),
        ("filter.bpf", 0o100644, filter_b, (0, 0)),
        ("probes.bin", 0o100644, probes_b, (0, 0)),
        ("dev", 0o040755, b"", (0, 0)),
        ("dev/console", 0o020600, b"", (5, 1)),
        ("dev/null", 0o020666, b"", (1, 3)),
    ]
    import gzip
    with open(path, "wb") as f:
        f.write(gzip.compress(cpio_newc(entries)))


def run_vm(initrd):
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = QEMU_LIB + ":" + env.get("LD_LIBRARY_PATH", "")
    cmd = [
        QEMU, "-kernel", VMLINUZ, "-initrd", initrd,
        "-append", "console=ttyS0 SECCOMPC_INIT=1 panic=-1 loglevel=3",
        "-display", "none", "-serial", "stdio", "-monitor", "none",
        "-no-reboot", "-m", "256", "-smp", "2",
        "-L", QEMU_FIRMWARE,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=QEMU_TIMEOUT, env=env)
    return proc.stdout + proc.stderr


def extract_results(console_out, results_path):
    m = re.search(r"@@RESULTS-BEGIN@@\s*([0-9a-f\s]*?)\s*@@RESULTS-END@@",
                  console_out)
    if not m:
        return False
    hexstr = re.sub(r"\s", "", m.group(1))
    with open(results_path, "wb") as f:
        f.write(bytes.fromhex(hexstr))
    return True


def test_policy(name):
    policy_path = os.path.join(HERE, "policies", name + ".json")
    outdir = os.path.join(BUILD, name)
    os.makedirs(outdir, exist_ok=True)
    policy = seccompc.load_policy(policy_path)

    comp = seccompc.compile_policy(policy)
    seccompc.verify_static(comp.insns)
    seccompc.write_outputs(comp, policy, policy_path, outdir)
    print(f"compile: {len(comp.insns)} insns, {comp.n_expanded} "
          f"long-jump fixups, {len(policy.rules)} rules")

    filter_bytes = seccompc.encode_filter(comp.insns)
    cases, mismatches = seccompc.run_selftest(policy, filter_bytes, 1234)
    if mismatches:
        print(f"selftest: FAILED ({len(mismatches)} mismatches)")
        return False
    print(f"selftest: {len(cases)} synthesized cases, "
          f"evaluator == interpreter on all")

    plan = seccompc.build_plan(policy, cases)
    probes_path = os.path.join(outdir, "probes.bin")
    expect_path = os.path.join(outdir, "expect.json")
    results_path = os.path.join(outdir, "results.bin")
    seccompc.write_plan(plan, probes_path, expect_path)
    print(f"genplan: {len(plan)} probe cases")

    initrd = os.path.join(outdir, "initrd.cpio.gz")
    with open(probes_path, "rb") as f:
        probes_b = f.read()
    build_initramfs(initrd, PROBE_BIN, filter_bytes, probes_b)

    console = run_vm(initrd)
    with open(os.path.join(outdir, "console.log"), "w") as f:
        f.write(console)
    for line in console.splitlines():
        if line.startswith("probe:"):
            print(f"  guest: {line}")
    if not extract_results(console, results_path):
        print("vm: FAILED (no results on serial console; see console.log)")
        return False

    import json
    with open(expect_path) as f:
        expect = json.load(f)
    with open(results_path, "rb") as f:
        results = f.read()
    ok, lines = seccompc.check_results(expect, results)
    for line in lines:
        print(f"check: {line}")
    return ok


def main(argv):
    global PROBE_BIN
    names = [os.path.splitext(os.path.basename(a))[0] for a in argv] or POLICIES
    print("== building static x86-64 probe ==")
    PROBE_BIN = build_probe()
    print(f"probe: {PROBE_BIN}")
    ok = True
    for name in names:
        print(f"=== {name} ===")
        try:
            if not test_policy(name):
                ok = False
        except Exception as e:  # keep testing other policies
            print(f"ERROR: {e}")
            ok = False
    print("ALL VM TESTS PASSED" if ok else "VM TESTS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
